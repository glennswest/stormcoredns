//! The DNS server: one `Server` per (transport, listen address), each
//! dispatching requests to the plugin chain of the best-matching zone.

pub mod build;
pub mod config;
pub mod grpc;
pub mod https;
pub mod quic;
pub mod tls;

use crate::dnsutil;
use crate::plugin::{client_write, Handler, HttpInfo, Next, Proto, Reply, Request};
use anyhow::{anyhow, Context, Result};
use once_cell::sync::Lazy;
use config::{ServerConfig, Transport};
use futures::FutureExt;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::serialize::binary::BinDecodable;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// A zone entry inside a server: the config and its finalised chain.
pub struct ZoneEntry {
    pub config: Arc<ServerConfig>,
    pub chain: Arc<Vec<Arc<dyn Handler>>>,
}

pub struct Server {
    /// Label for logs and metrics, e.g. `dns://:53`.
    pub label: String,
    pub transport: Transport,
    /// Bind addresses (`:53`, `127.0.0.1:53` ...).
    pub addrs: Vec<String>,
    /// zone → configs (several when `view` splits a zone).
    pub zones: HashMap<String, Vec<ZoneEntry>>,
    pub tls: Option<Arc<rustls::ServerConfig>>,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub idle_timeout: Duration,
    pub num_sockets: usize,
    pub debug: bool,
    pub graceful_timeout: Duration,
}

impl Server {
    /// Find the zone entry for a query name: longest matching zone, then
    /// the first config whose `view` filter accepts the request.
    fn lookup<'s>(&'s self, req: &Request) -> Option<&'s ZoneEntry> {
        let qname = req.name_uncached();
        let mut cursor: &str = &qname;
        loop {
            if let Some(entries) = self.zones.get(cursor) {
                for e in entries {
                    match &e.config.filter {
                        Some(f) if !f(req) => continue,
                        _ => return Some(e),
                    }
                }
            }
            if cursor == "." {
                return None;
            }
            // strip the leftmost label
            cursor = match cursor.find('.') {
                Some(i) if i + 1 < cursor.len() => &cursor[i + 1..],
                _ => ".",
            };
        }
    }

    /// Serve a wire-format query and return the wire-format response (None
    /// if nothing should be sent, which only happens for unparsable
    /// queries that have no id).
    pub async fn serve_bytes(
        &self,
        buf: &[u8],
        remote: SocketAddr,
        local: SocketAddr,
        proto: Proto,
        http: Option<HttpInfo>,
        tls_server_name: Option<String>,
    ) -> Option<Vec<u8>> {
        let msg = match Message::from_bytes(buf) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("{}: dropping malformed query from {}: {}", self.label, remote, e);
                // FORMERR with the id if we can read one
                if buf.len() >= 2 {
                    let id = u16::from_be_bytes([buf[0], buf[1]]);
                    let mut m = Message::new();
                    m.set_id(id);
                    m.set_message_type(hickory_proto::op::MessageType::Response);
                    m.set_response_code(ResponseCode::FormErr);
                    return m.to_vec().ok();
                }
                return None;
            }
        };
        let mut req = Request::new(msg, remote, local, proto);
        req.server = self.label.clone();
        req.http = http;
        req.tls_server_name = tls_server_name;
        let resp = self.serve_request(&mut req).await;
        let max = req.size();
        match dnsutil::encode_with_limit(&resp, max) {
            Ok(b) => Some(b),
            Err(e) => {
                tracing::warn!("{}: encoding response: {}", self.label, e);
                dnsutil::error_reply(&req.msg, ResponseCode::ServFail).to_vec().ok()
            }
        }
    }

    /// Run the request through the chain and always produce a response.
    pub async fn serve_request(&self, req: &mut Request) -> Message {
        // RFC 6891: unsupported EDNS version → BADVERS
        if let Some(e) = req.msg.edns() {
            if e.version() != 0 {
                let mut m = dnsutil::error_reply(&req.msg, ResponseCode::BADVERS);
                if let Some(ne) = m.extensions_mut().as_mut() {
                    ne.set_version(0);
                }
                return m;
            }
        }
        if req.msg.queries().is_empty() {
            return dnsutil::error_reply(&req.msg, ResponseCode::Refused);
        }
        let entry = match self.lookup(req) {
            Some(e) => e,
            None => {
                tracing::debug!("{}: no zone for {} from {}", self.label, req.name_uncached(), req.remote);
                return dnsutil::error_reply(&req.msg, ResponseCode::Refused);
            }
        };
        req.zone = entry.config.zone.clone();
        req.view = entry.config.view_name.clone();
        let chain = entry.chain.clone();
        let fut = Next::new(&chain).serve(req);
        let result = std::panic::AssertUnwindSafe(fut).catch_unwind().await;
        match result {
            Ok(Ok(Reply::Msg(mut m))) => {
                // make sure the id and question match the query
                m.set_id(req.msg.id());
                m.set_message_type(hickory_proto::op::MessageType::Response);
                if m.queries().is_empty() {
                    if let Some(q) = req.msg.queries().first() {
                        m.add_query(q.clone());
                    }
                }
                m
            }
            Ok(Ok(Reply::Rcode(rc))) => {
                if !client_write(rc) {
                    tracing::debug!("{}: {} {}: {:?} without response", self.label, req.name_uncached(), req.qtype(), rc);
                }
                dnsutil::error_reply(&req.msg, rc)
            }
            Ok(Err(e)) => {
                tracing::debug!("{}: {} {}: {}", self.label, req.name_uncached(), req.qtype(), e);
                dnsutil::error_reply(&req.msg, e.rcode)
            }
            Err(panic) => {
                crate::metrics::PANIC_COUNT.inc();
                let what = panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "unknown".into());
                tracing::error!("{}: panic serving {}: {}", self.label, req.name_uncached(), what);
                dnsutil::error_reply(&req.msg, ResponseCode::ServFail)
            }
        }
    }

    // ---------------------------------------------------------------- UDP

    pub async fn run_udp(self: Arc<Self>, sock: Arc<UdpSocket>, cancel: CancellationToken) {
        let local = sock.local_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, remote) = tokio::select! {
                _ = cancel.cancelled() => return,
                r = sock.recv_from(&mut buf) => match r {
                    Ok(v) => v,
                    Err(e) => {
                        // ICMP unreachable errors show up here on some platforms; keep going
                        tracing::debug!("{}: udp recv: {}", self.label, e);
                        continue;
                    }
                },
            };
            let pkt = buf[..n].to_vec();
            let srv = self.clone();
            let sock = sock.clone();
            tokio::spawn(async move {
                if let Some(resp) = srv.serve_bytes(&pkt, remote, local, Proto::Udp, None, None).await {
                    if let Err(e) = sock.send_to(&resp, remote).await {
                        tracing::debug!("{}: udp send to {}: {}", srv.label, remote, e);
                    }
                }
            });
        }
    }

    // ---------------------------------------------------------------- TCP

    pub async fn run_tcp(self: Arc<Self>, listener: TcpListener, cancel: CancellationToken) {
        loop {
            let (stream, remote) = tokio::select! {
                _ = cancel.cancelled() => return,
                r = listener.accept() => match r {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!("{}: tcp accept: {}", self.label, e);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                },
            };
            let local = stream.local_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
            let srv = self.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                srv.serve_stream(stream, remote, local, Proto::Tcp, None, cancel).await;
            });
        }
    }

    /// Serve length-prefixed DNS messages over a stream (TCP, TLS, QUIC-bidi
    /// is handled separately). Handles pipelining: each query is answered
    /// as it completes, responses are serialised through a channel.
    pub async fn serve_stream<S>(
        self: Arc<Self>,
        stream: S,
        remote: SocketAddr,
        local: SocketAddr,
        proto: Proto,
        tls_server_name: Option<String>,
        cancel: CancellationToken,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let (mut rd, mut wr) = tokio::io::split(stream);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        let label = self.label.clone();
        let write_timeout = self.write_timeout;
        let writer = tokio::spawn(async move {
            while let Some(resp) = rx.recv().await {
                let len = (resp.len() as u16).to_be_bytes();
                let mut out = Vec::with_capacity(resp.len() + 2);
                out.extend_from_slice(&len);
                out.extend_from_slice(&resp);
                match tokio::time::timeout(write_timeout, wr.write_all(&out)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        tracing::debug!("{}: stream write to {}: {}", label, remote, e);
                        break;
                    }
                    Err(_) => {
                        tracing::debug!("{}: stream write to {} timed out", label, remote);
                        break;
                    }
                }
            }
            let _ = wr.shutdown().await;
        });
        loop {
            let mut lenbuf = [0u8; 2];
            let r = tokio::select! {
                _ = cancel.cancelled() => break,
                r = tokio::time::timeout(self.idle_timeout, rd.read_exact(&mut lenbuf)) => r,
            };
            match r {
                Ok(Ok(_)) => {}
                _ => break,
            }
            let len = u16::from_be_bytes(lenbuf) as usize;
            if len == 0 {
                break;
            }
            let mut pkt = vec![0u8; len];
            match tokio::time::timeout(self.read_timeout, rd.read_exact(&mut pkt)).await {
                Ok(Ok(_)) => {}
                _ => break,
            }
            let srv = self.clone();
            let tx = tx.clone();
            let sni = tls_server_name.clone();
            tokio::spawn(async move {
                if let Some(resp) = srv.serve_bytes(&pkt, remote, local, proto, None, sni).await {
                    let _ = tx.send(resp).await;
                }
            });
        }
        drop(tx);
        let _ = writer.await;
    }
}

/// Bind a UDP socket with SO_REUSEADDR/SO_REUSEPORT so a reloaded instance
/// can bind before the old one is torn down.
pub fn bind_udp(addr: &str) -> Result<std::net::UdpSocket> {
    let sa = resolve_bind(addr)?;
    let sock = socket2::Socket::new(
        if sa.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 },
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    sock.set_reuse_address(true)?;
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    sock.set_reuse_port(true)?;
    if sa.is_ipv6() {
        let _ = sock.set_only_v6(false);
    }
    sock.set_nonblocking(true)?;
    // large buffers: bursts of queries should not be dropped by the kernel
    let _ = sock.set_recv_buffer_size(4 << 20);
    let _ = sock.set_send_buffer_size(4 << 20);
    sock.bind(&sa.into()).with_context(|| format!("binding udp {}", addr))?;
    Ok(sock.into())
}

pub fn bind_tcp(addr: &str) -> Result<std::net::TcpListener> {
    let sa = resolve_bind(addr)?;
    let sock = socket2::Socket::new(
        if sa.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 },
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    sock.set_reuse_address(true)?;
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    sock.set_reuse_port(true)?;
    if sa.is_ipv6() {
        let _ = sock.set_only_v6(false);
    }
    sock.set_nonblocking(true)?;
    sock.bind(&sa.into()).with_context(|| format!("binding tcp {}", addr))?;
    sock.listen(1024)?;
    Ok(sock.into())
}

/// `:53` → `[::]:53` (dual stack) or `0.0.0.0:53` when IPv6 is unavailable;
/// `host:port` otherwise.
pub fn resolve_bind(addr: &str) -> Result<SocketAddr> {
    if let Some(port) = addr.strip_prefix(':') {
        let p: u16 = port.parse().map_err(|_| anyhow!("bad port in {}", addr))?;
        // prefer dual-stack wildcard; fall back to v4 if v6 is disabled
        let v6: SocketAddr = format!("[::]:{}", p).parse().unwrap();
        if std::net::UdpSocket::bind(v6).is_ok() || std::net::TcpListener::bind(v6).is_ok() {
            return Ok(v6);
        }
        return Ok(format!("0.0.0.0:{}", p).parse().unwrap());
    }
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(sa);
    }
    // host name: resolve synchronously
    use std::net::ToSocketAddrs;
    addr.to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
        .ok_or_else(|| anyhow!("cannot resolve bind address {}", addr))
}

/// A running set of servers built from one Corefile.
pub struct Instance {
    pub servers: Vec<Arc<Server>>,
    pub configs: Vec<Arc<ServerConfig>>,
    cancel: CancellationToken,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    shutdown_hooks: Vec<config::Hook>,
    pub restart_failed_hooks: Vec<config::Hook>,
}

/// Signalled (by the `reload` plugin) to request a restart of the whole
/// instance from the Corefile on disk.
pub static RELOAD: Lazy<watch::Sender<u64>> = Lazy::new(|| watch::channel(0u64).0);

/// Ask the main loop to reload the Corefile.
pub fn request_reload() {
    RELOAD.send_modify(|v| *v += 1);
}

impl Instance {
    /// Build configs from parsed server blocks, run startup hooks, bind
    /// listeners, and start serving.
    pub async fn start(blocks: Vec<crate::corefile::ServerBlock>, opts: &build::BuildOptions) -> Result<Instance> {
        let mut built = build::build(blocks, opts)?;
        let mut shutdown_hooks = Vec::new();
        let mut restart_failed_hooks = Vec::new();
        let mut startup_hooks = Vec::new();
        let mut configs = Vec::new();
        for c in built.configs.drain(..) {
            let mut c = c;
            c.finalize_chain();
            startup_hooks.append(&mut c.startup);
            shutdown_hooks.append(&mut c.shutdown);
            restart_failed_hooks.append(&mut c.restart_failed);
            configs.push(Arc::new(c));
        }
        let servers = build::group_servers(&configs)?;
        let cancel = CancellationToken::new();
        let mut tasks = Vec::new();

        // bind everything first so a failure leaves nothing half-started
        let mut bound: Vec<(Arc<Server>, Vec<BoundListener>)> = Vec::new();
        for srv in &servers {
            let mut ls = Vec::new();
            for addr in &srv.addrs {
                for _ in 0..srv.num_sockets.max(1) {
                    match srv.transport {
                        Transport::Dns => {
                            let u = bind_udp(addr)?;
                            let t = bind_tcp(addr)?;
                            ls.push(BoundListener::Udp(u));
                            ls.push(BoundListener::Tcp(t));
                        }
                        Transport::Tls | Transport::Https | Transport::Grpc => {
                            let t = bind_tcp(addr)?;
                            ls.push(BoundListener::Tcp(t));
                        }
                        Transport::Quic => {
                            let u = bind_udp(addr)?;
                            ls.push(BoundListener::Udp(u));
                        }
                    }
                }
            }
            bound.push((srv.clone(), ls));
        }

        for h in startup_hooks {
            h().await?;
        }

        for (srv, ls) in bound {
            for l in ls {
                let c = cancel.clone();
                let s = srv.clone();
                let task = match (srv.transport, l) {
                    (Transport::Dns, BoundListener::Udp(u)) => {
                        let sock = Arc::new(UdpSocket::from_std(u)?);
                        tokio::spawn(s.run_udp(sock, c))
                    }
                    (Transport::Dns, BoundListener::Tcp(t)) => {
                        let l = TcpListener::from_std(t)?;
                        tokio::spawn(s.run_tcp(l, c))
                    }
                    (Transport::Tls, BoundListener::Tcp(t)) => {
                        let l = TcpListener::from_std(t)?;
                        tokio::spawn(tls::run_tls(s, l, c))
                    }
                    (Transport::Https, BoundListener::Tcp(t)) => {
                        let l = TcpListener::from_std(t)?;
                        tokio::spawn(https::run_https(s, l, c))
                    }
                    (Transport::Grpc, BoundListener::Tcp(t)) => {
                        let l = TcpListener::from_std(t)?;
                        tokio::spawn(grpc::run_grpc(s, l, c))
                    }
                    (Transport::Quic, BoundListener::Udp(u)) => tokio::spawn(quic::run_quic(s, u, c)),
                    _ => unreachable!("transport/listener mismatch"),
                };
                tasks.push(task);
            }
        }
        for srv in &servers {
            for a in &srv.addrs {
                let shown = if a.starts_with(':') { format!("[::]{}", a) } else { a.clone() };
                tracing::info!("{}://{} on {}", srv.transport.scheme(), shown, srv.zones.keys().cloned().collect::<Vec<_>>().join(", "));
            }
        }
        Ok(Instance { servers, configs, cancel, tasks, shutdown_hooks, restart_failed_hooks })
    }

    /// Stop listeners and run shutdown hooks.
    pub async fn stop(mut self) {
        self.cancel.cancel();
        for t in self.tasks.drain(..) {
            let _ = tokio::time::timeout(Duration::from_secs(5), t).await;
        }
        for h in self.shutdown_hooks.drain(..) {
            if let Err(e) = h().await {
                tracing::warn!("shutdown hook: {}", e);
            }
        }
    }

    /// Resolves when the `reload` plugin asks for a restart.
    pub async fn wait_reload() {
        let mut rx = RELOAD.subscribe();
        rx.mark_unchanged();
        if rx.changed().await.is_err() {
            futures::future::pending::<()>().await;
        }
    }
}

enum BoundListener {
    Udp(std::net::UdpSocket),
    Tcp(std::net::TcpListener),
}
