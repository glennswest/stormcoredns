//! The DNS server: one `Server` per (transport, listen address), each
//! dispatching requests to the plugin chain of the best-matching zone.

pub mod build;
pub mod config;
pub mod grpc;
pub mod http_util;
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
    pub graceful_timeout: Duration,
}

impl Server {
    /// Find the zone entry for a query name: longest matching zone, then
    /// the first config whose `view` filter accepts the request. As in
    /// CoreDNS, a config's metadata is collected before its filter runs, so
    /// `metadata()` in a view expression sees the providers' labels.
    fn lookup<'s>(&'s self, req: &mut Request) -> Option<&'s ZoneEntry> {
        let qname = req.name_uncached();
        let mut cursor: &str = &qname;
        loop {
            if let Some(entries) = self.zones.get(cursor) {
                for e in entries {
                    if let Some(md) = &e.config.metadata {
                        md.collect(req);
                    }
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
    /// if nothing should be sent: dropped, or unparsable without an id).
    /// Multi-message replies are reduced to their first message.
    pub async fn serve_bytes(
        &self,
        buf: &[u8],
        remote: SocketAddr,
        local: SocketAddr,
        proto: Proto,
        http: Option<HttpInfo>,
        tls_server_name: Option<String>,
    ) -> Option<Vec<u8>> {
        self.serve_bytes_all(buf, remote, local, proto, http, tls_server_name).await.and_then(|mut v| if v.is_empty() { None } else { Some(v.swap_remove(0)) })
    }

    /// Serve a wire-format query; every message of the reply, encoded.
    pub async fn serve_bytes_all(
        &self,
        buf: &[u8],
        remote: SocketAddr,
        local: SocketAddr,
        proto: Proto,
        http: Option<HttpInfo>,
        tls_server_name: Option<String>,
    ) -> Option<Vec<Vec<u8>>> {
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
                    return m.to_vec().ok().map(|b| vec![b]);
                }
                return None;
            }
        };
        let mut req = Request::new(msg, remote, local, proto);
        req.server = self.label.clone();
        req.http = http;
        req.tls_server_name = tls_server_name;
        req.raw = Some(Arc::new(buf.to_vec()));
        let msgs = self.serve_request_all(&mut req).await?;
        let max = req.size();
        let mut out = Vec::with_capacity(msgs.len());
        for resp in &msgs {
            match dnsutil::encode_with_limit(resp, max) {
                Ok(b) => out.push(b),
                Err(e) => {
                    tracing::warn!("{}: encoding response: {}", self.label, e);
                    out.push(dnsutil::error_reply(&req.msg, ResponseCode::ServFail).to_vec().ok()?);
                }
            }
        }
        Some(out)
    }

    /// Run the request through the chain and produce a response, or `None`
    /// when a plugin asked for the query to be dropped.
    pub async fn serve_request(&self, req: &mut Request) -> Option<Message> {
        self.serve_request_inner(req).await.map(|mut v| v.swap_remove(0))
    }

    /// Like `serve_request` but keeps every message of a multi-message
    /// reply (zone transfers).
    pub async fn serve_request_all(&self, req: &mut Request) -> Option<Vec<Message>> {
        self.serve_request_inner(req).await
    }

    async fn serve_request_inner(&self, req: &mut Request) -> Option<Vec<Message>> {
        // RFC 6891: unsupported EDNS version → BADVERS
        if let Some(e) = req.msg.edns() {
            if e.version() != 0 {
                let mut m = dnsutil::error_reply(&req.msg, ResponseCode::BADVERS);
                if let Some(ne) = m.extensions_mut().as_mut() {
                    ne.set_version(0);
                }
                return Some(vec![m]);
            }
        }
        if req.msg.queries().is_empty() {
            return Some(vec![dnsutil::error_reply(&req.msg, ResponseCode::Refused)]);
        }
        let entry = match self.lookup(req) {
            Some(e) => e,
            None => {
                tracing::debug!("{}: no zone for {} from {}", self.label, req.name_uncached(), req.remote);
                return Some(vec![dnsutil::error_reply(&req.msg, ResponseCode::Refused)]);
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
                Some(vec![m])
            }
            Ok(Ok(Reply::Multi(v))) => {
                let v: Vec<Message> = v
                    .into_iter()
                    .map(|mut m| {
                        m.set_id(req.msg.id());
                        m.set_message_type(hickory_proto::op::MessageType::Response);
                        m
                    })
                    .collect();
                if v.is_empty() {
                    Some(vec![dnsutil::error_reply(&req.msg, ResponseCode::ServFail)])
                } else {
                    Some(v)
                }
            }
            Ok(Ok(Reply::Drop)) => None,
            Ok(Ok(Reply::Rcode(rc))) => {
                if !client_write(rc) {
                    tracing::debug!("{}: {} {}: {:?} without response", self.label, req.name_uncached(), req.qtype(), rc);
                }
                Some(vec![dnsutil::error_reply(&req.msg, rc)])
            }
            Ok(Err(e)) => {
                tracing::debug!("{}: {} {}: {}", self.label, req.name_uncached(), req.qtype(), e);
                Some(vec![dnsutil::error_reply(&req.msg, e.rcode)])
            }
            Err(panic) => {
                crate::metrics::PANIC_COUNT.inc();
                let what = panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "unknown".into());
                tracing::error!("{}: panic serving {}: {}", self.label, req.name_uncached(), what);
                if entry.config.values.contains_key(crate::plugins::debug::KEY) {
                    // `debug`: panics are not recovered, as in CoreDNS (Go exits 2 on a panic)
                    tracing::error!("{}: debug is on, exiting on the panic", self.label);
                    std::process::exit(2);
                }
                Some(vec![dnsutil::error_reply(&req.msg, ResponseCode::ServFail)])
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
                if let Some(msgs) = srv.serve_bytes_all(&pkt, remote, local, proto, None, sni).await {
                    for resp in msgs {
                        if tx.send(resp).await.is_err() {
                            break;
                        }
                    }
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

/// Can this host open IPv6 sockets? Probed once by binding `[::]:0`.
pub fn ipv6_available() -> bool {
    static V6: Lazy<bool> = Lazy::new(|| std::net::UdpSocket::bind("[::]:0").is_ok());
    *V6
}

/// `:53` → `[::]:53` (dual stack) or `0.0.0.0:53` when IPv6 is unavailable;
/// `host:port` otherwise.
pub fn resolve_bind(addr: &str) -> Result<SocketAddr> {
    if let Some(port) = addr.strip_prefix(':') {
        let p: u16 = port.parse().map_err(|_| anyhow!("bad port in {}", addr))?;
        // dual-stack wildcard when IPv6 works on this host. Not decided by
        // binding the real port: during a reload the old instance still
        // holds it, and a privileged port may not bind here (#8).
        if ipv6_available() {
            return Ok(format!("[::]:{}", p).parse().unwrap());
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
    final_shutdown_hooks: Vec<config::Hook>,
    restart_hooks: Vec<config::RestartHook>,
    restart_failed_hooks: Vec<config::RestartHook>,
}

/// Signalled (by the `reload` plugin) to request a restart of the whole
/// instance from the Corefile on disk.
pub static RELOAD: Lazy<watch::Sender<u64>> = Lazy::new(|| watch::channel(0u64).0);

/// Ask the main loop to reload the Corefile.
pub fn request_reload() {
    RELOAD.send_modify(|v| *v += 1);
}

/// The servers of the running instance, for in-process self lookups.
pub static CURRENT: Lazy<arc_swap::ArcSwap<Vec<Arc<Server>>>> = Lazy::new(|| arc_swap::ArcSwap::from_pointee(Vec::new()));

/// `upstream.Lookup`: resolve `name`/`qtype` through this server's own
/// plugin chain (what CoreDNS does by querying itself over loopback).
/// Prefers the server the request arrived on.
pub async fn self_lookup(req: &Request, name: hickory_proto::rr::Name, qtype: hickory_proto::rr::RecordType) -> Result<Message> {
    if req.lookup_depth >= 8 {
        return Err(anyhow!("self lookup nesting too deep for {}", name));
    }
    let servers = CURRENT.load();
    let srv = servers
        .iter()
        .find(|s| s.label == req.server)
        .or_else(|| servers.first())
        .cloned()
        .ok_or_else(|| anyhow!("no running server for self lookup"))?;
    let mut r = req.new_with_question(name, qtype);
    r.lookup_depth += 1;
    r.server = srv.label.clone();
    srv.serve_request(&mut r).await.ok_or_else(|| anyhow!("query for {} was dropped", r.name_uncached()))
}

impl Instance {
    /// Build configs from parsed server blocks, finalise chains and run
    /// post-finalize wiring, bind listeners, run startup hooks (a failing
    /// hook aborts the start), and start serving.
    pub async fn start(blocks: Vec<crate::corefile::ServerBlock>, opts: &build::BuildOptions) -> Result<Instance> {
        let mut built = build::build(blocks, opts)?;
        let mut shutdown_hooks = Vec::new();
        let mut final_shutdown_hooks = Vec::new();
        let mut restart_hooks = Vec::new();
        let mut restart_failed_hooks = Vec::new();
        let mut startup_hooks = Vec::new();
        let mut configs = Vec::new();
        for c in built.configs.drain(..) {
            let mut c = c;
            c.finalize_chain();
            startup_hooks.append(&mut c.startup);
            shutdown_hooks.append(&mut c.shutdown);
            final_shutdown_hooks.append(&mut c.final_shutdown);
            restart_hooks.append(&mut c.restart);
            restart_failed_hooks.append(&mut c.restart_failed);
            configs.push(Arc::new(c));
        }
        crate::plugins::post_finalize(&configs);
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
        CURRENT.store(Arc::new(servers.clone()));
        for srv in &servers {
            for a in &srv.addrs {
                let shown = if a.starts_with(':') { format!("[::]{}", a) } else { a.clone() };
                tracing::info!("{}://{} on {}", srv.transport.scheme(), shown, srv.zones.keys().cloned().collect::<Vec<_>>().join(", "));
            }
        }
        Ok(Instance { servers, configs, cancel, tasks, shutdown_hooks, final_shutdown_hooks, restart_hooks, restart_failed_hooks })
    }

    /// Run the `on_restart` hooks before a reload; the first error stops
    /// them and is returned (the reload must not go ahead).
    pub async fn run_restart_hooks(&self) -> Result<()> {
        for h in &self.restart_hooks {
            h().await?;
        }
        Ok(())
    }

    /// Run the `on_restart_failed` hooks after a failed reload.
    pub async fn run_restart_failed_hooks(&self) {
        for h in &self.restart_failed_hooks {
            if let Err(e) = h().await {
                tracing::warn!("restart_failed hook: {}", e);
            }
        }
    }

    /// Process exit: the final-shutdown hooks (`health` lameduck, with DNS
    /// still answering and `/ready` at 503), then `stop`. A reload calls
    /// `stop` alone, so it is never delayed by lameduck.
    pub async fn stop_final(mut self) {
        for h in self.final_shutdown_hooks.drain(..) {
            if let Err(e) = h().await {
                tracing::warn!("final shutdown hook: {}", e);
            }
        }
        self.stop().await;
    }

    /// Run shutdown hooks, then stop listeners, waiting up to the longest
    /// server `graceful_timeout` for them to finish.
    pub async fn stop(mut self) {
        for h in self.shutdown_hooks.drain(..) {
            if let Err(e) = h().await {
                tracing::warn!("shutdown hook: {}", e);
            }
        }
        self.cancel.cancel();
        let grace = self.servers.iter().map(|s| s.graceful_timeout).max().unwrap_or(Duration::from_secs(5));
        let deadline = tokio::time::Instant::now() + grace;
        for t in self.tasks.drain(..) {
            let _ = tokio::time::timeout_at(deadline, t).await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn counting(n: &Arc<AtomicUsize>, fail: bool) -> config::RestartHook {
        let n = n.clone();
        Arc::new(move || {
            n.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { if fail { Err(anyhow!("no")) } else { Ok(()) } })
        })
    }

    /// A metadata provider that labels queries for `flag.*` names.
    struct Flagger;
    #[async_trait::async_trait]
    impl Handler for Flagger {
        fn name(&self) -> &'static str {
            "flagger"
        }
        fn metadata(&self, req: &mut Request) {
            if req.name_uncached().starts_with("flag.") {
                req.metadata.set_static("test/flag", "yes");
            }
        }
        async fn serve_dns(&self, req: &mut Request, next: crate::plugin::Next<'_>) -> crate::plugin::DnsResult {
            next.serve(req).await
        }
    }

    #[test]
    fn view_filters_see_collected_metadata() {
        let key = config::parse_key(".").unwrap();
        let mut viewed = config::ServerConfig::new(&key, 0, 0);
        viewed.view_name = "flagged".into();
        let expr = crate::plugins::view::parse("metadata('test/flag') == 'yes'").unwrap();
        viewed.filter = Some(Arc::new(move |r: &Request| expr.eval(r)));
        let providers: Vec<Arc<dyn Handler>> = vec![Arc::new(Flagger)];
        viewed.metadata = Some(crate::plugins::metadata::Metadata::new(vec![".".into()], providers));
        let plain = config::ServerConfig::new(&key, 1, 0);
        let entry = |c: config::ServerConfig| ZoneEntry { config: Arc::new(c), chain: Arc::new(Vec::new()) };
        let srv = Server {
            label: "dns://:0".into(),
            transport: Transport::Dns,
            addrs: vec![],
            zones: HashMap::from([(".".to_string(), vec![entry(viewed), entry(plain)])]),
            tls: None,
            read_timeout: Duration::from_secs(1),
            write_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(1),
            num_sockets: 1,
            graceful_timeout: Duration::from_secs(1),
        };
        let mut r = Request::for_test("flag.example.org.", hickory_proto::rr::RecordType::A);
        assert_eq!(srv.lookup(&mut r).unwrap().config.view_name, "flagged");
        assert_eq!(r.metadata.value("test/flag").as_deref(), Some("yes"), "the chain sees the metadata too");
        let mut r = Request::for_test("other.example.org.", hickory_proto::rr::RecordType::A);
        assert_eq!(srv.lookup(&mut r).unwrap().config.view_name, "");
    }

    #[test]
    fn port_held_by_another_listener_stays_dual_stack() {
        // the old instance during a reload: a reuseport listener on the port
        let held = bind_tcp("[::]:0").or_else(|_| bind_tcp("0.0.0.0:0")).unwrap();
        let port = held.local_addr().unwrap().port();
        let sa = resolve_bind(&format!(":{}", port)).unwrap();
        if ipv6_available() {
            assert_eq!(sa, format!("[::]:{}", port).parse::<SocketAddr>().unwrap(), "still dual stack while the port is held");
            // and the new instance can bind it next to the old one
            assert!(bind_tcp(&sa.to_string()).is_ok());
        } else {
            assert_eq!(sa, format!("0.0.0.0:{}", port).parse::<SocketAddr>().unwrap());
        }
        assert_eq!(resolve_bind("127.0.0.1:53").unwrap(), "127.0.0.1:53".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn lameduck_only_at_process_exit() {
        let corefile = ".:0 {\n bind 127.0.0.1\n health 127.0.0.1:18080 {\n  lameduck 2s\n }\n ready 127.0.0.1:18181\n whoami\n}\n";
        let start = || async {
            let blocks = crate::corefile::parser::parse_str(corefile, "t", std::path::Path::new(".")).unwrap();
            let opts = build::BuildOptions { default_port: 0, ..Default::default() };
            Instance::start(blocks, &opts).await.unwrap()
        };
        let get = |path: &'static str| async move {
            let c = reqwest::Client::builder().timeout(Duration::from_secs(2)).build().unwrap();
            c.get(format!("http://127.0.0.1:{}", path)).send().await.map(|r| r.status().as_u16()).unwrap_or(0)
        };
        let old = start().await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(get("18080/health").await, 200);
        // a reload: the new instance starts, the old one stops without lameduck
        let new = start().await;
        let t = std::time::Instant::now();
        old.stop().await;
        assert!(t.elapsed() < Duration::from_secs(2), "a reload does not wait for lameduck ({:?})", t.elapsed());
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(get("18080/health").await, 200, "healthy after the reload");
        assert_eq!(get("18181/ready").await, 200);
        // process exit: lameduck with /health still OK and /ready not
        let t = std::time::Instant::now();
        let exit = tokio::spawn(new.stop_final());
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(get("18080/health").await, 200, "/health stays OK during lameduck, as in CoreDNS");
        assert_eq!(get("18181/ready").await, 503, "/ready is 503 during lameduck");
        exit.await.unwrap();
        assert!(t.elapsed() >= Duration::from_secs(2), "exit waited for lameduck");
    }

    #[tokio::test]
    async fn restart_hooks_run_on_every_reload_attempt() {
        let blocks = crate::corefile::parser::parse_str(".:0 {\n bind 127.0.0.1\n whoami\n}\n", "t", std::path::Path::new(".")).unwrap();
        let opts = build::BuildOptions { default_port: 0, ..Default::default() };
        let mut inst = Instance::start(blocks, &opts).await.unwrap();
        let (restart, failed) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        inst.restart_hooks.push(counting(&restart, false));
        inst.restart_failed_hooks.push(counting(&failed, false));
        for _ in 0..2 {
            inst.run_restart_hooks().await.unwrap();
            inst.run_restart_failed_hooks().await;
        }
        assert_eq!(restart.load(Ordering::SeqCst), 2);
        assert_eq!(failed.load(Ordering::SeqCst), 2);
        // a failing restart hook stops the ones after it and reports the error
        let bad = Arc::new(AtomicUsize::new(0));
        inst.restart_hooks.insert(0, counting(&bad, true));
        assert!(inst.run_restart_hooks().await.is_err());
        assert_eq!(bad.load(Ordering::SeqCst), 1);
        assert_eq!(restart.load(Ordering::SeqCst), 2);
        let t = std::time::Instant::now();
        inst.stop().await;
        assert!(t.elapsed() < Duration::from_secs(5));
    }
}
