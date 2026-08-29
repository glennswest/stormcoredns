//! `forward` — proxy queries to upstream resolvers over UDP, TCP or TLS
//! with health checking, upstream selection policies and connection reuse.
//!
//! ```text
//! forward FROM TO... {
//!     except IGNORED_NAMES...
//!     force_tcp
//!     prefer_udp
//!     expire DURATION
//!     max_fails INTEGER
//!     tls CERT KEY CA
//!     tls_servername NAME
//!     policy random|round_robin|sequential
//!     health_check DURATION [no_rec] [domain FQDN]
//!     max_concurrent MAX
//!     next RCODE...
//!     failover RCODE...
//! }
//! ```

use crate::dnsutil::{self, Upstream, UpstreamTransport};
use crate::plugin::replacer::rcode_from_str;
use crate::plugin::{error, Controller, DnsResult, Handler, Next, Proto, Reply, Request};
use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use prometheus::{HistogramVec, IntCounter, IntCounterVec};
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

// ------------------------------------------------------------------ metrics

pub static REQUEST_COUNT: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(prometheus::Opts::new("coredns_forward_requests_total", "Counter of requests made per upstream."), &["to"]).unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});
pub static RCODE_COUNT: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(prometheus::Opts::new("coredns_forward_responses_total", "Counter of responses received per upstream."), &["rcode", "to"]).unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});
pub static REQUEST_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    let c = HistogramVec::new(
        prometheus::HistogramOpts::new("coredns_forward_request_duration_seconds", "Histogram of the time each request took.").buckets(crate::metrics::time_buckets()),
        &["to", "rcode"],
    )
    .unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});
pub static HEALTHCHECK_FAILURES: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(prometheus::Opts::new("coredns_forward_healthcheck_failures_total", "Counter of the number of failed healthchecks."), &["to"]).unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});
pub static HEALTHCHECK_BROKEN: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new("coredns_forward_healthcheck_broken_total", "Counter of the number of complete failures of the healthchecks.").unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});
pub static MAX_CONCURRENT_REJECTS: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new("coredns_forward_max_concurrent_rejects_total", "Counter of the number of queries rejected because the concurrent queries were at maximum.").unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});
pub static CONN_CACHE_HITS: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(prometheus::Opts::new("coredns_forward_conn_cache_hits_total", "Counter of connection cache hits per upstream and protocol."), &["to", "proto"]).unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});
pub static CONN_CACHE_MISSES: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(prometheus::Opts::new("coredns_forward_conn_cache_misses_total", "Counter of connection cache misses per upstream and protocol."), &["to", "proto"]).unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});

// ------------------------------------------------------------------ proxy

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Random,
    RoundRobin,
    Sequential,
}

/// One upstream server.
pub struct Proxy {
    pub addr: SocketAddr,
    pub addr_str: String,
    pub transport: UpstreamTransport,
    pub tls: Option<Arc<rustls::ClientConfig>>,
    pub tls_server_name: Option<ServerName<'static>>,
    fails: AtomicU32,
    /// Health checking is running (started on first failure).
    probing: AtomicBool,
    /// Idle stream connections, newest last.
    pool: Mutex<Vec<(StreamConn, Instant)>>,
    expire: Duration,
    read_timeout: Duration,
}

pub enum StreamConn {
    Tcp(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl StreamConn {
    async fn exchange(&mut self, wire: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(wire.len() + 2);
        out.extend_from_slice(&(wire.len() as u16).to_be_bytes());
        out.extend_from_slice(wire);
        match self {
            StreamConn::Tcp(s) => stream_exchange(s, &out, timeout).await,
            StreamConn::Tls(s) => stream_exchange(s, &out, timeout).await,
        }
    }
}

async fn stream_exchange<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(s: &mut S, out: &[u8], timeout: Duration) -> Result<Vec<u8>> {
    tokio::time::timeout(timeout, async {
        s.write_all(out).await?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await?;
        let n = u16::from_be_bytes(len) as usize;
        let mut buf = vec![0u8; n];
        s.read_exact(&mut buf).await?;
        Ok::<_, anyhow::Error>(buf)
    })
    .await
    .map_err(|_| anyhow!("i/o timeout"))?
}

impl Proxy {
    pub fn new(up: &Upstream, tls: Option<Arc<rustls::ClientConfig>>, tls_server_name: Option<String>, expire: Duration) -> Result<Proxy> {
        let addr: SocketAddr = up.addr.parse().map_err(|_| anyhow!("upstream {} is not an IP address", up.addr))?;
        let sni = match (&tls_server_name, up.transport) {
            (Some(n), _) => Some(ServerName::try_from(n.clone()).map_err(|_| anyhow!("bad tls_servername {}", n))?),
            (None, UpstreamTransport::Tls) => Some(ServerName::IpAddress(addr.ip().into())),
            _ => None,
        };
        Ok(Proxy {
            addr,
            addr_str: up.addr.clone(),
            transport: up.transport,
            tls,
            tls_server_name: sni,
            fails: AtomicU32::new(0),
            probing: AtomicBool::new(false),
            pool: Mutex::new(Vec::new()),
            expire,
            read_timeout: Duration::from_secs(5),
        })
    }

    pub fn fails(&self) -> u32 {
        self.fails.load(Ordering::Relaxed)
    }

    pub fn down(&self, max_fails: u32) -> bool {
        max_fails != 0 && self.fails() >= max_fails
    }

    fn take_conn(&self) -> Option<StreamConn> {
        let mut pool = self.pool.lock();
        while let Some((c, t)) = pool.pop() {
            if t.elapsed() < self.expire {
                return Some(c);
            }
        }
        None
    }

    fn put_conn(&self, c: StreamConn) {
        let mut pool = self.pool.lock();
        if pool.len() < 64 {
            pool.push((c, Instant::now()));
        }
    }

    async fn dial(&self, use_tls: bool) -> Result<StreamConn> {
        let s = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(self.addr))
            .await
            .map_err(|_| anyhow!("dial {}: timeout", self.addr))??;
        let _ = s.set_nodelay(true);
        if use_tls {
            let cfg = self.tls.clone().ok_or_else(|| anyhow!("no TLS config for {}", self.addr))?;
            let conn = tokio_rustls::TlsConnector::from(cfg);
            let sni = self.tls_server_name.clone().unwrap_or(ServerName::IpAddress(self.addr.ip().into()));
            let tls = tokio::time::timeout(Duration::from_secs(5), conn.connect(sni, s))
                .await
                .map_err(|_| anyhow!("tls handshake with {}: timeout", self.addr))??;
            Ok(StreamConn::Tls(tls))
        } else {
            Ok(StreamConn::Tcp(s))
        }
    }

    /// Send `wire` and return the raw response. `proto` is "udp" or "tcp".
    pub async fn exchange(&self, wire: &[u8], want_tcp: bool) -> Result<Vec<u8>> {
        let use_tls = self.transport == UpstreamTransport::Tls;
        if !want_tcp && !use_tls {
            let sock = if self.addr.is_ipv4() { UdpSocket::bind("0.0.0.0:0").await? } else { UdpSocket::bind("[::]:0").await? };
            sock.connect(self.addr).await?;
            sock.send(wire).await?;
            let mut buf = vec![0u8; 65535];
            let deadline = Instant::now() + self.read_timeout;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    bail!("i/o timeout");
                }
                let n = tokio::time::timeout(remaining, sock.recv(&mut buf)).await.map_err(|_| anyhow!("i/o timeout"))??;
                // ignore responses whose id does not match (spoofing / stale)
                if n >= 2 && wire.len() >= 2 && buf[0] == wire[0] && buf[1] == wire[1] {
                    return Ok(buf[..n].to_vec());
                }
            }
        }
        // stream: reuse a pooled connection, retry once on a fresh one
        let proto = if use_tls { "tcp-tls" } else { "tcp" };
        let mut conn = match self.take_conn() {
            Some(c) => {
                CONN_CACHE_HITS.with_label_values(&[&self.addr_str, proto]).inc();
                c
            }
            None => {
                CONN_CACHE_MISSES.with_label_values(&[&self.addr_str, proto]).inc();
                self.dial(use_tls).await?
            }
        };
        match conn.exchange(wire, self.read_timeout).await {
            Ok(r) => {
                self.put_conn(conn);
                Ok(r)
            }
            Err(_) => {
                let mut fresh = self.dial(use_tls).await?;
                let r = fresh.exchange(wire, self.read_timeout).await?;
                self.put_conn(fresh);
                Ok(r)
            }
        }
    }

    /// One health-check probe: `. NS` (or a configured domain) — the
    /// upstream must answer *something* (rcode is irrelevant).
    async fn probe(&self, recursion_desired: bool, domain: &Name) -> bool {
        let mut m = Message::new();
        m.set_id(rand::random());
        m.set_recursion_desired(recursion_desired);
        m.add_query(Query::query(domain.clone(), RecordType::NS));
        let Ok(wire) = m.to_vec() else { return false };
        match tokio::time::timeout(Duration::from_secs(5), self.exchange(&wire, self.transport == UpstreamTransport::Tls)).await {
            Ok(Ok(resp)) => match Message::from_bytes(&resp) {
                Ok(r) => r.id() == m.id(),
                Err(_) => false,
            },
            _ => false,
        }
    }
}

// ------------------------------------------------------------------ forward

pub struct Forward {
    pub from: String,
    pub ignored: Vec<String>,
    pub proxies: Vec<Arc<Proxy>>,
    pub policy: Policy,
    pub max_fails: u32,
    pub force_tcp: bool,
    pub prefer_udp: bool,
    pub health_interval: Duration,
    pub health_no_rec: bool,
    pub health_domain: Name,
    pub max_concurrent: usize,
    pub next_rcodes: Vec<ResponseCode>,
    pub failover_rcodes: Vec<ResponseCode>,
    concurrent: AtomicUsize,
    rr: AtomicUsize,
    /// Set by the `tls` block.
    pub tls_config: Option<Arc<rustls::ClientConfig>>,
    pub tls_server_name: Option<String>,
}

impl Forward {
    /// Ordered list of proxies to try for this request (`policy.List`).
    fn list(&self) -> Vec<Arc<Proxy>> {
        let n = self.proxies.len();
        match self.policy {
            Policy::Sequential => self.proxies.clone(),
            Policy::RoundRobin => {
                let start = self.rr.fetch_add(1, Ordering::Relaxed) % n.max(1);
                let mut v = Vec::with_capacity(n);
                for i in 0..n {
                    v.push(self.proxies[(start + i) % n].clone());
                }
                v
            }
            Policy::Random => {
                use rand::seq::SliceRandom;
                let mut v = self.proxies.clone();
                v.shuffle(&mut rand::thread_rng());
                v
            }
        }
    }

    fn start_health_check(self: &Arc<Self>, p: Arc<Proxy>) {
        if p.probing.swap(true, Ordering::SeqCst) {
            return;
        }
        let f = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(f.health_interval).await;
                if p.fails() == 0 {
                    break;
                }
                if p.probe(!f.health_no_rec, &f.health_domain).await {
                    p.fails.store(0, Ordering::Relaxed);
                    break;
                }
                HEALTHCHECK_FAILURES.with_label_values(&[&p.addr_str]).inc();
                p.fails.fetch_add(1, Ordering::Relaxed);
            }
            p.probing.store(false, Ordering::SeqCst);
        });
    }

    /// Send the request to `p`, retrying over TCP when the UDP answer is
    /// truncated. Returns the parsed response.
    async fn connect(&self, p: &Proxy, req: &Request) -> Result<Message> {
        let want_tcp = self.force_tcp || (!self.prefer_udp && req.proto != Proto::Udp);
        let wire = req.msg.to_vec()?;
        let start = Instant::now();
        REQUEST_COUNT.with_label_values(&[&p.addr_str]).inc();
        let mut raw = p.exchange(&wire, want_tcp).await?;
        let mut resp = Message::from_bytes(&raw)?;
        if resp.truncated() && !want_tcp {
            // retry over TCP
            raw = p.exchange(&wire, true).await?;
            resp = Message::from_bytes(&raw)?;
        }
        let rc = crate::plugin::replacer::rcode_str(resp.response_code());
        RCODE_COUNT.with_label_values(&[&rc, &p.addr_str]).inc();
        REQUEST_DURATION.with_label_values(&[&p.addr_str, &rc]).observe(start.elapsed().as_secs_f64());
        Ok(resp)
    }
}

pub struct ForwardHandler(pub Arc<Forward>);

#[async_trait]
impl Handler for ForwardHandler {
    fn name(&self) -> &'static str {
        "forward"
    }

    fn ready(&self) -> Option<bool> {
        None
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let f = &self.0;
        let name = req.name();
        if !dnsutil::is_subdomain(&f.from, &name) || crate::plugin::zones_match(&f.ignored, &name).is_some() {
            return next.serve(req).await;
        }
        if f.max_concurrent > 0 {
            let cur = f.concurrent.fetch_add(1, Ordering::Relaxed);
            if cur >= f.max_concurrent {
                f.concurrent.fetch_sub(1, Ordering::Relaxed);
                MAX_CONCURRENT_REJECTS.inc();
                return Err(error("forward", anyhow!("concurrent queries exceeded maximum {}", f.max_concurrent)).with_rcode(ResponseCode::Refused));
            }
        }
        let r = self.forward(req).await;
        if f.max_concurrent > 0 {
            f.concurrent.fetch_sub(1, Ordering::Relaxed);
        }
        r
    }
}

impl ForwardHandler {
    async fn forward(&self, req: &mut Request) -> DnsResult {
        let f = &self.0;
        let list = f.list();
        let mut last_err: Option<anyhow::Error> = None;
        let mut fails = 0;
        let mut tried_any_down = false;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut i = 0;
        let mut last_reply: Option<Message> = None;
        loop {
            if Instant::now() > deadline {
                break;
            }
            // pick the next healthy proxy; if all are down, try each once anyway
            let p = loop {
                if i >= list.len() {
                    break None;
                }
                let p = list[i].clone();
                i += 1;
                if !p.down(f.max_fails) {
                    break Some(p);
                }
                if !tried_any_down && i == list.len() && list.iter().all(|p| p.down(f.max_fails)) {
                    tried_any_down = true;
                    // all down: retry the list once from the start, ignoring health
                    i = 0;
                    break Some(p);
                }
            };
            let Some(p) = p else { break };
            let need_tcp_retry = false;
            let _ = need_tcp_retry;
            match f.connect(&p, req).await {
                Ok(mut resp) => {
                    if !req.matches(&resp) {
                        // wrong id/question: treat as failure of this upstream
                        last_err = Some(anyhow!("upstream {} returned mismatched response", p.addr_str));
                        fails += 1;
                        continue;
                    }
                    p.fails.store(0, Ordering::Relaxed);
                    let rc = resp.response_code();
                    if (f.next_rcodes.contains(&rc) || f.failover_rcodes.contains(&rc)) && i < list.len() {
                        last_reply = Some(resp);
                        continue;
                    }
                    resp.set_id(req.msg.id());
                    return Ok(Reply::Msg(resp));
                }
                Err(e) => {
                    p.fails.fetch_add(1, Ordering::Relaxed);
                    f.start_health_check(p.clone());
                    fails += 1;
                    last_err = Some(anyhow!("{}: {}", p.addr_str, e));
                }
            }
        }
        if let Some(r) = last_reply {
            let mut r = r;
            r.set_id(req.msg.id());
            return Ok(Reply::Msg(r));
        }
        if fails == 0 {
            return Err(error("forward", anyhow!("no upstream host")));
        }
        Err(error("forward", last_err.unwrap_or_else(|| anyhow!("no healthy upstream"))))
    }
}

// ------------------------------------------------------------------ setup

pub fn parse(c: &mut Controller<'_>) -> Result<Forward> {
    let args = c.remaining_args_until_brace();
    if args.len() < 2 {
        return Err(c.arg_err());
    }
    let from = dnsutil::normalize_zone(&args[0])?.into_iter().next().unwrap();
    let ups = dnsutil::parse_host_port_or_file(&args[1..])?;
    if ups.is_empty() {
        return Err(c.errf("no upstream servers"));
    }
    let mut f = Forward {
        from,
        ignored: Vec::new(),
        proxies: Vec::new(),
        policy: Policy::Random,
        max_fails: 2,
        force_tcp: false,
        prefer_udp: false,
        health_interval: Duration::from_millis(500),
        health_no_rec: false,
        health_domain: Name::root(),
        max_concurrent: 0,
        next_rcodes: Vec::new(),
        failover_rcodes: Vec::new(),
        concurrent: AtomicUsize::new(0),
        rr: AtomicUsize::new(0),
        tls_config: None,
        tls_server_name: None,
    };
    let mut expire = Duration::from_secs(10);
    let mut tls_files: Option<(Option<String>, Option<String>, Option<String>)> = None;
    while c.next_block() {
        match c.val() {
            "except" => {
                for e in c.remaining_args() {
                    f.ignored.extend(dnsutil::normalize_zone(&e)?);
                }
            }
            "force_tcp" => f.force_tcp = true,
            "prefer_udp" => f.prefer_udp = true,
            "expire" => {
                let a = c.remaining_args();
                if a.len() != 1 {
                    return Err(c.arg_err());
                }
                expire = dnsutil::parse_duration(&a[0])?;
            }
            "max_fails" => {
                let a = c.remaining_args();
                if a.len() != 1 {
                    return Err(c.arg_err());
                }
                f.max_fails = a[0].parse().map_err(|_| c.errf(format!("bad max_fails {}", a[0])))?;
            }
            "tls" => {
                let a = c.remaining_args();
                tls_files = Some(match a.len() {
                    0 => (None, None, None),
                    1 => (None, None, Some(a[0].clone())),
                    2 => (Some(a[0].clone()), Some(a[1].clone()), None),
                    3 => (Some(a[0].clone()), Some(a[1].clone()), Some(a[2].clone())),
                    _ => return Err(c.arg_err()),
                });
            }
            "tls_servername" => {
                let a = c.remaining_args();
                if a.len() != 1 {
                    return Err(c.arg_err());
                }
                f.tls_server_name = Some(a[0].clone());
            }
            "policy" => {
                let a = c.remaining_args();
                if a.len() != 1 {
                    return Err(c.arg_err());
                }
                f.policy = match a[0].as_str() {
                    "random" => Policy::Random,
                    "round_robin" => Policy::RoundRobin,
                    "sequential" => Policy::Sequential,
                    o => return Err(c.errf(format!("unknown policy '{}'", o))),
                };
            }
            "health_check" => {
                let a = c.remaining_args();
                if a.is_empty() {
                    return Err(c.arg_err());
                }
                f.health_interval = dnsutil::parse_duration(&a[0])?;
                let mut j = 1;
                while j < a.len() {
                    match a[j].as_str() {
                        "no_rec" => f.health_no_rec = true,
                        "domain" => {
                            j += 1;
                            let d = a.get(j).ok_or_else(|| c.errf("health_check domain needs a name"))?;
                            f.health_domain = dnsutil::name_from_str(d)?;
                        }
                        o => return Err(c.errf(format!("health_check: unknown option {}", o))),
                    }
                    j += 1;
                }
            }
            "max_concurrent" => {
                let a = c.remaining_args();
                if a.len() != 1 {
                    return Err(c.arg_err());
                }
                f.max_concurrent = a[0].parse().map_err(|_| c.errf(format!("bad max_concurrent {}", a[0])))?;
            }
            "next" | "failover" => {
                let which = c.val().to_string();
                let a = c.remaining_args();
                if a.is_empty() {
                    return Err(c.arg_err());
                }
                for r in a {
                    let rc = rcode_from_str(&r).ok_or_else(|| c.errf(format!("{}: unknown rcode {}", which, r)))?;
                    if which == "next" {
                        f.next_rcodes.push(rc);
                    } else {
                        f.failover_rcodes.push(rc);
                    }
                }
            }
            o => return Err(c.errf(format!("unknown property '{}'", o))),
        }
    }
    let needs_tls = ups.iter().any(|u| u.transport == UpstreamTransport::Tls);
    if needs_tls || tls_files.is_some() {
        let (cert, key, ca) = tls_files.clone().unwrap_or((None, None, None));
        let root = c.config.root.clone();
        let resolve = |p: &String| if std::path::Path::new(p).is_absolute() { std::path::PathBuf::from(p) } else { root.join(p) };
        let client_cert = match (&cert, &key) {
            (Some(cc), Some(kk)) => Some((resolve(cc), resolve(kk))),
            _ => None,
        };
        let ca_p = ca.as_ref().map(|p| resolve(p));
        f.tls_config = Some(crate::server::tls::client_config(
            ca_p.as_deref(),
            client_cert.as_ref().map(|(a, b)| (a.as_path(), b.as_path())),
            false,
        )?);
    }
    for u in &ups {
        match u.transport {
            UpstreamTransport::Dns | UpstreamTransport::Tls => {}
            other => return Err(c.errf(format!("forward: unsupported upstream transport {}://", other.as_str()))),
        }
        f.proxies.push(Arc::new(Proxy::new(u, f.tls_config.clone(), f.tls_server_name.clone(), expire)?));
    }
    if f.proxies.len() > 15 && f.policy != Policy::Sequential {
        // CoreDNS limit; keep it for parity
        return Err(c.errf("more than 15 TOs configured"));
    }
    Ok(f)
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    while c.next() {
        let f = parse(c)?;
        c.add_plugin(Arc::new(ForwardHandler(Arc::new(f))));
    }
    Ok(())
}

/// Convenience for other plugins (`upstream` self-lookups via forward):
/// resolve `name`/`qtype` through the first forward instance's proxies.
pub async fn lookup(f: &Forward, name: Name, qtype: RecordType) -> Result<Message> {
    let mut m = Message::new();
    m.set_id(rand::random());
    m.set_recursion_desired(true);
    m.set_op_code(OpCode::Query);
    m.set_message_type(MessageType::Query);
    m.add_query(Query::query(name, qtype));
    let req = Request::new(m, "127.0.0.1:0".parse().unwrap(), "127.0.0.1:0".parse().unwrap(), Proto::Udp);
    for p in f.list() {
        if p.down(f.max_fails) {
            continue;
        }
        if let Ok(r) = f.connect(&p, &req).await {
            return Ok(r);
        }
    }
    bail!("no upstream host")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corefile::lex;

    fn ctl_parse(s: &str) -> Result<Forward> {
        let toks = lex(s, "t");
        let pk = crate::server::config::parse_key(".").unwrap();
        let mut cfg = crate::server::config::ServerConfig::new(&pk, 0, 0);
        let mut once = std::collections::HashSet::new();
        let mut c = Controller::new("forward", toks, &mut cfg, ".".into(), vec![".".into()], 0, 0, &mut once);
        c.next();
        parse(&mut c)
    }

    #[test]
    fn parses_block() {
        let f = ctl_parse("forward . 8.8.8.8 tls://1.1.1.1 {\n max_fails 5\n policy round_robin\n except a.example.org\n force_tcp\n next NXDOMAIN\n}\n").unwrap();
        assert_eq!(f.proxies.len(), 2);
        assert_eq!(f.max_fails, 5);
        assert_eq!(f.policy, Policy::RoundRobin);
        assert_eq!(f.ignored, vec!["a.example.org."]);
        assert!(f.force_tcp);
        assert_eq!(f.next_rcodes, vec![ResponseCode::NXDomain]);
        assert_eq!(f.proxies[1].transport, UpstreamTransport::Tls);
    }

    #[test]
    fn rejects_bad() {
        assert!(ctl_parse("forward .\n").is_err());
        assert!(ctl_parse("forward . 8.8.8.8 {\n policy nope\n}\n").is_err());
    }
}
