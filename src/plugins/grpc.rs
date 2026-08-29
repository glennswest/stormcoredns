//! `grpc FROM TO... { except; tls CERT KEY CA; tls_servername NAME; policy ... }`
//! — proxies queries to upstreams speaking the CoreDNS gRPC protocol
//! (`coredns.dns.DnsService/Query`).

use crate::dnsutil::{self, Upstream, UpstreamTransport};
use crate::plugin::{error, Controller, DnsResult, Handler, Next, Reply, Request};
use crate::server::grpc::pb::dns_service_client::DnsServiceClient;
use crate::server::grpc::pb::DnsPacket;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use once_cell::sync::Lazy;
use prometheus::{HistogramVec, IntCounterVec};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

static REQUEST_COUNT: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(prometheus::Opts::new("coredns_grpc_requests_total", "Counter of requests made per upstream."), &["to"]).unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});
static RCODE_COUNT: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(prometheus::Opts::new("coredns_grpc_responses_total", "Counter of responses received per upstream."), &["rcode", "to"]).unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});
static REQUEST_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    let c = HistogramVec::new(prometheus::HistogramOpts::new("coredns_grpc_request_duration_seconds", "Histogram of the time each request took.").buckets(crate::metrics::time_buckets()), &["to", "rcode"]).unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Random,
    RoundRobin,
    Sequential,
}

pub struct Proxy {
    addr: String,
    endpoint: Endpoint,
    client: Mutex<Option<DnsServiceClient<Channel>>>,
    fails: AtomicU32,
}

impl Proxy {
    async fn client(&self) -> Result<DnsServiceClient<Channel>> {
        let mut g = self.client.lock().await;
        if let Some(c) = g.as_ref() {
            return Ok(c.clone());
        }
        let ch = self.endpoint.connect().await.map_err(|e| anyhow!("connecting to {}: {}", self.addr, e))?;
        let c = DnsServiceClient::new(ch);
        *g = Some(c.clone());
        Ok(c)
    }

    async fn query(&self, wire: Vec<u8>) -> Result<Message> {
        let mut c = self.client().await?;
        let start = Instant::now();
        REQUEST_COUNT.with_label_values(&[&self.addr]).inc();
        let resp = match tokio::time::timeout(Duration::from_secs(5), c.query(tonic::Request::new(DnsPacket { msg: wire }))).await {
            Ok(Ok(r)) => r.into_inner().msg,
            Ok(Err(e)) => {
                *self.client.lock().await = None;
                return Err(anyhow!("{}: {}", self.addr, e));
            }
            Err(_) => return Err(anyhow!("{}: timeout", self.addr)),
        };
        let m = Message::from_bytes(&resp)?;
        let rc = crate::plugin::replacer::rcode_str(m.response_code());
        RCODE_COUNT.with_label_values(&[&rc, &self.addr]).inc();
        REQUEST_DURATION.with_label_values(&[&self.addr, &rc]).observe(start.elapsed().as_secs_f64());
        Ok(m)
    }
}

pub struct Grpc {
    from: String,
    ignored: Vec<String>,
    proxies: Vec<Arc<Proxy>>,
    policy: Policy,
    rr: AtomicUsize,
}

impl Grpc {
    fn list(&self) -> Vec<Arc<Proxy>> {
        let n = self.proxies.len();
        match self.policy {
            Policy::Sequential => self.proxies.clone(),
            Policy::RoundRobin => {
                let s = self.rr.fetch_add(1, Ordering::Relaxed) % n.max(1);
                (0..n).map(|i| self.proxies[(s + i) % n].clone()).collect()
            }
            Policy::Random => {
                use rand::seq::SliceRandom;
                let mut v = self.proxies.clone();
                v.shuffle(&mut rand::thread_rng());
                v
            }
        }
    }
}

#[async_trait]
impl Handler for Grpc {
    fn name(&self) -> &'static str {
        "grpc"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let name = req.name();
        if !dnsutil::is_subdomain(&self.from, &name) || crate::plugin::zones_match(&self.ignored, &name).is_some() {
            return next.serve(req).await;
        }
        let wire = req.msg.to_vec().map_err(|e| error("grpc", e))?;
        let mut last = None;
        for p in self.list() {
            if p.fails.load(Ordering::Relaxed) >= 2 && p.fails.fetch_sub(1, Ordering::Relaxed) > 2 {
                continue; // back off a failing upstream, but retry it eventually
            }
            match p.query(wire.clone()).await {
                Ok(mut m) => {
                    p.fails.store(0, Ordering::Relaxed);
                    if !req.matches(&m) {
                        last = Some(anyhow!("{}: mismatched response", p.addr));
                        continue;
                    }
                    m.set_id(req.msg.id());
                    return Ok(Reply::Msg(m));
                }
                Err(e) => {
                    p.fails.fetch_add(1, Ordering::Relaxed);
                    last = Some(e);
                }
            }
        }
        Err(error("grpc", last.unwrap_or_else(|| anyhow!("no upstream host"))))
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    while c.next() {
        let args = c.remaining_args_until_brace();
        if args.len() < 2 {
            return Err(c.arg_err());
        }
        let from = dnsutil::normalize_zone(&args[0])?.into_iter().next().unwrap();
        let ups: Vec<Upstream> = dnsutil::parse_host_port_or_file(&args[1..])?;
        let mut ignored = Vec::new();
        let mut policy = Policy::Random;
        let mut tls_files: Option<(Option<String>, Option<String>, Option<String>)> = None;
        let mut tls_servername: Option<String> = None;
        while c.next_block() {
            match c.val() {
                "except" => {
                    for e in c.remaining_args() {
                        ignored.extend(dnsutil::normalize_zone(&e)?);
                    }
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
                    tls_servername = Some(a[0].clone());
                }
                "policy" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    policy = match a[0].as_str() {
                        "random" => Policy::Random,
                        "round_robin" => Policy::RoundRobin,
                        "sequential" => Policy::Sequential,
                        o => return Err(c.errf(format!("unknown policy '{}'", o))),
                    };
                }
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        let root = c.config.root.clone();
        let resolve = |p: &String| if std::path::Path::new(p).is_absolute() { std::path::PathBuf::from(p) } else { root.join(p) };
        let mut proxies = Vec::new();
        for u in ups {
            let use_tls = tls_files.is_some() || u.transport == UpstreamTransport::Tls;
            let scheme = if use_tls { "https" } else { "http" };
            let mut ep = Endpoint::from_shared(format!("{}://{}", scheme, u.addr)).map_err(|e| c.errf(format!("bad upstream {}: {}", u.addr, e)))?;
            ep = ep.connect_timeout(Duration::from_secs(5)).timeout(Duration::from_secs(5));
            if use_tls {
                let mut tls = ClientTlsConfig::new();
                if let Some((cert, key, ca)) = &tls_files {
                    if let Some(ca) = ca {
                        let pem = std::fs::read(resolve(ca)).map_err(|e| c.errf(format!("reading {}: {}", ca, e)))?;
                        tls = tls.ca_certificate(tonic::transport::Certificate::from_pem(pem));
                    }
                    if let (Some(cert), Some(key)) = (cert, key) {
                        let cp = std::fs::read(resolve(cert)).map_err(|e| c.errf(format!("reading {}: {}", cert, e)))?;
                        let kp = std::fs::read(resolve(key)).map_err(|e| c.errf(format!("reading {}: {}", key, e)))?;
                        tls = tls.identity(tonic::transport::Identity::from_pem(cp, kp));
                    }
                }
                if let Some(sn) = &tls_servername {
                    tls = tls.domain_name(sn.clone());
                }
                ep = ep.tls_config(tls).map_err(|e| c.errf(format!("tls config: {}", e)))?;
            }
            proxies.push(Arc::new(Proxy { addr: u.addr.clone(), endpoint: ep, client: Mutex::new(None), fails: AtomicU32::new(0) }));
        }
        c.add_plugin(Arc::new(Grpc { from, ignored, proxies, policy, rr: AtomicUsize::new(0) }));
    }
    Ok(())
}
