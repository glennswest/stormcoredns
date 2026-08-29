//! `loop` — detects forwarding loops: at startup it sends a random query
//! for the server block's zone to itself; if that query is seen more than
//! once the server exits with an error.

use crate::plugin::{Controller, DnsResult, Handler, Next, Request};
use async_trait::async_trait;
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use rand::Rng;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub struct Loop {
    zone: String,
    qname: String,
    seen: AtomicU32,
    off: AtomicBool,
    addr: String,
}

#[async_trait]
impl Handler for Loop {
    fn name(&self) -> &'static str {
        "loop"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        if self.off.load(Ordering::Relaxed) {
            return next.serve(req).await;
        }
        let name = req.name();
        if name == self.qname && req.qtype() == RecordType::HINFO {
            let n = self.seen.fetch_add(1, Ordering::Relaxed) + 1;
            if n > 1 {
                tracing::error!(
                    "plugin/loop: Loop ({} -> {}) detected for zone \"{}\", see https://coredns.io/plugins/loop#troubleshooting. Query: \"HINFO {}\"",
                    req.remote,
                    self.addr,
                    self.zone,
                    self.qname
                );
                std::process::exit(1);
            }
        }
        next.serve(req).await
    }
}

fn random_label() -> String {
    let mut rng = rand::thread_rng();
    (0..16).map(|_| (b'a' + rng.gen_range(0..26)) as char).collect()
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/loop: this plugin can only be used once per Server Block"));
        }
        if c.next_arg() {
            return Err(c.arg_err());
        }
    }
    let zone = c.zone().to_string();
    let qname = crate::dnsutil::join(&[&random_label(), &random_label()], &zone);
    // where to send the probe: the first bind address or loopback
    let host = c.config.listen_hosts.first().cloned().unwrap_or_else(|| "127.0.0.1".to_string());
    let host = if host == "0.0.0.0" || host == "::" { "127.0.0.1".to_string() } else { host };
    let addr = if host.contains(':') { format!("[{}]:{}", host, c.config.port) } else { format!("{}:{}", host, c.config.port) };
    let l = Arc::new(Loop { zone: zone.clone(), qname: qname.clone(), seen: AtomicU32::new(0), off: AtomicBool::new(false), addr: addr.clone() });
    c.add_plugin(l.clone());
    c.on_startup(Box::new(move || {
        Box::pin(async move {
            tokio::spawn(async move {
                // give the listeners a moment to come up, then probe
                tokio::time::sleep(Duration::from_secs(1)).await;
                let mut m = Message::new();
                m.set_id(rand::random());
                m.set_recursion_desired(true);
                m.add_query(Query::query(Name::from_ascii(&qname).unwrap_or_else(|_| Name::root()), RecordType::HINFO));
                let wire = match m.to_vec() {
                    Ok(w) => w,
                    Err(_) => return,
                };
                for _ in 0..3 {
                    if let Ok(sock) = tokio::net::UdpSocket::bind(if addr.starts_with('[') { "[::]:0" } else { "0.0.0.0:0" }).await {
                        if sock.send_to(&wire, &addr).await.is_ok() {
                            let mut buf = [0u8; 512];
                            if tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf)).await.is_ok() {
                                break;
                            }
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                // after the check window, stop looking
                tokio::time::sleep(Duration::from_secs(30)).await;
                l.off.store(true, Ordering::Relaxed);
            });
            Ok(())
        })
    }));
    Ok(())
}
