//! `loop` — detects forwarding loops: at startup it sends a random query
//! for the server block's zone to itself; if that query is seen more than
//! twice the server exits with an error (CoreDNS's threshold).
//!
//! The probe is retried when no answer comes back (slow or unreachable
//! upstream). Each attempt uses its own random name, so a retry is never
//! counted as the earlier probe coming back: only one name arriving again
//! through the chain is a loop.

use crate::plugin::{Controller, DnsResult, Handler, Next, Request};
use async_trait::async_trait;
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use rand::Rng;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Probe attempts at startup, each with its own name.
const ATTEMPTS: usize = 3;

pub struct Loop {
    zone: String,
    /// One probe name per attempt, with how often each has arrived.
    probes: Vec<(String, AtomicU32)>,
    off: AtomicBool,
    addr: String,
}

impl Loop {
    fn new(zone: String, addr: String) -> Loop {
        let probes = (0..ATTEMPTS)
            .map(|_| (crate::dnsutil::join(&[&random_label(), &random_label()], &zone), AtomicU32::new(0)))
            .collect();
        Loop { zone, probes, off: AtomicBool::new(false), addr }
    }

    /// Counts an arrival of `name`; true when it is one of our probes and
    /// has now been seen more than twice, i.e. it came back through a loop.
    fn looped(&self, name: &str) -> bool {
        match self.probes.iter().find(|(q, _)| q == name) {
            Some((_, seen)) => seen.fetch_add(1, Ordering::Relaxed) + 1 > 2,
            None => false,
        }
    }
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
        if req.qtype() == RecordType::HINFO {
            let name = req.name();
            if self.looped(&name) {
                tracing::error!(
                    "plugin/loop: Loop ({} -> {}) detected for zone \"{}\", see https://coredns.io/plugins/loop#troubleshooting. Query: \"HINFO {}\"",
                    req.remote,
                    self.addr,
                    self.zone,
                    name
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
    // where to send the probe: the first bind address or loopback
    let host = c.config.listen_hosts.first().cloned().unwrap_or_else(|| "127.0.0.1".to_string());
    let host = if host == "0.0.0.0" || host == "::" { "127.0.0.1".to_string() } else { host };
    let addr = if host.contains(':') { format!("[{}]:{}", host, c.config.port) } else { format!("{}:{}", host, c.config.port) };
    let l = Arc::new(Loop::new(zone, addr.clone()));
    c.add_plugin(l.clone());
    c.on_startup(Box::new(move || {
        Box::pin(async move {
            tokio::spawn(async move {
                // give the listeners a moment to come up, then probe
                tokio::time::sleep(Duration::from_secs(1)).await;
                // a fresh name per attempt: a retry must not look like the
                // previous probe coming back (#18)
                for (qname, _) in &l.probes {
                    let mut m = Message::new();
                    m.set_id(rand::random());
                    m.set_recursion_desired(true);
                    m.add_query(Query::query(Name::from_ascii(qname).unwrap_or_else(|_| Name::root()), RecordType::HINFO));
                    let wire = match m.to_vec() {
                        Ok(w) => w,
                        Err(_) => break,
                    };
                    if let Ok(sock) = tokio::net::UdpSocket::bind(if addr.starts_with('[') { "[::]:0" } else { "0.0.0.0:0" }).await {
                        if sock.send_to(&wire, &addr).await.is_ok() {
                            let mut buf = [0u8; 512];
                            if tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf)).await.is_ok() {
                                break;
                            }
                        }
                    }
                    tracing::warn!("plugin/loop: no answer to the loop probe HINFO {} from {} within 2s (slow or unreachable upstream?); not a loop", qname, addr);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retried_probes_are_not_a_loop() {
        // every attempt answered late by the upstream, each name arriving once
        let l = Loop::new("example.org.".into(), "127.0.0.1:53".into());
        assert_eq!(l.probes.len(), ATTEMPTS);
        for (q, _) in &l.probes {
            assert!(!l.looped(q));
        }
        // names are distinct and inside the zone
        let names: std::collections::HashSet<_> = l.probes.iter().map(|(q, _)| q.clone()).collect();
        assert_eq!(names.len(), ATTEMPTS);
        assert!(l.probes.iter().all(|(q, _)| q.ends_with(".example.org.")));
    }

    #[test]
    fn one_probe_coming_back_is_a_loop() {
        let l = Loop::new(".".into(), "127.0.0.1:53".into());
        let q = l.probes[0].0.clone();
        assert!(!l.looped(&q));
        assert!(!l.looped(&q));
        assert!(l.looped(&q));
    }

    #[test]
    fn other_names_are_ignored() {
        let l = Loop::new(".".into(), "127.0.0.1:53".into());
        for _ in 0..5 {
            assert!(!l.looped("example.org."));
        }
    }
}
