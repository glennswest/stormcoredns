//! `transfer` — outbound zone transfers (AXFR, and IXFR answered as a full
//! transfer) for zones served by plugins that implement
//! `Handler::transfer` (file, secondary, auto, sign), plus NOTIFY.
//!
//! ```text
//! transfer [ZONE...] {
//!     to HOST...       # "*" allows every client
//! }
//! ```

use crate::dnsutil;
use crate::plugin::{Controller, DnsResult, Handler, Next, Proto, Reply, Request};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Weak};

/// Every configured transfer instance, so `notify()` can reach them.
static INSTANCES: Lazy<Mutex<Vec<Weak<Transfer>>>> = Lazy::new(|| Mutex::new(Vec::new()));

/// Approximate upper bound for one transfer message on the wire.
const MSG_LIMIT: usize = 60_000;

pub struct Transfer {
    zones: Vec<String>,
    /// Allowed clients (and NOTIFY targets). `None` in `any` = "*".
    to: Vec<SocketAddr>,
    any: bool,
    /// Sibling handlers that may serve the zone data.
    sources: ArcSwap<Vec<Arc<dyn Handler>>>,
}

impl Transfer {
    fn allowed(&self, ip: IpAddr) -> bool {
        self.any || self.to.iter().any(|a| a.ip() == ip)
    }

    fn records(&self, zone: &str) -> Option<Vec<Record>> {
        for h in self.sources.load().iter() {
            if let Some(r) = h.transfer(zone) {
                return Some(r);
            }
        }
        None
    }
}

fn serial_of(records: &[Record]) -> Option<u32> {
    records.iter().find_map(|r| match r.data() {
        Some(RData::SOA(soa)) => Some(soa.serial()),
        _ => None,
    })
}

/// Split records into AXFR messages: SOA, RRs..., SOA.
fn build_messages(req: &Request, mut records: Vec<Record>) -> Vec<Message> {
    let soa_pos = records.iter().position(|r| r.record_type() == RecordType::SOA);
    let soa = match soa_pos {
        Some(i) => records.remove(i),
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut cur = req.new_reply();
    cur.set_authoritative(true);
    *cur.extensions_mut() = None;
    let mut size = 12 + 64;
    let push = |cur: &mut Message, size: &mut usize, r: Record, out: &mut Vec<Message>, req: &Request| {
        let rlen = r.to_bytes().map(|b| b.len()).unwrap_or(64);
        if *size + rlen > MSG_LIMIT && !cur.answers().is_empty() {
            let mut next = req.new_reply();
            next.set_authoritative(true);
            *next.extensions_mut() = None;
            out.push(std::mem::replace(cur, next));
            *size = 12 + 64;
        }
        cur.add_answer(r);
        *size += rlen;
    };
    push(&mut cur, &mut size, soa.clone(), &mut out, req);
    for r in records {
        push(&mut cur, &mut size, r, &mut out, req);
    }
    push(&mut cur, &mut size, soa, &mut out, req);
    out.push(cur);
    // only the first message carries the question
    for m in out.iter_mut().skip(1) {
        m.take_queries();
    }
    out
}

#[async_trait]
impl Handler for Transfer {
    fn name(&self) -> &'static str {
        "transfer"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let qtype = req.qtype();
        if qtype != RecordType::AXFR && qtype != RecordType::IXFR {
            return next.serve(req).await;
        }
        let qname = req.name();
        let Some(zone) = crate::plugin::zones_match(&self.zones, &qname).map(|z| z.to_string()) else {
            return next.serve(req).await;
        };
        if zone != qname {
            return next.serve(req).await;
        }
        if !self.allowed(req.ip()) {
            let mut m = req.new_reply();
            m.set_response_code(ResponseCode::Refused);
            return Ok(Reply::Msg(m));
        }
        let Some(records) = self.records(&zone) else {
            return next.serve(req).await;
        };
        // IXFR: same serial → just the SOA
        if qtype == RecordType::IXFR {
            let client_serial = req.msg.name_servers().iter().find_map(|r| match r.data() {
                Some(RData::SOA(s)) => Some(s.serial()),
                _ => None,
            });
            if let (Some(cs), Some(ours)) = (client_serial, serial_of(&records)) {
                if cs == ours {
                    let mut m = req.new_reply();
                    m.set_authoritative(true);
                    if let Some(soa) = records.iter().find(|r| r.record_type() == RecordType::SOA) {
                        m.add_answer(soa.clone());
                    }
                    return Ok(Reply::Msg(m));
                }
            }
        }
        if req.proto == Proto::Udp {
            // RFC 5936: AXFR needs TCP; answer with the SOA and TC so the
            // client retries over TCP
            let mut m = req.new_reply();
            m.set_authoritative(true);
            m.set_truncated(true);
            if let Some(soa) = records.iter().find(|r| r.record_type() == RecordType::SOA) {
                m.add_answer(soa.clone());
            }
            return Ok(Reply::Msg(m));
        }
        tracing::info!("plugin/transfer: outgoing transfer of {} records for {} to {}", records.len(), zone, req.ip());
        Ok(Reply::Multi(build_messages(req, records)))
    }
}

/// Send NOTIFY for `zone` to every configured `to` address (called by
/// plugins when a zone they serve changes).
pub fn notify(zone: &str) {
    let zone = dnsutil::fqdn(zone);
    let targets: Vec<SocketAddr> = INSTANCES
        .lock()
        .iter()
        .filter_map(|w| w.upgrade())
        .filter(|t| crate::plugin::zones_match(&t.zones, &zone).map(|z| z == zone).unwrap_or(false))
        .flat_map(|t| t.to.clone())
        .collect();
    if targets.is_empty() {
        return;
    }
    let Ok(name) = hickory_proto::rr::Name::from_ascii(&zone) else { return };
    tokio::spawn(async move {
        for addr in targets {
            let mut m = Message::new();
            m.set_id(rand::random());
            m.set_op_code(OpCode::Notify);
            m.set_message_type(MessageType::Query);
            m.set_authoritative(true);
            m.add_query(Query::query(name.clone(), RecordType::SOA));
            let Ok(wire) = m.to_vec() else { continue };
            let bind = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            if let Ok(sock) = tokio::net::UdpSocket::bind(bind).await {
                if sock.send_to(&wire, addr).await.is_ok() {
                    let mut buf = [0u8; 512];
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), sock.recv(&mut buf)).await;
                }
            }
            tracing::info!("plugin/transfer: sent notify for zone {} to {}", zone, addr);
        }
    });
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    while c.next() {
        let args = c.remaining_args_until_brace();
        let zones = c.origins_from_args_or_server_block(&args)?;
        let mut to = Vec::new();
        let mut any = false;
        let mut seen_to = false;
        while c.next_block() {
            match c.val() {
                "to" => {
                    seen_to = true;
                    let a = c.remaining_args();
                    if a.is_empty() {
                        return Err(c.arg_err());
                    }
                    for h in a {
                        if h == "*" {
                            any = true;
                            continue;
                        }
                        let hp = dnsutil::host_port(&h, 53)?;
                        let sa: SocketAddr = hp.parse().map_err(|_| c.errf(format!("to: {} is not an IP address", h)))?;
                        to.push(sa);
                    }
                }
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        if !seen_to {
            return Err(c.errf("'to' is required"));
        }
        let t = Arc::new(Transfer { zones, to, any, sources: ArcSwap::from_pointee(Vec::new()) });
        INSTANCES.lock().push(Arc::downgrade(&t));
        c.add_plugin(t.clone());
        let t2 = t.clone();
        crate::plugins::wire::register(c, move |cfg| {
            let sources: Vec<Arc<dyn Handler>> = cfg.plugins.iter().filter(|(n, _)| *n != "transfer").map(|(_, h)| h.clone()).collect();
            t2.sources.store(Arc::new(sources));
        });
    }
    // drop dead weak refs from earlier instances
    INSTANCES.lock().retain(|w| w.strong_count() > 0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, SOA};
    use hickory_proto::rr::Name;

    #[test]
    fn splits_messages() {
        let z = Name::from_ascii("example.org.").unwrap();
        let mut recs = vec![Record::from_rdata(z.clone(), 300, RData::SOA(SOA::new(z.clone(), z.clone(), 1, 1, 1, 1, 1)))];
        for i in 0..5000u32 {
            let n = Name::from_ascii(format!("host{}.example.org.", i)).unwrap();
            recs.push(Record::from_rdata(n, 300, RData::A(A::new(10, 0, (i >> 8) as u8, i as u8))));
        }
        let req = Request::for_test("example.org.", RecordType::AXFR);
        let msgs = build_messages(&req, recs);
        assert!(msgs.len() > 1);
        let total: usize = msgs.iter().map(|m| m.answers().len()).sum();
        assert_eq!(total, 5002);
        assert_eq!(msgs[0].answers()[0].record_type(), RecordType::SOA);
        assert_eq!(msgs.last().unwrap().answers().last().unwrap().record_type(), RecordType::SOA);
        for m in &msgs {
            assert!(m.to_vec().unwrap().len() < 65535);
        }
    }
}
