//! `erratic` — deliberately misbehaves for testing: drops, truncates or
//! delays every Nth query (counting from the first), as CoreDNS does. It
//! answers A (192.0.2.53, 30 copies with `large`), AAAA (2001:db8::53) and
//! AXFR (a small zone; truncated transfers lack the closing SOA); any other
//! type gets SERVFAIL. Ready only while the query count is 3 or 4.
//!
//! ```text
//! erratic {
//!     drop [AMOUNT]
//!     truncate [AMOUNT]
//!     delay [AMOUNT [DURATION]]
//!     large
//! }
//! ```

use crate::plugin::{Controller, DnsResult, Handler, Next, Reply, Request};
use async_trait::async_trait;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{A, AAAA, NS, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub struct Erratic {
    drop: u64,
    truncate: u64,
    delay: u64,
    duration: Duration,
    large: bool,
    q: AtomicU64,
}

#[async_trait]
impl Handler for Erratic {
    fn name(&self) -> &'static str {
        "erratic"
    }

    fn autopath(&self, _req: &Request) -> Option<Vec<String>> {
        Some(vec!["a.example.org.".into(), "b.example.org.".into(), String::new()])
    }

    /// As in CoreDNS: ready while the query count is in [3, 5), so tests
    /// can watch readiness flip.
    fn ready(&self) -> Option<bool> {
        let q = self.q.load(Ordering::Relaxed);
        Some((3..5).contains(&q))
    }

    async fn serve_dns(&self, req: &mut Request, _next: Next<'_>) -> DnsResult {
        // as in CoreDNS: erratic answers everything itself, counting from 0
        let n = self.q.fetch_add(1, Ordering::Relaxed);
        let drop = self.drop > 0 && n % self.drop == 0;
        let delay = self.delay > 0 && n % self.delay == 0;
        let trunc = self.truncate > 0 && n % self.truncate == 0;
        if drop {
            return Ok(Reply::Drop);
        }
        if delay {
            tokio::time::sleep(self.duration).await;
        }
        let qname = req.qname();
        let mut m = req.new_reply();
        m.set_authoritative(true);
        m.set_truncated(trunc);
        match req.qtype() {
            RecordType::A => {
                let count = if self.large { 30 } else { 1 };
                for _ in 0..count {
                    m.add_answer(Record::from_rdata(qname.clone(), 0, RData::A(A::new(192, 0, 2, 53))));
                }
            }
            RecordType::AAAA => {
                m.add_answer(Record::from_rdata(qname, 0, RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53))));
            }
            RecordType::AXFR => {
                // a small zone; truncation leaves out the closing SOA
                let mut x = req.new_reply();
                x.set_authoritative(true);
                for r in xfr_records(&qname, !trunc) {
                    x.add_answer(r);
                }
                return Ok(Reply::Multi(vec![x]));
            }
            _ => return Ok(Reply::Rcode(ResponseCode::ServFail)),
        }
        Ok(Reply::Msg(m))
    }
}

/// CoreDNS's erratic zone: SOA, two NS, two AAAA (and the closing SOA).
fn xfr_records(zone: &Name, close: bool) -> Vec<Record> {
    let n = |l: &str| Name::from_ascii(l).ok().and_then(|x| x.append_domain(zone).ok()).unwrap_or_else(|| zone.clone());
    let soa = Record::from_rdata(
        zone.clone(),
        0,
        RData::SOA(SOA::new(Name::from_ascii("sns.dns.icann.org.").unwrap(), Name::from_ascii("noc.dns.icann.org.").unwrap(), 2018050825, 7200, 3600, 1209600, 3600)),
    );
    let mut v = vec![
        soa.clone(),
        Record::from_rdata(zone.clone(), 0, RData::NS(NS(n("b")))),
        Record::from_rdata(zone.clone(), 0, RData::NS(NS(n("a")))),
        Record::from_rdata(n("a"), 0, RData::AAAA(AAAA::new(0x2001, 0xbd8, 0, 0, 0, 0, 0, 0x53))),
        Record::from_rdata(n("b"), 0, RData::AAAA(AAAA::new(0x2001, 0x500, 0, 0, 0, 0, 0, 0x54))),
    ];
    if close {
        v.push(soa);
    }
    v
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/erratic: this plugin can only be used once per Server Block"));
        }
        let mut e = Erratic { drop: 0, truncate: 0, delay: 0, duration: Duration::from_millis(100), large: false, q: AtomicU64::new(0) };
        while c.next_block() {
            match c.val() {
                "drop" | "truncate" | "delay" => {
                    let key = c.val().to_string();
                    let a = c.remaining_args();
                    let amount: u64 = match a.first() {
                        Some(v) => v.parse().map_err(|_| c.errf(format!("illegal amount value given \"{}\"", v)))?,
                        None => 2,
                    };
                    if amount == 0 {
                        return Err(c.errf("illegal amount value given \"0\""));
                    }
                    match key.as_str() {
                        "drop" => e.drop = amount,
                        "truncate" => e.truncate = amount,
                        _ => {
                            e.delay = amount;
                            if let Some(d) = a.get(1) {
                                e.duration = crate::dnsutil::parse_duration(d)?;
                            }
                        }
                    }
                    if a.len() > 2 || (key != "delay" && a.len() > 1) {
                        return Err(c.arg_err());
                    }
                }
                "large" => e.large = true,
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        c.add_plugin(Arc::new(e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(drop: u64) -> Erratic {
        Erratic { drop, truncate: 0, delay: 0, duration: Duration::ZERO, large: false, q: AtomicU64::new(0) }
    }

    #[tokio::test]
    async fn counts_from_zero_and_answers_everything() {
        let h = e(2);
        let mut req = Request::for_test("example.org.", RecordType::A);
        assert!(matches!(h.serve_dns(&mut req, Next::new(&[])).await.unwrap(), Reply::Drop), "query 0 is dropped");
        let m = h.serve_dns(&mut req, Next::new(&[])).await.unwrap().into_msg().unwrap();
        assert_eq!(m.answers().len(), 1);
        let h = e(0);
        let mut req = Request::for_test("example.org.", RecordType::MX);
        assert!(matches!(h.serve_dns(&mut req, Next::new(&[])).await.unwrap(), Reply::Rcode(ResponseCode::ServFail)));
        let mut req = Request::for_test("example.org.", RecordType::AXFR);
        match h.serve_dns(&mut req, Next::new(&[])).await.unwrap() {
            Reply::Multi(v) => {
                let a = v[0].answers();
                assert_eq!(a.len(), 6);
                assert_eq!(a[0].record_type(), RecordType::SOA);
                assert_eq!(a[5].record_type(), RecordType::SOA);
            }
            o => panic!("{:?}", o),
        }
        // readiness flips: 2 queries so far, then ready at 3 and 4
        assert_eq!(h.ready(), Some(false));
        let mut req = Request::for_test("example.org.", RecordType::A);
        h.serve_dns(&mut req, Next::new(&[])).await.unwrap();
        assert_eq!(h.ready(), Some(true));
    }
}
