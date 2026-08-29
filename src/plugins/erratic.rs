//! `erratic` — deliberately misbehaves for testing: drops, truncates or
//! delays every Nth A/AAAA/AXFR query, optionally with large answers.
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
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
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

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let qtype = req.qtype();
        if !matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::AXFR) {
            return next.serve(req).await;
        }
        let n = self.q.fetch_add(1, Ordering::Relaxed) + 1;
        if self.drop > 0 && n % self.drop == 0 {
            return Ok(Reply::Drop);
        }
        if self.delay > 0 && n % self.delay == 0 {
            tokio::time::sleep(self.duration).await;
        }
        let mut m = req.new_reply();
        m.set_authoritative(true);
        let count = if self.large { 30 } else { 1 };
        for i in 0..count {
            match qtype {
                RecordType::A => m.add_answer(Record::from_rdata(req.qname(), 30, RData::A(A::new(192, 0, 2, 53u8.wrapping_add(i))))),
                _ => m.add_answer(Record::from_rdata(req.qname(), 30, RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53 + i as u16)))),
            };
        }
        if self.truncate > 0 && n % self.truncate == 0 {
            m.set_truncated(true);
            m.take_answers();
        }
        Ok(Reply::Msg(m))
    }
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
