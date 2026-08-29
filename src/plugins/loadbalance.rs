//! `loadbalance [round_robin|weighted WEIGHT_FILE]` — shuffles the order
//! of A, AAAA and MX records in answers (CNAMEs stay in front).
//!
//! ```text
//! loadbalance [round_robin]
//! loadbalance weighted WEIGHT_FILE {
//!     reload DURATION
//! }
//! ```
//! The weight file lists, per domain, `IP WEIGHT` lines; the first record
//! in the answer is chosen with probability proportional to its weight.

use crate::plugin::{Controller, DnsResult, Handler, Next, Reply, Request};
use anyhow::Result;
use async_trait::async_trait;
use hickory_proto::op::Message;
use hickory_proto::rr::{RData, Record, RecordType};
use parking_lot::RwLock;
use rand::seq::SliceRandom;
use rand::Rng;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Default)]
pub struct Weights {
    /// domain (lowercase FQDN) → (ip → weight)
    pub domains: HashMap<String, HashMap<IpAddr, u8>>,
}

pub enum Policy {
    RoundRobin,
    Weighted(Arc<RwLock<Weights>>),
}

pub struct LoadBalance {
    policy: Policy,
}

fn shuffle_section(records: Vec<Record>, first: Option<&Record>) -> Vec<Record> {
    let mut cname = Vec::new();
    let mut addr = Vec::new();
    let mut mx = Vec::new();
    let mut rest = Vec::new();
    for r in records {
        match r.record_type() {
            RecordType::CNAME => cname.push(r),
            RecordType::A | RecordType::AAAA => addr.push(r),
            RecordType::MX => mx.push(r),
            _ => rest.push(r),
        }
    }
    let mut rng = rand::thread_rng();
    addr.shuffle(&mut rng);
    mx.shuffle(&mut rng);
    if let Some(f) = first {
        if let Some(pos) = addr.iter().position(|r| r == f) {
            addr.swap(0, pos);
        }
    }
    let mut out = cname;
    out.extend(addr);
    out.extend(mx);
    out.extend(rest);
    out
}

fn weighted_first(w: &Weights, qname: &str, answers: &[Record]) -> Option<Record> {
    let table = w.domains.get(&qname.to_ascii_lowercase())?;
    let candidates: Vec<(&Record, u8)> = answers
        .iter()
        .filter_map(|r| match r.data() {
            Some(RData::A(a)) => Some((r, *table.get(&IpAddr::V4(a.0)).unwrap_or(&1))),
            Some(RData::AAAA(a)) => Some((r, *table.get(&IpAddr::V6(a.0)).unwrap_or(&1))),
            _ => None,
        })
        .collect();
    if candidates.is_empty() {
        return None;
    }
    let total: u32 = candidates.iter().map(|(_, w)| *w as u32).sum();
    if total == 0 {
        return None;
    }
    let mut pick = rand::thread_rng().gen_range(0..total);
    for (r, w) in candidates {
        if pick < w as u32 {
            return Some(r.clone());
        }
        pick -= w as u32;
    }
    None
}

impl LoadBalance {
    fn balance(&self, qname: &str, m: &mut Message) {
        let first = match &self.policy {
            Policy::RoundRobin => None,
            Policy::Weighted(w) => weighted_first(&w.read(), qname, m.answers()),
        };
        let a = m.take_answers();
        m.insert_answers(shuffle_section(a, first.as_ref()));
        let x = m.take_additionals();
        m.insert_additionals(shuffle_section(x, None));
    }
}

#[async_trait]
impl Handler for LoadBalance {
    fn name(&self) -> &'static str {
        "loadbalance"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let qname = req.name();
        let mut r = next.serve(req).await?;
        if let Reply::Msg(m) = &mut r {
            self.balance(&qname, m);
        }
        Ok(r)
    }
}

pub fn parse_weight_file(path: &PathBuf) -> Result<Weights> {
    let text = std::fs::read_to_string(path)?;
    let mut w = Weights::default();
    let mut current: Option<String> = None;
    for (ln, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 1 {
            current = Some(crate::dnsutil::fqdn(parts[0]));
            continue;
        }
        if parts.len() == 2 {
            let ip: IpAddr = parts[0].parse().map_err(|_| anyhow::anyhow!("{}:{}: bad IP {}", path.display(), ln + 1, parts[0]))?;
            let weight: u8 = parts[1].parse().map_err(|_| anyhow::anyhow!("{}:{}: bad weight {}", path.display(), ln + 1, parts[1]))?;
            let d = current.clone().ok_or_else(|| anyhow::anyhow!("{}:{}: weight before any domain", path.display(), ln + 1))?;
            w.domains.entry(d).or_default().insert(ip, weight);
            continue;
        }
        anyhow::bail!("{}:{}: unexpected line", path.display(), ln + 1);
    }
    Ok(w)
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/loadbalance: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args_until_brace();
        let policy = match args.first().map(|s| s.as_str()) {
            None | Some("round_robin") => {
                if args.len() > 1 {
                    return Err(c.arg_err());
                }
                Policy::RoundRobin
            }
            Some("weighted") => {
                let f = args.get(1).ok_or_else(|| c.errf("missing weight file argument"))?;
                let path = if std::path::Path::new(f).is_absolute() { PathBuf::from(f) } else { c.config.root.join(f) };
                let mut reload = Duration::from_secs(30);
                while c.next_block() {
                    match c.val() {
                        "reload" => {
                            let a = c.remaining_args();
                            if a.len() != 1 {
                                return Err(c.arg_err());
                            }
                            reload = crate::dnsutil::parse_duration(&a[0])?;
                        }
                        o => return Err(c.errf(format!("unknown property '{}'", o))),
                    }
                }
                let weights = Arc::new(RwLock::new(parse_weight_file(&path).map_err(|e| c.errf(e))?));
                if !reload.is_zero() {
                    let w = weights.clone();
                    let p = path.clone();
                    c.on_startup(Box::new(move || {
                        Box::pin(async move {
                            tokio::spawn(async move {
                                let mut last = std::fs::metadata(&p).and_then(|m| m.modified()).ok();
                                loop {
                                    tokio::time::sleep(reload).await;
                                    let now = std::fs::metadata(&p).and_then(|m| m.modified()).ok();
                                    if now != last {
                                        last = now;
                                        match parse_weight_file(&p) {
                                            Ok(nw) => *w.write() = nw,
                                            Err(e) => tracing::warn!("plugin/loadbalance: reloading {}: {}", p.display(), e),
                                        }
                                    }
                                }
                            });
                            Ok(())
                        })
                    }));
                }
                Policy::Weighted(weights)
            }
            Some(o) => return Err(c.errf(format!("unknown policy: {}", o))),
        };
        c.add_plugin(Arc::new(LoadBalance { policy }));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, CNAME};
    use hickory_proto::rr::Name;

    #[test]
    fn cname_stays_first() {
        let n = Name::from_ascii("a.example.org.").unwrap();
        let recs = vec![
            Record::from_rdata(n.clone(), 1, RData::CNAME(CNAME(Name::from_ascii("b.example.org.").unwrap()))),
            Record::from_rdata(n.clone(), 1, RData::A(A::new(1, 1, 1, 1))),
            Record::from_rdata(n.clone(), 1, RData::A(A::new(2, 2, 2, 2))),
        ];
        for _ in 0..10 {
            let out = shuffle_section(recs.clone(), None);
            assert_eq!(out[0].record_type(), RecordType::CNAME);
            assert_eq!(out.len(), 3);
        }
    }
}
