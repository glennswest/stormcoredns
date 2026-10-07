//! `acl` — allow, block (REFUSED), filter (empty NOERROR) or drop queries
//! by source network and query type.
//!
//! ```text
//! acl [ZONES...] {
//!     ACTION [type QTYPE...] [net SOURCE...]
//! }
//! ```
//! ACTION is `allow`, `block`, `filter` or `drop`. As in CoreDNS, the
//! first matching policy of the first matching rule decides; a rule with
//! no matching policy passes the query on to the next rule, and a query no
//! rule decides is allowed. Blocked (REFUSED) and filtered (empty NOERROR)
//! replies carry an Extended DNS Error (Blocked 15 / Filtered 17).

use crate::plugin::{Controller, DnsResult, Handler, Next, Reply, Request};
use async_trait::async_trait;
use hickory_proto::op::{Edns, Message, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::RecordType;
use ipnet::IpNet;
use once_cell::sync::Lazy;
use prometheus::IntCounterVec;
use std::sync::Arc;

static BLOCK_COUNT: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(prometheus::Opts::new("coredns_acl_blocked_requests_total", "Counter of DNS requests being blocked."), &["server", "zone", "view"]).unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});
static FILTER_COUNT: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(prometheus::Opts::new("coredns_acl_filtered_requests_total", "Counter of DNS requests being filtered."), &["server", "zone", "view"]).unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});
static ALLOW_COUNT: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(prometheus::Opts::new("coredns_acl_allowed_requests_total", "Counter of DNS requests being allowed."), &["server", "view"]).unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});
static DROP_COUNT: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(prometheus::Opts::new("coredns_acl_dropped_requests_total", "Counter of DNS requests being dropped."), &["server", "zone", "view"]).unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Allow,
    Block,
    Filter,
    Drop,
}

#[derive(Debug)]
struct Policy {
    action: Action,
    /// Empty = all types.
    qtypes: Vec<RecordType>,
    nets: Vec<IpNet>,
}

impl Policy {
    fn matches(&self, req: &Request) -> bool {
        if !self.qtypes.is_empty() && !self.qtypes.contains(&req.qtype()) {
            return false;
        }
        let ip = req.ip();
        self.nets.iter().any(|n| n.contains(&ip))
    }
}

struct Rule {
    zones: Vec<String>,
    policies: Vec<Policy>,
}

pub struct Acl {
    rules: Vec<Rule>,
}

#[async_trait]
impl Handler for Acl {
    fn name(&self) -> &'static str {
        "acl"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let name = req.name();
        for rule in &self.rules {
            let Some(zone) = crate::plugin::zones_match(&rule.zones, &name) else { continue };
            let zone = zone.to_string();
            match rule.policies.iter().find(|p| p.matches(req)).map(|p| p.action) {
                // no policy matched: the next rule decides
                None => continue,
                Some(Action::Allow) => break,
                Some(Action::Block) => {
                    BLOCK_COUNT.with_label_values(&[&req.server, &zone, &req.view]).inc();
                    let mut m = req.new_reply();
                    m.set_response_code(ResponseCode::Refused);
                    add_ede(&mut m, EDE_BLOCKED);
                    return Ok(Reply::Msg(m));
                }
                Some(Action::Filter) => {
                    FILTER_COUNT.with_label_values(&[&req.server, &zone, &req.view]).inc();
                    let mut m = req.new_reply();
                    add_ede(&mut m, EDE_FILTERED);
                    return Ok(Reply::Msg(m));
                }
                Some(Action::Drop) => {
                    DROP_COUNT.with_label_values(&[&req.server, &zone, &req.view]).inc();
                    return Ok(Reply::Drop);
                }
            }
        }
        ALLOW_COUNT.with_label_values(&[&req.server, &req.view]).inc();
        next.serve(req).await
    }
}

/// Extended DNS Error codes (RFC 8914).
const EDE_BLOCKED: u16 = 15;
const EDE_FILTERED: u16 = 17;
const EDNS_EDE: u16 = 15;

/// Add an EDE option, with EDNS0 (4096, DO) as CoreDNS sets it.
fn add_ede(m: &mut Message, code: u16) {
    let mut e = m.extensions().clone().unwrap_or_else(Edns::new);
    e.set_max_payload(4096);
    e.set_dnssec_ok(true);
    e.options_mut().insert(EdnsOption::Unknown(EDNS_EDE, code.to_be_bytes().to_vec()));
    m.set_edns(e);
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut rules = Vec::new();
    while c.next() {
        let args = c.remaining_args_until_brace();
        let zones = c.origins_from_args_or_server_block(&args)?;
        let mut policies = Vec::new();
        while c.next_block() {
            let action = match c.val() {
                "allow" => Action::Allow,
                "block" => Action::Block,
                "filter" => Action::Filter,
                "drop" => Action::Drop,
                o => return Err(c.errf(format!("unexpected token '{}'; expect allow, block, filter or drop", o))),
            };
            let toks = c.remaining_args();
            let mut qtypes = Vec::new();
            let mut nets: Vec<IpNet> = Vec::new();
            let mut i = 0;
            let mut has_net = false;
            while i < toks.len() {
                match toks[i].as_str() {
                    "type" => {
                        i += 1;
                        let mut got = false;
                        while i < toks.len() && toks[i] != "net" {
                            qtypes.push(crate::dnsutil::record_type_from_str(&toks[i]).map_err(|e| c.errf(e))?);
                            got = true;
                            i += 1;
                        }
                        if !got {
                            return Err(c.errf("no types specified after 'type'"));
                        }
                    }
                    "net" => {
                        i += 1;
                        has_net = true;
                        let mut got = false;
                        while i < toks.len() && toks[i] != "type" {
                            let t = &toks[i];
                            if t == "*" {
                                nets.push("0.0.0.0/0".parse().unwrap());
                                nets.push("::/0".parse().unwrap());
                            } else if let Ok(n) = t.parse::<IpNet>() {
                                nets.push(n);
                            } else if let Ok(ip) = t.parse::<std::net::IpAddr>() {
                                nets.push(IpNet::from(ip));
                            } else {
                                return Err(c.errf(format!("illegal CIDR notation \"{}\"", t)));
                            }
                            got = true;
                            i += 1;
                        }
                        if !got {
                            return Err(c.errf("no networks specified after 'net'"));
                        }
                    }
                    o => return Err(c.errf(format!("unexpected token '{}'; expect 'type' or 'net'", o))),
                }
            }
            if !has_net {
                nets.push("0.0.0.0/0".parse().unwrap());
                nets.push("::/0".parse().unwrap());
            }
            policies.push(Policy { action, qtypes, nets });
        }
        rules.push(Rule { zones, policies });
    }
    c.add_plugin(Arc::new(Acl { rules }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blocks_by_net() {
        let acl = Acl {
            rules: vec![Rule {
                zones: vec![".".into()],
                policies: vec![
                    Policy { action: Action::Allow, qtypes: vec![], nets: vec!["10.0.0.0/8".parse().unwrap()] },
                    Policy { action: Action::Block, qtypes: vec![], nets: vec!["0.0.0.0/0".parse().unwrap()] },
                ],
            }],
        };
        let mut req = Request::for_test("example.org.", RecordType::A);
        let r = acl.serve_dns(&mut req, Next::new(&[])).await.unwrap();
        assert_eq!(r.rcode(), ResponseCode::Refused);
        req.remote = "10.1.2.3:5".parse().unwrap();
        assert!(acl.serve_dns(&mut req, Next::new(&[])).await.is_err(), "allowed → falls to empty chain");
    }

    #[tokio::test]
    async fn unmatched_rule_falls_through_and_ede() {
        let acl = Acl {
            rules: vec![
                // matches the zone, but no policy matches 192.0.2.1
                Rule { zones: vec![".".into()], policies: vec![Policy { action: Action::Allow, qtypes: vec![], nets: vec!["10.0.0.0/8".parse().unwrap()] }] },
                Rule { zones: vec!["example.org.".into()], policies: vec![Policy { action: Action::Filter, qtypes: vec![], nets: vec!["0.0.0.0/0".parse().unwrap()] }] },
            ],
        };
        let mut req = Request::for_test("example.org.", RecordType::A);
        req.remote = "192.0.2.1:5".parse().unwrap();
        let r = acl.serve_dns(&mut req, Next::new(&[])).await.unwrap();
        let m = r.msg().unwrap();
        assert_eq!(m.response_code(), ResponseCode::NoError);
        let e = m.extensions().as_ref().unwrap();
        let ede = e.options().get(hickory_proto::rr::rdata::opt::EdnsCode::from(15)).unwrap();
        assert_eq!(ede, &EdnsOption::Unknown(15, vec![0, 17]));
    }
}
