//! `dns64` — synthesises AAAA records from A records for IPv6-only
//! clients (RFC 6147).
//!
//! ```text
//! dns64 [ZONES...] {
//!     prefix CIDR          # default 64:ff9b::/96
//!     translate_all
//!     allow_ipv4
//! }
//! ```

use crate::plugin::{Controller, DnsResult, Handler, Next, Reply, Request};
use async_trait::async_trait;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::AAAA;
use hickory_proto::rr::{RData, Record, RecordType};
use ipnet::Ipv6Net;
use once_cell::sync::Lazy;
use prometheus::IntCounterVec;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

static REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(prometheus::Opts::new("coredns_dns64_requests_translated_total", "Counter of DNS requests translated by dns64."), &["server"]).unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});

pub struct Dns64 {
    zones: Vec<String>,
    prefix: Ipv6Net,
    translate_all: bool,
    allow_ipv4: bool,
}

impl Dns64 {
    /// Map a v4 address into the prefix (RFC 6052 for /96; other lengths
    /// place the 32 bits at the prefix boundary, skipping bits 64..71).
    pub fn synth(&self, v4: Ipv4Addr) -> Ipv6Addr {
        let p = u128::from(self.prefix.network());
        let v = u32::from(v4) as u128;
        let len = self.prefix.prefix_len() as u32;
        // RFC 6052 §2.2: bits 64..71 ("u") are always zero
        let addr = match len {
            32 => p | (v << 64),
            40 => p | ((v >> 8) << 64) | ((v & 0xff) << 48),
            48 => p | ((v >> 16) << 64) | ((v & 0xffff) << 40),
            56 => p | ((v >> 24) << 64) | ((v & 0xff_ffff) << 32),
            64 => p | (v << 24),
            _ => p | v,
        };
        Ipv6Addr::from(addr)
    }
}

#[async_trait]
impl Handler for Dns64 {
    fn name(&self) -> &'static str {
        "dns64"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let name = req.name();
        if req.qtype() != RecordType::AAAA || crate::plugin::zones_match(&self.zones, &name).is_none() {
            return next.serve(req).await;
        }
        if !self.allow_ipv4 && matches!(req.ip(), IpAddr::V4(_)) {
            return next.serve(req).await;
        }
        let mut r = next.serve(req).await?;
        let Some(m) = r.msg_mut() else { return Ok(r) };
        let has_aaaa = m.answers().iter().any(|a| a.record_type() == RecordType::AAAA);
        let negative = matches!(m.response_code(), ResponseCode::NoError | ResponseCode::NXDomain) && !has_aaaa;
        if !negative && !self.translate_all {
            return Ok(r);
        }
        // fetch the A records through our own chain
        let Ok(a_resp) = crate::server::self_lookup(req, req.qname(), RecordType::A).await else { return Ok(r) };
        let ttl_cap = m
            .name_servers()
            .iter()
            .find_map(|rr| match rr.data() {
                Some(RData::SOA(s)) => Some(rr.ttl().min(s.minimum())),
                _ => None,
            })
            .unwrap_or(u32::MAX);
        let mut synthesized = Vec::new();
        for a in a_resp.answers() {
            match a.data() {
                Some(RData::A(v4)) => {
                    let ttl = a.ttl().min(ttl_cap);
                    synthesized.push(Record::from_rdata(a.name().clone(), ttl, RData::AAAA(AAAA(self.synth(v4.0)))));
                }
                Some(RData::CNAME(_)) => synthesized.push(a.clone()),
                _ => {}
            }
        }
        if synthesized.is_empty() {
            return Ok(r);
        }
        REQUESTS.with_label_values(&[&req.server]).inc();
        let mut answers: Vec<Record> = if self.translate_all { m.take_answers().into_iter().filter(|x| x.record_type() != RecordType::AAAA).collect() } else { Vec::new() };
        answers.extend(synthesized);
        m.set_response_code(ResponseCode::NoError);
        m.take_answers();
        m.take_name_servers();
        m.insert_answers(answers);
        Ok(r)
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/dns64: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args_until_brace();
        let zones = c.origins_from_args_or_server_block(&args)?;
        let mut d = Dns64 { zones, prefix: "64:ff9b::/96".parse().unwrap(), translate_all: false, allow_ipv4: false };
        while c.next_block() {
            match c.val() {
                "prefix" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    let p: Ipv6Net = a[0].parse().map_err(|e| c.errf(format!("invalid prefix {}: {}", a[0], e)))?;
                    if ![32, 40, 48, 56, 64, 96].contains(&p.prefix_len()) {
                        return Err(c.errf("dns64: prefix length must be one of 32, 40, 48, 56, 64 or 96"));
                    }
                    d.prefix = p;
                }
                "translate_all" => d.translate_all = true,
                "allow_ipv4" => d.allow_ipv4 = true,
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        c.add_plugin(Arc::new(d));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_prefix() {
        let d = Dns64 { zones: vec![], prefix: "64:ff9b::/96".parse().unwrap(), translate_all: false, allow_ipv4: false };
        assert_eq!(d.synth(Ipv4Addr::new(192, 0, 2, 33)), "64:ff9b::c000:221".parse::<Ipv6Addr>().unwrap());
    }
}
