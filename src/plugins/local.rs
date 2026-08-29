//! `local` — answers for `localhost.`, `localhost.localdomain.`,
//! `ip6-localhost.`, `ip6-loopback.` and their reverse names without
//! leaking them upstream.

use crate::plugin::{Controller, DnsResult, Handler, Next, Reply, Request};
use async_trait::async_trait;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{A, AAAA, PTR, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

pub struct Local;

const NAMES: &[&str] = &["localhost.", "localhost.localdomain.", "ip6-localhost.", "ip6-loopback."];
const TTL: u32 = 604800;

fn soa(name: &Name) -> Record {
    Record::from_rdata(name.clone(), TTL, RData::SOA(SOA::new(name.clone(), Name::from_ascii("root.localhost.").unwrap(), 1, 604800, 86400, 2419200, TTL)))
}

#[async_trait]
impl Handler for Local {
    fn name(&self) -> &'static str {
        "local"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let qname = req.name();
        let qtype = req.qtype();
        let name = req.qname();
        let mut m = req.new_reply();
        m.set_authoritative(true);
        if NAMES.contains(&qname.as_str()) {
            let v6 = qname.starts_with("ip6-");
            match qtype {
                RecordType::A if !v6 => m.add_answer(Record::from_rdata(name.clone(), TTL, RData::A(A(Ipv4Addr::LOCALHOST)))),
                RecordType::AAAA => m.add_answer(Record::from_rdata(name.clone(), TTL, RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)))),
                RecordType::ANY => {
                    if !v6 {
                        m.add_answer(Record::from_rdata(name.clone(), TTL, RData::A(A(Ipv4Addr::LOCALHOST))));
                    }
                    m.add_answer(Record::from_rdata(name.clone(), TTL, RData::AAAA(AAAA(Ipv6Addr::LOCALHOST))))
                }
                _ => m.add_name_server(soa(&Name::from_ascii("localhost.").unwrap())),
            };
            return Ok(Reply::Msg(m));
        }
        let loopback_v4 = "1.0.0.127.in-addr.arpa.";
        let loopback_v6 = crate::dnsutil::reverse_name_str(Ipv6Addr::LOCALHOST.into());
        if qname == loopback_v4 || qname == loopback_v6 {
            if matches!(qtype, RecordType::PTR | RecordType::ANY) {
                m.add_answer(Record::from_rdata(name.clone(), TTL, RData::PTR(PTR(Name::from_ascii("localhost.").unwrap()))));
            } else {
                m.add_name_server(soa(&name));
            }
            return Ok(Reply::Msg(m));
        }
        // the rest of 127/8 and the localhost zone: NXDOMAIN
        if qname.ends_with(".localhost.") || (qname.ends_with(".127.in-addr.arpa.") && qname != loopback_v4) {
            m.set_response_code(ResponseCode::NXDomain);
            m.add_name_server(soa(&Name::from_ascii("localhost.").unwrap()));
            return Ok(Reply::Msg(m));
        }
        next.serve(req).await
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/local: this plugin can only be used once per Server Block"));
        }
        if c.next_arg() {
            return Err(c.arg_err());
        }
        c.add_plugin(Arc::new(Local));
    }
    Ok(())
}
