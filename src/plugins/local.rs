//! `local` — answers for `localhost.`, `localhost.<anything>`, and the
//! `0.in-addr.arpa.`, `127.in-addr.arpa.` and `255.in-addr.arpa.` zones
//! without leaking them upstream. A port of CoreDNS's plugin: anything
//! else in those zones is NXDOMAIN with the zone's SOA, and
//! `localhost.<domain>` queries are counted in
//! `coredns_local_localhost_requests_total`.

use crate::plugin::{Controller, DnsResult, Handler, Next, Reply, Request};
use async_trait::async_trait;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, NS, PTR, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use once_cell::sync::Lazy;
use prometheus::IntCounter;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

static LOCALHOST_COUNT: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new("coredns_local_localhost_requests_total", "Counter of localhost.<domain> requests.").unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});

pub struct Local;

const ZONES: &[&str] = &["localhost.", "0.in-addr.arpa.", "127.in-addr.arpa.", "255.in-addr.arpa."];
const TTL: u32 = 604800;

fn n(s: &str) -> Name {
    Name::from_ascii(s).unwrap_or_else(|_| Name::root())
}

fn soa(origin: &Name) -> Record {
    Record::from_rdata(origin.clone(), TTL, RData::SOA(SOA::new(n("localhost."), n("root.localhost."), 1, 0, 0, 0, TTL)))
}

fn a(name: &Name) -> Record {
    Record::from_rdata(name.clone(), TTL, RData::A(A(Ipv4Addr::LOCALHOST)))
}

fn aaaa(name: &Name) -> Record {
    Record::from_rdata(name.clone(), TTL, RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)))
}

#[async_trait]
impl Handler for Local {
    fn name(&self) -> &'static str {
        "local"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let lname = req.name();
        let qtype = req.qtype();
        let qname = req.qname();
        let mut m = req.new_reply();

        // localhost.<more labels>: 127.0.0.1 / ::1
        if lname.len() > "localhost.".len() && lname.starts_with("localhost.") {
            LOCALHOST_COUNT.inc();
            match qtype {
                RecordType::A => m.add_answer(a(&qname)),
                RecordType::AAAA => m.add_answer(aaaa(&qname)),
                _ => m.add_name_server(soa(&qname)),
            };
            return Ok(Reply::Msg(m));
        }

        let Some(zone) = crate::plugin::zones_match(&ZONES.iter().map(|z| z.to_string()).collect::<Vec<_>>(), &lname).map(|z| z.to_string()) else {
            return next.serve(req).await;
        };
        // the zone with the query's own spelling
        let zone_name = qname.trim_to(crate::dnsutil::count_labels(&zone));
        match lname.as_str() {
            "localhost." | "0.in-addr.arpa." | "127.in-addr.arpa." | "255.in-addr.arpa." => match qtype {
                RecordType::A if lname == "localhost." => {
                    m.add_answer(a(&qname));
                }
                RecordType::AAAA if lname == "localhost." => {
                    m.add_answer(aaaa(&qname));
                }
                RecordType::SOA => {
                    m.add_answer(soa(&qname));
                }
                RecordType::NS => {
                    m.add_answer(Record::from_rdata(qname.clone(), TTL, RData::NS(NS(n("localhost.")))));
                }
                _ => {
                    m.add_name_server(soa(&qname));
                }
            },
            "1.0.0.127.in-addr.arpa." => match qtype {
                RecordType::PTR => {
                    m.add_answer(Record::from_rdata(qname.clone(), TTL, RData::PTR(PTR(n("localhost.")))));
                }
                _ => {
                    m.add_name_server(soa(&zone_name));
                }
            },
            _ => {}
        }
        if m.answers().is_empty() && m.name_servers().is_empty() {
            nxdomain(&mut m, &zone_name);
        }
        Ok(Reply::Msg(m))
    }
}

fn nxdomain(m: &mut Message, zone: &Name) {
    m.add_name_server(soa(zone));
    m.set_response_code(ResponseCode::NXDomain);
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn q(name: &str, t: RecordType) -> Result<Message, crate::plugin::PluginError> {
        let mut req = Request::for_test(name, t);
        Local.serve_dns(&mut req, Next::new(&[])).await.map(|r| r.into_msg().unwrap())
    }

    #[tokio::test]
    async fn matches_coredns() {
        let m = q("localhost.", RecordType::A).await.unwrap();
        assert_eq!(m.answers().len(), 1);
        let m = q("localhost.cluster.local.", RecordType::AAAA).await.unwrap();
        assert_eq!(m.answers()[0].record_type(), RecordType::AAAA);
        let m = q("1.0.0.127.in-addr.arpa.", RecordType::PTR).await.unwrap();
        assert_eq!(m.answers().len(), 1);
        let m = q("5.0.0.127.in-addr.arpa.", RecordType::PTR).await.unwrap();
        assert_eq!(m.response_code(), ResponseCode::NXDomain);
        assert_eq!(m.name_servers()[0].name().to_ascii(), "127.in-addr.arpa.");
        let m = q("0.in-addr.arpa.", RecordType::NS).await.unwrap();
        assert_eq!(m.answers()[0].record_type(), RecordType::NS);
        let m = q("1.255.in-addr.arpa.", RecordType::PTR).await.unwrap();
        assert_eq!(m.response_code(), ResponseCode::NXDomain);
        let m = q("foo.localhost.", RecordType::A).await.unwrap();
        assert_eq!(m.response_code(), ResponseCode::NXDomain);
        // not ours
        assert!(q("example.org.", RecordType::A).await.is_err());
        assert!(q("ip6-localhost.", RecordType::AAAA).await.is_err(), "CoreDNS does not answer ip6-localhost");
    }
}
