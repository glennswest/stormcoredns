//! `whoami` — answers with the client's IP (A/AAAA) and port (SRV) in the
//! additional section. Useful to check the chain end to end.

use crate::plugin::{Controller, DnsResult, Handler, Next, Reply, Request};
use async_trait::async_trait;
use hickory_proto::rr::rdata::{A, AAAA, SRV};
use hickory_proto::rr::{Name, RData, Record};
use std::net::IpAddr;
use std::sync::Arc;

pub struct Whoami;

#[async_trait]
impl Handler for Whoami {
    fn name(&self) -> &'static str {
        "whoami"
    }

    async fn serve_dns(&self, req: &mut Request, _next: Next<'_>) -> DnsResult {
        let mut m = req.new_reply();
        m.set_authoritative(true);
        let qname = req.qname();
        let ip = req.ip();
        let rr = match ip {
            IpAddr::V4(v4) => Record::from_rdata(qname.clone(), 0, RData::A(A(v4))),
            IpAddr::V6(v6) => Record::from_rdata(qname.clone(), 0, RData::AAAA(AAAA(v6))),
        };
        let srv_name = Name::from_ascii(format!("_{}._{}.", req.port(), proto_label(req)))
            .and_then(|n| n.append_domain(&qname))
            .unwrap_or_else(|_| qname.clone());
        let srv = Record::from_rdata(srv_name, 0, RData::SRV(SRV::new(0, 0, req.port(), qname)));
        m.add_additional(rr);
        m.add_additional(srv);
        Ok(Reply::Msg(m))
    }
}

fn proto_label(req: &Request) -> &'static str {
    match req.proto {
        crate::plugin::Proto::Udp => "udp",
        _ => "tcp",
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    c.next();
    if c.next_arg() {
        return Err(c.arg_err());
    }
    c.add_plugin(Arc::new(Whoami));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::RecordType;

    #[tokio::test]
    async fn answers_with_client_ip() {
        let mut req = Request::for_test("example.org.", RecordType::A);
        let r = Whoami.serve_dns(&mut req, Next::new(&[])).await.unwrap();
        let m = r.into_msg().unwrap();
        assert_eq!(m.additionals().len(), 2);
        assert!(matches!(m.additionals()[0].data(), Some(RData::A(_))));
        assert_eq!(m.additionals()[1].name().to_ascii(), "_40000._udp.example.org.");
    }
}
