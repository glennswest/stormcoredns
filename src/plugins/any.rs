//! `any` — answers ANY queries with a minimal HINFO record (RFC 8482)
//! instead of a large response that could be used for amplification.

use crate::plugin::{Controller, DnsResult, Handler, Next, Reply, Request};
use async_trait::async_trait;
use hickory_proto::rr::rdata::HINFO;
use hickory_proto::rr::{RData, Record, RecordType};
use std::sync::Arc;

pub struct Any;

#[async_trait]
impl Handler for Any {
    fn name(&self) -> &'static str {
        "any"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        if req.qtype() != RecordType::ANY {
            return next.serve(req).await;
        }
        let mut m = req.new_reply();
        m.set_authoritative(true);
        m.add_answer(Record::from_rdata(req.qname(), 8482, RData::HINFO(HINFO::new("ANY obsoleted".into(), "See RFC 8482".into()))));
        Ok(Reply::Msg(m))
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/any: this plugin can only be used once per Server Block"));
        }
        if c.next_arg() {
            return Err(c.arg_err());
        }
        c.add_plugin(Arc::new(Any));
    }
    Ok(())
}
