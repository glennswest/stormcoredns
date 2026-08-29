//! `minimal` — strips the authority and additional sections (except OPT)
//! from positive answers, keeping responses small.

use crate::plugin::{Controller, DnsResult, Handler, Next, Request};
use async_trait::async_trait;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use std::sync::Arc;

pub struct Minimal;

#[async_trait]
impl Handler for Minimal {
    fn name(&self) -> &'static str {
        "minimal"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let mut r = next.serve(req).await?;
        if let Some(m) = r.msg_mut() {
            let positive = m.response_code() == ResponseCode::NoError && !m.answers().is_empty();
            // delegations (NS in authority, no answers) must keep their glue
            if positive {
                m.take_name_servers();
                let extra = m.take_additionals();
                m.insert_additionals(extra.into_iter().filter(|r| r.record_type() == RecordType::OPT).collect());
            }
        }
        Ok(r)
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/minimal: this plugin can only be used once per Server Block"));
        }
        if c.next_arg() {
            return Err(c.arg_err());
        }
        c.add_plugin(Arc::new(Minimal));
    }
    Ok(())
}
