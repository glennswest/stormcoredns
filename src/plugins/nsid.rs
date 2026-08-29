//! `nsid [DATA]` — adds an EDNS0 NSID option (RFC 5001) to responses when
//! the client asked for one. Default DATA is the hostname.

use crate::plugin::{Controller, DnsResult, Handler, Next, Request};
use async_trait::async_trait;
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use std::sync::Arc;

pub struct Nsid {
    data: Vec<u8>,
}

#[async_trait]
impl Handler for Nsid {
    fn name(&self) -> &'static str {
        "nsid"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let wants = req.msg.edns().map(|e| e.option(EdnsCode::NSID).is_some()).unwrap_or(false);
        let mut r = next.serve(req).await?;
        if wants {
            if let Some(m) = r.msg_mut() {
                let e = m.extensions_mut().get_or_insert_with(|| {
                    let mut e = hickory_proto::op::Edns::new();
                    e.set_max_payload(crate::dnsutil::UDP_BUFFER_SIZE);
                    e
                });
                e.options_mut().insert(EdnsOption::Unknown(u16::from(EdnsCode::NSID), self.data.clone()));
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
            return Err(c.errf("plugin/nsid: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args();
        let data = if args.is_empty() {
            hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or_else(|_| "localhost".into())
        } else {
            args.join(" ")
        };
        c.add_plugin(Arc::new(Nsid { data: data.into_bytes() }));
    }
    Ok(())
}
