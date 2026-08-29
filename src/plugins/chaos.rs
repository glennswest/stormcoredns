//! `chaos [VERSION] [AUTHORS...]` — answers CH-class TXT queries for
//! `version.bind`, `version.server`, `authors.bind`, `hostname.bind` and
//! `id.server`.

use crate::plugin::{Controller, DnsResult, Handler, Next, Reply, Request};
use async_trait::async_trait;
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use std::sync::Arc;

pub struct Chaos {
    version: String,
    authors: Vec<String>,
}

#[async_trait]
impl Handler for Chaos {
    fn name(&self) -> &'static str {
        "chaos"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        if req.qclass() != DNSClass::CH || req.qtype() != RecordType::TXT {
            return next.serve(req).await;
        }
        let qname = req.name();
        let texts: Vec<String> = match qname.as_str() {
            "version.bind." | "version.server." => vec![self.version.clone()],
            "hostname.bind." | "id.server." => vec![hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or_else(|_| "localhost".into())],
            "authors.bind." => self.authors.clone(),
            _ => return next.serve(req).await,
        };
        let mut m = req.new_reply();
        m.set_authoritative(true);
        for t in texts {
            let mut r = Record::from_rdata(req.qname(), 0, RData::TXT(TXT::new(vec![t])));
            r.set_dns_class(DNSClass::CH);
            m.add_answer(r);
        }
        Ok(Reply::Msg(m))
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/chaos: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args();
        let (version, authors) = match args.len() {
            0 => (format!("CoreDNS-{} (stormcoredns-{})", crate::COREDNS_COMPAT, crate::VERSION), vec!["Miek Gieben".to_string(), "stormcoredns contributors".to_string()]),
            _ => {
                let v = args[0].clone();
                let mut a: Vec<String> = args[1..].to_vec();
                a.sort();
                a.dedup();
                (v, a)
            }
        };
        c.add_plugin(Arc::new(Chaos { version, authors }));
    }
    Ok(())
}
