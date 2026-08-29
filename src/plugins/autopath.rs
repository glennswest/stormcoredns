//! `autopath [ZONE...] RESOLV-CONF` — server-side search path expansion.
//! When a query arrives for `name.<first search domain>`, the remaining
//! search domains (and the bare name) are tried through the rest of the
//! chain; the first NOERROR answer is returned with a CNAME from the
//! original name. Collapses the ndots:5 round trips clients would make.
//!
//! RESOLV-CONF is a resolv.conf file (its `search` line) or `@PLUGIN`
//! (`@kubernetes`: per-pod search path from the kubernetes plugin).

use crate::dnsutil;
use crate::plugin::{Controller, DnsResult, Handler, Next, Reply, Request};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::CNAME;
use hickory_proto::rr::{Name, RData, Record};
use once_cell::sync::Lazy;
use prometheus::IntCounterVec;
use std::sync::Arc;

static SUCCESS: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(prometheus::Opts::new("coredns_autopath_success_total", "Counter of requests that did autopath."), &["server"]).unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});

pub enum Source {
    /// Static search path (from a resolv.conf).
    Static(Vec<String>),
    /// A sibling plugin that implements `Handler::autopath`.
    Plugin(&'static str, ArcSwapOption<Arc<dyn Handler>>),
}

pub struct Autopath {
    zones: Vec<String>,
    source: Source,
}

impl Autopath {
    fn search_path(&self, req: &Request) -> Option<Vec<String>> {
        match &self.source {
            Source::Static(sp) => Some(sp.clone()),
            Source::Plugin(_, h) => h.load().as_ref().and_then(|h| h.autopath(req)),
        }
    }
}

/// Parse the `search` (or `domain`) line of a resolv.conf into FQDNs.
pub fn search_from_resolv(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let rest = if let Some(r) = line.strip_prefix("search") {
            r
        } else if let Some(r) = line.strip_prefix("domain") {
            r
        } else {
            continue;
        };
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        out.clear();
        for d in rest.split_whitespace() {
            out.push(dnsutil::fqdn(d));
        }
    }
    out
}

#[async_trait]
impl Handler for Autopath {
    fn name(&self) -> &'static str {
        "autopath"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let qname = req.name();
        if crate::plugin::zones_match(&self.zones, &qname).is_none() {
            return next.serve(req).await;
        }
        let Some(sp) = self.search_path(req) else {
            return next.serve(req).await;
        };
        // the query must end in the first search domain
        let Some(first) = sp.first() else { return next.serve(req).await };
        if first.is_empty() || !dnsutil::is_subdomain(first, &qname) || qname == *first {
            return next.serve(req).await;
        }
        let base = dnsutil::trim_zone(&qname, first).unwrap_or_default();
        if base.is_empty() {
            return next.serve(req).await;
        }
        let qtype = req.qtype();
        let orig = req.qname();
        let mut first_reply: Option<Reply> = None;
        for s in &sp {
            let candidate = if s.is_empty() { format!("{}.", base) } else { dnsutil::join(&[&base], s) };
            let Ok(cname) = Name::from_ascii(&candidate) else { continue };
            let mut r2 = req.new_with_question(cname.clone(), qtype);
            let reply = next.serve(&mut r2).await;
            match reply {
                Ok(Reply::Msg(m)) if m.response_code() == ResponseCode::NoError => {
                    if candidate == qname {
                        return Ok(Reply::Msg(m));
                    }
                    SUCCESS.with_label_values(&[&req.server]).inc();
                    let mut out = req.new_reply();
                    out.set_authoritative(m.authoritative());
                    out.set_recursion_available(m.recursion_available());
                    let ttl = m.answers().iter().map(|r| r.ttl()).min().unwrap_or(0);
                    out.add_answer(Record::from_rdata(orig.clone(), ttl, RData::CNAME(CNAME(cname))));
                    for r in m.answers() {
                        out.add_answer(r.clone());
                    }
                    for r in m.name_servers() {
                        out.add_name_server(r.clone());
                    }
                    for r in m.additionals() {
                        if r.record_type() != hickory_proto::rr::RecordType::OPT {
                            out.add_additional(r.clone());
                        }
                    }
                    return Ok(Reply::Msg(out));
                }
                Ok(other) => {
                    if first_reply.is_none() && candidate == qname {
                        first_reply = Some(other);
                    }
                }
                Err(e) => return Err(e),
            }
        }
        match first_reply {
            Some(Reply::Msg(mut m)) => {
                m.set_id(req.msg.id());
                Ok(Reply::Msg(m))
            }
            Some(r) => Ok(r),
            None => next.serve(req).await,
        }
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/autopath: this plugin can only be used once per Server Block"));
        }
        let mut args = c.remaining_args();
        if args.is_empty() {
            return Err(c.arg_err());
        }
        let resolv = args.pop().unwrap();
        let zones = c.origins_from_args_or_server_block(&args)?;
        let source = if let Some(plugin) = resolv.strip_prefix('@') {
            let name: &'static str = match plugin {
                "kubernetes" => "kubernetes",
                "erratic" => "erratic",
                o => return Err(c.errf(format!("unknown plugin for autopath: @{}", o))),
            };
            Source::Plugin(name, ArcSwapOption::empty())
        } else {
            let path = if std::path::Path::new(&resolv).is_absolute() { std::path::PathBuf::from(&resolv) } else { c.config.root.join(&resolv) };
            let text = std::fs::read_to_string(&path).map_err(|e| c.errf(format!("reading {}: {}", path.display(), e)))?;
            let mut sp = search_from_resolv(&text);
            sp.push(String::new());
            Source::Static(sp)
        };
        let ap = Arc::new(Autopath { zones, source });
        c.add_plugin(ap.clone());
        if let Source::Plugin(name, _) = &ap.source {
            let name = *name;
            let ap2 = ap.clone();
            crate::plugins::wire::register(c, move |cfg| match cfg.handler(name) {
                Some(h) => {
                    if let Source::Plugin(_, slot) = &ap2.source {
                        slot.store(Some(Arc::new(h)));
                    }
                }
                None => tracing::error!("plugin/autopath: @{} is not enabled in this server block", name),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolv_search() {
        let sp = search_from_resolv("nameserver 1.1.1.1\nsearch default.svc.cluster.local svc.cluster.local cluster.local\noptions ndots:5\n");
        assert_eq!(sp, vec!["default.svc.cluster.local.", "svc.cluster.local.", "cluster.local."]);
    }
}
