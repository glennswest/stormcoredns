//! `metadata [ZONES...]` — enables per-request metadata: before the view
//! filter and the chain run (the server calls `collect`, as CoreDNS's
//! `metaCollector`), every plugin in the server block that implements
//! `Handler::metadata` attaches its labels, which `view` `metadata()`,
//! log `{/label}`, rewrite and template `.Meta` can read.

use crate::plugin::{Controller, DnsResult, Handler, Next, Request};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use std::sync::Arc;

pub struct Metadata {
    zones: Vec<String>,
    providers: ArcSwap<Vec<Arc<dyn Handler>>>,
}

#[async_trait]
impl Handler for Metadata {
    fn name(&self) -> &'static str {
        "metadata"
    }

    /// Collected by the server before the view filter; nothing to do here.
    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        next.serve(req).await
    }
}

impl Metadata {
    pub fn new(zones: Vec<String>, providers: Vec<Arc<dyn Handler>>) -> Arc<Metadata> {
        Arc::new(Metadata { zones, providers: ArcSwap::from_pointee(providers) })
    }

    /// Fresh metadata for `req` from every provider, when the name is in
    /// the plugin's zones (CoreDNS's `Collect`).
    pub fn collect(&self, req: &mut Request) {
        req.metadata = Default::default();
        let name = req.name_uncached();
        if crate::plugin::zones_match(&self.zones, &name).is_some() {
            for p in self.providers.load().iter() {
                p.metadata(req);
            }
        }
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/metadata: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args();
        let zones = c.origins_from_args_or_server_block(&args)?;
        let m = Metadata::new(zones, Vec::new());
        c.add_plugin(m.clone());
        c.config.metadata = Some(m.clone());
        crate::plugins::wire::register(c, move |cfg| {
            let providers: Vec<Arc<dyn Handler>> = cfg.plugins.iter().filter(|(n, _)| *n != "metadata").map(|(_, h)| h.clone()).collect();
            m.providers.store(Arc::new(providers));
        });
    }
    Ok(())
}
