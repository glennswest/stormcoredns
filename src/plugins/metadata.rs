//! `metadata [ZONES...]` — enables per-request metadata: before the chain
//! runs, every plugin in the server block that implements
//! `Handler::metadata` attaches its labels, which later plugins (log
//! `{/label}`, view `metadata()`, rewrite) can read.

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

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let name = req.name();
        if crate::plugin::zones_match(&self.zones, &name).is_some() {
            for p in self.providers.load().iter() {
                p.metadata(req);
            }
        }
        next.serve(req).await
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
        let m = Arc::new(Metadata { zones, providers: ArcSwap::from_pointee(Vec::new()) });
        c.config.metadata = true;
        c.add_plugin(m.clone());
        crate::plugins::wire::register(c, move |cfg| {
            let providers: Vec<Arc<dyn Handler>> = cfg.plugins.iter().filter(|(n, _)| *n != "metadata").map(|(_, h)| h.clone()).collect();
            m.providers.store(Arc::new(providers));
        });
    }
    Ok(())
}
