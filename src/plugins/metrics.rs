//! `prometheus [ADDRESS]` — records the core `coredns_dns_*` metrics for
//! every request in the server block and serves `/metrics` (default
//! `localhost:9153`).

use crate::metrics as vars;
use crate::plugin::{Controller, DnsResult, Handler, Next, Request};
use crate::server::config::ServerConfig;
use crate::server::http_util::{self, Endpoints};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use prometheus::Encoder;
use std::sync::Arc;

static ENDPOINTS: Lazy<Endpoints> = Lazy::new(Endpoints::default);

pub struct Metrics;

#[async_trait]
impl Handler for Metrics {
    fn name(&self) -> &'static str {
        "prometheus"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let r = next.serve(req).await;
        let server = req.server.clone();
        let zone = req.zone.clone();
        let view = req.view.clone();
        let family = if req.family() == 1 { "1" } else { "2" };
        let proto = req.proto_str();
        let qtype = req.type_str();
        vars::REQUEST_COUNT.with_label_values(&[&server, &zone, &view, proto, family, &qtype]).inc();
        vars::REQUEST_DURATION.with_label_values(&[&server, &zone, &view]).observe(req.start.elapsed().as_secs_f64());
        vars::REQUEST_SIZE.with_label_values(&[&server, &zone, &view, proto]).observe(req.size() as f64);
        if req.do_bit() {
            vars::REQUEST_DO.with_label_values(&[&server, &zone, &view]).inc();
        }
        let (rcode, plugin, size) = match &r {
            Ok(rep) => {
                let size = rep.msg().and_then(|m| m.to_vec().ok()).map(|v| v.len()).unwrap_or(0);
                (rep.rcode(), "", size)
            }
            Err(e) => (e.rcode, e.plugin, 0),
        };
        vars::RESPONSE_RCODE
            .with_label_values(&[&server, &zone, &view, &crate::plugin::replacer::rcode_str(rcode), plugin])
            .inc();
        vars::RESPONSE_SIZE.with_label_values(&[&server, &zone, &view, proto]).observe(size as f64);
        r
    }
}

pub fn post_finalize(configs: &[Arc<ServerConfig>]) {
    vars::PLUGIN_ENABLED.reset();
    for c in configs {
        if c.handler("prometheus").is_none() {
            continue;
        }
        let label = c.server_label();
        for (name, _) in &c.plugins {
            vars::PLUGIN_ENABLED.with_label_values(&[&label, &c.zone, &c.view_name, name]).set(1);
        }
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut addr = "localhost:9153".to_string();
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/prometheus: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args();
        match args.len() {
            0 => {}
            1 => addr = args[0].clone(),
            _ => return Err(c.arg_err()),
        }
        if c.next_block() {
            return Err(c.errf("plugin/prometheus: unexpected block"));
        }
    }
    // touch the core collectors so they are registered even before traffic
    Lazy::force(&vars::REQUEST_COUNT);
    Lazy::force(&vars::REQUEST_DURATION);
    Lazy::force(&vars::REQUEST_SIZE);
    Lazy::force(&vars::REQUEST_DO);
    Lazy::force(&vars::RESPONSE_SIZE);
    Lazy::force(&vars::RESPONSE_RCODE);
    Lazy::force(&vars::PANIC_COUNT);
    Lazy::force(&vars::PLUGIN_ENABLED);
    Lazy::force(&vars::BUILD_INFO);
    c.add_plugin(Arc::new(Metrics));
    c.once_per_server_block(|c| {
        ENDPOINTS.install(c, &addr, |req| async move {
            if req.uri().path() != "/metrics" {
                return http_util::text(404, "not found");
            }
            let families = vars::REGISTRY.gather();
            let enc = prometheus::TextEncoder::new();
            let mut buf = Vec::new();
            if enc.encode(&families, &mut buf).is_err() {
                return http_util::text(500, "encoding metrics failed");
            }
            http_util::with_type(200, "text/plain; version=0.0.4; charset=utf-8", buf)
        });
        Ok(())
    })?;
    Ok(())
}
