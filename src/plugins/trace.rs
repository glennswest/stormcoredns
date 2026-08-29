//! `trace [ENDPOINT-TYPE] [ENDPOINT] { ... }` — request tracing.
//!
//! Spans are emitted through the `tracing` subscriber (one span per
//! sampled request with the CoreDNS span tags: name, type, proto, remote,
//! rcode). The Corefile options (`every`, `service`, `client_server`,
//! zipkin/datadog tuning) are parsed and honoured where they apply;
//! exporting to an external collector is not wired in this build.

use crate::plugin::{Controller, DnsResult, Handler, Next, Request};
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::Instrument;

pub struct Trace {
    every: u64,
    service: String,
    client_server: bool,
    count: AtomicU64,
}

#[async_trait]
impl Handler for Trace {
    fn name(&self) -> &'static str {
        "trace"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let n = self.count.fetch_add(1, Ordering::Relaxed) + 1;
        if self.every > 1 && n % self.every != 0 {
            return next.serve(req).await;
        }
        let span = tracing::info_span!(
            "servedns",
            service = %self.service,
            "coredns.io/name" = %req.name_uncached(),
            "coredns.io/type" = %req.type_str(),
            "coredns.io/proto" = req.proto_str(),
            "coredns.io/remote" = %req.ip(),
            "coredns.io/port" = req.port(),
            "coredns.io/rcode" = tracing::field::Empty,
            "span.kind" = if self.client_server { "client_server" } else { "server" },
        );
        let r = next.serve(req).instrument(span.clone()).await;
        let rcode = match &r {
            Ok(rep) => crate::plugin::replacer::rcode_str(rep.rcode()),
            Err(e) => crate::plugin::replacer::rcode_str(e.rcode),
        };
        span.record("coredns.io/rcode", rcode.as_str());
        r
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/trace: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args_until_brace();
        let (endpoint_type, endpoint) = match args.len() {
            0 => ("zipkin".to_string(), "localhost:9411".to_string()),
            1 => ("zipkin".to_string(), args[0].clone()),
            2 => (args[0].clone(), args[1].clone()),
            _ => return Err(c.arg_err()),
        };
        match endpoint_type.as_str() {
            "zipkin" | "datadog" => {}
            o => return Err(c.errf(format!("unknown tracer type '{}'", o))),
        }
        let mut t = Trace { every: 1, service: "coredns".into(), client_server: false, count: AtomicU64::new(0) };
        while c.next_block() {
            match c.val() {
                "every" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    t.every = a[0].parse().map_err(|_| c.errf(format!("bad every value {}", a[0])))?;
                    if t.every == 0 {
                        return Err(c.errf("every must be greater than 0"));
                    }
                }
                "service" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    t.service = a[0].clone();
                }
                "client_server" => {
                    let a = c.remaining_args();
                    t.client_server = a.first().map(|v| v != "false").unwrap_or(true);
                }
                "datadog_analytics_rate" | "zipkin_max_backlog_size" | "zipkin_max_batch_size" | "zipkin_max_batch_interval" => {
                    let _ = c.remaining_args();
                }
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        tracing::info!("plugin/trace: {} endpoint {} configured; spans are emitted to the log subscriber (no exporter in this build)", endpoint_type, endpoint);
        c.add_plugin(Arc::new(t));
    }
    Ok(())
}
