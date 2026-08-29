//! `health [ADDRESS] { lameduck DURATION }` — HTTP `/health` endpoint
//! (default `:8080`). Returns 200 "OK"; during the lameduck period at
//! shutdown it returns 503 and the process keeps serving DNS.

use crate::plugin::Controller;
use crate::server::config::ServerConfig;
use crate::server::http_util::{self, Endpoints};
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

static HEALTHY: AtomicBool = AtomicBool::new(true);
static ENDPOINTS: Lazy<Endpoints> = Lazy::new(Endpoints::default);

pub fn post_finalize(_configs: &[Arc<ServerConfig>]) {
    HEALTHY.store(true, Ordering::Relaxed);
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut addr = ":8080".to_string();
    let mut lameduck = Duration::ZERO;
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/health: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args_until_brace();
        match args.len() {
            0 => {}
            1 => addr = args[0].clone(),
            _ => return Err(c.arg_err()),
        }
        while c.next_block() {
            match c.val() {
                "lameduck" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    lameduck = crate::dnsutil::parse_duration(&a[0]).map_err(|e| c.errf(format!("invalid lameduck duration: {}", e)))?;
                }
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
    }
    c.once_per_server_block(|c| {
        // periodic self-check, as CoreDNS does, for the health metrics
        let probe_addr = http_util::normalize_addr(&addr);
        let cancel = tokio_util::sync::CancellationToken::new();
        let probe_cancel = cancel.clone();
        c.on_startup(Box::new(move || {
            Box::pin(async move {
                tokio::spawn(async move {
                    let url = if probe_addr.starts_with(':') { format!("http://127.0.0.1{}/health", probe_addr) } else { format!("http://{}/health", probe_addr) };
                    let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build().ok();
                    loop {
                        tokio::select! {
                            _ = probe_cancel.cancelled() => return,
                            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                        }
                        if let Some(cl) = &client {
                            let start = Instant::now();
                            match cl.get(&url).send().await {
                                Ok(r) if r.status().is_success() => {
                                    crate::metrics::HEALTH_DURATION.observe(start.elapsed().as_secs_f64());
                                }
                                _ => crate::metrics::HEALTH_FAILURES.inc(),
                            }
                        }
                    }
                });
                Ok(())
            })
        }));
        c.on_shutdown(Box::new(move || {
            Box::pin(async move {
                cancel.cancel();
                if !lameduck.is_zero() {
                    HEALTHY.store(false, Ordering::Relaxed);
                    tracing::info!("plugin/health: going lameduck for {:?}", lameduck);
                    tokio::time::sleep(lameduck).await;
                }
                Ok(())
            })
        }));
        ENDPOINTS.install(c, &addr, |req| async move {
            if req.uri().path() != "/health" {
                return http_util::text(404, "not found");
            }
            if HEALTHY.load(Ordering::Relaxed) {
                http_util::text(200, "OK")
            } else {
                http_util::text(503, "lameduck")
            }
        });
        Ok(())
    })?;
    Ok(())
}
