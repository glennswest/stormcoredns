//! `cancel [TIMEOUT]` — bounds the time the rest of the chain may spend
//! on a request (default 5001 ms). On expiry the client gets SERVFAIL.

use crate::plugin::{error, Controller, DnsResult, Handler, Next, Request};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct Cancel {
    timeout: Duration,
}

#[async_trait]
impl Handler for Cancel {
    fn name(&self) -> &'static str {
        "cancel"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let deadline = Instant::now() + self.timeout;
        req.deadline = Some(match req.deadline {
            Some(d) if d < deadline => d,
            _ => deadline,
        });
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), next.serve(req)).await {
            Ok(r) => r,
            Err(_) => Err(error("cancel", anyhow::anyhow!("request for {} timed out after {:?}", req.name_uncached(), self.timeout))),
        }
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/cancel: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args();
        let timeout = match args.len() {
            0 => Duration::from_millis(5001),
            1 => {
                let d = crate::dnsutil::parse_duration(&args[0])?;
                if d.is_zero() {
                    return Err(c.errf("timeout must be greater than 0"));
                }
                d
            }
            _ => return Err(c.arg_err()),
        };
        c.add_plugin(Arc::new(Cancel { timeout }));
    }
    Ok(())
}
