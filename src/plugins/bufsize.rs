//! `bufsize [SIZE]` — caps the EDNS0 UDP buffer size advertised by the
//! client (default 512) so responses stay below the fragmentation limit.

use crate::plugin::{Controller, DnsResult, Handler, Next, Request};
use async_trait::async_trait;
use std::sync::Arc;

pub struct Bufsize {
    size: u16,
}

#[async_trait]
impl Handler for Bufsize {
    fn name(&self) -> &'static str {
        "bufsize"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        if let Some(e) = req.msg.extensions_mut().as_mut() {
            if e.max_payload() > self.size {
                e.set_max_payload(self.size);
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
            return Err(c.errf("plugin/bufsize: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args();
        let size = match args.len() {
            0 => 512,
            1 => {
                let s: u16 = args[0].parse().map_err(|_| c.errf(format!("invalid size {}", args[0])))?;
                if !(512..=4096).contains(&s) {
                    return Err(c.errf("bufsize must be between 512 and 4096"));
                }
                s
            }
            _ => return Err(c.arg_err()),
        };
        c.add_plugin(Arc::new(Bufsize { size }));
    }
    Ok(())
}
