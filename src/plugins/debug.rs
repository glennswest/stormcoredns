//! `debug` — in CoreDNS, disables panic recovery and enables debug
//! output. Here it is accepted and has no effect: panic recovery is
//! always on, and log levels come from `STORMCOREDNS_LOG`/`RUST_LOG`.

use crate::plugin::Controller;

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/debug: this plugin can only be used once per Server Block"));
        }
        if c.next_arg() {
            return Err(c.arg_err());
        }
    }
    Ok(())
}
