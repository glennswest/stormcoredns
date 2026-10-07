//! `debug` — as in CoreDNS, disables panic recovery for the server block:
//! a panic while serving a query is logged and the process exits (status
//! 2, like an unrecovered Go panic). Without `debug`, the query gets
//! SERVFAIL and `coredns_panics_total` counts it. Debug-level logging is
//! not switched on here: log levels come from `STORMCOREDNS_LOG`/`RUST_LOG`.

use crate::plugin::Controller;

/// Set in `ServerConfig.values` when `debug` is present.
pub const KEY: &str = "debug/on";

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
        c.config.values.insert(KEY.into(), "1".into());
    }
    Ok(())
}
