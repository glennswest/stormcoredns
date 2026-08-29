//! `debug` — disables panic recovery (we always recover, so this only
//! turns on verbose logging for the server block) and enables debug
//! output from plugins that check `config.debug`.

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
    c.config.debug = true;
    Ok(())
}
