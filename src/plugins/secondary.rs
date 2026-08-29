//! `secondary` plugin — not implemented yet.

use crate::plugin::Controller;

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    Err(c.errf("plugin/secondary: not implemented yet in this build"))
}
