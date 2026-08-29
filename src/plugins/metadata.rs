//! `metadata` plugin — not implemented yet.

use crate::plugin::Controller;

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    Err(c.errf("plugin/metadata: not implemented yet in this build"))
}
