//! `k8s_external` plugin — not implemented yet.

use crate::plugin::Controller;

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    Err(c.errf("plugin/k8s_external: not implemented yet in this build"))
}
