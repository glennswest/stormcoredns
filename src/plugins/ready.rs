//! `ready [ADDRESS]` — HTTP `/ready` endpoint (default `:8181`) that
//! returns 200 once every plugin that reports readiness is ready, and 503
//! listing the plugins that are not.

use crate::plugin::{Controller, Handler};
use crate::server::config::ServerConfig;
use crate::server::http_util::{self, Endpoints};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::sync::Arc;

/// Server blocks (by index) that enabled `ready`, filled during setup.
static ENABLED_BLOCKS: Lazy<Mutex<HashSet<usize>>> = Lazy::new(|| Mutex::new(HashSet::new()));
/// Plugins that participate in readiness, (plugin name, handler).
static PLUGINS: Lazy<Mutex<Vec<(&'static str, Arc<dyn Handler>)>>> = Lazy::new(|| Mutex::new(Vec::new()));
static ENDPOINTS: Lazy<Endpoints> = Lazy::new(Endpoints::default);

pub fn post_finalize(configs: &[Arc<ServerConfig>]) {
    let blocks = std::mem::take(&mut *ENABLED_BLOCKS.lock());
    let mut list = Vec::new();
    for c in configs {
        if !blocks.contains(&c.block_index) {
            continue;
        }
        for (name, h) in &c.plugins {
            if h.ready().is_some() {
                list.push((*name, h.clone()));
            }
        }
    }
    *PLUGINS.lock() = list;
}

/// Names of plugins that are not (yet) ready.
pub fn not_ready() -> Vec<&'static str> {
    let mut out = Vec::new();
    for (name, h) in PLUGINS.lock().iter() {
        if h.ready() == Some(false) && !out.contains(name) {
            out.push(*name);
        }
    }
    out
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut addr = ":8181".to_string();
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/ready: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args();
        match args.len() {
            0 => {}
            1 => addr = args[0].clone(),
            _ => return Err(c.arg_err()),
        }
        if c.next_block() {
            return Err(c.errf("plugin/ready: unexpected block"));
        }
    }
    ENABLED_BLOCKS.lock().insert(c.server_block_index);
    c.once_per_server_block(|c| {
        ENDPOINTS.install(c, &addr, |req| async move {
            if req.uri().path() != "/ready" {
                return http_util::text(404, "not found");
            }
            let nr = not_ready();
            if nr.is_empty() {
                http_util::text(200, "OK")
            } else {
                http_util::text(503, nr.join(","))
            }
        });
        Ok(())
    })?;
    Ok(())
}
