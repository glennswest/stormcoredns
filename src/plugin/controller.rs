//! `Controller`: the argument to every plugin `setup` function — a token
//! `Dispenser` over the directive's tokens plus the server config being
//! built (what `dnsserver.GetConfig(c)` returns in CoreDNS).

use super::Handler;
use crate::corefile::{Dispenser, Token};
use crate::server::config::{Hook, ServerConfig};
use std::collections::HashSet;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

pub struct Controller<'a> {
    pub dispenser: Dispenser,
    pub config: &'a mut ServerConfig,
    /// The server-block key this setup call is for (`c.Key`).
    pub key: String,
    /// All keys of the server block (`c.ServerBlockKeys`).
    pub server_block_keys: Vec<String>,
    pub server_block_index: usize,
    pub server_block_key_index: usize,
    once: &'a mut HashSet<(usize, String)>,
    pub directive: &'static str,
}

impl<'a> Controller<'a> {
    pub fn new(
        directive: &'static str,
        tokens: Vec<Token>,
        config: &'a mut ServerConfig,
        key: String,
        server_block_keys: Vec<String>,
        server_block_index: usize,
        server_block_key_index: usize,
        once: &'a mut HashSet<(usize, String)>,
    ) -> Self {
        Controller {
            dispenser: Dispenser::new(tokens),
            config,
            key,
            server_block_keys,
            server_block_index,
            server_block_key_index,
            once,
            directive,
        }
    }

    /// Append a handler to this server config's plugin chain. Order in the
    /// chain is fixed by `registry::ORDER`, not by call order.
    pub fn add_plugin(&mut self, h: Arc<dyn Handler>) {
        self.config.add_plugin(self.directive, h);
    }

    /// Run `f` only for the first key of a server block (`c.OncePerServerBlock`).
    /// Returns `Ok(true)` if it ran.
    pub fn once_per_server_block(&mut self, f: impl FnOnce(&mut Controller<'_>) -> anyhow::Result<()>) -> anyhow::Result<bool> {
        let k = (self.server_block_index, self.directive.to_string());
        if self.once.contains(&k) {
            return Ok(false);
        }
        self.once.insert(k);
        f(self)?;
        Ok(true)
    }

    /// True on the first key of the server block, without running anything.
    pub fn is_first_key(&self) -> bool {
        self.server_block_key_index == 0
    }

    pub fn on_startup(&mut self, h: Hook) {
        self.config.startup.push(h);
    }
    pub fn on_shutdown(&mut self, h: Hook) {
        self.config.shutdown.push(h);
    }
    pub fn on_restart(&mut self, h: Hook) {
        self.config.restart.push(h);
    }
    pub fn on_restart_failed(&mut self, h: Hook) {
        self.config.restart_failed.push(h);
    }

    /// The normalised zone of the current key's config.
    pub fn zone(&self) -> &str {
        &self.config.zone
    }

    /// Normalised zones of every key in the server block (what plugins use
    /// when no zone args are given).
    pub fn server_block_zones(&self) -> Vec<String> {
        self.server_block_keys
            .iter()
            .filter_map(|k| crate::server::config::parse_key(k).ok())
            .map(|k| k.zone)
            .collect()
    }

    /// `plugin.OriginsFromArgsOrServerBlock(args, c.ServerBlockKeys)`.
    pub fn origins_from_args_or_server_block(&self, args: &[String]) -> anyhow::Result<Vec<String>> {
        super::origins_from_args_or_server_block(args, &self.server_block_zones())
    }

    /// Plugin-attributed config error: `plugin/<name>: <msg>`.
    pub fn plugin_err(&self, e: anyhow::Error) -> anyhow::Error {
        anyhow::anyhow!("plugin/{}: {}", self.directive, e)
    }
}

impl<'a> Deref for Controller<'a> {
    type Target = Dispenser;
    fn deref(&self) -> &Dispenser {
        &self.dispenser
    }
}
impl<'a> DerefMut for Controller<'a> {
    fn deref_mut(&mut self) -> &mut Dispenser {
        &mut self.dispenser
    }
}
