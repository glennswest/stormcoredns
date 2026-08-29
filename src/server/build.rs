//! Turn parsed server blocks into `ServerConfig`s by running each
//! directive's `setup`, then group the configs into listeners.

use super::config::{parse_key, ServerConfig, Transport};
use super::{Server, ZoneEntry};
use crate::corefile::{ServerBlock, Token};
use crate::plugin::registry;
use crate::plugin::Controller;
use anyhow::{anyhow, bail, Result};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct BuildOptions {
    /// Port for keys that carry none (`-dns.port`).
    pub default_port: u16,
    pub corefile: PathBuf,
    pub quiet: bool,
}

impl Default for BuildOptions {
    fn default() -> Self {
        BuildOptions { default_port: 53, corefile: PathBuf::from("Corefile"), quiet: false }
    }
}

pub struct Built {
    pub configs: Vec<ServerConfig>,
}

pub fn build(blocks: Vec<ServerBlock>, opts: &BuildOptions) -> Result<Built> {
    // 1. unknown directives are an error before anything runs
    for b in &blocks {
        for d in &b.directives {
            if registry::lookup(&d.name).is_none() {
                let t = &d.tokens[0];
                bail!("{}:{} - Error during parsing: Unknown directive '{}'", t.file, t.line, d.name);
            }
        }
    }

    // 2. one config per key
    let mut configs: Vec<ServerConfig> = Vec::new();
    let mut index: Vec<Vec<usize>> = Vec::new(); // block → config indices
    for (bi, b) in blocks.iter().enumerate() {
        let mut idxs = Vec::new();
        if b.keys.is_empty() {
            bail!("Corefile:{} - Error during parsing: server block has no keys", b.line);
        }
        for (ki, k) in b.keys.iter().enumerate() {
            let mut pk = parse_key(k).map_err(|e| anyhow!("Corefile:{} - Error during parsing: {}", b.line, e))?;
            if !pk.explicit_port && pk.transport == Transport::Dns {
                pk.port = opts.default_port;
            }
            let mut c = ServerConfig::new(&pk, bi, ki);
            if let Some(dir) = opts.corefile.parent() {
                if dir.as_os_str().is_empty() {
                    c.root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                } else {
                    c.root = std::env::current_dir().map(|d| d.join(dir)).unwrap_or_else(|_| dir.to_path_buf());
                }
            }
            idxs.push(configs.len());
            configs.push(c);
        }
        index.push(idxs);
    }

    // 3. run setups: directive-major, then block, then key
    let mut once: HashSet<(usize, String)> = HashSet::new();
    for def in registry::ORDER {
        for (bi, b) in blocks.iter().enumerate() {
            let tokens: Vec<Token> = b
                .directives
                .iter()
                .filter(|d| d.name == def.name)
                .flat_map(|d| d.tokens.iter().cloned())
                .collect();
            if tokens.is_empty() {
                continue;
            }
            let setup = match def.setup {
                Some(s) => s,
                None => {
                    let t = &tokens[0];
                    bail!("{}:{} - plugin/{}: not implemented in this build", t.file, t.line, def.name);
                }
            };
            for (ki, &ci) in index[bi].iter().enumerate() {
                let key = b.keys[ki].clone();
                let cfg = &mut configs[ci];
                let mut ctl = Controller::new(def.name, tokens.clone(), cfg, key, b.keys.clone(), bi, ki, &mut once);
                setup(&mut ctl).map_err(|e| {
                    let s = e.to_string();
                    if s.starts_with("plugin/") {
                        e
                    } else {
                        anyhow!("plugin/{}: {}", def.name, s)
                    }
                })?;
            }
        }
    }

    Ok(Built { configs })
}

/// Group configs into one `Server` per (transport, bind address). A zone
/// may appear more than once in a server only when `view` distinguishes
/// the configs.
pub fn group_servers(configs: &[Arc<ServerConfig>]) -> Result<Vec<Arc<Server>>> {
    let mut groups: HashMap<(Transport, String), Vec<Arc<ServerConfig>>> = HashMap::new();
    let mut order: Vec<(Transport, String)> = Vec::new();
    for c in configs {
        for addr in c.listen_addrs() {
            let k = (c.transport, addr);
            if !groups.contains_key(&k) {
                order.push(k.clone());
            }
            groups.entry(k).or_default().push(c.clone());
        }
    }
    let mut servers = Vec::new();
    for k in order {
        let cfgs = groups.remove(&k).unwrap();
        let mut zones: HashMap<String, Vec<ZoneEntry>> = HashMap::new();
        let mut tls = None;
        let mut read_timeout = Duration::from_secs(2);
        let mut write_timeout = Duration::from_secs(2);
        let mut idle_timeout = Duration::from_secs(10);
        let mut num_sockets = 1;
        let mut debug = false;
        for c in cfgs {
            if let Some(existing) = zones.get(&c.zone) {
                let dup = existing.iter().any(|e| e.config.view_name == c.view_name);
                if dup {
                    bail!(
                        "cannot serve zone {} on {}://{} twice (use the view plugin to split it)",
                        c.zone,
                        k.0.scheme(),
                        k.1
                    );
                }
            }
            if c.tls.is_some() {
                tls = c.tls.clone();
            }
            if let Some(t) = c.read_timeout {
                read_timeout = t;
            }
            if let Some(t) = c.write_timeout {
                write_timeout = t;
            }
            if let Some(t) = c.idle_timeout {
                idle_timeout = t;
            }
            num_sockets = num_sockets.max(c.num_sockets);
            debug |= c.debug;
            let chain = Arc::new(c.chain());
            zones.entry(c.zone.clone()).or_default().push(ZoneEntry { config: c, chain });
        }
        // configs with a view must come before the catch-all (no view) one
        for entries in zones.values_mut() {
            entries.sort_by_key(|e| e.config.filter.is_none());
        }
        if matches!(k.0, Transport::Tls | Transport::Quic) && tls.is_none() {
            bail!("{}://{}: the tls plugin is required for this transport", k.0.scheme(), k.1);
        }
        let label = format!("{}://{}", k.0.scheme(), k.1);
        servers.push(Arc::new(Server {
            label,
            transport: k.0,
            addrs: vec![k.1.clone()],
            zones,
            tls,
            read_timeout,
            write_timeout,
            idle_timeout,
            num_sockets,
            debug,
            graceful_timeout: Duration::from_secs(5),
        }));
    }
    Ok(servers)
}
