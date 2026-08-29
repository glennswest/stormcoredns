//! One module per CoreDNS plugin, named after the directive.

pub mod root;
pub mod metadata;
pub mod geoip;
pub mod cancel;
pub mod tls;
pub mod timeouts;
pub mod multisocket;
pub mod reload;
pub mod nsid;
pub mod bufsize;
pub mod bind;
pub mod debug;
pub mod trace;
pub mod ready;
pub mod health;
pub mod pprof;
pub mod metrics;
pub mod errors;
pub mod log;
pub mod dnstap;
pub mod local;
pub mod dns64;
pub mod acl;
pub mod any;
pub mod chaos;
pub mod loadbalance;
pub mod tsig;
pub mod cache;
pub mod rewrite;
pub mod header;
pub mod dnssec;
pub mod autopath;
pub mod minimal;
pub mod template;
pub mod transfer;
pub mod hosts;
pub mod file;
pub mod auto;
pub mod secondary;
pub mod etcd;
pub mod r#loop;
pub mod forward;
pub mod grpc;
pub mod erratic;
pub mod whoami;
pub mod on;
pub mod sign;
pub mod view;
pub mod kubernetes;
pub mod k8s_external;
pub mod clouddns;
pub mod azure;
pub mod route53;

/// Called once all configs are finalised (chains sorted) and before
/// listeners start: lets plugins that need the complete plugin list
/// (ready, health, prometheus) see it.
pub fn post_finalize(configs: &[std::sync::Arc<crate::server::config::ServerConfig>]) {
    wire::run(configs);
    ready::post_finalize(configs);
    health::post_finalize(configs);
    metrics::post_finalize(configs);
}

/// Deferred cross-plugin wiring: a plugin's `setup` runs before the
/// plugins after it in `plugin.cfg` exist, so anything that needs a sibling
/// handler (autopath → kubernetes, k8s_external → kubernetes, transfer →
/// file/secondary) registers a closure here that runs once the server
/// block's chain is complete (`c.OnStartup` + `config.Handler()` in CoreDNS).
pub mod wire {
    use crate::server::config::ServerConfig;
    use once_cell::sync::Lazy;
    use parking_lot::Mutex;
    use std::sync::Arc;

    type WireFn = Box<dyn FnOnce(&ServerConfig) + Send>;
    static PENDING: Lazy<Mutex<Vec<(usize, usize, WireFn)>>> = Lazy::new(|| Mutex::new(Vec::new()));

    /// Register `f` to run against the finished config of (block, key).
    pub fn register(c: &crate::plugin::Controller<'_>, f: impl FnOnce(&ServerConfig) + Send + 'static) {
        PENDING.lock().push((c.server_block_index, c.server_block_key_index, Box::new(f)));
    }

    pub fn run(configs: &[Arc<ServerConfig>]) {
        let pending = std::mem::take(&mut *PENDING.lock());
        for (bi, ki, f) in pending {
            if let Some(cfg) = configs.iter().find(|c| c.block_index == bi && c.key_index == ki) {
                f(cfg);
            }
        }
    }
}
