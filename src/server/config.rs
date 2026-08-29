//! Per-key server configuration (`dnsserver.Config`).

use crate::plugin::{Handler, Request};
use anyhow::{anyhow, bail, Result};
use futures::future::BoxFuture;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Dns,
    Tls,
    Https,
    Quic,
    Grpc,
}

impl Transport {
    pub fn scheme(&self) -> &'static str {
        match self {
            Transport::Dns => "dns",
            Transport::Tls => "tls",
            Transport::Https => "https",
            Transport::Quic => "quic",
            Transport::Grpc => "grpc",
        }
    }
    pub fn default_port(&self) -> u16 {
        match self {
            Transport::Dns => 53,
            Transport::Tls => 853,
            Transport::Https => 443,
            Transport::Quic => 853,
            Transport::Grpc => 443,
        }
    }
    pub fn from_scheme(s: &str) -> Option<Transport> {
        match s {
            "dns" => Some(Transport::Dns),
            "tls" => Some(Transport::Tls),
            "https" => Some(Transport::Https),
            "quic" => Some(Transport::Quic),
            "grpc" => Some(Transport::Grpc),
            _ => None,
        }
    }
}

/// A parsed server-block key: `[scheme://]zone[:port]`.
#[derive(Debug, Clone)]
pub struct ParsedKey {
    pub transport: Transport,
    pub zone: String,
    pub port: u16,
    /// True when the key carried an explicit port.
    pub explicit_port: bool,
    /// Bind IP given in the key (`dns://.:53` has none, `127.0.0.1:53`-style
    /// keys are not zones but Caddy hosts; CoreDNS treats them as zones, we do too).
    pub ipv4_only: bool,
}

pub fn parse_key(key: &str) -> Result<ParsedKey> {
    let (transport, rest) = match key.find("://") {
        Some(i) => {
            let s = &key[..i];
            let t = Transport::from_scheme(s).ok_or_else(|| anyhow!("unknown transport scheme '{}' in key '{}'", s, key))?;
            (t, &key[i + 3..])
        }
        None => (Transport::Dns, key),
    };
    // split off :port, being careful with IPv6 reverse zones which contain
    // no colons after normalisation (they are names), but raw keys like
    // "[::1]:53" could appear — CoreDNS does not support those either.
    let (zone_part, port, explicit) = match rest.rfind(':') {
        Some(i) if !rest[i + 1..].is_empty() && rest[i + 1..].chars().all(|c| c.is_ascii_digit()) && !rest[..i].contains(':') => {
            let p: u16 = rest[i + 1..].parse().map_err(|_| anyhow!("bad port in key '{}'", key))?;
            (&rest[..i], p, true)
        }
        _ => (rest, transport.default_port(), false),
    };
    let zone_part = if zone_part.is_empty() { "." } else { zone_part };
    let zones = crate::dnsutil::normalize_zone(zone_part)?;
    if zones.len() != 1 {
        bail!("server block key '{}' expands to {} zones; use a class-aligned reverse prefix", key, zones.len());
    }
    Ok(ParsedKey { transport, zone: zones.into_iter().next().unwrap(), port, explicit_port: explicit, ipv4_only: false })
}

pub type Hook = Box<dyn FnOnce() -> BoxFuture<'static, Result<()>> + Send + Sync>;
pub type FilterFn = Arc<dyn Fn(&Request) -> bool + Send + Sync>;

pub struct ServerConfig {
    /// Normalised zone, e.g. `example.org.`; `.` for root.
    pub zone: String,
    pub port: u16,
    pub transport: Transport,
    /// `bind` addresses; empty means all interfaces.
    pub listen_hosts: Vec<String>,
    pub debug: bool,
    pub stacktrace: bool,
    pub root: PathBuf,
    /// TLS config from the `tls` plugin (for tls://, https://, quic://, grpc://).
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// Handlers in chain order (sorted by `registry::position` before serving).
    pub plugins: Vec<(&'static str, Arc<dyn Handler>)>,
    /// `view` name, "" if none.
    pub view_name: String,
    /// Request filter from the `view` plugin.
    pub filter: Option<FilterFn>,
    /// TSIG secrets: key name → base64 secret (from `tsig`).
    pub tsig_secrets: HashMap<String, String>,
    pub read_timeout: Option<Duration>,
    pub write_timeout: Option<Duration>,
    pub idle_timeout: Option<Duration>,
    /// Number of listening sockets per address (`multisocket`), default 1.
    pub num_sockets: usize,
    pub startup: Vec<Hook>,
    pub shutdown: Vec<Hook>,
    pub restart: Vec<Hook>,
    pub restart_failed: Vec<Hook>,
    /// The `metadata` plugin is enabled in this block.
    pub metadata: bool,
    /// Arbitrary per-config values plugins share at setup (e.g. `tls`
    /// client-auth mode, `pprof` address). Keyed by "plugin/key".
    pub values: HashMap<String, String>,
    /// Which key index inside its server block this config is for.
    pub key_index: usize,
    pub block_index: usize,
}

impl ServerConfig {
    pub fn new(key: &ParsedKey, block_index: usize, key_index: usize) -> Self {
        ServerConfig {
            zone: key.zone.clone(),
            port: key.port,
            transport: key.transport,
            listen_hosts: Vec::new(),
            debug: false,
            stacktrace: false,
            root: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            tls: None,
            plugins: Vec::new(),
            view_name: String::new(),
            filter: None,
            tsig_secrets: HashMap::new(),
            read_timeout: None,
            write_timeout: None,
            idle_timeout: None,
            num_sockets: 1,
            startup: Vec::new(),
            shutdown: Vec::new(),
            restart: Vec::new(),
            restart_failed: Vec::new(),
            metadata: false,
            values: HashMap::new(),
            key_index,
            block_index,
        }
    }

    pub fn add_plugin(&mut self, name: &'static str, h: Arc<dyn Handler>) {
        self.plugins.push((name, h));
    }

    /// Handler by directive name (`config.Handler("cache")`).
    pub fn handler(&self, name: &str) -> Option<Arc<dyn Handler>> {
        self.plugins.iter().find(|(n, _)| *n == name).map(|(_, h)| h.clone())
    }

    /// Names of all handlers in this config (`config.Handlers()`).
    pub fn handler_names(&self) -> Vec<&'static str> {
        self.plugins.iter().map(|(n, _)| *n).collect()
    }

    /// Sort the chain into `plugin.cfg` order. Plugins added by the same
    /// directive keep their relative order.
    pub fn finalize_chain(&mut self) {
        self.plugins.sort_by_key(|(n, _)| crate::plugin::registry::position(n).unwrap_or(usize::MAX));
    }

    pub fn chain(&self) -> Vec<Arc<dyn Handler>> {
        self.plugins.iter().map(|(_, h)| h.clone()).collect()
    }

    /// The metrics/log label for this server: `dns://:53`, `tls://:853`...
    pub fn server_label(&self) -> String {
        format!("{}://:{}", self.transport.scheme(), self.port)
    }

    /// The listening addresses for this config: each bind host with the port.
    pub fn listen_addrs(&self) -> Vec<String> {
        if self.listen_hosts.is_empty() {
            vec![format!(":{}", self.port)]
        } else {
            self.listen_hosts.iter().map(|h| format!("{}:{}", h, self.port)).collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        let k = parse_key(".").unwrap();
        assert_eq!((k.transport, k.zone.as_str(), k.port), (Transport::Dns, ".", 53));
        let k = parse_key("example.org:1053").unwrap();
        assert_eq!((k.zone.as_str(), k.port), ("example.org.", 1053));
        let k = parse_key("tls://.").unwrap();
        assert_eq!((k.transport, k.port), (Transport::Tls, 853));
        let k = parse_key("https://Example.ORG:8443").unwrap();
        assert_eq!((k.transport, k.zone.as_str(), k.port), (Transport::Https, "example.org.", 8443));
        let k = parse_key("10.0.0.0/8").unwrap();
        assert_eq!(k.zone, "10.in-addr.arpa.");
        assert!(parse_key("ftp://.").is_err());
    }
}
