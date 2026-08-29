//! The plugin contract.
//!
//! This is CoreDNS's `plugin.Handler` in Rust. A handler receives the
//! request and a `Next` cursor over the rest of the chain and returns a
//! `Reply` — either a fully formed response message, or an rcode when it did
//! not (and no later plugin did) write one. Errors carry the rcode the server
//! should answer with; the `errors` plugin logs them.
//!
//! Instead of a `ResponseWriter` that plugins wrap to observe the answer,
//! responses travel *back* through the chain as return values: a plugin that
//! wants to see or edit the response (cache, rewrite, loadbalance, dnssec,
//! header, minimal, log, prometheus) simply inspects `next.serve(req).await`.

pub mod controller;
pub mod registry;
pub mod replacer;
pub mod request;

use async_trait::async_trait;
use hickory_proto::op::{Message, ResponseCode};
use std::fmt;
use std::sync::Arc;

pub use controller::Controller;
pub use request::{Extensions, Metadata, Proto, Request};

/// The outcome of serving a request.
#[derive(Debug)]
pub enum Reply {
    /// A response message was produced and will be written to the client.
    Msg(Message),
    /// No plugin produced a response; the server answers with this rcode.
    /// (`Rcode(NoError)` means "handled, nothing to send" — only a plugin
    /// that has genuinely already written, e.g. dnstap tap-only, uses it.)
    Rcode(ResponseCode),
}

impl Reply {
    pub fn rcode(&self) -> ResponseCode {
        match self {
            Reply::Msg(m) => m.response_code(),
            Reply::Rcode(r) => *r,
        }
    }
    pub fn msg(&self) -> Option<&Message> {
        match self {
            Reply::Msg(m) => Some(m),
            Reply::Rcode(_) => None,
        }
    }
    pub fn msg_mut(&mut self) -> Option<&mut Message> {
        match self {
            Reply::Msg(m) => Some(m),
            Reply::Rcode(_) => None,
        }
    }
    pub fn into_msg(self) -> Option<Message> {
        match self {
            Reply::Msg(m) => Some(m),
            Reply::Rcode(_) => None,
        }
    }
}

/// An error raised by a plugin. `rcode` is what the client will see.
#[derive(Debug)]
pub struct PluginError {
    pub plugin: &'static str,
    pub rcode: ResponseCode,
    pub source: anyhow::Error,
}

impl PluginError {
    pub fn new(plugin: &'static str, source: impl Into<anyhow::Error>) -> Self {
        PluginError { plugin, rcode: ResponseCode::ServFail, source: source.into() }
    }
    pub fn with_rcode(mut self, rcode: ResponseCode) -> Self {
        self.rcode = rcode;
        self
    }
}

impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "plugin/{}: {}", self.plugin, self.source)
    }
}
impl std::error::Error for PluginError {}

/// `plugin.Error(name, err)` — wrap an error with the plugin name.
pub fn error(plugin: &'static str, err: impl Into<anyhow::Error>) -> PluginError {
    PluginError::new(plugin, err)
}

pub type DnsResult = Result<Reply, PluginError>;

/// A plugin in the chain.
#[async_trait]
pub trait Handler: Send + Sync + 'static {
    /// The plugin's directive name.
    fn name(&self) -> &'static str;

    /// Handle the request, calling `next.serve(req)` to pass it on.
    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult;

    /// Readiness signal for the `ready` plugin. `None` means the plugin
    /// does not participate; `Some(false)` blocks readiness.
    fn ready(&self) -> Option<bool> {
        None
    }

    /// Health signal for the `health` plugin (CoreDNS `Healther`).
    fn health(&self) -> Option<bool> {
        None
    }
}

/// Cursor over the remainder of the plugin chain.
#[derive(Clone, Copy)]
pub struct Next<'a> {
    chain: &'a [Arc<dyn Handler>],
}

impl<'a> Next<'a> {
    pub fn new(chain: &'a [Arc<dyn Handler>]) -> Self {
        Next { chain }
    }

    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// Name of the next plugin, if any.
    pub fn name(&self) -> Option<&'static str> {
        self.chain.first().map(|h| h.name())
    }

    /// Call the next plugin. If there is none, returns `SERVFAIL` with a
    /// "no next plugin found" error, exactly like `plugin.NextOrFailure`.
    pub async fn serve(self, req: &mut Request) -> DnsResult {
        match self.chain.split_first() {
            Some((h, rest)) => h.serve_dns(req, Next { chain: rest }).await,
            None => Err(PluginError::new("core", anyhow::anyhow!("no next plugin found"))),
        }
    }
}

/// `plugin.NextOrFailure(name, next, ...)`: call the next plugin or fail
/// with an error attributed to `name`.
pub async fn next_or_failure(name: &'static str, next: Next<'_>, req: &mut Request) -> DnsResult {
    if next.is_empty() {
        return Err(PluginError::new(name, anyhow::anyhow!("no next plugin found")));
    }
    next.serve(req).await
}

/// `plugin.ClientWrite(rcode)`: does this rcode mean the plugin itself
/// answered the client (true), or should the server send an error (false)?
pub fn client_write(rcode: ResponseCode) -> bool {
    !matches!(
        rcode,
        ResponseCode::ServFail | ResponseCode::Refused | ResponseCode::FormErr | ResponseCode::NotImp
    )
}

/// Longest-suffix zone matching (`plugin.Zones.Matches`). `zones` and
/// `name` are lowercase FQDNs with a trailing dot.
pub fn zones_match<'z>(zones: &'z [String], name: &str) -> Option<&'z str> {
    let mut best: Option<&str> = None;
    for z in zones {
        if crate::dnsutil::is_subdomain(z, name) {
            match best {
                Some(b) if b.len() >= z.len() => {}
                _ => best = Some(z.as_str()),
            }
        }
    }
    best
}

/// Normalise a list of zone arguments (`plugin.Zones.Normalize`). Reverse
/// CIDR notation is expanded.
pub fn normalize_zones(zones: &[String]) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    for z in zones {
        out.extend(crate::dnsutil::normalize_zone(z)?);
    }
    Ok(out)
}

/// Build a `Vec<String>` of zones from directive args, defaulting to the
/// server block's zone when none are given (`plugin.OriginsFromArgsOrServerBlock`).
pub fn origins_from_args_or_server_block(args: &[String], server_zones: &[String]) -> anyhow::Result<Vec<String>> {
    if args.is_empty() {
        let mut v = Vec::new();
        for z in server_zones {
            v.extend(crate::dnsutil::normalize_zone(z)?);
        }
        return Ok(v);
    }
    normalize_zones(args)
}
