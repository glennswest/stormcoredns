//! Shared machinery for the cloud DNS backends (`route53`, `azure`,
//! `clouddns`): each periodically fetches its hosted zones as zone-file
//! text, parses them into `Zone`s and serves them like `file`, with
//! `fallthrough`.

use crate::plugin::{DnsResult, Next, Reply, Request};
use crate::plugins::file::zone::Zone;
use anyhow::Result;
use arc_swap::ArcSwap;
use futures::future::BoxFuture;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Fetches the presentation-format records of one hosted zone.
pub type Fetcher = Arc<dyn Fn(String) -> BoxFuture<'static, Result<String>> + Send + Sync>;

pub struct CloudZones {
    pub plugin: &'static str,
    /// zone origin → provider zone id
    pub ids: Vec<(String, String)>,
    pub zones: ArcSwap<HashMap<String, Arc<Zone>>>,
    pub fallthrough: Option<Vec<String>>,
    pub refresh: Duration,
    pub synced: AtomicBool,
}

impl CloudZones {
    pub fn new(plugin: &'static str, ids: Vec<(String, String)>, fallthrough: Option<Vec<String>>, refresh: Duration) -> Arc<Self> {
        Arc::new(CloudZones { plugin, ids, zones: ArcSwap::from_pointee(HashMap::new()), fallthrough, refresh, synced: AtomicBool::new(false) })
    }

    pub fn names(&self) -> Vec<String> {
        self.ids.iter().map(|(z, _)| z.clone()).collect()
    }

    /// Fetch every zone once; a zone that fails keeps its previous copy
    /// (or stays missing until its first success).
    pub async fn refresh_once(&self, fetch: &Fetcher) {
        let mut next: HashMap<String, Arc<Zone>> = (**self.zones.load()).clone();
        for (origin, id) in &self.ids {
            match fetch(id.clone()).await {
                Ok(text) => match Zone::parse(&text, origin, None) {
                    Ok(z) => {
                        tracing::debug!("plugin/{}: refreshed {} ({} records)", self.plugin, origin, z.len());
                        next.insert(origin.clone(), Arc::new(z));
                    }
                    Err(e) => tracing::error!("plugin/{}: parsing {}: {}", self.plugin, origin, e),
                },
                Err(e) => tracing::error!("plugin/{}: fetching {}: {}", self.plugin, origin, e),
            }
        }
        // ready once every zone has loaded at least once (a failed fetch keeps
        // a zone missing, so `/ready` stays 503 rather than serving NXDOMAIN)
        let all = self.ids.iter().all(|(origin, _)| next.contains_key(origin));
        if all && !self.synced.swap(true, Ordering::Relaxed) {
            tracing::info!("plugin/{}: all {} zones loaded", self.plugin, self.ids.len());
        }
        self.zones.store(Arc::new(next));
    }

    pub fn spawn_refresh(self: &Arc<Self>, fetch: Fetcher, cancel: tokio_util::sync::CancellationToken) {
        let me = self.clone();
        tokio::spawn(async move {
            me.refresh_once(&fetch).await;
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(me.refresh) => me.refresh_once(&fetch).await,
                }
            }
        });
    }

    pub async fn serve(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let qname = req.name();
        let names = self.names();
        let Some(z) = crate::plugin::zones_match(&names, &qname).map(|z| z.to_string()) else {
            return next.serve(req).await;
        };
        let zone = self.zones.load().get(&z).cloned();
        match zone {
            Some(zone) => {
                let m = zone.lookup(req, true).await;
                if m.response_code() == hickory_proto::op::ResponseCode::NXDomain {
                    if let Some(ft) = &self.fallthrough {
                        if crate::plugin::zones_match(ft, &qname).is_some() {
                            return next.serve(req).await;
                        }
                    }
                }
                Ok(Reply::Msg(m))
            }
            None => {
                let mut m = req.new_reply();
                m.set_response_code(hickory_proto::op::ResponseCode::ServFail);
                Ok(Reply::Msg(m))
            }
        }
    }
}

/// Parse `ZONE:ID` arguments.
pub fn parse_zone_ids(args: &[String], plugin: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for a in args {
        let (zone, id) = a.split_once(':').ok_or_else(|| anyhow::anyhow!("plugin/{}: invalid zone '{}', expected ZONE:ID", plugin, a))?;
        out.push((crate::dnsutil::fqdn(zone), id.to_string()));
    }
    if out.is_empty() {
        anyhow::bail!("plugin/{}: no zones specified", plugin);
    }
    Ok(out)
}

/// A minimal XML text extractor for the Route53 response shapes.
pub fn xml_tags<'a>(text: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find(&open) {
        let after = &rest[i + open.len()..];
        let Some(j) = after.find(&close) else { break };
        out.push(&after[..j]);
        rest = &after[j + close.len()..];
    }
    out
}

pub fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

/// A record line in zone-file syntax.
pub fn rr_line(name: &str, ttl: u32, rtype: &str, rdata: &str) -> String {
    format!("{} {} IN {} {}\n", crate::dnsutil::fqdn(name), ttl, rtype, rdata)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZONE: &str = "$ORIGIN example.org.\n@ 300 IN SOA ns h 1 2 3 4 5\nwww 300 IN A 192.0.2.1\n";

    #[tokio::test]
    async fn ready_only_when_every_zone_loaded() {
        let z = CloudZones::new("test", vec![("example.org.".into(), "ok".into()), ("example.net.".into(), "bad".into())], None, Duration::from_secs(60));
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let f2 = fail.clone();
        let fetch: Fetcher = Arc::new(move |id: String| {
            let fail = f2.load(Ordering::Relaxed);
            Box::pin(async move {
                if id == "bad" && fail {
                    anyhow::bail!("unavailable")
                }
                Ok(if id == "ok" { ZONE.to_string() } else { ZONE.replace("example.org.", "example.net.") })
            })
        });
        z.refresh_once(&fetch).await;
        assert!(!z.synced.load(Ordering::Relaxed), "one zone failed: not ready");
        assert_eq!(z.zones.load().len(), 1);
        fail.store(false, Ordering::Relaxed);
        z.refresh_once(&fetch).await;
        assert!(z.synced.load(Ordering::Relaxed));
        // a later failure keeps the previous copy and readiness
        fail.store(true, Ordering::Relaxed);
        z.refresh_once(&fetch).await;
        assert!(z.synced.load(Ordering::Relaxed));
        assert_eq!(z.zones.load().len(), 2);
    }
}
