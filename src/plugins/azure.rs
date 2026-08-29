//! `azure RESOURCE_GROUP:ZONE... { ... }` — serves Azure DNS zones
//! (public or private), refreshed periodically.
//!
//! ```text
//! azure rg1:example.org {
//!     tenant TENANT_ID
//!     client CLIENT_ID
//!     secret CLIENT_SECRET
//!     subscription SUBSCRIPTION_ID
//!     environment ENVIRONMENT      # AzurePublicCloud (default) | AzureUSGovernmentCloud | AzureChinaCloud
//!     access private|public
//!     fallthrough [ZONES...]
//! }
//! ```
//! Options fall back to `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,
//! `AZURE_CLIENT_SECRET` and `AZURE_SUBSCRIPTION_ID`.

use super::cloud::{self, CloudZones, Fetcher};
use crate::plugin::{Controller, DnsResult, Handler, Next, Request};
use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct AzureAuth {
    pub tenant: String,
    pub client: String,
    pub secret: String,
    pub login_host: String,
    pub management: String,
    token: Arc<Mutex<Option<(String, Instant)>>>,
}

impl AzureAuth {
    async fn token(&self, http: &reqwest::Client) -> Result<String> {
        if let Some((t, exp)) = self.token.lock().clone() {
            if Instant::now() < exp {
                return Ok(t);
            }
        }
        let url = format!("{}/{}/oauth2/v2.0/token", self.login_host, self.tenant);
        let scope = format!("{}/.default", self.management);
        let form = [("grant_type", "client_credentials"), ("client_id", self.client.as_str()), ("client_secret", self.secret.as_str()), ("scope", scope.as_str())];
        let resp: serde_json::Value = http.post(&url).form(&form).send().await?.error_for_status()?.json().await?;
        let token = resp.get("access_token").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("no access_token in response"))?.to_string();
        let expires = resp.get("expires_in").and_then(|v| v.as_u64()).unwrap_or(3600);
        *self.token.lock() = Some((token.clone(), Instant::now() + Duration::from_secs(expires.saturating_sub(60))));
        Ok(token)
    }
}

fn json_str<'a>(v: &'a serde_json::Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(|x| x.as_str())
}

/// Convert one Azure record set into zone-file lines.
fn rrset_lines(rs: &serde_json::Value, zone: &str) -> String {
    let mut out = String::new();
    let rel = json_str(rs, "name").unwrap_or("@");
    let name = if rel == "@" { zone.to_string() } else { format!("{}.{}", rel, zone) };
    let ty = json_str(rs, "type").unwrap_or("").rsplit('/').next().unwrap_or("").to_string();
    let Some(p) = rs.get("properties") else { return out };
    let ttl = p.get("TTL").and_then(|t| t.as_u64()).unwrap_or(300) as u32;
    let arr = |k: &str| p.get(k).and_then(|a| a.as_array()).cloned().unwrap_or_default();
    match ty.as_str() {
        "A" => arr("ARecords").iter().filter_map(|r| json_str(r, "ipv4Address")).for_each(|v| out.push_str(&cloud::rr_line(&name, ttl, "A", v))),
        "AAAA" => arr("AAAARecords").iter().filter_map(|r| json_str(r, "ipv6Address")).for_each(|v| out.push_str(&cloud::rr_line(&name, ttl, "AAAA", v))),
        "CNAME" => {
            if let Some(v) = p.get("CNAMERecord").and_then(|r| json_str(r, "cname")) {
                out.push_str(&cloud::rr_line(&name, ttl, "CNAME", &crate::dnsutil::fqdn(v)));
            }
        }
        "MX" => arr("MXRecords").iter().for_each(|r| {
            if let (Some(pref), Some(ex)) = (r.get("preference").and_then(|x| x.as_u64()), json_str(r, "exchange")) {
                out.push_str(&cloud::rr_line(&name, ttl, "MX", &format!("{} {}", pref, crate::dnsutil::fqdn(ex))));
            }
        }),
        "NS" => arr("NSRecords").iter().filter_map(|r| json_str(r, "nsdname")).for_each(|v| out.push_str(&cloud::rr_line(&name, ttl, "NS", &crate::dnsutil::fqdn(v)))),
        "PTR" => arr("PTRRecords").iter().filter_map(|r| json_str(r, "ptrdname")).for_each(|v| out.push_str(&cloud::rr_line(&name, ttl, "PTR", &crate::dnsutil::fqdn(v)))),
        "SRV" => arr("SRVRecords").iter().for_each(|r| {
            let g = |k: &str| r.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
            if let Some(t) = json_str(r, "target") {
                out.push_str(&cloud::rr_line(&name, ttl, "SRV", &format!("{} {} {} {}", g("priority"), g("weight"), g("port"), crate::dnsutil::fqdn(t))));
            }
        }),
        "TXT" => arr("TXTRecords").iter().for_each(|r| {
            let parts: Vec<String> = r.get("value").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|s| s.as_str()).map(|s| format!("\"{}\"", s.replace('"', "\\\""))).collect()).unwrap_or_default();
            if !parts.is_empty() {
                out.push_str(&cloud::rr_line(&name, ttl, "TXT", &parts.join(" ")));
            }
        }),
        "CAA" => arr("caaRecords").iter().for_each(|r| {
            if let (Some(f), Some(tag), Some(v)) = (r.get("flags").and_then(|x| x.as_u64()), json_str(r, "tag"), json_str(r, "value")) {
                out.push_str(&cloud::rr_line(&name, ttl, "CAA", &format!("{} {} \"{}\"", f, tag, v)));
            }
        }),
        "SOA" => {
            if let Some(s) = p.get("SOARecord") {
                let g = |k: &str| s.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
                out.push_str(&cloud::rr_line(
                    &name,
                    ttl,
                    "SOA",
                    &format!("{} {} {} {} {} {} {}", crate::dnsutil::fqdn(json_str(s, "host").unwrap_or("ns1-01.azure-dns.com")), crate::dnsutil::fqdn(json_str(s, "email").unwrap_or("azuredns-hostmaster.microsoft.com")), g("serialNumber"), g("refreshTime"), g("retryTime"), g("expireTime"), g("minimumTTL")),
                ));
            }
        }
        _ => {}
    }
    out
}

async fn fetch_zone(http: reqwest::Client, auth: AzureAuth, subscription: String, private: bool, rg_zone: String) -> Result<String> {
    let (rg, zone) = rg_zone.split_once(':').ok_or_else(|| anyhow!("bad zone id {}", rg_zone))?;
    let zone_fq = crate::dnsutil::fqdn(zone);
    let (provider, api) = if private { ("privateDnsZones", "2018-09-01") } else { ("dnsZones", "2018-05-01") };
    let mut url = format!("{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/{}/{}/all?api-version={}", auth.management, subscription, rg, provider, zone.trim_end_matches('.'), api);
    let mut out = String::new();
    loop {
        let token = auth.token(&http).await?;
        let resp = http.get(&url).bearer_auth(&token).send().await?;
        let status = resp.status();
        let body: serde_json::Value = resp.json().await?;
        if !status.is_success() {
            bail!("azure {}: {}", status, body);
        }
        for rs in body.get("value").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
            out.push_str(&rrset_lines(&rs, &zone_fq));
        }
        match body.get("nextLink").and_then(|v| v.as_str()) {
            Some(next) if !next.is_empty() => url = next.to_string(),
            _ => break,
        }
    }
    if !out.contains(" SOA ") {
        out.push_str(&cloud::rr_line(&zone_fq, 3600, "SOA", &format!("ns1-01.azure-dns.com. azuredns-hostmaster.microsoft.com. {} 3600 300 2419200 300", chrono::Utc::now().timestamp())));
    }
    Ok(out)
}

pub struct Azure(Arc<CloudZones>);

#[async_trait]
impl Handler for Azure {
    fn name(&self) -> &'static str {
        "azure"
    }
    fn ready(&self) -> Option<bool> {
        Some(self.0.synced.load(std::sync::atomic::Ordering::Relaxed))
    }
    fn transfer(&self, zone: &str) -> Option<Vec<hickory_proto::rr::Record>> {
        self.0.zones.load().get(zone).map(|z| z.all_records())
    }
    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        self.0.serve(req, next).await
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/azure: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args_until_brace();
        // RESOURCE_GROUP:ZONE → (zone origin, "rg:zone")
        let mut ids = Vec::new();
        for a in &args {
            let (rg, zone) = a.split_once(':').ok_or_else(|| c.errf(format!("invalid zone '{}', expected RESOURCE_GROUP:ZONE", a)))?;
            ids.push((crate::dnsutil::fqdn(zone), format!("{}:{}", rg, zone)));
        }
        if ids.is_empty() {
            return Err(c.errf("no zones specified"));
        }
        let env = |k: &str| std::env::var(k).ok();
        let (mut tenant, mut client, mut secret, mut subscription) = (env("AZURE_TENANT_ID"), env("AZURE_CLIENT_ID"), env("AZURE_CLIENT_SECRET"), env("AZURE_SUBSCRIPTION_ID"));
        let mut environment = "AzurePublicCloud".to_string();
        let mut private = false;
        let mut fallthrough = None;
        while c.next_block() {
            let key = c.val().to_string();
            let a = c.remaining_args();
            match key.as_str() {
                "tenant" | "client" | "secret" | "subscription" | "environment" | "access" => {
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    match key.as_str() {
                        "tenant" => tenant = Some(a[0].clone()),
                        "client" => client = Some(a[0].clone()),
                        "secret" => secret = Some(a[0].clone()),
                        "subscription" => subscription = Some(a[0].clone()),
                        "environment" => environment = a[0].clone(),
                        _ => {
                            private = match a[0].as_str() {
                                "private" => true,
                                "public" => false,
                                o => return Err(c.errf(format!("unknown access '{}'", o))),
                            }
                        }
                    }
                }
                "fallthrough" => fallthrough = Some(if a.is_empty() { vec![".".into()] } else { crate::plugin::normalize_zones(&a)? }),
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        let (login_host, management) = match environment.as_str() {
            "AzurePublicCloud" => ("https://login.microsoftonline.com", "https://management.azure.com"),
            "AzureUSGovernmentCloud" => ("https://login.microsoftonline.us", "https://management.usgovcloudapi.net"),
            "AzureChinaCloud" => ("https://login.chinacloudapi.cn", "https://management.chinacloudapi.cn"),
            o => return Err(c.errf(format!("unknown environment '{}'", o))),
        };
        let (Some(tenant), Some(client), Some(secret), Some(subscription)) = (tenant, client, secret, subscription) else {
            return Err(c.errf("tenant, client, secret and subscription are required (or the AZURE_* environment)"));
        };
        let auth = AzureAuth { tenant, client, secret, login_host: login_host.into(), management: management.into(), token: Arc::new(Mutex::new(None)) };
        let zones = CloudZones::new("azure", ids, fallthrough, Duration::from_secs(60));
        c.add_plugin(Arc::new(Azure(zones.clone())));
        let http = reqwest::Client::builder().timeout(Duration::from_secs(30)).build().map_err(|e| c.errf(e))?;
        let fetch: Fetcher = Arc::new(move |id| {
            let (http, auth, sub) = (http.clone(), auth.clone(), subscription.clone());
            Box::pin(async move { fetch_zone(http, auth, sub, private, id).await })
        });
        let cancel = tokio_util::sync::CancellationToken::new();
        let stop = cancel.clone();
        c.on_startup(Box::new(move || {
            Box::pin(async move {
                zones.spawn_refresh(fetch, cancel);
                Ok(())
            })
        }));
        c.on_shutdown(Box::new(move || {
            Box::pin(async move {
                stop.cancel();
                Ok(())
            })
        }));
    }
    Ok(())
}
