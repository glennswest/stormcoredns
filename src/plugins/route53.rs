//! `route53 ZONE:HOSTED_ZONE_ID... { ... }` — serves AWS Route53 hosted
//! zones, refreshed periodically.
//!
//! ```text
//! route53 example.org.:Z1Z2Z3Z4 {
//!     aws_access_key AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
//!     aws_endpoint ENDPOINT
//!     credentials PROFILE [FILENAME]
//!     fallthrough [ZONES...]
//!     refresh DURATION
//! }
//! ```
//! Credentials: the `aws_access_key` option, `credentials` profile file,
//! or `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN`.

use super::cloud::{self, CloudZones, Fetcher};
use crate::plugin::{Controller, DnsResult, Handler, Next, Request};
use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct Credentials {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = HmacSha256::new_from_slice(key).expect("hmac key");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

/// AWS Signature Version 4 for a GET against Route53 (us-east-1).
pub fn sign_v4(creds: &Credentials, host: &str, path: &str, query: &str, now: chrono::DateTime<chrono::Utc>) -> Vec<(String, String)> {
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let region = "us-east-1";
    let service = "route53";
    let payload_hash = hex::encode(Sha256::digest(b""));
    let mut headers: Vec<(String, String)> = vec![("host".into(), host.to_string()), ("x-amz-content-sha256".into(), payload_hash.clone()), ("x-amz-date".into(), amz_date.clone())];
    if let Some(t) = &creds.session_token {
        headers.push(("x-amz-security-token".into(), t.clone()));
    }
    headers.sort();
    let canonical_headers: String = headers.iter().map(|(k, v)| format!("{}:{}\n", k, v.trim())).collect();
    let signed_headers: String = headers.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");
    let canonical_request = format!("GET\n{}\n{}\n{}\n{}\n{}", path, query, canonical_headers, signed_headers, payload_hash);
    let scope = format!("{}/{}/{}/aws4_request", date, region, service);
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{}\n{}\n{}", amz_date, scope, hex::encode(Sha256::digest(canonical_request.as_bytes())));
    let k_date = hmac(format!("AWS4{}", creds.secret_key).as_bytes(), date.as_bytes());
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, service.as_bytes());
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex::encode(hmac(&k_signing, string_to_sign.as_bytes()));
    let auth = format!("AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}", creds.access_key, scope, signed_headers, signature);
    let mut out: Vec<(String, String)> = headers.into_iter().filter(|(k, _)| k != "host").collect();
    out.push(("authorization".into(), auth));
    out
}

/// Read `[profile]` from an AWS shared credentials file.
pub fn profile_credentials(file: &std::path::Path, profile: &str) -> Result<Credentials> {
    let text = std::fs::read_to_string(file).map_err(|e| anyhow!("reading {}: {}", file.display(), e))?;
    let mut in_profile = false;
    let (mut ak, mut sk, mut tok) = (None, None, None);
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_profile = line.trim_matches(|c| c == '[' || c == ']').trim() == profile;
            continue;
        }
        if !in_profile {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            match k.trim() {
                "aws_access_key_id" => ak = Some(v.trim().to_string()),
                "aws_secret_access_key" => sk = Some(v.trim().to_string()),
                "aws_session_token" => tok = Some(v.trim().to_string()),
                _ => {}
            }
        }
    }
    match (ak, sk) {
        (Some(a), Some(s)) => Ok(Credentials { access_key: a, secret_key: s, session_token: tok }),
        _ => bail!("profile {} not found in {}", profile, file.display()),
    }
}

/// Fetch every record set of a hosted zone as zone-file text.
async fn fetch_zone(client: reqwest::Client, creds: Credentials, endpoint: String, zone_id: String) -> Result<String> {
    let host = endpoint.trim_start_matches("https://").trim_end_matches('/').to_string();
    let mut out = String::new();
    let mut next_name: Option<String> = None;
    let mut next_type: Option<String> = None;
    loop {
        let path = format!("/2013-04-01/hostedzone/{}/rrset", zone_id);
        let mut q: Vec<String> = vec!["maxitems=1000".into()];
        if let Some(n) = &next_name {
            q.push(format!("name={}", percent_encoding::utf8_percent_encode(n, percent_encoding::NON_ALPHANUMERIC)));
        }
        if let Some(t) = &next_type {
            q.push(format!("type={}", t));
        }
        q.sort();
        let query = q.join("&");
        let headers = sign_v4(&creds, &host, &path, &query, chrono::Utc::now());
        let mut req = client.get(format!("https://{}{}?{}", host, path, query));
        for (k, v) in headers {
            req = req.header(k, v);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            bail!("route53 {}: {}", status, body.chars().take(300).collect::<String>());
        }
        for rrset in cloud::xml_tags(&body, "ResourceRecordSet") {
            let name = cloud::xml_tags(rrset, "Name").first().map(|s| cloud::xml_unescape(s)).unwrap_or_default();
            let rtype = cloud::xml_tags(rrset, "Type").first().map(|s| s.to_string()).unwrap_or_default();
            if cloud::xml_tags(rrset, "AliasTarget").first().is_some() {
                // alias records need Route53 resolution; expose as CNAME to the target
                if let Some(target) = cloud::xml_tags(rrset, "DNSName").first() {
                    out.push_str(&cloud::rr_line(&name.replace("\\052", "*"), 60, "CNAME", &cloud::xml_unescape(target)));
                }
                continue;
            }
            let ttl: u32 = cloud::xml_tags(rrset, "TTL").first().and_then(|t| t.parse().ok()).unwrap_or(300);
            for v in cloud::xml_tags(rrset, "Value") {
                out.push_str(&cloud::rr_line(&name.replace("\\052", "*"), ttl, &rtype, &cloud::xml_unescape(v)));
            }
        }
        let truncated = cloud::xml_tags(&body, "IsTruncated").first().map(|s| *s == "true").unwrap_or(false);
        if !truncated {
            break;
        }
        next_name = cloud::xml_tags(&body, "NextRecordName").first().map(|s| cloud::xml_unescape(s));
        next_type = cloud::xml_tags(&body, "NextRecordType").first().map(|s| s.to_string());
        if next_name.is_none() {
            break;
        }
    }
    Ok(out)
}

pub struct Route53(Arc<CloudZones>);

#[async_trait]
impl Handler for Route53 {
    fn name(&self) -> &'static str {
        "route53"
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
            return Err(c.errf("plugin/route53: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args_until_brace();
        let ids = cloud::parse_zone_ids(&args, "route53").map_err(|e| c.errf(e))?;
        let mut creds: Option<Credentials> = None;
        let mut endpoint = "https://route53.amazonaws.com".to_string();
        let mut fallthrough = None;
        let mut refresh = Duration::from_secs(60);
        while c.next_block() {
            match c.val() {
                "aws_access_key" => {
                    let a = c.remaining_args();
                    if a.len() != 2 {
                        return Err(c.arg_err());
                    }
                    creds = Some(Credentials { access_key: a[0].clone(), secret_key: a[1].clone(), session_token: None });
                }
                "aws_endpoint" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    endpoint = a[0].clone();
                }
                "credentials" => {
                    let a = c.remaining_args();
                    if a.is_empty() || a.len() > 2 {
                        return Err(c.arg_err());
                    }
                    let file = a.get(1).map(std::path::PathBuf::from).unwrap_or_else(|| std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".aws/credentials"));
                    creds = Some(profile_credentials(&file, &a[0]).map_err(|e| c.errf(e))?);
                }
                "fallthrough" => {
                    let a = c.remaining_args();
                    fallthrough = Some(if a.is_empty() { vec![".".into()] } else { crate::plugin::normalize_zones(&a)? });
                }
                "refresh" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    refresh = crate::dnsutil::parse_duration(&a[0])?;
                }
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        let creds = match creds {
            Some(c) => c,
            None => match (std::env::var("AWS_ACCESS_KEY_ID"), std::env::var("AWS_SECRET_ACCESS_KEY")) {
                (Ok(a), Ok(s)) => Credentials { access_key: a, secret_key: s, session_token: std::env::var("AWS_SESSION_TOKEN").ok() },
                _ => return Err(c.errf("no AWS credentials: use aws_access_key, credentials, or the AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY environment")),
            },
        };
        let zones = CloudZones::new("route53", ids, fallthrough, refresh);
        c.add_plugin(Arc::new(Route53(zones.clone())));
        let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).build().map_err(|e| c.errf(e))?;
        let fetch: Fetcher = Arc::new(move |id| {
            let (client, creds, endpoint) = (client.clone(), creds.clone(), endpoint.clone());
            Box::pin(async move { fetch_zone(client, creds, endpoint, id).await })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigv4_shape() {
        let creds = Credentials { access_key: "AKID".into(), secret_key: "SECRET".into(), session_token: None };
        let h = sign_v4(&creds, "route53.amazonaws.com", "/2013-04-01/hostedzone/Z1/rrset", "maxitems=1000", chrono::Utc::now());
        let auth = h.iter().find(|(k, _)| k == "authorization").unwrap();
        assert!(auth.1.starts_with("AWS4-HMAC-SHA256 Credential=AKID/"));
        assert!(auth.1.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
    }
}
