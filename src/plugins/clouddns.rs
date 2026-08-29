//! `clouddns PROJECT_ID:MANAGED_ZONE_NAME... { ... }` — serves Google
//! Cloud DNS managed zones, refreshed periodically.
//!
//! ```text
//! clouddns my-project:example-zone {
//!     credentials FILENAME        # service-account JSON
//!     fallthrough [ZONES...]
//! }
//! ```
//! Authentication: the `credentials` file, `GOOGLE_APPLICATION_CREDENTIALS`,
//! or the GCE metadata server when running on Google Cloud.

use super::cloud::{self, CloudZones, Fetcher};
use crate::plugin::{Controller, DnsResult, Handler, Next, Request};
use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use base64::Engine;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub enum GoogleAuth {
    ServiceAccount { email: String, key_pkcs8: Vec<u8>, token_uri: String },
    Metadata,
}

#[derive(Clone)]
pub struct Authenticator {
    auth: GoogleAuth,
    token: Arc<Mutex<Option<(String, Instant)>>>,
}

fn b64url(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

impl Authenticator {
    pub fn from_json(text: &str) -> Result<Authenticator> {
        let v: serde_json::Value = serde_json::from_str(text)?;
        let email = v.get("client_email").and_then(|e| e.as_str()).ok_or_else(|| anyhow!("credentials: no client_email"))?.to_string();
        let pem = v.get("private_key").and_then(|e| e.as_str()).ok_or_else(|| anyhow!("credentials: no private_key"))?;
        let token_uri = v.get("token_uri").and_then(|e| e.as_str()).unwrap_or("https://oauth2.googleapis.com/token").to_string();
        let mut rd = std::io::BufReader::new(pem.as_bytes());
        let key = rustls_pemfile::private_key(&mut rd)?.ok_or_else(|| anyhow!("credentials: private_key is not a PEM private key"))?;
        let key_pkcs8 = match key {
            rustls::pki_types::PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der().to_vec(),
            _ => bail!("credentials: private_key must be PKCS#8"),
        };
        Ok(Authenticator { auth: GoogleAuth::ServiceAccount { email, key_pkcs8, token_uri }, token: Arc::new(Mutex::new(None)) })
    }

    pub fn metadata() -> Authenticator {
        Authenticator { auth: GoogleAuth::Metadata, token: Arc::new(Mutex::new(None)) }
    }

    async fn token(&self, http: &reqwest::Client) -> Result<String> {
        if let Some((t, exp)) = self.token.lock().clone() {
            if Instant::now() < exp {
                return Ok(t);
            }
        }
        let (token, expires) = match &self.auth {
            GoogleAuth::ServiceAccount { email, key_pkcs8, token_uri } => {
                let now = chrono::Utc::now().timestamp();
                let header = b64url(br#"{"alg":"RS256","typ":"JWT"}"#);
                let claims = serde_json::json!({
                    "iss": email,
                    "scope": "https://www.googleapis.com/auth/ndev.clouddns.readonly",
                    "aud": token_uri,
                    "iat": now,
                    "exp": now + 3600,
                });
                let signing_input = format!("{}.{}", header, b64url(claims.to_string().as_bytes()));
                let key = ring::signature::RsaKeyPair::from_pkcs8(key_pkcs8).map_err(|e| anyhow!("service account key: {}", e))?;
                let mut sig = vec![0u8; key.public().modulus_len()];
                key.sign(&ring::signature::RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), signing_input.as_bytes(), &mut sig).map_err(|e| anyhow!("signing JWT: {}", e))?;
                let jwt = format!("{}.{}", signing_input, b64url(&sig));
                let form = [("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"), ("assertion", jwt.as_str())];
                let resp: serde_json::Value = http.post(token_uri).form(&form).send().await?.error_for_status()?.json().await?;
                (
                    resp.get("access_token").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("no access_token"))?.to_string(),
                    resp.get("expires_in").and_then(|v| v.as_u64()).unwrap_or(3600),
                )
            }
            GoogleAuth::Metadata => {
                let resp: serde_json::Value = http
                    .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
                    .header("Metadata-Flavor", "Google")
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                (
                    resp.get("access_token").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("no access_token"))?.to_string(),
                    resp.get("expires_in").and_then(|v| v.as_u64()).unwrap_or(3600),
                )
            }
        };
        *self.token.lock() = Some((token.clone(), Instant::now() + Duration::from_secs(expires.saturating_sub(60))));
        Ok(token)
    }
}

async fn fetch_zone(http: reqwest::Client, auth: Authenticator, project_zone: String) -> Result<String> {
    let (project, zone) = project_zone.split_once(':').ok_or_else(|| anyhow!("bad zone id {}", project_zone))?;
    let mut out = String::new();
    let mut page: Option<String> = None;
    loop {
        let token = auth.token(&http).await?;
        let mut url = format!("https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/rrsets?maxResults=1000", project, zone);
        if let Some(p) = &page {
            url.push_str(&format!("&pageToken={}", p));
        }
        let resp = http.get(&url).bearer_auth(&token).send().await?;
        let status = resp.status();
        let body: serde_json::Value = resp.json().await?;
        if !status.is_success() {
            bail!("clouddns {}: {}", status, body);
        }
        for rs in body.get("rrsets").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
            let name = rs.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let ty = rs.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let ttl = rs.get("ttl").and_then(|v| v.as_u64()).unwrap_or(300) as u32;
            for rd in rs.get("rrdatas").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
                if let Some(d) = rd.as_str() {
                    out.push_str(&cloud::rr_line(name, ttl, ty, d));
                }
            }
        }
        match body.get("nextPageToken").and_then(|v| v.as_str()) {
            Some(t) if !t.is_empty() => page = Some(t.to_string()),
            _ => break,
        }
    }
    Ok(out)
}

pub struct CloudDns(Arc<CloudZones>);

#[async_trait]
impl Handler for CloudDns {
    fn name(&self) -> &'static str {
        "clouddns"
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
            return Err(c.errf("plugin/clouddns: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args_until_brace();
        // PROJECT:ZONE_NAME; the DNS origin comes from the zone name? No —
        // CoreDNS uses the managed zone's dnsName, which we learn on the
        // first fetch. We require the origin in a third field when the
        // managed zone name is not the domain: PROJECT:ZONE_NAME[:ORIGIN].
        let mut ids = Vec::new();
        for a in &args {
            let parts: Vec<&str> = a.split(':').collect();
            match parts.len() {
                2 => ids.push((crate::dnsutil::fqdn(parts[1]), format!("{}:{}", parts[0], parts[1]))),
                3 => ids.push((crate::dnsutil::fqdn(parts[2]), format!("{}:{}", parts[0], parts[1]))),
                _ => return Err(c.errf(format!("invalid zone '{}', expected PROJECT_ID:MANAGED_ZONE_NAME[:ORIGIN]", a))),
            }
        }
        if ids.is_empty() {
            return Err(c.errf("no zones specified"));
        }
        let mut credentials: Option<std::path::PathBuf> = std::env::var("GOOGLE_APPLICATION_CREDENTIALS").ok().map(std::path::PathBuf::from);
        let mut fallthrough = None;
        while c.next_block() {
            match c.val() {
                "credentials" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    credentials = Some(if std::path::Path::new(&a[0]).is_absolute() { std::path::PathBuf::from(&a[0]) } else { c.config.root.join(&a[0]) });
                }
                "fallthrough" => {
                    let a = c.remaining_args();
                    fallthrough = Some(if a.is_empty() { vec![".".into()] } else { crate::plugin::normalize_zones(&a)? });
                }
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        let auth = match credentials {
            Some(p) => {
                let text = std::fs::read_to_string(&p).map_err(|e| c.errf(format!("reading {}: {}", p.display(), e)))?;
                Authenticator::from_json(&text).map_err(|e| c.errf(e))?
            }
            None => Authenticator::metadata(),
        };
        let zones = CloudZones::new("clouddns", ids, fallthrough, Duration::from_secs(60));
        c.add_plugin(Arc::new(CloudDns(zones.clone())));
        let http = reqwest::Client::builder().timeout(Duration::from_secs(30)).build().map_err(|e| c.errf(e))?;
        let fetch: Fetcher = Arc::new(move |id| {
            let (http, auth) = (http.clone(), auth.clone());
            Box::pin(async move { fetch_zone(http, auth, id).await })
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
