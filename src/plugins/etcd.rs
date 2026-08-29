//! `etcd [ZONES...] { ... }` — serves records stored in etcd using the
//! SkyDNS key layout (`/skydns/<reversed labels>/...` with JSON values).
//!
//! ```text
//! etcd [ZONES...] {
//!     fallthrough [ZONES...]
//!     path /skydns
//!     endpoint ENDPOINT...
//!     credentials USERNAME PASSWORD
//!     tls CERT KEY CACERT
//! }
//! ```
//! A value looks like `{"host":"10.0.0.1","port":8080,"priority":10,
//! "weight":20,"ttl":30,"text":"...","mail":false,"targetstrip":0}`.

use crate::dnsutil;
use crate::plugin::{error, Controller, DnsResult, Handler, Next, Reply, Request};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use etcd_client::{Client, ConnectOptions, GetOptions};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde::Deserialize;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Service {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub priority: u16,
    #[serde(default)]
    pub weight: u16,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub mail: bool,
    #[serde(default)]
    pub ttl: u32,
    #[serde(default)]
    pub targetstrip: usize,
    #[serde(default)]
    pub group: String,
    /// Filled in from the key.
    #[serde(skip)]
    pub key: String,
}

impl Service {
    fn ip(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }
    fn ttl(&self) -> u32 {
        if self.ttl == 0 {
            30
        } else {
            self.ttl
        }
    }
    /// Synthesised owner for SRV/MX targets that are IPs: `<hash>.<name>`.
    fn target_name(&self, qname: &Name) -> Name {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        use std::hash::{Hash, Hasher};
        self.key.hash(&mut h);
        let label = format!("{:x}", h.finish());
        Name::from_ascii(&label).ok().and_then(|n| n.append_domain(qname).ok()).unwrap_or_else(|| qname.clone())
    }
}

pub struct Etcd {
    zones: Vec<String>,
    path: String,
    endpoints: Vec<String>,
    options: Option<ConnectOptions>,
    client: Mutex<Option<Client>>,
    fallthrough: Option<Vec<String>>,
}

/// `a.b.example.org.` under zone path → `/skydns/org/example/b/a`
fn key_for(path: &str, name: &str) -> String {
    let mut labels: Vec<&str> = name.trim_end_matches('.').split('.').filter(|l| !l.is_empty()).collect();
    labels.reverse();
    let mut k = path.trim_end_matches('/').to_string();
    for l in labels {
        k.push('/');
        k.push_str(if l == "*" || l == "any" { "*" } else { l });
    }
    k
}

impl Etcd {
    async fn client(&self) -> Result<Client> {
        let mut g = self.client.lock().await;
        if let Some(c) = g.as_ref() {
            return Ok(c.clone());
        }
        let c = Client::connect(self.endpoints.clone(), self.options.clone()).await.map_err(|e| anyhow!("connecting to etcd: {}", e))?;
        *g = Some(c.clone());
        Ok(c)
    }

    /// All services at `name` and below (`/skydns/org/example/x/` prefix).
    async fn records(&self, name: &str, exact: bool) -> Result<Vec<Service>> {
        let key = key_for(&self.path, name);
        let mut client = self.client().await?;
        // wildcard segments: fetch the parent prefix and filter
        let (prefix, filter): (String, Option<Vec<String>>) = if let Some(i) = key.find("/*") {
            (key[..i + 1].to_string(), Some(key.split('/').map(|s| s.to_string()).collect()))
        } else if exact {
            (key.clone(), None)
        } else {
            (format!("{}/", key), None)
        };
        let resp = client.get(prefix.clone(), Some(GetOptions::new().with_prefix())).await.map_err(|e| anyhow!("etcd get {}: {}", prefix, e))?;
        let mut out = Vec::new();
        for kv in resp.kvs() {
            let k = kv.key_str().unwrap_or("").to_string();
            if exact && filter.is_none() && k != key {
                continue;
            }
            if let Some(pat) = &filter {
                let parts: Vec<&str> = k.split('/').collect();
                if parts.len() < pat.len() {
                    continue;
                }
                let ok = pat.iter().enumerate().all(|(i, p)| p == "*" || parts.get(i).map(|x| *x == p).unwrap_or(false));
                if !ok {
                    continue;
                }
            }
            match serde_json::from_slice::<Service>(kv.value()) {
                Ok(mut s) => {
                    s.key = k;
                    out.push(s);
                }
                Err(e) => tracing::warn!("plugin/etcd: bad value at {}: {}", k, e),
            }
        }
        if !exact && out.is_empty() {
            // fall back to the exact key
            let resp = client.get(key.clone(), None).await.map_err(|e| anyhow!("etcd get {}: {}", key, e))?;
            for kv in resp.kvs() {
                if let Ok(mut s) = serde_json::from_slice::<Service>(kv.value()) {
                    s.key = kv.key_str().unwrap_or("").to_string();
                    out.push(s);
                }
            }
        }
        Ok(out)
    }

    fn soa(&self, zone: &str) -> Record {
        let z = Name::from_ascii(zone).unwrap_or_else(|_| Name::root());
        let ns = Name::from_ascii(dnsutil::join(&["ns", "dns"], zone)).unwrap_or_else(|_| z.clone());
        let mbox = Name::from_ascii(dnsutil::join(&["hostmaster"], zone)).unwrap_or_else(|_| z.clone());
        Record::from_rdata(z, 300, RData::SOA(SOA::new(ns, mbox, chrono::Utc::now().timestamp() as u32, 7200, 1800, 86400, 30)))
    }

    async fn serve(&self, req: &mut Request, zone: &str) -> Result<Option<Message>> {
        let qname = req.name();
        let qtype = req.qtype();
        let name = req.qname();
        let mut m = req.new_reply();
        m.set_authoritative(true);
        if qname == zone {
            match qtype {
                RecordType::SOA | RecordType::ANY => m.add_answer(self.soa(zone)),
                RecordType::NS => {
                    let ns = self.records(&dnsutil::join(&["ns", "dns"], zone), false).await?;
                    for s in &ns {
                        if let Some(ip) = s.ip() {
                            let target = s.target_name(&Name::from_ascii(dnsutil::join(&["ns", "dns"], zone)).unwrap_or_else(|_| name.clone()));
                            m.add_answer(Record::from_rdata(name.clone(), s.ttl(), RData::NS(NS(target.clone()))));
                            m.add_additional(match ip {
                                IpAddr::V4(v) => Record::from_rdata(target, s.ttl(), RData::A(A(v))),
                                IpAddr::V6(v) => Record::from_rdata(target, s.ttl(), RData::AAAA(AAAA(v))),
                            });
                        } else if let Ok(t) = Name::from_ascii(dnsutil::fqdn(&s.host)) {
                            m.add_answer(Record::from_rdata(name.clone(), s.ttl(), RData::NS(NS(t))));
                        }
                    }
                    if m.answers().is_empty() {
                        m.add_name_server(self.soa(zone));
                    }
                    &mut m
                }
                _ => m.add_name_server(self.soa(zone)),
            };
            return Ok(Some(m));
        }
        let services = self.records(&qname, false).await?;
        if services.is_empty() {
            return Ok(None);
        }
        match qtype {
            RecordType::A | RecordType::AAAA | RecordType::ANY => {
                for s in &services {
                    match (s.ip(), qtype) {
                        (Some(IpAddr::V4(v)), RecordType::A | RecordType::ANY) => m.add_answer(Record::from_rdata(name.clone(), s.ttl(), RData::A(A(v)))),
                        (Some(IpAddr::V6(v)), RecordType::AAAA | RecordType::ANY) => m.add_answer(Record::from_rdata(name.clone(), s.ttl(), RData::AAAA(AAAA(v)))),
                        (None, _) if !s.host.is_empty() => {
                            let target = Name::from_ascii(dnsutil::fqdn(&s.host))?;
                            m.add_answer(Record::from_rdata(name.clone(), s.ttl(), RData::CNAME(CNAME(target.clone()))));
                            if qtype != RecordType::ANY {
                                if let Ok(r) = crate::server::self_lookup(req, target, qtype).await {
                                    for a in r.answers() {
                                        m.add_answer(a.clone());
                                    }
                                }
                            }
                            &mut m
                        }
                        _ => &mut m,
                    };
                }
            }
            RecordType::CNAME => {
                for s in services.iter().filter(|s| s.ip().is_none() && !s.host.is_empty()) {
                    m.add_answer(Record::from_rdata(name.clone(), s.ttl(), RData::CNAME(CNAME(Name::from_ascii(dnsutil::fqdn(&s.host))?))));
                }
            }
            RecordType::SRV => {
                let n = services.len().max(1) as u16;
                for s in &services {
                    let (target, extra) = match s.ip() {
                        Some(ip) => {
                            let t = s.target_name(&name);
                            let rr = match ip {
                                IpAddr::V4(v) => Record::from_rdata(t.clone(), s.ttl(), RData::A(A(v))),
                                IpAddr::V6(v) => Record::from_rdata(t.clone(), s.ttl(), RData::AAAA(AAAA(v))),
                            };
                            (t, Some(rr))
                        }
                        None => {
                            let mut t = Name::from_ascii(dnsutil::fqdn(&s.host))?;
                            if s.targetstrip > 0 {
                                t = t.trim_to(t.num_labels().saturating_sub(s.targetstrip as u8) as usize);
                            }
                            (t, None)
                        }
                    };
                    let weight = if s.weight == 0 { 100 / n } else { s.weight };
                    m.add_answer(Record::from_rdata(name.clone(), s.ttl(), RData::SRV(SRV::new(s.priority, weight, s.port, target))));
                    if let Some(e) = extra {
                        m.add_additional(e);
                    }
                }
            }
            RecordType::MX => {
                for s in services.iter().filter(|s| s.mail) {
                    let target = match s.ip() {
                        Some(ip) => {
                            let t = s.target_name(&name);
                            m.add_additional(match ip {
                                IpAddr::V4(v) => Record::from_rdata(t.clone(), s.ttl(), RData::A(A(v))),
                                IpAddr::V6(v) => Record::from_rdata(t.clone(), s.ttl(), RData::AAAA(AAAA(v))),
                            });
                            t
                        }
                        None => Name::from_ascii(dnsutil::fqdn(&s.host))?,
                    };
                    m.add_answer(Record::from_rdata(name.clone(), s.ttl(), RData::MX(MX::new(s.priority, target))));
                }
            }
            RecordType::TXT => {
                for s in services.iter().filter(|s| !s.text.is_empty()) {
                    m.add_answer(Record::from_rdata(name.clone(), s.ttl(), RData::TXT(TXT::new(vec![s.text.clone()]))));
                }
            }
            RecordType::PTR => {
                for s in services.iter().filter(|s| !s.host.is_empty()) {
                    m.add_answer(Record::from_rdata(name.clone(), s.ttl(), RData::PTR(PTR(Name::from_ascii(dnsutil::fqdn(&s.host))?))));
                }
            }
            _ => {}
        }
        if m.answers().is_empty() {
            m.add_name_server(self.soa(zone));
        }
        Ok(Some(m))
    }
}

#[async_trait]
impl Handler for Etcd {
    fn name(&self) -> &'static str {
        "etcd"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let qname = req.name();
        let Some(zone) = crate::plugin::zones_match(&self.zones, &qname).map(|z| z.to_string()) else {
            return next.serve(req).await;
        };
        match self.serve(req, &zone).await {
            Ok(Some(m)) => Ok(Reply::Msg(m)),
            Ok(None) => {
                if let Some(ft) = &self.fallthrough {
                    if crate::plugin::zones_match(ft, &qname).is_some() {
                        return next.serve(req).await;
                    }
                }
                let mut m = req.new_reply();
                m.set_authoritative(true);
                m.set_response_code(ResponseCode::NXDomain);
                m.add_name_server(self.soa(&zone));
                Ok(Reply::Msg(m))
            }
            Err(e) => Err(error("etcd", e)),
        }
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/etcd: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args_until_brace();
        let zones = c.origins_from_args_or_server_block(&args)?;
        let mut path = "/skydns".to_string();
        let mut endpoints = vec!["http://localhost:2379".to_string()];
        let mut options = ConnectOptions::new();
        let mut fallthrough = None;
        let root = c.config.root.clone();
        while c.next_block() {
            match c.val() {
                "path" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    path = a[0].clone();
                }
                "endpoint" => {
                    let a = c.remaining_args();
                    if a.is_empty() {
                        return Err(c.arg_err());
                    }
                    endpoints = a;
                }
                "credentials" => {
                    let a = c.remaining_args();
                    if a.len() != 2 {
                        return Err(c.errf("credentials requires 2 arguments"));
                    }
                    options = options.with_user(a[0].clone(), a[1].clone());
                }
                "tls" => {
                    let a = c.remaining_args();
                    let resolve = |p: &str| if std::path::Path::new(p).is_absolute() { std::path::PathBuf::from(p) } else { root.join(p) };
                    let mut tls = etcd_client::TlsOptions::new();
                    match a.len() {
                        0 => {}
                        1 => tls = tls.ca_certificate(etcd_client::Certificate::from_pem(std::fs::read(resolve(&a[0])).map_err(|e| c.errf(e))?)),
                        2 | 3 => {
                            let cert = std::fs::read(resolve(&a[0])).map_err(|e| c.errf(e))?;
                            let key = std::fs::read(resolve(&a[1])).map_err(|e| c.errf(e))?;
                            tls = tls.identity(etcd_client::Identity::from_pem(cert, key));
                            if let Some(ca) = a.get(2) {
                                tls = tls.ca_certificate(etcd_client::Certificate::from_pem(std::fs::read(resolve(ca)).map_err(|e| c.errf(e))?));
                            }
                        }
                        _ => return Err(c.arg_err()),
                    }
                    options = options.with_tls(tls);
                }
                "fallthrough" => {
                    let a = c.remaining_args();
                    fallthrough = Some(if a.is_empty() { vec![".".into()] } else { crate::plugin::normalize_zones(&a)? });
                }
                "upstream" | "stubzones" => {
                    let _ = c.remaining_args();
                }
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        c.add_plugin(Arc::new(Etcd { zones, path, endpoints, options: Some(options), client: Mutex::new(None), fallthrough }));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        assert_eq!(key_for("/skydns", "x.skydns.local."), "/skydns/local/skydns/x");
        assert_eq!(key_for("/skydns", "*.skydns.local."), "/skydns/local/skydns/*");
    }
}
