//! `tsig` — verifies TSIG-signed requests and signs responses (RFC 8945).
//!
//! ```text
//! tsig [ZONES...] {
//!     secret NAME KEY
//!     secrets FILE
//!     require all|none|[QTYPE...]
//! }
//! ```
//! KEY is base64 (HMAC-SHA256 is assumed for `secret`; `secrets` files
//! are BIND `key` statements with an `algorithm`).

use crate::plugin::{Controller, DnsResult, Handler, Next, Reply, Request};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::Engine;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::dnssec::rdata::tsig::{TsigAlgorithm, TSIG};
use hickory_proto::rr::dnssec::rdata::DNSSECRData;
use hickory_proto::rr::dnssec::tsig::TSigner;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct Secret {
    pub name: Name,
    pub algorithm: TsigAlgorithm,
    pub key: Vec<u8>,
}

pub struct Tsig {
    zones: Vec<String>,
    secrets: HashMap<String, Secret>,
    /// `None` = none required; `Some(empty)` = all; else these types.
    require: Option<Vec<RecordType>>,
}

const FUDGE: u16 = 300;
const BADSIG: u16 = 16;
const BADKEY: u16 = 17;
const BADTIME: u16 = 18;

fn parse_algorithm(s: &str) -> Result<TsigAlgorithm> {
    Ok(match s.trim_end_matches('.').to_ascii_lowercase().as_str() {
        "hmac-md5" | "hmac-md5.sig-alg.reg.int" => TsigAlgorithm::HmacMd5,
        "hmac-sha1" => TsigAlgorithm::HmacSha1,
        "hmac-sha224" => TsigAlgorithm::HmacSha224,
        "hmac-sha256" => TsigAlgorithm::HmacSha256,
        "hmac-sha384" => TsigAlgorithm::HmacSha384,
        "hmac-sha512" => TsigAlgorithm::HmacSha512,
        o => return Err(anyhow!("unsupported TSIG algorithm {}", o)),
    })
}

/// Parse BIND-style `key "name" { algorithm X; secret "Y"; };` statements.
pub fn parse_secrets_file(text: &str) -> Result<Vec<Secret>> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("key") {
        let after = &rest[i + 3..];
        let Some(open) = after.find('{') else { break };
        let name = after[..open].trim().trim_matches('"').trim().to_string();
        let Some(close) = after.find('}') else { break };
        let body = &after[open + 1..close];
        let mut alg = TsigAlgorithm::HmacSha256;
        let mut secret = None;
        for stmt in body.split(';') {
            let stmt = stmt.trim();
            if let Some(v) = stmt.strip_prefix("algorithm") {
                alg = parse_algorithm(v.trim().trim_matches('"'))?;
            } else if let Some(v) = stmt.strip_prefix("secret") {
                secret = Some(base64::engine::general_purpose::STANDARD.decode(v.trim().trim_matches('"').as_bytes()).map_err(|e| anyhow!("bad secret for {}: {}", name, e))?);
            }
        }
        if let Some(key) = secret {
            out.push(Secret { name: Name::from_ascii(crate::dnsutil::fqdn(&name))?, algorithm: alg, key });
        }
        rest = &after[close + 1..];
    }
    Ok(out)
}

fn tsig_of(m: &Message) -> Option<(&Record, &TSIG)> {
    m.signature().iter().chain(m.additionals().iter()).find_map(|r| match r.data() {
        Some(RData::DNSSEC(DNSSECRData::TSIG(t))) => Some((r, t)),
        _ => None,
    })
}

impl Tsig {
    fn required(&self, qtype: RecordType) -> bool {
        match &self.require {
            None => false,
            Some(v) if v.is_empty() => true,
            Some(v) => v.contains(&qtype),
        }
    }

    /// Build an unsigned-error response carrying a TSIG with `error`.
    fn tsig_error(&self, req: &Request, keyname: &Name, alg: TsigAlgorithm, error: u16) -> Message {
        let mut m = req.new_reply();
        m.set_response_code(ResponseCode::NotAuth);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let t = TSIG::new(alg, now, FUDGE, Vec::new(), req.msg.id(), error, Vec::new());
        let mut r = Record::from_rdata(keyname.clone(), 0, RData::DNSSEC(DNSSECRData::TSIG(t)));
        r.set_dns_class(DNSClass::ANY);
        m.add_tsig(r);
        m
    }

    /// Sign `m` as the response to a request whose MAC was `req_mac`.
    fn sign_response(&self, req: &Request, secret: &Secret, req_mac: &[u8], m: &mut Message) -> Result<()> {
        let signer = TSigner::new(secret.key.clone(), secret.algorithm, secret.name.clone(), FUDGE).map_err(|e| anyhow!("{}", e))?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let pre = TSIG::new(secret.algorithm, now, FUDGE, Vec::new(), req.msg.id(), 0, Vec::new());
        let tbs = hickory_proto::rr::dnssec::tsig::message_tbs(Some(req_mac), m, &pre, &secret.name).map_err(|e| anyhow!("{}", e))?;
        let mac = signer.sign(&tbs).map_err(|e| anyhow!("{}", e))?;
        let t = pre.set_mac(mac);
        let mut r = Record::from_rdata(secret.name.clone(), 0, RData::DNSSEC(DNSSECRData::TSIG(t)));
        r.set_dns_class(DNSClass::ANY);
        m.add_tsig(r);
        Ok(())
    }
}

#[async_trait]
impl Handler for Tsig {
    fn name(&self) -> &'static str {
        "tsig"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let qname = req.name();
        if crate::plugin::zones_match(&self.zones, &qname).is_none() {
            return next.serve(req).await;
        }
        let tsig = tsig_of(&req.msg).map(|(r, t)| (crate::dnsutil::name_str(r.name()), t.algorithm().clone(), r.name().clone()));
        let Some((keyname, alg, keyname_n)) = tsig else {
            if self.required(req.qtype()) {
                let mut m = req.new_reply();
                m.set_response_code(ResponseCode::Refused);
                return Ok(Reply::Msg(m));
            }
            return next.serve(req).await;
        };
        let Some(secret) = self.secrets.get(&keyname).cloned() else {
            return Ok(Reply::Msg(self.tsig_error(req, &keyname_n, alg, BADKEY)));
        };
        let Some(raw) = req.raw.clone() else {
            return Ok(Reply::Msg(self.tsig_error(req, &keyname_n, alg, BADSIG)));
        };
        let signer = match TSigner::new(secret.key.clone(), secret.algorithm, secret.name.clone(), FUDGE) {
            Ok(s) => s,
            Err(_) => return Ok(Reply::Msg(self.tsig_error(req, &keyname_n, alg, BADKEY))),
        };
        let (req_mac, _range, _time) = match signer.verify_message_byte(None, &raw, true) {
            Ok(v) => v,
            Err(e) => {
                let msg = e.to_string();
                let code = if msg.contains("time") { BADTIME } else { BADSIG };
                tracing::debug!("plugin/tsig: verification failed for {}: {}", keyname, e);
                return Ok(Reply::Msg(self.tsig_error(req, &keyname_n, alg, code)));
            }
        };
        req.tsig_verified = Some(secret.name.clone());
        // strip the TSIG before handing the query on
        let _ = req.msg.take_signature();
        let mut r = next.serve(req).await?;
        if let Some(m) = r.msg_mut() {
            if let Err(e) = self.sign_response(req, &secret, &req_mac, m) {
                tracing::warn!("plugin/tsig: signing response: {}", e);
            }
        }
        Ok(r)
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/tsig: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args_until_brace();
        let zones = c.origins_from_args_or_server_block(&args)?;
        let mut secrets: HashMap<String, Secret> = HashMap::new();
        let mut require = None;
        let root = c.config.root.clone();
        while c.next_block() {
            match c.val() {
                "secret" => {
                    let a = c.remaining_args();
                    if a.len() != 2 {
                        return Err(c.arg_err());
                    }
                    let name = crate::dnsutil::fqdn(&a[0]);
                    let key = base64::engine::general_purpose::STANDARD.decode(a[1].as_bytes()).map_err(|e| c.errf(format!("bad secret for {}: {}", a[0], e)))?;
                    secrets.insert(name.clone(), Secret { name: Name::from_ascii(&name).map_err(|e| c.errf(e))?, algorithm: TsigAlgorithm::HmacSha256, key });
                }
                "secrets" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    let p = if std::path::Path::new(&a[0]).is_absolute() { std::path::PathBuf::from(&a[0]) } else { root.join(&a[0]) };
                    let text = std::fs::read_to_string(&p).map_err(|e| c.errf(format!("reading {}: {}", p.display(), e)))?;
                    for s in parse_secrets_file(&text).map_err(|e| c.errf(e))? {
                        secrets.insert(crate::dnsutil::name_str(&s.name), s);
                    }
                }
                "require" => {
                    let a = c.remaining_args();
                    if a.is_empty() {
                        return Err(c.arg_err());
                    }
                    require = match a[0].as_str() {
                        "all" => Some(Vec::new()),
                        "none" => None,
                        _ => {
                            let mut v = Vec::new();
                            for t in &a {
                                v.push(crate::dnsutil::record_type_from_str(t).map_err(|e| c.errf(e))?);
                            }
                            Some(v)
                        }
                    };
                }
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        if secrets.is_empty() {
            return Err(c.errf("no secrets defined"));
        }
        c.config.tsig_secrets = secrets.iter().map(|(k, s)| (k.clone(), base64::engine::general_purpose::STANDARD.encode(&s.key))).collect();
        c.add_plugin(Arc::new(Tsig { zones, secrets, require }));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bind_key_file() {
        let s = parse_secrets_file("key \"xfer.\" {\n algorithm hmac-sha256;\n secret \"c2VjcmV0\";\n};\n").unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].name.to_ascii(), "xfer.");
        assert_eq!(s[0].key, b"secret");
    }
}
