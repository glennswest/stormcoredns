//! `tsig` — verifies TSIG-signed requests and signs responses (RFC 8945).
//!
//! ```text
//! tsig [ZONES...] {
//!     secret NAME KEY
//!     secrets FILE
//!     require all|none|[QTYPE...]
//! }
//! ```
//! KEY is base64. A `secret` key works with whatever algorithm the client
//! signs with, as in CoreDNS; `secrets` files are BIND `key` statements
//! with an `algorithm`. hickory computes HMAC-SHA256/384/512 only, so
//! MD5, SHA1 and SHA224 get BADKEY; AXFR replies are not signed.

use crate::plugin::{Controller, DnsResult, Handler, Next, Reply, Request};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::Engine;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::tsig::{make_tsig_record, TsigAlgorithm, TsigError, TSIG};
use hickory_proto::rr::tsig::TSigner;
use hickory_proto::rr::{Name, RecordType};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct Secret {
    pub name: Name,
    /// `None` for `secret NAME KEY`: the request's algorithm is used, as in CoreDNS
    pub algorithm: Option<TsigAlgorithm>,
    pub key: Vec<u8>,
}

pub struct Tsig {
    zones: Vec<String>,
    secrets: HashMap<String, Secret>,
    /// `None` = none required; `Some(empty)` = all; else these types.
    require: Option<Vec<RecordType>>,
}

const FUDGE: u16 = 300;

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
            out.push(Secret { name: Name::from_ascii(crate::dnsutil::fqdn(&name))?, algorithm: Some(alg), key });
        }
        rest = &after[close + 1..];
    }
    Ok(out)
}

/// The request's TSIG: its key name and RDATA (hickory keeps it out of the
/// additional section).
fn tsig_of(m: &Message) -> Option<(&Name, &TSIG)> {
    m.signature().map(|r| (&r.name, &r.data))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
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
    fn tsig_error(&self, req: &Request, keyname: &Name, alg: TsigAlgorithm, error: TsigError) -> Message {
        let mut m = req.new_reply();
        m.metadata.response_code = ResponseCode::NotAuth;
        let t = TSIG::new(alg, now_secs(), FUDGE, Vec::new(), req.msg.metadata.id, Some(error), Vec::new());
        m.set_signature(Box::new(make_tsig_record(keyname.clone(), t)));
        m
    }

    /// Sign `m` as the response to a request whose MAC was `req_mac`.
    fn sign_response(&self, req: &Request, secret: &Secret, req_mac: &[u8], m: &mut Message) -> Result<()> {
        let alg = secret.algorithm.clone().unwrap_or(TsigAlgorithm::HmacSha256);
        let signer = TSigner::new(secret.key.clone(), alg.clone(), secret.name.clone(), FUDGE).map_err(|e| anyhow!("{}", e))?;
        // RFC 8945 4.3.1: request MAC, the response without its TSIG, then the TSIG variables
        let pre = TSIG::new(alg, now_secs(), FUDGE, Vec::new(), req.msg.metadata.id, None, Vec::new());
        let unsigned = m.to_vec().map_err(|e| anyhow!("{}", e))?;
        let tbs = signer.encode_response_tbs(req_mac, &unsigned, &pre).map_err(|e| anyhow!("{}", e))?;
        let mac = signer.sign(&tbs).map_err(|e| anyhow!("{}", e))?;
        m.set_signature(Box::new(make_tsig_record(secret.name.clone(), pre.set_mac(mac))));
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
        let tsig = tsig_of(&req.msg).map(|(n, t)| (crate::dnsutil::name_str(n), t.algorithm.clone(), n.clone()));
        let Some((keyname, alg, keyname_n)) = tsig else {
            if self.required(req.qtype()) {
                let mut m = req.new_reply();
                m.metadata.response_code = ResponseCode::Refused;
                return Ok(Reply::Msg(m));
            }
            return next.serve(req).await;
        };
        let Some(mut secret) = self.secrets.get(&keyname).cloned() else {
            return Ok(Reply::Msg(self.tsig_error(req, &keyname_n, alg, TsigError::BadKey)));
        };
        match &secret.algorithm {
            None => secret.algorithm = Some(alg.clone()),
            Some(a) if *a != alg => return Ok(Reply::Msg(self.tsig_error(req, &keyname_n, alg, TsigError::BadKey))),
            Some(_) => {}
        }
        let Some(raw) = req.raw.clone() else {
            return Ok(Reply::Msg(self.tsig_error(req, &keyname_n, alg, TsigError::BadSig)));
        };
        let signer = match TSigner::new(secret.key.clone(), alg.clone(), secret.name.clone(), FUDGE) {
            Ok(s) => s,
            Err(_) => return Ok(Reply::Msg(self.tsig_error(req, &keyname_n, alg, TsigError::BadKey))),
        };
        let (req_mac, _time, window) = match signer.verify_message_byte(&raw, None, true) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("plugin/tsig: verification failed for {}: {}", keyname, e);
                return Ok(Reply::Msg(self.tsig_error(req, &keyname_n, alg, TsigError::BadSig)));
            }
        };
        // RFC 8945 5.2.3: the MAC is good; the time must be within the fudge
        if !(window.start..=window.end).contains(&now_secs()) {
            tracing::debug!("plugin/tsig: {} signed outside the time window {:?}", keyname, window);
            return Ok(Reply::Msg(self.tsig_error(req, &keyname_n, alg, TsigError::BadTime)));
        }
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
                    secrets.insert(name.clone(), Secret { name: Name::from_ascii(&name).map_err(|e| c.errf(e))?, algorithm: None, key });
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
