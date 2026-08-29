//! DNSSEC key loading (BIND `K*.key`/`.private` pairs, PEM/PKCS#8) and
//! RRset signing shared by the `dnssec` and `sign` plugins.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use hickory_proto::rr::dnssec::rdata::{DNSSECRData, DNSKEY, RRSIG};
use hickory_proto::rr::dnssec::tbs::rrset_tbs;
use hickory_proto::rr::dnssec::{Algorithm, KeyFormat, KeyPair, Private};
use hickory_proto::rr::{DNSClass, Name, RData, Record};
use std::path::{Path, PathBuf};

pub struct DnsKey {
    /// Owner name of the key (lowercase FQDN), from the `.key` file.
    pub name: String,
    pub algorithm: Algorithm,
    pub pair: KeyPair<Private>,
    pub dnskey: DNSKEY,
    pub key_tag: u16,
    /// Key-signing key (flags 257).
    pub ksk: bool,
}

impl DnsKey {
    pub fn dnskey_record(&self, owner: &Name, ttl: u32) -> Record {
        Record::from_rdata(owner.clone(), ttl, RData::DNSSEC(DNSSECRData::DNSKEY(self.dnskey.clone())))
    }

    /// Sign one RRset (all records share owner, class and type).
    pub fn sign_rrset(&self, set: &[Record], signer_name: &Name, inception: u32, expiration: u32) -> Result<Record> {
        let first = set.first().ok_or_else(|| anyhow!("empty rrset"))?;
        let name = first.name();
        // label count excludes a leading wildcard label
        let mut labels = name.num_labels();
        if name.is_wildcard() {
            labels = labels.saturating_sub(1);
        }
        let ttl = set.iter().map(|r| r.ttl()).min().unwrap_or(first.ttl());
        let tbs = rrset_tbs(name, DNSClass::IN, labels, first.record_type(), self.algorithm, ttl, expiration, inception, self.key_tag, signer_name, set)
            .map_err(|e| anyhow!("tbs: {}", e))?;
        let sig = self.pair.sign(self.algorithm, &tbs).map_err(|e| anyhow!("sign: {}", e))?;
        let rrsig = RRSIG::new(first.record_type(), self.algorithm, labels, ttl, expiration, inception, self.key_tag, signer_name.clone(), sig);
        Ok(Record::from_rdata(name.clone(), ttl, RData::DNSSEC(DNSSECRData::RRSIG(rrsig))))
    }
}

fn build(pair: KeyPair<Private>, algorithm: Algorithm, name: &str, ksk: bool) -> Result<DnsKey> {
    let mut dnskey = pair.to_dnskey(algorithm).map_err(|e| anyhow!("dnskey: {}", e))?;
    if ksk {
        dnskey = DNSKEY::new(true, true, false, algorithm, dnskey.public_key().to_vec());
    }
    let key_tag = dnskey.calculate_key_tag().map_err(|e| anyhow!("key tag: {}", e))?;
    Ok(DnsKey { name: crate::dnsutil::fqdn(name), algorithm, pair, dnskey, key_tag, ksk })
}

/// Generate a fresh key (tests, and `sign` when asked to).
pub fn generate(algorithm: Algorithm, name: &str) -> Result<DnsKey> {
    let pair = KeyPair::generate(algorithm).map_err(|e| anyhow!("generate: {}", e))?;
    build(pair, algorithm, name, true)
}

fn parse_algorithm(n: u8) -> Result<Algorithm> {
    Ok(match n {
        13 => Algorithm::ECDSAP256SHA256,
        14 => Algorithm::ECDSAP384SHA384,
        15 => Algorithm::ED25519,
        8 | 10 => bail!("RSA keys (algorithm {}) are not supported by this build; use ECDSA (13/14) or ED25519 (15)", n),
        o => bail!("unsupported DNSSEC algorithm {}", o),
    })
}

/// Load a key given any of: the base name (`Kexample.org.+013+12345`),
/// the `.key` file, the `.private` file, or a PEM/PKCS#8 private key.
pub fn load_key(path: &Path) -> Result<DnsKey> {
    let s = path.to_string_lossy().to_string();
    let base = if let Some(b) = s.strip_suffix(".key") {
        PathBuf::from(b)
    } else if let Some(b) = s.strip_suffix(".private") {
        PathBuf::from(b)
    } else if s.ends_with(".pem") {
        return load_pem(path);
    } else {
        path.to_path_buf()
    };
    let key_file = PathBuf::from(format!("{}.key", base.display()));
    let private_file = PathBuf::from(format!("{}.private", base.display()));
    if !key_file.exists() && !private_file.exists() {
        // maybe a bare PEM/PKCS#8 file
        if path.exists() {
            return load_pem(path);
        }
        bail!("key files {} / {} not found", key_file.display(), private_file.display());
    }
    let (name, flags, alg_num, public) = parse_key_file(&key_file)?;
    let (alg_num2, private) = parse_private_file(&private_file)?;
    if alg_num != alg_num2 {
        bail!("{}: algorithm mismatch between .key ({}) and .private ({})", base.display(), alg_num, alg_num2);
    }
    let algorithm = parse_algorithm(alg_num)?;
    let pair = match algorithm {
        Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384 => {
            let alg = if algorithm == Algorithm::ECDSAP256SHA256 { &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING } else { &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING };
            let mut uncompressed = vec![0x04];
            uncompressed.extend_from_slice(&public);
            let kp = ring::signature::EcdsaKeyPair::from_private_key_and_public_key(alg, &private, &uncompressed, &ring::rand::SystemRandom::new())
                .map_err(|e| anyhow!("{}: bad ECDSA key: {}", base.display(), e))?;
            KeyPair::from_ecdsa(kp)
        }
        Algorithm::ED25519 => {
            let kp = ring::signature::Ed25519KeyPair::from_seed_and_public_key(&private, &public).map_err(|e| anyhow!("{}: bad ED25519 key: {}", base.display(), e))?;
            KeyPair::from_ed25519(kp)
        }
        _ => unreachable!(),
    };
    let ksk = flags & 1 == 1;
    build(pair, algorithm, &name, ksk)
}

/// `.key`: `example.org. [TTL] IN DNSKEY FLAGS 3 ALG BASE64`.
fn parse_key_file(p: &Path) -> Result<(String, u16, u8, Vec<u8>)> {
    let text = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
    for line in text.lines() {
        let line = line.split(';').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        let Some(i) = toks.iter().position(|t| *t == "DNSKEY") else { continue };
        if toks.len() < i + 4 {
            bail!("{}: malformed DNSKEY line", p.display());
        }
        let name = toks[0].to_string();
        let flags: u16 = toks[i + 1].parse()?;
        let alg: u8 = toks[i + 3].parse()?;
        let b64: String = toks[i + 4..].concat();
        let public = base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()).map_err(|e| anyhow!("{}: bad base64: {}", p.display(), e))?;
        return Ok((name, flags, alg, public));
    }
    bail!("{}: no DNSKEY record found", p.display())
}

/// `.private`: `Private-key-format: v1.3`, `Algorithm: 13 (...)`, `PrivateKey: BASE64`.
fn parse_private_file(p: &Path) -> Result<(u8, Vec<u8>)> {
    let text = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
    let mut alg = None;
    let mut key = None;
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let v = v.trim();
            match k.trim() {
                "Algorithm" => alg = v.split_whitespace().next().and_then(|n| n.parse::<u8>().ok()),
                "PrivateKey" => key = Some(base64::engine::general_purpose::STANDARD.decode(v.as_bytes()).map_err(|e| anyhow!("{}: bad base64: {}", p.display(), e))?),
                _ => {}
            }
        }
    }
    match (alg, key) {
        (Some(a), Some(k)) => Ok((a, k)),
        _ => bail!("{}: missing Algorithm or PrivateKey", p.display()),
    }
}

/// PEM/PKCS#8 private key; the algorithm is inferred by trying each.
fn load_pem(p: &Path) -> Result<DnsKey> {
    let bytes = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
    let fmt = if bytes.starts_with(b"-----") { KeyFormat::Pem } else { KeyFormat::Pkcs8 };
    for alg in [Algorithm::ECDSAP256SHA256, Algorithm::ECDSAP384SHA384, Algorithm::ED25519] {
        if let Ok(pair) = fmt.decode_key(&bytes, None, alg) {
            let name = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| ".".into());
            return build(pair, alg, &name, true);
        }
    }
    bail!("{}: not a supported ECDSA/ED25519 private key", p.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_signs() {
        let k = generate(Algorithm::ECDSAP256SHA256, "example.org.").unwrap();
        assert!(k.ksk);
        let n = Name::from_ascii("www.example.org.").unwrap();
        let set = vec![Record::from_rdata(n, 300, RData::A(hickory_proto::rr::rdata::A::new(1, 2, 3, 4)))];
        let sig = k.sign_rrset(&set, &Name::from_ascii("example.org.").unwrap(), 1, 2).unwrap();
        assert_eq!(sig.record_type(), hickory_proto::rr::RecordType::RRSIG);
    }
}
