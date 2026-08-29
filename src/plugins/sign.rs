//! `sign` — offline zone signing: adds DNSKEY/CDS/CDNSKEY, an NSEC chain
//! and RRSIGs to a zone file and writes `db.<origin>.signed` for the
//! `file` plugin to serve; re-signs before signatures expire.
//!
//! ```text
//! sign DBFILE [ZONES...] {
//!     key file|directory KEY...|DIR
//!     directory DIR
//! }
//! ```
//! Every key is used as a CSK (signs everything). Signatures are valid
//! for 32 days; the zone is re-signed every 6 days (±jitter) and whenever
//! the source file changes.

use crate::plugin::{Controller, DnsResult, Handler, Next, Request};
use crate::plugins::dnssec::keys::{load_key, DnsKey};
use crate::plugins::dnssec::rrsets;
use crate::plugins::file::zone::Zone;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use hickory_proto::rr::dnssec::rdata::{DNSSECRData, CDNSKEY, CDS, DNSKEY, NSEC};
use hickory_proto::rr::dnssec::DigestType;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub struct Signer {
    pub origin: String,
    pub dbfile: PathBuf,
    pub directory: PathBuf,
    pub keys: Vec<Arc<DnsKey>>,
}

impl Signer {
    pub fn signed_path(&self) -> PathBuf {
        self.directory.join(format!("db.{}signed", self.origin.trim_end_matches('.').to_string() + "."))
    }

    /// Sign the zone and write the signed file. Returns the serial used.
    pub fn sign_once(&self) -> Result<u32> {
        let text = std::fs::read_to_string(&self.dbfile).with_context(|| format!("reading {}", self.dbfile.display()))?;
        let zone = Zone::parse(&text, &self.origin, Some(self.dbfile.clone()))?;
        let apex = zone.origin_name.clone();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let inception = (now - 3 * 3600) as u32;
        let expiration = (now + 32 * 86400) as u32;
        let serial = zone.serial.max(now as u32);

        // collect unsigned records (drop old DNSSEC material), bump serial
        let mut records: Vec<Record> = Vec::new();
        for r in zone.all_records() {
            match r.record_type() {
                RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3 | RecordType::NSEC3PARAM | RecordType::DNSKEY | RecordType::CDS | RecordType::CDNSKEY => continue,
                RecordType::SOA => {
                    if let Some(RData::SOA(s)) = r.data() {
                        let soa = hickory_proto::rr::rdata::SOA::new(s.mname().clone(), s.rname().clone(), serial, s.refresh(), s.retry(), s.expire(), s.minimum());
                        records.push(Record::from_rdata(r.name().clone(), r.ttl(), RData::SOA(soa)));
                    }
                }
                _ => records.push(r),
            }
        }
        let dnskey_ttl = 3600;
        for k in &self.keys {
            records.push(k.dnskey_record(&apex, dnskey_ttl));
            let dk: &DNSKEY = &k.dnskey;
            records.push(Record::from_rdata(apex.clone(), dnskey_ttl, RData::DNSSEC(DNSSECRData::CDNSKEY(CDNSKEY::new(dk.zone_key(), dk.secure_entry_point(), dk.revoke(), dk.algorithm(), dk.public_key().to_vec())))));
            if let Ok(ds) = dk.to_ds(&apex, DigestType::SHA256) {
                records.push(Record::from_rdata(apex.clone(), dnskey_ttl, RData::DNSSEC(DNSSECRData::CDS(CDS::new(ds.key_tag(), ds.algorithm(), ds.digest_type(), ds.digest().to_vec())))));
            }
        }

        // NSEC chain over all owner names in canonical order
        let mut by_name: BTreeMap<Name, HashSet<RecordType>> = BTreeMap::new();
        for r in &records {
            by_name.entry(r.name().clone()).or_default().insert(r.record_type());
        }
        // delegation points only own NS (and DS) from the parent's view
        let names: Vec<Name> = by_name.keys().cloned().collect();
        let soa_min = records.iter().find_map(|r| match r.data() {
            Some(RData::SOA(s)) => Some(s.minimum()),
            _ => None,
        }).unwrap_or(3600);
        let mut nsecs = Vec::new();
        for (i, n) in names.iter().enumerate() {
            let next = names.get(i + 1).cloned().unwrap_or_else(|| apex.clone());
            let mut types: Vec<RecordType> = by_name[n].iter().cloned().collect();
            types.push(RecordType::NSEC);
            types.push(RecordType::RRSIG);
            types.sort_by_key(|t| u16::from(*t));
            types.dedup();
            nsecs.push(Record::from_rdata(n.clone(), soa_min, RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(next, types)))));
        }
        records.extend(nsecs);

        // sign every RRset (skip glue below delegations)
        let delegations: Vec<Name> = by_name.iter().filter(|(n, t)| **n != apex && t.contains(&RecordType::NS)).map(|(n, _)| n.clone()).collect();
        let mut sigs = Vec::new();
        for set in rrsets(&records) {
            let owner = &set[0].name();
            let t = set[0].record_type();
            let below_cut = delegations.iter().any(|d| d.zone_of(owner) && (*owner != *d || !matches!(t, RecordType::DS | RecordType::NSEC)));
            if below_cut && !(owner == &apex) {
                // records at/below a delegation are not signed by the parent (except DS/NSEC at the cut)
                if !(delegations.contains(owner) && matches!(t, RecordType::DS | RecordType::NSEC)) {
                    continue;
                }
            }
            for k in &self.keys {
                sigs.push(k.sign_rrset(&set, &apex, inception, expiration)?);
            }
        }
        records.extend(sigs);

        // write
        std::fs::create_dir_all(&self.directory).with_context(|| format!("creating {}", self.directory.display()))?;
        let mut out = String::new();
        out.push_str(&format!("; File written on {} by stormcoredns sign\n$ORIGIN {}\n$TTL {}\n", chrono::Utc::now().to_rfc3339(), self.origin, soa_min));
        // SOA first, then the rest in name order
        records.sort_by(|a, b| a.name().cmp(b.name()).then(u16::from(a.record_type()).cmp(&u16::from(b.record_type()))));
        if let Some(pos) = records.iter().position(|r| r.record_type() == RecordType::SOA) {
            let soa = records.remove(pos);
            records.insert(0, soa);
        }
        for r in &records {
            out.push_str(&format!("{}\n", r));
        }
        let path = self.signed_path();
        let tmp = path.with_extension("signed.tmp");
        std::fs::write(&tmp, out).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &path).with_context(|| format!("renaming to {}", path.display()))?;
        tracing::info!("plugin/sign: signed {} with {} keys, serial {}, written to {}", self.origin, self.keys.len(), serial, path.display());
        Ok(serial)
    }
}

/// The plugin has no request-time behaviour; it only signs.
pub struct SignHandler;

#[async_trait]
impl Handler for SignHandler {
    fn name(&self) -> &'static str {
        "sign"
    }
    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        next.serve(req).await
    }
}

fn keys_in_dir(dir: &PathBuf) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?.flatten() {
        let p = e.path();
        if p.extension().map(|x| x == "key").unwrap_or(false) && p.file_name().map(|f| f.to_string_lossy().starts_with('K')).unwrap_or(false) {
            out.push(p);
        }
    }
    out.sort();
    Ok(out)
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut signers: Vec<Arc<Signer>> = Vec::new();
    while c.next() {
        let mut args = c.remaining_args_until_brace();
        if args.is_empty() {
            return Err(c.arg_err());
        }
        let db = args.remove(0);
        let dbfile = if std::path::Path::new(&db).is_absolute() { PathBuf::from(&db) } else { c.config.root.join(&db) };
        let origins = c.origins_from_args_or_server_block(&args)?;
        let root = c.config.root.clone();
        let resolve = |p: &str| if std::path::Path::new(p).is_absolute() { PathBuf::from(p) } else { root.join(p) };
        let mut keys: Vec<Arc<DnsKey>> = Vec::new();
        let mut directory = PathBuf::from("/var/lib/coredns");
        while c.next_block() {
            match c.val() {
                "key" => {
                    let a = c.remaining_args();
                    if a.len() < 2 {
                        return Err(c.errf("key file|directory KEY..."));
                    }
                    match a[0].as_str() {
                        "file" => {
                            for k in &a[1..] {
                                keys.push(Arc::new(load_key(&resolve(k)).map_err(|e| c.errf(e))?));
                            }
                        }
                        "directory" => {
                            for d in &a[1..] {
                                for k in keys_in_dir(&resolve(d)).map_err(|e| c.errf(e))? {
                                    keys.push(Arc::new(load_key(&k).map_err(|e| c.errf(e))?));
                                }
                            }
                        }
                        o => return Err(c.errf(format!("key: expected file or directory, got {}", o))),
                    }
                }
                "directory" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    directory = resolve(&a[0]);
                }
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        if keys.is_empty() {
            return Err(c.errf("no keys specified"));
        }
        for o in origins {
            signers.push(Arc::new(Signer { origin: o, dbfile: dbfile.clone(), directory: directory.clone(), keys: keys.clone() }));
        }
    }
    c.add_plugin(Arc::new(SignHandler));
    // sign now so the file plugin can load the output at startup
    for s in &signers {
        s.sign_once().map_err(|e| c.errf(format!("signing {}: {}", s.origin, e)))?;
    }
    let cancel = tokio_util::sync::CancellationToken::new();
    let stop = cancel.clone();
    c.on_startup(Box::new(move || {
        Box::pin(async move {
            for s in signers {
                let cancel = cancel.clone();
                tokio::spawn(async move {
                    let mut last_mtime = std::fs::metadata(&s.dbfile).and_then(|m| m.modified()).ok();
                    let mut last_sign = tokio::time::Instant::now();
                    let resign = Duration::from_secs(6 * 86400);
                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => return,
                            _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                        }
                        let mtime = std::fs::metadata(&s.dbfile).and_then(|m| m.modified()).ok();
                        let jitter = Duration::from_secs(rand::random::<u64>() % 3600);
                        if mtime != last_mtime || last_sign.elapsed() + jitter > resign {
                            last_mtime = mtime;
                            last_sign = tokio::time::Instant::now();
                            if let Err(e) = s.sign_once() {
                                tracing::error!("plugin/sign: re-signing {}: {}", s.origin, e);
                            }
                        }
                    }
                });
            }
            Ok(())
        })
    }));
    c.on_shutdown(Box::new(move || {
        Box::pin(async move {
            stop.cancel();
            Ok(())
        })
    }));
    let _ = anyhow!("");
    Ok(())
}
