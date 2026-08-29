//! `dnssec` — on-the-fly DNSSEC signing of responses from later plugins
//! (RRSIG for every RRset, DNSKEY at the apex, "black lies" NSEC for
//! negative answers), with a signature cache.
//!
//! ```text
//! dnssec [ZONES...] {
//!     key file KEY...
//!     cache_capacity CAPACITY
//! }
//! ```
//! KEY is a BIND-style key pair base name (`Kexample.org.+013+12345`,
//! with `.key` and `.private`) or a PEM/PKCS#8 private key. Algorithms
//! ECDSAP256SHA256, ECDSAP384SHA384 and ED25519 are supported.

pub mod keys;

use crate::plugin::{Controller, DnsResult, Handler, Next, Reply, Request};
use async_trait::async_trait;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::dnssec::rdata::{DNSSECRData, NSEC};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use keys::DnsKey;
use lru::LruCache;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use prometheus::{IntCounterVec, IntGaugeVec};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::Arc;

static CACHE_SIZE: Lazy<IntGaugeVec> = Lazy::new(|| {
    let g = IntGaugeVec::new(prometheus::Opts::new("coredns_dnssec_cache_entries", "The number of elements in the dnssec cache."), &["server", "type"]).unwrap();
    crate::metrics::register(Box::new(g.clone()));
    g
});
static CACHE_HITS: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(prometheus::Opts::new("coredns_dnssec_cache_hits_total", "The count of cache hits."), &["server"]).unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});
static CACHE_MISSES: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(prometheus::Opts::new("coredns_dnssec_cache_misses_total", "The count of cache misses."), &["server"]).unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});

/// Signature inception is backdated 3h, expiration is 8 days out.
pub fn incep_expir(now: u64) -> (u32, u32) {
    ((now - 3 * 3600) as u32, (now + 8 * 86400) as u32)
}

/// Types the black-lies NSEC claims exist at a non-apex name.
const BITMAP: &[RecordType] = &[
    RecordType::A,
    RecordType::HINFO,
    RecordType::TXT,
    RecordType::AAAA,
    RecordType::SRV,
    RecordType::SSHFP,
    RecordType::RRSIG,
    RecordType::NSEC,
    RecordType::TLSA,
    RecordType::OPENPGPKEY,
];
const APEX_BITMAP: &[RecordType] = &[
    RecordType::A,
    RecordType::NS,
    RecordType::SOA,
    RecordType::HINFO,
    RecordType::MX,
    RecordType::TXT,
    RecordType::AAAA,
    RecordType::SRV,
    RecordType::SSHFP,
    RecordType::RRSIG,
    RecordType::NSEC,
    RecordType::DNSKEY,
    RecordType::TLSA,
    RecordType::OPENPGPKEY,
];

pub struct Dnssec {
    zones: Vec<String>,
    keys: Vec<Arc<DnsKey>>,
    cache: Mutex<LruCache<u64, Vec<Record>>>,
}

/// Group records into RRsets by (owner, type), preserving first-seen order.
pub fn rrsets(records: &[Record]) -> Vec<Vec<Record>> {
    let mut order: Vec<(String, RecordType)> = Vec::new();
    let mut map: HashMap<(String, RecordType), Vec<Record>> = HashMap::new();
    for r in records {
        if r.record_type() == RecordType::OPT || r.record_type() == RecordType::RRSIG {
            continue;
        }
        let k = (crate::dnsutil::name_str(r.name()), r.record_type());
        if !map.contains_key(&k) {
            order.push(k.clone());
        }
        map.entry(k).or_default().push(r.clone());
    }
    order.into_iter().map(|k| map.remove(&k).unwrap()).collect()
}

impl Dnssec {
    fn zone_for(&self, name: &str) -> Option<&str> {
        crate::plugin::zones_match(&self.zones, name)
    }

    fn sign_set(&self, set: &[Record], zone: &str, server: &str) -> Vec<Record> {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        for r in set {
            format!("{}", r).hash(&mut h);
        }
        zone.hash(&mut h);
        let key = h.finish();
        if let Some(sigs) = self.cache.lock().get(&key) {
            CACHE_HITS.with_label_values(&[server]).inc();
            return sigs.clone();
        }
        CACHE_MISSES.with_label_values(&[server]).inc();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let (incep, expir) = incep_expir(now);
        let signer = Name::from_ascii(zone).unwrap_or_else(|_| Name::root());
        let mut sigs = Vec::new();
        for k in &self.keys {
            match k.sign_rrset(set, &signer, incep, expir) {
                Ok(sig) => sigs.push(sig),
                Err(e) => tracing::warn!("plugin/dnssec: signing {} {}: {}", set[0].name(), set[0].record_type(), e),
            }
        }
        let mut c = self.cache.lock();
        c.put(key, sigs.clone());
        CACHE_SIZE.with_label_values(&[server, "signature"]).set(c.len() as i64);
        sigs
    }

    fn nsec(&self, req: &Request, zone: &str, nodata: bool, server: &str) -> Vec<Record> {
        let qname = req.qname();
        let is_apex = req.name_uncached() == zone;
        let mut types: Vec<RecordType> = if is_apex { APEX_BITMAP.to_vec() } else { BITMAP.to_vec() };
        if nodata {
            types.retain(|t| *t != req.qtype());
        }
        let next = Name::from_ascii("\\000").ok().and_then(|n| n.append_domain(&qname).ok()).unwrap_or_else(|| qname.clone());
        let ttl = 3600;
        let nsec = Record::from_rdata(qname, ttl, RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(next, types))));
        let mut out = vec![nsec.clone()];
        out.extend(self.sign_set(&[nsec], zone, server));
        out
    }

    fn sign_response(&self, req: &Request, zone: &str, m: &mut Message) {
        let server = req.server.clone();
        // DNSKEY at the apex is ours
        if req.qtype() == RecordType::DNSKEY && req.name_uncached() == zone {
            let apex = Name::from_ascii(zone).unwrap_or_else(|_| Name::root());
            let mut set: Vec<Record> = self.keys.iter().map(|k| k.dnskey_record(&apex, 3600)).collect();
            let sigs = self.sign_set(&set, zone, &server);
            set.extend(sigs);
            m.set_response_code(ResponseCode::NoError);
            m.take_answers();
            m.take_name_servers();
            m.insert_answers(set);
            m.set_authoritative(true);
            return;
        }
        let rcode = m.response_code();
        let negative = matches!(rcode, ResponseCode::NXDomain) || (rcode == ResponseCode::NoError && m.answers().is_empty());
        for section in 0..2 {
            let recs = if section == 0 { m.take_answers() } else { m.take_name_servers() };
            let mut out = Vec::new();
            for set in rrsets(&recs) {
                out.extend(set.iter().cloned());
                out.extend(self.sign_set(&set, zone, &server));
            }
            // keep any RRSIG/OPT that were already there
            out.extend(recs.into_iter().filter(|r| r.record_type() == RecordType::RRSIG));
            if section == 0 {
                m.insert_answers(out);
            } else {
                m.insert_name_servers(out);
            }
        }
        if negative {
            let nodata = rcode == ResponseCode::NoError;
            for r in self.nsec(req, zone, nodata, &server) {
                m.add_name_server(r);
            }
            // black lies: the name "exists"
            if rcode == ResponseCode::NXDomain {
                m.set_response_code(ResponseCode::NoError);
            }
        }
    }
}

#[async_trait]
impl Handler for Dnssec {
    fn name(&self) -> &'static str {
        "dnssec"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let name = req.name();
        let Some(zone) = self.zone_for(&name).map(|z| z.to_string()) else {
            return next.serve(req).await;
        };
        let do_bit = req.do_bit();
        let want_dnskey = req.qtype() == RecordType::DNSKEY && name == zone;
        if !do_bit && !want_dnskey {
            return next.serve(req).await;
        }
        if want_dnskey {
            let mut m = req.new_reply();
            self.sign_response(req, &zone, &mut m);
            return Ok(Reply::Msg(m));
        }
        let mut r = next.serve(req).await?;
        if let Some(m) = r.msg_mut() {
            if matches!(m.response_code(), ResponseCode::NoError | ResponseCode::NXDomain) {
                self.sign_response(req, &zone, m);
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
            return Err(c.errf("plugin/dnssec: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args_until_brace();
        let zones = c.origins_from_args_or_server_block(&args)?;
        let mut keys: Vec<Arc<DnsKey>> = Vec::new();
        let mut capacity = 10000usize;
        let root = c.config.root.clone();
        while c.next_block() {
            match c.val() {
                "key" => {
                    let a = c.remaining_args();
                    if a.len() < 2 || a[0] != "file" {
                        return Err(c.errf("key file KEY... expected"));
                    }
                    for k in &a[1..] {
                        let p = if std::path::Path::new(k).is_absolute() { std::path::PathBuf::from(k) } else { root.join(k) };
                        keys.push(Arc::new(keys::load_key(&p).map_err(|e| c.errf(e))?));
                    }
                }
                "cache_capacity" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    capacity = a[0].parse().map_err(|_| c.errf(format!("bad cache_capacity {}", a[0])))?;
                }
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        if keys.is_empty() {
            return Err(c.errf("no keys specified"));
        }
        // every zone needs a key whose name matches it
        for z in &zones {
            if !keys.iter().any(|k| crate::dnsutil::is_subdomain(&k.name, z) || crate::dnsutil::is_subdomain(z, &k.name)) {
                tracing::warn!("plugin/dnssec: no key for zone {}; signing with all keys anyway", z);
            }
        }
        c.add_plugin(Arc::new(Dnssec { zones, keys, cache: Mutex::new(LruCache::new(NonZeroUsize::new(capacity.max(1)).unwrap())) }));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::A;

    struct Static;
    #[async_trait]
    impl Handler for Static {
        fn name(&self) -> &'static str {
            "static"
        }
        async fn serve_dns(&self, req: &mut Request, _next: Next<'_>) -> DnsResult {
            let mut m = req.new_reply();
            if req.name_uncached().starts_with("nx.") {
                m.set_response_code(ResponseCode::NXDomain);
            } else {
                m.add_answer(Record::from_rdata(req.qname(), 30, RData::A(A::new(10, 0, 0, 1))));
            }
            Ok(Reply::Msg(m))
        }
    }

    #[tokio::test]
    async fn signs_and_black_lies() {
        let key = keys::generate(hickory_proto::rr::dnssec::Algorithm::ECDSAP256SHA256, "example.org.").unwrap();
        let d = Arc::new(Dnssec { zones: vec!["example.org.".into()], keys: vec![Arc::new(key)], cache: Mutex::new(LruCache::new(NonZeroUsize::new(10).unwrap())) });
        let chain: Vec<Arc<dyn Handler>> = vec![d.clone(), Arc::new(Static)];
        let mut req = Request::for_test("www.example.org.", RecordType::A);
        req.msg.extensions_mut().get_or_insert_with(hickory_proto::op::Edns::new).set_dnssec_ok(true);
        let m = Next::new(&chain).serve(&mut req).await.unwrap().into_msg().unwrap();
        assert_eq!(m.answers().len(), 2);
        assert_eq!(m.answers()[1].record_type(), RecordType::RRSIG);
        let mut req = Request::for_test("nx.example.org.", RecordType::A);
        req.msg.extensions_mut().get_or_insert_with(hickory_proto::op::Edns::new).set_dnssec_ok(true);
        let m = Next::new(&chain).serve(&mut req).await.unwrap().into_msg().unwrap();
        assert_eq!(m.response_code(), ResponseCode::NoError, "black lie");
        assert!(m.name_servers().iter().any(|r| r.record_type() == RecordType::NSEC));
        let mut req = Request::for_test("example.org.", RecordType::DNSKEY);
        let m = Next::new(&chain).serve(&mut req).await.unwrap().into_msg().unwrap();
        assert_eq!(m.answers()[0].record_type(), RecordType::DNSKEY);
    }
}
