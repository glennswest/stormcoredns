//! `dnssec` — on-the-fly DNSSEC signing of responses from later plugins,
//! as CoreDNS's `Sign`: RRSIGs for every RRset of a positive answer
//! (answer, authority, additional), DNSKEY at the apex, "black lies" NSEC
//! for NXDOMAIN/NODATA (the queried type left out of the bitmap, TTL from
//! the SOA, rcode NOERROR), and for referrals the DS set signed or a
//! delegation NSEC (the NS set and glue are not signed). Signatures are
//! cached and re-made once they are within two days of expiring.
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
use crate::plugins::cache::{typify, RespType};
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

const LOC: RecordType = RecordType::Unknown(29);
const CERT: RecordType = RecordType::Unknown(37);
const HIP: RecordType = RecordType::Unknown(55);
const SPF: RecordType = RecordType::Unknown(99);

/// The black-lies NSEC bitmaps, as CoreDNS's `black_lies.go`.
fn zone_bitmap() -> Vec<RecordType> {
    use RecordType::*;
    vec![A, HINFO, TXT, AAAA, LOC, SRV, CERT, SSHFP, RRSIG, NSEC, TLSA, HIP, OPENPGPKEY, SPF]
}
fn apex_bitmap() -> Vec<RecordType> {
    use RecordType::*;
    vec![A, NS, SOA, HINFO, MX, TXT, AAAA, LOC, SRV, CERT, SSHFP, RRSIG, NSEC, DNSKEY, TLSA, HIP, OPENPGPKEY, SPF]
}
fn delegation_bitmap() -> Vec<RecordType> {
    use RecordType::*;
    vec![A, NS, HINFO, TXT, AAAA, LOC, SRV, CERT, SSHFP, RRSIG, NSEC, TLSA, HIP, OPENPGPKEY, SPF]
}

/// A cached signature is used while it is valid for at least two more days
/// (3/4 of the 8-day validity), as in CoreDNS; after that it is re-made.
const CACHE_MARGIN: u64 = 2 * 86400;

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
        if matches!(r.record_type(), RecordType::OPT | RecordType::RRSIG | RecordType::TSIG | RecordType::SIG) {
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

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Is every RRSIG still valid at `t`?
fn valid_at(sigs: &[Record], t: u64) -> bool {
    sigs.iter().all(|r| match r.data() {
        Some(RData::DNSSEC(DNSSECRData::RRSIG(s))) => (s.sig_expiration() as u64) > t,
        _ => true,
    })
}

impl Dnssec {
    fn zone_for(&self, name: &str) -> Option<&str> {
        crate::plugin::zones_match(&self.zones, name)
    }

    fn sign_set(&self, set: &[Record], zone: &str, server: &str, now: u64) -> Vec<Record> {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        for r in set {
            format!("{}", r).hash(&mut h);
        }
        zone.hash(&mut h);
        let key = h.finish();
        if let Some(sigs) = self.cache.lock().get(&key) {
            if valid_at(sigs, now + CACHE_MARGIN) {
                CACHE_HITS.with_label_values(&[server]).inc();
                return sigs.clone();
            }
        }
        CACHE_MISSES.with_label_values(&[server]).inc();
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

    /// The black-lies NSEC for the query name (and its RRSIGs), as CoreDNS
    /// builds it: the queried type is left out of the bitmap for NXDOMAIN
    /// and NODATA (unless the query is for NSEC itself).
    fn nsec(&self, req: &Request, zone: &str, kind: RespType, ttl: u32, server: &str, now: u64) -> Vec<Record> {
        let qname = req.qname();
        let qtype = req.qtype();
        let filter = |mut v: Vec<RecordType>| {
            if matches!(kind, RespType::NoError | RespType::NameError) && qtype != RecordType::NSEC {
                v.retain(|t| *t != qtype);
            }
            v
        };
        // next name: \000.<qname>, or <first label>\000.<rest> for a delegation
        let mut next = Name::from_ascii("\\000").ok().and_then(|n| n.append_domain(&qname).ok()).unwrap_or_else(|| qname.clone());
        let types = if req.name_uncached() == zone {
            filter(apex_bitmap())
        } else if kind == RespType::Delegation || qtype == RecordType::DS {
            if kind == RespType::Delegation && !qname.is_root() {
                let mut labels: Vec<Vec<u8>> = qname.iter().map(|l| l.to_vec()).collect();
                labels[0].push(0);
                if let Ok(mut n) = Name::from_labels(labels) {
                    n.set_fqdn(true);
                    next = n;
                }
            }
            delegation_bitmap()
        } else {
            filter(zone_bitmap())
        };
        let nsec = Record::from_rdata(qname, ttl, RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(next, types))));
        let mut out = vec![nsec.clone()];
        out.extend(self.sign_set(&[nsec], zone, server, now));
        out
    }

    /// Sign `m` as CoreDNS's `Sign` does.
    fn sign_response(&self, req: &Request, zone: &str, m: &mut Message) {
        self.sign_response_at(req, zone, m, now_secs())
    }

    fn sign_response_at(&self, req: &Request, zone: &str, m: &mut Message, now: u64) {
        let server = req.server.clone();
        // DNSKEY at the apex is ours
        if req.qtype() == RecordType::DNSKEY && req.name_uncached() == zone {
            let apex = Name::from_ascii(zone).unwrap_or_else(|_| Name::root());
            let mut set: Vec<Record> = self.keys.iter().map(|k| k.dnskey_record(&apex, 3600)).collect();
            let sigs = self.sign_set(&set, zone, &server, now);
            set.extend(sigs);
            m.set_response_code(ResponseCode::NoError);
            m.take_answers();
            m.take_name_servers();
            m.insert_answers(set);
            m.set_authoritative(true);
            return;
        }
        let kind = typify(m);
        match kind {
            // referral: sign the DS set, or deny it with an NSEC; the NS set
            // and glue are not ours to sign
            RespType::Delegation => {
                let ttl = m.name_servers().first().map(|r| r.ttl()).unwrap_or(3600);
                let ds: Vec<Record> = m.name_servers().iter().filter(|r| r.record_type() == RecordType::DS).cloned().collect();
                let add = if ds.is_empty() { self.nsec(req, zone, kind, ttl, &server, now) } else { self.sign_set(&ds, zone, &server, now) };
                for r in add {
                    m.add_name_server(r);
                }
            }
            // NXDOMAIN/NODATA: only the plain "one SOA in authority" shape is
            // signed; the black lie turns it into NOERROR
            RespType::NameError | RespType::NoError => {
                let ns = m.name_servers();
                if ns.len() != 1 || ns[0].record_type() != RecordType::SOA {
                    return;
                }
                let soa = ns[0].clone();
                let ttl = soa.ttl();
                let mut auth = vec![soa.clone()];
                auth.extend(self.sign_set(&[soa], zone, &server, now));
                let nsec = self.nsec(req, zone, kind, ttl, &server, now);
                m.set_response_code(ResponseCode::NoError);
                m.take_name_servers();
                if req.qtype() == RecordType::NSEC {
                    // the NSEC is the answer; no SOA
                    m.insert_answers(nsec);
                } else {
                    auth.extend(nsec);
                    m.insert_name_servers(auth);
                }
            }
            RespType::Success => {
                let answers = sign_section(self, m.take_answers(), zone, &server, now);
                m.insert_answers(answers);
                let auth = sign_section(self, m.take_name_servers(), zone, &server, now);
                m.insert_name_servers(auth);
                let extra = sign_section(self, m.take_additionals(), zone, &server, now);
                m.insert_additionals(extra);
            }
            _ => {}
        }
    }
}

/// Each RRset of a section followed by its RRSIGs; RRSIG/OPT/TSIG already
/// there are kept.
fn sign_section(d: &Dnssec, recs: Vec<Record>, zone: &str, server: &str, now: u64) -> Vec<Record> {
    let mut out = Vec::new();
    for set in rrsets(&recs) {
        out.extend(set.iter().cloned());
        out.extend(d.sign_set(&set, zone, server, now));
    }
    out.extend(recs.into_iter().filter(|r| matches!(r.record_type(), RecordType::RRSIG | RecordType::OPT | RecordType::TSIG | RecordType::SIG)));
    out
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
    use hickory_proto::rr::dnssec::rdata::DS as DsRdata;
    use hickory_proto::rr::rdata::{A, NS, SOA};

    /// Answers by name prefix: `nx.` NXDOMAIN+SOA, `nodata.` NOERROR+SOA,
    /// `sub.` / `ds.` referrals (with a DS for `ds.`), else an A record.
    struct Static;
    #[async_trait]
    impl Handler for Static {
        fn name(&self) -> &'static str {
            "static"
        }
        async fn serve_dns(&self, req: &mut Request, _next: Next<'_>) -> DnsResult {
            let mut m = req.new_reply();
            let n = req.name_uncached();
            let apex = Name::from_ascii("example.org.").unwrap();
            let soa = Record::from_rdata(apex.clone(), 300, RData::SOA(SOA::new(Name::from_ascii("ns.example.org.").unwrap(), Name::from_ascii("h.example.org.").unwrap(), 1, 2, 3, 4, 300)));
            if n.starts_with("nx.") || n.starts_with("nodata.") {
                if n.starts_with("nx.") {
                    m.set_response_code(ResponseCode::NXDomain);
                }
                m.set_authoritative(true);
                m.add_name_server(soa);
            } else if n.starts_with("sub.") || n.starts_with("ds.") {
                let cut = Name::from_ascii(&n).unwrap();
                m.add_name_server(Record::from_rdata(cut.clone(), 3600, RData::NS(NS(Name::from_ascii("ns.other.net.").unwrap()))));
                if n.starts_with("ds.") {
                    let ds = DsRdata::new(12345, hickory_proto::rr::dnssec::Algorithm::ECDSAP256SHA256, hickory_proto::rr::dnssec::DigestType::SHA256, vec![1; 32]);
                    m.add_name_server(Record::from_rdata(cut, 3600, RData::DNSSEC(DNSSECRData::DS(ds))));
                }
            } else {
                m.set_authoritative(true);
                m.add_answer(Record::from_rdata(req.qname(), 30, RData::A(A::new(10, 0, 0, 1))));
            }
            Ok(Reply::Msg(m))
        }
    }

    fn dnssec() -> Arc<Dnssec> {
        let key = keys::generate(hickory_proto::rr::dnssec::Algorithm::ECDSAP256SHA256, "example.org.").unwrap();
        Arc::new(Dnssec { zones: vec!["example.org.".into()], keys: vec![Arc::new(key)], cache: Mutex::new(LruCache::new(NonZeroUsize::new(10).unwrap())) })
    }

    async fn q(d: &Arc<Dnssec>, name: &str, t: RecordType) -> Message {
        let chain: Vec<Arc<dyn Handler>> = vec![d.clone(), Arc::new(Static)];
        let mut req = Request::for_test(name, t);
        req.msg.extensions_mut().get_or_insert_with(hickory_proto::op::Edns::new).set_dnssec_ok(true);
        Next::new(&chain).serve(&mut req).await.unwrap().into_msg().unwrap()
    }

    fn nsec_of(recs: &[Record]) -> (&Record, &NSEC) {
        recs.iter()
            .find_map(|r| match r.data() {
                Some(RData::DNSSEC(DNSSECRData::NSEC(n))) => Some((r, n)),
                _ => None,
            })
            .expect("an NSEC")
    }

    fn covered(recs: &[Record]) -> Vec<RecordType> {
        recs.iter()
            .filter_map(|r| match r.data() {
                Some(RData::DNSSEC(DNSSECRData::RRSIG(s))) => Some(s.type_covered()),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn signs_positive_answers() {
        let d = dnssec();
        let m = q(&d, "www.example.org.", RecordType::A).await;
        assert_eq!(m.answers().len(), 2);
        assert_eq!(m.answers()[1].record_type(), RecordType::RRSIG);
        let mut req = Request::for_test("example.org.", RecordType::DNSKEY);
        let chain: Vec<Arc<dyn Handler>> = vec![d.clone(), Arc::new(Static)];
        let m = Next::new(&chain).serve(&mut req).await.unwrap().into_msg().unwrap();
        assert_eq!(m.answers()[0].record_type(), RecordType::DNSKEY);
    }

    #[tokio::test]
    async fn black_lies_leave_out_the_queried_type() {
        let d = dnssec();
        for name in ["nx.example.org.", "nodata.example.org."] {
            let m = q(&d, name, RecordType::A).await;
            assert_eq!(m.response_code(), ResponseCode::NoError, "{}: black lie", name);
            let (r, n) = nsec_of(m.name_servers());
            assert!(!n.type_bit_maps().contains(&RecordType::A), "{}: A must not be claimed", name);
            assert!(n.type_bit_maps().contains(&RecordType::AAAA) && n.type_bit_maps().contains(&RecordType::NSEC));
            assert_eq!(r.ttl(), 300, "NSEC TTL from the SOA");
            assert_eq!(n.next_domain_name().to_ascii(), format!("\\000.{}", name));
            let c = covered(m.name_servers());
            assert!(c.contains(&RecordType::SOA) && c.contains(&RecordType::NSEC));
        }
        // a query for NSEC: the NSEC is the answer, the bitmap keeps NSEC
        let m = q(&d, "nx.example.org.", RecordType::NSEC).await;
        assert!(m.name_servers().is_empty());
        let (_, n) = nsec_of(m.answers());
        assert!(n.type_bit_maps().contains(&RecordType::NSEC));
    }

    #[tokio::test]
    async fn referrals_sign_ds_only() {
        let d = dnssec();
        let m = q(&d, "sub.example.org.", RecordType::A).await;
        assert!(!covered(m.name_servers()).contains(&RecordType::NS), "the NS set is not signed");
        let (_, n) = nsec_of(m.name_servers());
        assert_eq!(n.type_bit_maps(), delegation_bitmap().as_slice());
        assert_eq!(n.next_domain_name().to_ascii(), "sub\\000.example.org.");
        let m = q(&d, "ds.example.org.", RecordType::A).await;
        assert_eq!(covered(m.name_servers()), vec![RecordType::DS]);
        assert!(!m.name_servers().iter().any(|r| r.record_type() == RecordType::NSEC));
    }

    #[test]
    fn cached_signatures_are_remade_before_expiry() {
        let d = dnssec();
        let req = Request::for_test("www.example.org.", RecordType::A);
        let set = vec![Record::from_rdata(req.qname(), 30, RData::A(A::new(10, 0, 0, 1)))];
        let exp = |sigs: &[Record]| match sigs[0].data() {
            Some(RData::DNSSEC(DNSSECRData::RRSIG(s))) => s.sig_expiration(),
            _ => panic!(),
        };
        let t0 = now_secs();
        let a = d.sign_set(&set, "example.org.", "s", t0);
        assert_eq!(exp(&d.sign_set(&set, "example.org.", "s", t0 + 5 * 86400)), exp(&a), "valid for 3 more days: cached");
        let b = d.sign_set(&set, "example.org.", "s", t0 + 7 * 86400);
        assert!(exp(&b) > exp(&a), "within 2 days of expiry: re-signed");
    }
}
