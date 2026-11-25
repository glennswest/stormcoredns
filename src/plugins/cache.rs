//! `cache` — response cache with separate success and denial stores,
//! prefetch and serve-stale.
//!
//! ```text
//! cache [TTL] [ZONES...] {
//!     success CAPACITY [TTL] [MINTTL]
//!     denial CAPACITY [TTL] [MINTTL]
//!     prefetch AMOUNT [[DURATION] [PERCENTAGE%]]
//!     serve_stale [DURATION] [REFRESH_MODE]
//!     servfail DURATION
//!     disable success|denial [ZONES...]
//!     keepttl
//! }
//! ```

use crate::plugin::{Controller, DnsResult, Handler, Next, Reply, Request};
use async_trait::async_trait;
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, RecordType};
use lru::LruCache;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use prometheus::{IntCounterVec, IntGaugeVec};
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ------------------------------------------------------------------ metrics

fn cvec(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    let c = IntCounterVec::new(prometheus::Opts::new(name, help), labels).unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
}
static CACHE_SIZE: Lazy<IntGaugeVec> = Lazy::new(|| {
    let g = IntGaugeVec::new(prometheus::Opts::new("coredns_cache_entries", "The number of elements in the cache."), &["server", "type", "zones", "view"]).unwrap();
    crate::metrics::register(Box::new(g.clone()));
    g
});
static CACHE_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| cvec("coredns_cache_requests_total", "The count of cache requests.", &["server", "zones", "view"]));
static CACHE_HITS: Lazy<IntCounterVec> = Lazy::new(|| cvec("coredns_cache_hits_total", "The count of cache hits.", &["server", "type", "zones", "view"]));
static CACHE_MISSES: Lazy<IntCounterVec> = Lazy::new(|| cvec("coredns_cache_misses_total", "The count of cache misses. Deprecated, derive misses from cache hits/requests counters.", &["server", "zones", "view"]));
static CACHE_PREFETCHES: Lazy<IntCounterVec> = Lazy::new(|| cvec("coredns_cache_prefetch_total", "The number of times the cache has prefetched a cached item.", &["server", "zones", "view"]));
static CACHE_DROPS: Lazy<IntCounterVec> = Lazy::new(|| cvec("coredns_cache_drops_total", "The number responses that are not cached, because the reply is malformed.", &["server", "zones", "view"]));
static CACHE_STALE: Lazy<IntCounterVec> = Lazy::new(|| cvec("coredns_cache_served_stale_total", "The number of requests served from stale cache entries.", &["server", "zones", "view"]));
static CACHE_EVICTIONS: Lazy<IntCounterVec> = Lazy::new(|| cvec("coredns_cache_evictions_total", "The count of cache evictions.", &["server", "type", "zones", "view"]));

// ------------------------------------------------------------------ types

/// `response.Type`: how a response is classified for caching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RespType {
    /// NOERROR with answers.
    Success,
    /// NOERROR without answers (NODATA).
    NoError,
    /// NXDOMAIN.
    NameError,
    /// Referral: NS records in authority, not authoritative.
    Delegation,
    /// SERVFAIL, REFUSED, ...
    OtherError,
    /// Not a normal query response (update, notify, ...).
    Meta,
}

pub fn typify(m: &Message) -> RespType {
    if m.metadata.op_code != OpCode::Query {
        return RespType::Meta;
    }
    match m.metadata.response_code {
        ResponseCode::NoError => {
            if !m.answers.is_empty() {
                return RespType::Success;
            }
            let has_soa = m.authorities.iter().any(|r| r.record_type() == RecordType::SOA);
            let has_ns = m.authorities.iter().any(|r| r.record_type() == RecordType::NS);
            if has_soa {
                RespType::NoError
            } else if has_ns && !m.metadata.authoritative {
                RespType::Delegation
            } else {
                RespType::NoError
            }
        }
        ResponseCode::NXDomain => RespType::NameError,
        _ => RespType::OtherError,
    }
}

struct Item {
    msg: Message,
    stored: Instant,
    /// Original TTL of the item (seconds).
    ttl: u32,
    /// Prefetch bookkeeping: request count in the current window.
    fetches: u32,
    window_start: Instant,
}

impl Item {
    fn remaining(&self, now: Instant) -> i64 {
        self.ttl as i64 - now.duration_since(self.stored).as_secs() as i64
    }

    /// The stored message with TTLs aged by `elapsed` (or as stored when
    /// `keepttl`), re-addressed to `req`.
    fn to_msg(&self, req: &Request, now: Instant, keepttl: bool) -> Message {
        let mut m = self.msg.clone();
        m.metadata.id = req.msg.metadata.id;
        // the question as the client sent it (its case), as `SetReply` does
        m.queries.clear();
        m.add_queries(req.msg.queries.iter().cloned());
        // mirror the query's RD/CD flags
        m.metadata.recursion_desired = req.msg.metadata.recursion_desired;
        m.metadata.checking_disabled = req.msg.metadata.checking_disabled;
        if !keepttl {
            let age = now.duration_since(self.stored).as_secs() as u32;
            let adjust = |r: &mut hickory_proto::rr::Record| {
                if r.record_type() != RecordType::OPT {
                    r.ttl = r.ttl.saturating_sub(age);
                }
            };
            let mut a = std::mem::take(&mut m.answers);
            a.iter_mut().for_each(adjust);
            m.insert_answers(a);
            let mut n = std::mem::take(&mut m.authorities);
            n.iter_mut().for_each(adjust);
            m.insert_authorities(n);
            let mut x = std::mem::take(&mut m.additionals);
            x.iter_mut().for_each(adjust);
            m.insert_additionals(x);
        }
        // EDNS: answer with OPT only if the client sent one
        if req.msg.edns.is_some() {
            req.set_edns0(&mut m);
        } else {
            m.edns = None;
        }
        m
    }
}

struct Shard {
    map: Mutex<LruCache<u64, Item>>,
}

pub struct Store {
    shards: Vec<Shard>,
}

const SHARDS: usize = 256;

impl Store {
    fn new(cap: usize) -> Store {
        let per = (cap / SHARDS).max(1);
        let shards = (0..SHARDS).map(|_| Shard { map: Mutex::new(LruCache::new(NonZeroUsize::new(per).unwrap())) }).collect();
        Store { shards }
    }
    fn shard(&self, key: u64) -> &Shard {
        &self.shards[(key % SHARDS as u64) as usize]
    }
    fn len(&self) -> usize {
        self.shards.iter().map(|s| s.map.lock().len()).sum()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshMode {
    Immediate,
    Verify,
}

pub struct Cache {
    pub zones: Vec<String>,
    pub pcap: usize,
    pub pttl: Duration,
    pub minpttl: Duration,
    pub ncap: usize,
    pub nttl: Duration,
    pub minnttl: Duration,
    pub prefetch: u32,
    pub duration: Duration,
    pub percentage: u32,
    pub stale_upto: Duration,
    pub refresh_mode: RefreshMode,
    pub failttl: Duration,
    pub keepttl: bool,
    pub disable_success: Option<Vec<String>>,
    pub disable_denial: Option<Vec<String>>,
    pcache: Store,
    ncache: Store,
    inflight: dashmap::DashMap<u64, Arc<AtomicBool>>,
    zones_label: String,
}

/// Cache key: qname (lowercase), qtype, qclass, and the RD, DO and CD
/// bits — everything of the question that changes the answer
/// (finding 0c1633c2a684: an IN answer must not answer a CH query, nor an
/// RD=0 answer an RD=1 query).
pub fn key(name: &str, qtype: RecordType, qclass: DNSClass, rd: bool, do_bit: bool, cd: bool) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    name.to_ascii_lowercase().hash(&mut h);
    u16::from(qtype).hash(&mut h);
    u16::from(qclass).hash(&mut h);
    rd.hash(&mut h);
    do_bit.hash(&mut h);
    cd.hash(&mut h);
    h.finish()
}

/// The cache key of a request.
pub fn req_key(req: &Request, name: &str) -> u64 {
    key(name, req.qtype(), req.qclass(), req.msg.metadata.recursion_desired, req.do_bit(), req.msg.metadata.checking_disabled)
}

impl Cache {
    fn cacheable(&self, req: &Request) -> bool {
        req.msg.metadata.op_code == OpCode::Query && req.msg.queries.len() == 1 && req.qtype() != RecordType::ZERO
    }

    /// Store a response if it is cacheable, returning the TTL used.
    fn insert(&self, req: &Request, m: &Message, name: &str, server: &str, view: &str) -> Option<Duration> {
        if m.metadata.truncation {
            return None;
        }
        let rtype = typify(m);
        // a reply to a query must carry the whole question back: one
        // question, same name (any case), type and class
        let mut qname = name.to_ascii_lowercase();
        if !qname.ends_with('.') {
            qname.push('.');
        }
        let same_question = m.queries.len() == 1
            && m.queries.first().is_some_and(|q| {
                let mut n = q.name().to_ascii().to_ascii_lowercase();
                if !n.ends_with('.') {
                    n.push('.');
                }
                n == qname && q.query_type() == req.qtype() && q.query_class() == req.qclass()
            });
        if !same_question {
            CACHE_DROPS.with_label_values(&[server, &self.zones_label, view]).inc();
            return None;
        }
        let k = req_key(req, name);
        let (store, ttl) = match rtype {
            RespType::Success | RespType::Delegation => {
                if let Some(z) = &self.disable_success {
                    if crate::plugin::zones_match(z, name).is_some() {
                        return None;
                    }
                }
                let mut ttl = crate::dnsutil::minimal_ttl(m, false);
                if m.answers.is_empty() && m.authorities.is_empty() {
                    ttl = self.minpttl;
                }
                (&self.pcache, ttl.clamp(self.minpttl, self.pttl))
            }
            RespType::NoError | RespType::NameError => {
                if let Some(z) = &self.disable_denial {
                    if crate::plugin::zones_match(z, name).is_some() {
                        return None;
                    }
                }
                let mut ttl = crate::dnsutil::minimal_ttl(m, true);
                if m.authorities.is_empty() && m.answers.is_empty() {
                    ttl = self.minnttl;
                }
                (&self.ncache, ttl.clamp(self.minnttl, self.nttl))
            }
            RespType::OtherError => {
                if self.failttl.is_zero() {
                    return None;
                }
                (&self.ncache, self.failttl)
            }
            RespType::Meta => return None,
        };
        let mut stored = m.clone();
        // normalise: strip OPT, we add our own on the way out
        stored.edns = None;
        let _ = rtype;
        let item = Item { msg: stored, stored: Instant::now(), ttl: ttl.as_secs() as u32, fetches: 0, window_start: Instant::now() };
        let shard = store.shard(k);
        let mut map = shard.map.lock();
        if map.len() >= map.cap().get() && !map.contains(&k) {
            let t = if std::ptr::eq(store, &self.pcache) { "success" } else { "denial" };
            CACHE_EVICTIONS.with_label_values(&[server, t, &self.zones_label, view]).inc();
        }
        map.put(k, item);
        drop(map);
        // one entry per key: a new answer replaces whatever the other store
        // held for it (finding 67dabaa35868: a refreshed NXDOMAIN must not
        // stay hidden behind a stale positive entry, nor the reverse)
        let other = if std::ptr::eq(store, &self.pcache) { &self.ncache } else { &self.pcache };
        other.shard(k).map.lock().pop(&k);
        Some(ttl)
    }

    /// Look up `key` in both stores; returns the message to send plus
    /// whether a prefetch/stale-refresh should be triggered.
    fn get(&self, k: u64, req: &Request, server: &str, view: &str) -> Option<(Message, bool, bool)> {
        let now = Instant::now();
        for (store, t) in [(&self.pcache, "success"), (&self.ncache, "denial")] {
            let shard = store.shard(k);
            let mut map = shard.map.lock();
            if let Some(item) = map.get_mut(&k) {
                let remaining = item.remaining(now);
                let stale = remaining <= 0;
                if stale && now.duration_since(item.stored).as_secs() as i64 > item.ttl as i64 + self.stale_upto.as_secs() as i64 {
                    map.pop(&k);
                    return None;
                }
                // prefetch bookkeeping
                if now.duration_since(item.window_start) > self.duration {
                    item.window_start = now;
                    item.fetches = 0;
                }
                item.fetches += 1;
                let want_prefetch = self.prefetch > 0
                    && item.fetches >= self.prefetch
                    && !stale
                    && remaining as f64 <= item.ttl as f64 * (self.percentage as f64 / 100.0);
                CACHE_HITS.with_label_values(&[server, t, &self.zones_label, view]).inc();
                let mut m = item.to_msg(req, now, self.keepttl);
                if stale {
                    // stale answers carry TTL 0 (CoreDNS behaviour)
                    let zero = |r: &mut hickory_proto::rr::Record| {
                        if r.record_type() != RecordType::OPT {
                            r.ttl = 0;
                        }
                    };
                    let mut a = std::mem::take(&mut m.answers);
                    a.iter_mut().for_each(zero);
                    m.insert_answers(a);
                    let mut n = std::mem::take(&mut m.authorities);
                    n.iter_mut().for_each(zero);
                    m.insert_authorities(n);
                    let mut x = std::mem::take(&mut m.additionals);
                    x.iter_mut().for_each(zero);
                    m.insert_additionals(x);
                }
                return Some((m, want_prefetch, stale));
            }
        }
        None
    }

    fn refresh_in_background(self: &Arc<Self>, req: &Request, chain: Vec<Arc<dyn Handler>>, k: u64, prefetch: bool) {
        let flag = self.inflight.entry(k).or_insert_with(|| Arc::new(AtomicBool::new(false))).clone();
        if flag.swap(true, Ordering::SeqCst) {
            return; // already refreshing
        }
        let mut r2 = req.new_with_question(req.qname(), req.qtype());
        // the same question, class included, so the answer lands under `k`
        r2.msg.queries.clear();
        r2.msg.add_queries(req.msg.queries.iter().cloned());
        r2.msg.metadata.checking_disabled = req.msg.metadata.checking_disabled;
        r2.msg.metadata.recursion_desired = req.msg.metadata.recursion_desired;
        if req.do_bit() {
            r2.msg.edns.get_or_insert_with(hickory_proto::op::Edns::new).set_dnssec_ok(true);
        }
        let cache = self.clone();
        let server = req.server.clone();
        let view = req.view.clone();
        tokio::spawn(async move {
            let name = r2.name();
            if prefetch {
                CACHE_PREFETCHES.with_label_values(&[&server, &cache.zones_label, &view]).inc();
            }
            if let Ok(Reply::Msg(m)) = Next::new(&chain).serve(&mut r2).await {
                cache.insert(&r2, &m, &name, &server, &view);
            }
            cache.inflight.remove(&k);
        });
    }
}

pub struct CacheHandler(pub Arc<Cache>);

#[async_trait]
impl Handler for CacheHandler {
    fn name(&self) -> &'static str {
        "cache"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let c = &self.0;
        let name = req.name();
        if crate::plugin::zones_match(&c.zones, &name).is_none() || !c.cacheable(req) {
            return next.serve(req).await;
        }
        let server = req.server.clone();
        let view = req.view.clone();
        let k = req_key(req, &name);
        CACHE_REQUESTS.with_label_values(&[&server, &c.zones_label, &view]).inc();

        if let Some((m, want_prefetch, stale)) = c.get(k, req, &server, &view) {
            if stale {
                match c.refresh_mode {
                    RefreshMode::Verify => {
                        // try upstream first; fall back to the stale answer
                        match next.serve(req).await {
                            Ok(Reply::Msg(fresh)) if fresh.metadata.response_code != ResponseCode::ServFail => {
                                c.insert(req, &fresh, &name, &server, &view);
                                return Ok(Reply::Msg(fresh));
                            }
                            _ => {
                                CACHE_STALE.with_label_values(&[&server, &c.zones_label, &view]).inc();
                                return Ok(Reply::Msg(m));
                            }
                        }
                    }
                    RefreshMode::Immediate => {
                        CACHE_STALE.with_label_values(&[&server, &c.zones_label, &view]).inc();
                        c.refresh_in_background(req, next_chain(next), k, false);
                        return Ok(Reply::Msg(m));
                    }
                }
            }
            if want_prefetch {
                c.refresh_in_background(req, next_chain(next), k, true);
            }
            return Ok(Reply::Msg(m));
        }
        CACHE_MISSES.with_label_values(&[&server, &c.zones_label, &view]).inc();
        let r = next.serve(req).await;
        if let Ok(Reply::Msg(m)) = &r {
            c.insert(req, m, &name, &server, &view);
            CACHE_SIZE.with_label_values(&[&server, "success", &c.zones_label, &view]).set(c.pcache.len() as i64);
            CACHE_SIZE.with_label_values(&[&server, "denial", &c.zones_label, &view]).set(c.ncache.len() as i64);
        }
        r
    }
}

fn next_chain(next: Next<'_>) -> Vec<Arc<dyn Handler>> {
    next.chain().to_vec()
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/cache: this plugin can only be used once per Server Block"));
        }
        let mut args = c.remaining_args_until_brace();
        let mut pttl = Duration::from_secs(3600);
        let mut nttl = Duration::from_secs(1800);
        if let Some(first) = args.first() {
            if let Ok(secs) = first.parse::<u64>() {
                if secs == 0 {
                    return Err(c.errf("cache TTL can not be zero or negative"));
                }
                pttl = Duration::from_secs(secs);
                nttl = Duration::from_secs(secs);
                args.remove(0);
            }
        }
        let zones = c.origins_from_args_or_server_block(&args)?;
        let mut cache = Cache {
            zones_label: zones.join(","),
            zones,
            pcap: 9984,
            pttl,
            minpttl: Duration::from_secs(5),
            ncap: 9984,
            nttl,
            minnttl: Duration::from_secs(5),
            prefetch: 0,
            duration: Duration::from_secs(60),
            percentage: 10,
            stale_upto: Duration::ZERO,
            refresh_mode: RefreshMode::Immediate,
            // CoreDNS caches SERVFAIL for the minimal negative TTL (5 s) by default
            failttl: Duration::from_secs(5),
            keepttl: false,
            disable_success: None,
            disable_denial: None,
            pcache: Store::new(1),
            ncache: Store::new(1),
            inflight: dashmap::DashMap::new(),
        };
        while c.next_block() {
            match c.val() {
                "success" | "denial" => {
                    let which = c.val().to_string();
                    let a = c.remaining_args();
                    if a.is_empty() || a.len() > 3 {
                        return Err(c.arg_err());
                    }
                    let cap: usize = a[0].parse().map_err(|_| c.errf(format!("bad capacity {}", a[0])))?;
                    let ttl = match a.get(1) {
                        Some(t) => Some(Duration::from_secs(t.parse::<u64>().map_err(|_| c.errf(format!("bad ttl {}", t)))?)),
                        None => None,
                    };
                    let min = match a.get(2) {
                        Some(t) => Some(Duration::from_secs(t.parse::<u64>().map_err(|_| c.errf(format!("bad min ttl {}", t)))?)),
                        None => None,
                    };
                    if which == "success" {
                        cache.pcap = cap;
                        if let Some(t) = ttl {
                            cache.pttl = t;
                        }
                        if let Some(t) = min {
                            cache.minpttl = t;
                        }
                    } else {
                        cache.ncap = cap;
                        if let Some(t) = ttl {
                            cache.nttl = t;
                        }
                        if let Some(t) = min {
                            cache.minnttl = t;
                        }
                    }
                }
                "prefetch" => {
                    let a = c.remaining_args();
                    if a.is_empty() || a.len() > 3 {
                        return Err(c.arg_err());
                    }
                    cache.prefetch = a[0].parse().map_err(|_| c.errf(format!("bad prefetch amount {}", a[0])))?;
                    if let Some(d) = a.get(1) {
                        cache.duration = crate::dnsutil::parse_duration(d)?;
                    }
                    if let Some(p) = a.get(2) {
                        let p = p.trim_end_matches('%');
                        cache.percentage = p.parse().map_err(|_| c.errf(format!("bad percentage {}", p)))?;
                        if cache.percentage > 90 || cache.percentage < 10 {
                            return Err(c.errf("prefetch percentage should fall in range [10, 90]"));
                        }
                    }
                }
                "serve_stale" => {
                    let a = c.remaining_args();
                    if a.len() > 2 {
                        return Err(c.arg_err());
                    }
                    cache.stale_upto = Duration::from_secs(3600);
                    if let Some(d) = a.first() {
                        cache.stale_upto = crate::dnsutil::parse_duration(d)?;
                    }
                    if let Some(m) = a.get(1) {
                        cache.refresh_mode = match m.as_str() {
                            "immediate" => RefreshMode::Immediate,
                            "verify" => RefreshMode::Verify,
                            o => return Err(c.errf(format!("invalid refresh mode {}", o))),
                        };
                    }
                }
                "servfail" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    let d = crate::dnsutil::parse_duration(&a[0])?;
                    if d > Duration::from_secs(300) {
                        return Err(c.errf("servfail TTL can not exceed 5 minutes"));
                    }
                    cache.failttl = d;
                }
                "disable" => {
                    let a = c.remaining_args();
                    if a.is_empty() {
                        return Err(c.arg_err());
                    }
                    let zones = if a.len() > 1 { crate::plugin::normalize_zones(&a[1..])? } else { vec![".".to_string()] };
                    match a[0].as_str() {
                        "success" => cache.disable_success = Some(zones),
                        "denial" => cache.disable_denial = Some(zones),
                        o => return Err(c.errf(format!("cache type for disable needs to be \"success\" or \"denial\", got {}", o))),
                    }
                }
                "keepttl" => cache.keepttl = true,
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        cache.pcache = Store::new(cache.pcap);
        cache.ncache = Store::new(cache.ncap);
        c.add_plugin(Arc::new(CacheHandler(Arc::new(cache))));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record};

    struct Static(u32);
    #[async_trait]
    impl Handler for Static {
        fn name(&self) -> &'static str {
            "static"
        }
        async fn serve_dns(&self, req: &mut Request, _next: Next<'_>) -> DnsResult {
            let mut m = req.new_reply();
            m.add_answer(Record::from_rdata(req.qname(), self.0, RData::A(A::new(10, 0, 0, 1))));
            Ok(Reply::Msg(m))
        }
    }

    fn cache() -> Arc<Cache> {
        Arc::new(Cache {
            zones: vec![".".into()],
            pcap: 100,
            pttl: Duration::from_secs(3600),
            minpttl: Duration::from_secs(5),
            ncap: 100,
            nttl: Duration::from_secs(1800),
            minnttl: Duration::from_secs(5),
            prefetch: 0,
            duration: Duration::from_secs(60),
            percentage: 10,
            stale_upto: Duration::ZERO,
            refresh_mode: RefreshMode::Immediate,
            failttl: Duration::ZERO,
            keepttl: false,
            disable_success: None,
            disable_denial: None,
            pcache: Store::new(100),
            ncache: Store::new(100),
            inflight: dashmap::DashMap::new(),
            zones_label: ".".into(),
        })
    }

    #[tokio::test]
    async fn hit_after_miss() {
        let c = cache();
        let chain: Vec<Arc<dyn Handler>> = vec![Arc::new(CacheHandler(c.clone())), Arc::new(Static(300))];
        let mut r1 = Request::for_test("example.org.", RecordType::A);
        let m1 = Next::new(&chain).serve(&mut r1).await.unwrap().into_msg().unwrap();
        assert_eq!(m1.answers[0].ttl, 300);
        assert_eq!(c.pcache.len(), 1);
        let mut r2 = Request::for_test("EXAMPLE.org.", RecordType::A);
        let m2 = Next::new(&chain).serve(&mut r2).await.unwrap().into_msg().unwrap();
        assert_eq!(m2.metadata.id, r2.msg.metadata.id);
        assert_eq!(m2.answers[0].ttl, 300);
    }

    /// Answers with the query's own question, counting calls. `nx` switches
    /// it to NXDOMAIN; `wrong_type` makes it answer a different qtype.
    struct Upstream {
        calls: std::sync::atomic::AtomicU32,
        nx: AtomicBool,
        wrong_type: AtomicBool,
        ttl: u32,
    }
    impl Upstream {
        fn new(ttl: u32) -> Arc<Upstream> {
            Arc::new(Upstream { calls: Default::default(), nx: AtomicBool::new(false), wrong_type: AtomicBool::new(false), ttl })
        }
        fn calls(&self) -> u32 {
            self.calls.load(Ordering::SeqCst)
        }
    }
    #[async_trait]
    impl Handler for Upstream {
        fn name(&self) -> &'static str {
            "upstream"
        }
        async fn serve_dns(&self, req: &mut Request, _next: Next<'_>) -> DnsResult {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut m = req.new_reply();
            if self.wrong_type.load(Ordering::SeqCst) {
                let mut q = std::mem::take(&mut m.queries);
                q[0].set_query_type(RecordType::AAAA);
                m.add_queries(q);
            }
            if self.nx.load(Ordering::SeqCst) {
                m.metadata.response_code = ResponseCode::NXDomain;
            } else {
                let mut r = Record::from_rdata(req.qname(), self.ttl, RData::A(A::new(10, 0, 0, 1)));
                r.dns_class = req.qclass();
                m.add_answer(r);
            }
            Ok(Reply::Msg(m))
        }
    }

    async fn ask(chain: &[Arc<dyn Handler>], mut r: Request) -> Message {
        Next::new(chain).serve(&mut r).await.unwrap().into_msg().unwrap()
    }

    fn with_class(name: &str, class: DNSClass) -> Request {
        let mut r = Request::for_test(name, RecordType::A);
        let mut q = std::mem::take(&mut r.msg.queries);
        q[0].set_query_class(class);
        r.msg.add_queries(q);
        r
    }

    // finding 0c1633c2a684
    #[tokio::test]
    async fn key_separates_class_and_rd() {
        let c = cache();
        let up = Upstream::new(300);
        let chain: Vec<Arc<dyn Handler>> = vec![Arc::new(CacheHandler(c.clone())), up.clone()];

        let m = ask(&chain, with_class("example.org.", DNSClass::IN)).await;
        assert_eq!(m.queries[0].query_class(), DNSClass::IN);
        assert_eq!(up.calls(), 1);
        // a CH query is not answered with the cached IN answer
        let m = ask(&chain, with_class("example.org.", DNSClass::CH)).await;
        assert_eq!(up.calls(), 2);
        assert_eq!(m.queries[0].query_class(), DNSClass::CH);
        assert_eq!(m.answers[0].dns_class, DNSClass::CH);
        // each class now hits its own entry
        let m = ask(&chain, with_class("example.org.", DNSClass::IN)).await;
        assert_eq!(m.answers[0].dns_class, DNSClass::IN);
        let m = ask(&chain, with_class("example.org.", DNSClass::CH)).await;
        assert_eq!(m.answers[0].dns_class, DNSClass::CH);
        assert_eq!(up.calls(), 2);

        // RD=0 does not share the RD=1 entry
        let mut r = Request::for_test("example.org.", RecordType::A);
        r.msg.metadata.recursion_desired = false;
        let m = ask(&chain, r).await;
        assert_eq!(up.calls(), 3);
        assert!(!m.metadata.recursion_desired);
        let mut r = Request::for_test("example.org.", RecordType::A);
        r.msg.metadata.recursion_desired = false;
        ask(&chain, r).await;
        assert_eq!(up.calls(), 3);

        // a hit carries the client's question, in the client's case
        let m = ask(&chain, Request::for_test("ExAmPlE.org.", RecordType::A)).await;
        assert_eq!(up.calls(), 3);
        assert_eq!(m.queries[0].name().to_ascii(), "ExAmPlE.org.");
    }

    // finding 0c1633c2a684: validate the full question before storing
    #[tokio::test]
    async fn reply_for_another_question_is_not_cached() {
        let c = cache();
        let up = Upstream::new(300);
        up.wrong_type.store(true, Ordering::SeqCst);
        let chain: Vec<Arc<dyn Handler>> = vec![Arc::new(CacheHandler(c.clone())), up.clone()];
        ask(&chain, Request::for_test("example.org.", RecordType::A)).await;
        ask(&chain, Request::for_test("example.org.", RecordType::A)).await;
        assert_eq!(up.calls(), 2);
        assert_eq!(c.pcache.len() + c.ncache.len(), 0);
    }

    // finding 67dabaa35868
    #[tokio::test]
    async fn refreshed_denial_replaces_stale_positive() {
        let mut c = Arc::try_unwrap(cache()).ok().unwrap();
        c.minpttl = Duration::ZERO; // TTL 0: stale at once
        c.stale_upto = Duration::from_secs(3600);
        c.refresh_mode = RefreshMode::Immediate;
        let c = Arc::new(c);
        let up = Upstream::new(0);
        let chain: Vec<Arc<dyn Handler>> = vec![Arc::new(CacheHandler(c.clone())), up.clone()];

        let m = ask(&chain, Request::for_test("gone.example.org.", RecordType::A)).await;
        assert_eq!(m.answers.len(), 1);
        // the name is deleted upstream; the stale answer is served once and
        // refreshed in the background
        up.nx.store(true, Ordering::SeqCst);
        let m = ask(&chain, Request::for_test("gone.example.org.", RecordType::A)).await;
        assert_eq!(m.answers.len(), 1);
        for _ in 0..200 {
            if up.calls() == 2 && c.inflight.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(up.calls(), 2);
        assert_eq!(c.pcache.len(), 0);
        assert_eq!(c.ncache.len(), 1);
        // from now on the denial answers, from the cache
        let m = ask(&chain, Request::for_test("gone.example.org.", RecordType::A)).await;
        assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(up.calls(), 2);

        // and the reverse: a positive answer replaces a cached denial
        let k = req_key(&Request::for_test("gone.example.org.", RecordType::A), "gone.example.org.");
        up.nx.store(false, Ordering::SeqCst);
        let mut r = Request::for_test("gone.example.org.", RecordType::A);
        let mut fresh = r.new_reply();
        fresh.add_answer(Record::from_rdata(r.qname(), 300, RData::A(A::new(10, 0, 0, 2))));
        let name = r.name();
        c.insert(&r, &fresh, &name, "", "");
        assert!(c.ncache.shard(k).map.lock().peek(&k).is_none());
        let m = ask(&chain, Request::for_test("gone.example.org.", RecordType::A)).await;
        assert_eq!(m.metadata.response_code, ResponseCode::NoError);
        assert_eq!(m.answers.len(), 1);
    }

    #[test]
    fn typify_cases() {
        let mut m = Message::new(0, hickory_proto::op::MessageType::Query, hickory_proto::op::OpCode::Query);
        m.metadata.response_code = ResponseCode::NXDomain;
        assert_eq!(typify(&m), RespType::NameError);
        let mut m = Message::new(0, hickory_proto::op::MessageType::Query, hickory_proto::op::OpCode::Query);
        m.metadata.response_code = ResponseCode::ServFail;
        assert_eq!(typify(&m), RespType::OtherError);
        let mut m = Message::new(0, hickory_proto::op::MessageType::Query, hickory_proto::op::OpCode::Query);
        m.add_answer(Record::from_rdata(Name::root(), 1, RData::A(A::new(1, 1, 1, 1))));
        assert_eq!(typify(&m), RespType::Success);
    }
}
