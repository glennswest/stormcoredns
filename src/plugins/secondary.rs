//! `secondary` — slaves zones from primaries over AXFR, as CoreDNS: the
//! first transfer is retried with backoff (250 ms → 10 s); then the SOA
//! serial is checked over TCP every `refresh` (every `retry` after a
//! failure) and on NOTIFY from a primary's IP, and the zone is transferred
//! when the primary's serial is newer (RFC 1982). Once `expire` passes
//! without a good check, the zone is expired: SERVFAIL, no AXFR out, until
//! a transfer succeeds.
//!
//! ```text
//! secondary [ZONES...] {
//!     transfer from ADDRESS...
//! }
//! ```
//! Outbound transfers of a slaved zone are handled by the `transfer` plugin.

use crate::dnsutil;
use crate::plugin::{Controller, DnsResult, Handler, Next, Reply, Request};
use crate::plugins::file::zone::Zone;
use anyhow::{anyhow, bail, Result};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

pub struct SecondaryZone {
    pub origin: String,
    pub primaries: Vec<SocketAddr>,
    pub zone: ArcSwapOption<Zone>,
    /// Woken by NOTIFY to refresh immediately.
    pub kick: Notify,
    /// Set once SOA `expire` has passed without a good refresh.
    pub expired: AtomicBool,
}

pub struct Secondary {
    zones: Vec<Arc<SecondaryZone>>,
    names: Vec<String>,
}

/// Run an AXFR against `primary` and return the records.
pub async fn axfr(primary: SocketAddr, origin: &str) -> Result<Vec<Record>> {
    let name = Name::from_ascii(origin)?;
    let mut q = Message::new();
    q.set_id(rand::random());
    q.set_message_type(MessageType::Query);
    q.set_op_code(OpCode::Query);
    q.add_query(Query::query(name.clone(), RecordType::AXFR));
    let wire = q.to_vec()?;
    let mut stream = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(primary)).await.map_err(|_| anyhow!("connect {}: timeout", primary))??;
    let mut out = Vec::with_capacity(wire.len() + 2);
    out.extend_from_slice(&(wire.len() as u16).to_be_bytes());
    out.extend_from_slice(&wire);
    stream.write_all(&out).await?;
    let mut records = Vec::new();
    let mut soa_seen = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    loop {
        let mut len = [0u8; 2];
        tokio::time::timeout_at(deadline, stream.read_exact(&mut len)).await.map_err(|_| anyhow!("axfr from {}: timeout", primary))??;
        let n = u16::from_be_bytes(len) as usize;
        let mut buf = vec![0u8; n];
        tokio::time::timeout_at(deadline, stream.read_exact(&mut buf)).await.map_err(|_| anyhow!("axfr from {}: timeout", primary))??;
        let m = Message::from_bytes(&buf)?;
        if m.response_code() != ResponseCode::NoError {
            bail!("axfr from {}: {}", primary, crate::plugin::replacer::rcode_str(m.response_code()));
        }
        for r in m.answers() {
            if r.record_type() == RecordType::SOA {
                soa_seen += 1;
                if soa_seen == 2 {
                    return Ok(records);
                }
            }
            records.push(r.clone());
        }
        if m.answers().is_empty() {
            bail!("axfr from {}: empty message before final SOA", primary);
        }
    }
}

/// One DNS exchange over TCP (length-prefixed), 5 s overall.
async fn tcp_exchange(server: SocketAddr, q: &Message) -> Result<Message> {
    let wire = q.to_vec()?;
    let fut = async {
        let mut stream = tokio::net::TcpStream::connect(server).await?;
        let mut out = Vec::with_capacity(wire.len() + 2);
        out.extend_from_slice(&(wire.len() as u16).to_be_bytes());
        out.extend_from_slice(&wire);
        stream.write_all(&out).await?;
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await?;
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut buf).await?;
        Ok::<_, anyhow::Error>(Message::from_bytes(&buf)?)
    };
    tokio::time::timeout(Duration::from_secs(5), fut).await.map_err(|_| anyhow!("soa query to {}: timeout", server))?
}

/// The primary's SOA serial, asked over TCP as CoreDNS does (harder to spoof).
async fn primary_serial(primary: SocketAddr, origin: &str) -> Result<u32> {
    let mut q = Message::new();
    q.set_id(rand::random());
    q.add_query(Query::query(Name::from_ascii(origin)?, RecordType::SOA));
    let m = tcp_exchange(primary, &q).await?;
    if m.response_code() != ResponseCode::NoError {
        bail!("soa query to {}: {}", primary, crate::plugin::replacer::rcode_str(m.response_code()));
    }
    m.answers()
        .iter()
        .find_map(|r| match r.data() {
            Some(RData::SOA(s)) => Some(s.serial()),
            _ => None,
        })
        .ok_or_else(|| anyhow!("no SOA in answer from {}", primary))
}

/// RFC 1982 serial arithmetic: is serial `a` older than `b`? (CoreDNS's `less`.)
pub fn serial_less(a: u32, b: u32) -> bool {
    const MAX_INCREMENT: u32 = 2_147_483_647;
    if a < b {
        b - a <= MAX_INCREMENT
    } else {
        a - b > MAX_INCREMENT
    }
}

fn jitter(max_ms: u64) -> Duration {
    Duration::from_millis(rand::random::<u64>() % max_ms.max(1))
}

impl SecondaryZone {
    pub fn new(origin: String, primaries: Vec<SocketAddr>) -> SecondaryZone {
        SecondaryZone { origin, primaries, zone: ArcSwapOption::empty(), kick: Notify::new(), expired: AtomicBool::new(false) }
    }

    async fn transfer_in(&self) -> Result<()> {
        let mut last_err = None;
        for p in &self.primaries {
            match axfr(*p, &self.origin).await {
                Ok(records) => {
                    let z = Zone::from_records(&self.origin, records)?;
                    tracing::info!("plugin/secondary: transferred zone {} from {} (serial {}, {} records)", self.origin, p, z.serial, z.len());
                    self.zone.store(Some(Arc::new(z)));
                    self.expired.store(false, Ordering::Relaxed);
                    crate::plugins::transfer::notify(&self.origin);
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!("plugin/secondary: {}", e);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("no primaries")))
    }

    /// Ask the primaries (first that answers) whether their serial is newer
    /// than ours, per RFC 1982. An expired zone is always re-transferred.
    async fn should_transfer(&self) -> Result<bool> {
        let current = self.zone.load().as_ref().map(|z| z.serial);
        let mut last_err = None;
        for p in &self.primaries {
            match primary_serial(*p, &self.origin).await {
                Ok(s) => {
                    return Ok(match current {
                        None => true,
                        Some(c) => serial_less(c, s) || self.expired.load(Ordering::Relaxed),
                    })
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("no primaries")))
    }

    /// The SOA refresh, retry and expire timers of the zone we hold.
    fn timers(&self) -> (Duration, Duration, Duration) {
        let soa = self.zone.load().as_ref().and_then(|z| z.soa().cloned());
        let (refresh, retry, expire) = match soa.as_ref().and_then(|r| r.data()) {
            Some(RData::SOA(s)) => (s.refresh(), s.retry(), s.expire()),
            _ => (3600, 600, 604800),
        };
        let secs = |v: i32| Duration::from_secs(v.max(1) as u64);
        (secs(refresh), secs(retry), secs(expire))
    }

    /// The first transfer, retried with backoff (250 ms doubling to 10 s)
    /// until it succeeds, as CoreDNS does.
    async fn initial(&self, cancel: &CancellationToken) -> bool {
        let mut backoff = Duration::from_millis(250);
        loop {
            match self.transfer_in().await {
                Ok(()) => return true,
                Err(e) => tracing::warn!("plugin/secondary: all primaries of {} failed to transfer, retrying in {:?}: {}", self.origin, backoff, e),
            }
            tokio::select! {
                _ = cancel.cancelled() => return false,
                _ = tokio::time::sleep(backoff) => {}
                _ = self.kick.notified() => {}
            }
            backoff = (backoff * 2).min(Duration::from_secs(10));
        }
    }

    /// Refresh loop on the SOA timers (CoreDNS's `Update`): check every
    /// `refresh`; after a failed check or transfer, every `retry`; once
    /// `expire` has passed since the last good check, the zone is expired
    /// (SERVFAIL) until a transfer succeeds. NOTIFY checks at once.
    async fn run(self: Arc<Self>, cancel: CancellationToken) {
        if !self.initial(&cancel).await {
            return;
        }
        let mut last_good = tokio::time::Instant::now();
        let mut failing = false;
        loop {
            let (refresh, retry, expire) = self.timers();
            let wait = if failing { retry + jitter(2000) } else { refresh + jitter(5000) };
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(wait) => {}
                _ = self.kick.notified() => {}
            }
            let ok = match self.should_transfer().await {
                Ok(true) => self.transfer_in().await.is_ok(),
                Ok(false) => true,
                Err(e) => {
                    tracing::warn!("plugin/secondary: refresh check of {} failed: {}", self.origin, e);
                    false
                }
            };
            if ok {
                failing = false;
                last_good = tokio::time::Instant::now();
            } else {
                failing = true;
                if last_good.elapsed() >= expire && !self.expired.swap(true, Ordering::Relaxed) {
                    tracing::error!("plugin/secondary: zone {} expired: no good refresh in {:?}; answering SERVFAIL", self.origin, expire);
                }
            }
        }
    }
}

#[async_trait]
impl Handler for Secondary {
    fn name(&self) -> &'static str {
        "secondary"
    }

    fn transfer(&self, zone: &str) -> Option<Vec<Record>> {
        let sz = self.zones.iter().find(|z| z.origin == zone)?;
        if sz.expired.load(Ordering::Relaxed) {
            return None;
        }
        sz.zone.load().as_ref().map(|z| z.all_records())
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let qname = req.name();
        let Some(z) = crate::plugin::zones_match(&self.names, &qname) else {
            return next.serve(req).await;
        };
        let sz = self.zones.iter().find(|s| s.origin == z).unwrap();
        if req.msg.op_code() == OpCode::Notify {
            if sz.primaries.iter().any(|p| p.ip() == req.ip()) {
                sz.kick.notify_one();
            }
            return Ok(Reply::Msg(req.new_reply()));
        }
        match sz.zone.load().as_ref() {
            Some(_) if sz.expired.load(Ordering::Relaxed) => Ok(Reply::Msg({
                // expired: SERVFAIL, as CoreDNS
                let mut m = req.new_reply();
                m.set_response_code(ResponseCode::ServFail);
                m
            })),
            Some(zone) => Ok(Reply::Msg(zone.lookup(req, true).await)),
            None => {
                // not transferred yet: SERVFAIL like CoreDNS
                let mut m = req.new_reply();
                m.set_response_code(ResponseCode::ServFail);
                Ok(Reply::Msg(m))
            }
        }
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut zones: Vec<Arc<SecondaryZone>> = Vec::new();
    while c.next() {
        let args = c.remaining_args_until_brace();
        let origins = c.origins_from_args_or_server_block(&args)?;
        let mut primaries: Vec<SocketAddr> = Vec::new();
        while c.next_block() {
            match c.val() {
                "transfer" => {
                    let a = c.remaining_args();
                    if a.len() < 2 || a[0] != "from" {
                        return Err(c.errf("transfer from ADDRESS... expected"));
                    }
                    for h in &a[1..] {
                        let hp = dnsutil::host_port(h, 53)?;
                        primaries.push(hp.parse().map_err(|_| c.errf(format!("primary {} is not an IP address", h)))?);
                    }
                }
                "upstream" => {
                    let _ = c.remaining_args();
                }
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        if primaries.is_empty() {
            return Err(c.errf("secondary: 'transfer from' is required"));
        }
        for o in origins {
            zones.push(Arc::new(SecondaryZone::new(o, primaries.clone())));
        }
    }
    let names = zones.iter().map(|z| z.origin.clone()).collect();
    c.add_plugin(Arc::new(Secondary { zones: zones.clone(), names }));
    // the refresh tasks stop on shutdown, so a reload does not leak them
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    c.on_shutdown(Box::new(move || {
        Box::pin(async move {
            stop.cancel();
            Ok(())
        })
    }));
    c.on_startup(Box::new(move || {
        Box::pin(async move {
            for z in zones {
                tokio::spawn(z.run(cancel.clone()));
            }
            Ok(())
        })
    }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, SOA};
    use std::sync::atomic::AtomicU32;

    #[test]
    fn serial_arithmetic() {
        assert!(serial_less(1, 2));
        assert!(!serial_less(2, 1), "an older primary serial is not a newer zone");
        assert!(!serial_less(5, 5));
        assert!(serial_less(u32::MAX, 0), "wraps around");
        assert!(serial_less(4_000_000_000, 100));
        assert!(!serial_less(100, 4_000_000_000));
    }

    /// A primary for example.org. (refresh 1s, retry 1s, expire 3s) that
    /// answers SOA and AXFR over TCP with `serial`, or drops connections
    /// while `up` is false.
    async fn fake_primary(serial: Arc<AtomicU32>, up: Arc<AtomicBool>) -> SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                if !up.load(Ordering::SeqCst) {
                    continue;
                }
                let serial = serial.load(Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    if c.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
                    if c.read_exact(&mut buf).await.is_err() {
                        return;
                    }
                    let q = Message::from_bytes(&buf).unwrap();
                    let n = |s: &str| Name::from_ascii(s).unwrap();
                    let soa = Record::from_rdata(n("example.org."), 60, RData::SOA(SOA::new(n("ns.example.org."), n("h.example.org."), serial, 1, 1, 3, 60)));
                    let mut m = Message::new();
                    m.set_id(q.id());
                    m.set_message_type(MessageType::Response);
                    m.add_query(q.queries()[0].clone());
                    m.add_answer(soa.clone());
                    if q.queries()[0].query_type() == RecordType::AXFR {
                        m.add_answer(Record::from_rdata(n("www.example.org."), 60, RData::A(A::new(192, 0, 2, 1))));
                        m.add_answer(soa);
                    }
                    let wire = m.to_vec().unwrap();
                    let _ = c.write_all(&(wire.len() as u16).to_be_bytes()).await;
                    let _ = c.write_all(&wire).await;
                });
            }
        });
        addr
    }

    async fn until(what: &str, f: impl Fn() -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while !f() {
            assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {}", what);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[tokio::test]
    async fn refresh_retry_expire() {
        let (serial, up) = (Arc::new(AtomicU32::new(1)), Arc::new(AtomicBool::new(false)));
        let addr = fake_primary(serial.clone(), up.clone()).await;
        let z = Arc::new(SecondaryZone::new("example.org.".into(), vec![addr]));
        let cancel = CancellationToken::new();
        let task = tokio::spawn(z.clone().run(cancel.clone()));
        let cur = |z: &SecondaryZone| z.zone.load().as_ref().map(|z| z.serial);
        // the first transfer keeps retrying until the primary is up
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(cur(&z), None);
        up.store(true, Ordering::SeqCst);
        until("initial transfer", || cur(&z) == Some(1)).await;
        // a newer serial is transferred (NOTIFY checks at once)
        serial.store(2, Ordering::SeqCst);
        z.kick.notify_one();
        until("serial 2", || cur(&z) == Some(2)).await;
        // an older serial is not a downgrade
        serial.store(1, Ordering::SeqCst);
        z.kick.notify_one();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(cur(&z), Some(2));
        // primary gone: retries every `retry`, expired after `expire` (3s)
        up.store(false, Ordering::SeqCst);
        z.kick.notify_one();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!z.expired.load(Ordering::SeqCst), "not expired before `expire`");
        until("expired", || z.expired.load(Ordering::SeqCst)).await;
        let s = Secondary { zones: vec![z.clone()], names: vec!["example.org.".into()] };
        let mut req = Request::for_test("www.example.org.", RecordType::A);
        let m = s.serve_dns(&mut req, Next::new(&[])).await.unwrap().into_msg().unwrap();
        assert_eq!(m.response_code(), ResponseCode::ServFail, "expired zone is SERVFAIL");
        assert!(s.transfer("example.org.").is_none(), "no AXFR out of an expired zone");
        // primary back (same serial): an expired zone is transferred again
        up.store(true, Ordering::SeqCst);
        until("recovered", || !z.expired.load(Ordering::SeqCst)).await;
        let mut req = Request::for_test("www.example.org.", RecordType::A);
        let m = s.serve_dns(&mut req, Next::new(&[])).await.unwrap().into_msg().unwrap();
        assert_eq!(m.answers().len(), 1);
        // shutdown stops the loop
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(10), task).await.expect("the refresh task stops").unwrap();
    }
}
