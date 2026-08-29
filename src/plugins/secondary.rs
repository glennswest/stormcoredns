//! `secondary` — slaves zones from primaries over AXFR, refreshing on the
//! SOA timers and on NOTIFY.
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
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;

pub struct SecondaryZone {
    pub origin: String,
    pub primaries: Vec<SocketAddr>,
    pub zone: ArcSwapOption<Zone>,
    /// Woken by NOTIFY to refresh immediately.
    pub kick: Notify,
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

/// Query the primary's SOA serial over UDP.
async fn primary_serial(primary: SocketAddr, origin: &str) -> Result<u32> {
    let name = Name::from_ascii(origin)?;
    let mut q = Message::new();
    q.set_id(rand::random());
    q.add_query(Query::query(name, RecordType::SOA));
    let wire = q.to_vec()?;
    let sock = tokio::net::UdpSocket::bind(if primary.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?;
    sock.send_to(&wire, primary).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut buf)).await.map_err(|_| anyhow!("soa query to {}: timeout", primary))??;
    let m = Message::from_bytes(&buf[..n])?;
    m.answers()
        .iter()
        .find_map(|r| match r.data() {
            Some(RData::SOA(s)) => Some(s.serial()),
            _ => None,
        })
        .ok_or_else(|| anyhow!("no SOA in answer from {}", primary))
}

impl SecondaryZone {
    async fn transfer_in(&self) -> Result<()> {
        let mut last_err = None;
        for p in &self.primaries {
            match axfr(*p, &self.origin).await {
                Ok(records) => {
                    let z = Zone::from_records(&self.origin, records)?;
                    tracing::info!("plugin/secondary: transferred zone {} from {} (serial {}, {} records)", self.origin, p, z.serial, z.len());
                    self.zone.store(Some(Arc::new(z)));
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

    /// Refresh loop driven by the SOA timers.
    async fn run(self: Arc<Self>) {
        loop {
            let (refresh, retry, expire) = match self.zone.load().as_ref().and_then(|z| z.soa().cloned()) {
                Some(r) => match r.data() {
                    Some(RData::SOA(s)) => (s.refresh().max(1) as u64, s.retry().max(1) as u64, s.expire() as u64),
                    _ => (3600, 600, 604800),
                },
                None => (0, 60, 0),
            };
            let wait = if self.zone.load().is_none() { retry } else { refresh };
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(wait)) => {}
                _ = self.kick.notified() => {}
            }
            // check the serial first, transfer only when it moved
            let current = self.zone.load().as_ref().map(|z| z.serial);
            let mut need = current.is_none();
            if let Some(cur) = current {
                for p in &self.primaries {
                    match primary_serial(*p, &self.origin).await {
                        Ok(s) if s != cur => {
                            need = true;
                            break;
                        }
                        Ok(_) => break,
                        Err(e) => tracing::debug!("plugin/secondary: {}", e),
                    }
                }
            }
            if need {
                if let Err(e) = self.transfer_in().await {
                    tracing::warn!("plugin/secondary: refresh of {} failed: {}", self.origin, e);
                    let _ = expire;
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
            zones.push(Arc::new(SecondaryZone { origin: o, primaries: primaries.clone(), zone: ArcSwapOption::empty(), kick: Notify::new() }));
        }
    }
    let names = zones.iter().map(|z| z.origin.clone()).collect();
    c.add_plugin(Arc::new(Secondary { zones: zones.clone(), names }));
    c.on_startup(Box::new(move || {
        Box::pin(async move {
            for z in zones {
                let z2 = z.clone();
                tokio::spawn(async move {
                    if let Err(e) = z2.transfer_in().await {
                        tracing::warn!("plugin/secondary: initial transfer of {} failed: {}", z2.origin, e);
                    }
                    z2.run().await;
                });
            }
            Ok(())
        })
    }));
    Ok(())
}
