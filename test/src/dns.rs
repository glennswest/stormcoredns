//! A DNS client with nothing in the way: one query, UDP or TCP, optional
//! EDNS, the reply as a parsed message. No resolver library, no retries it
//! does not report, no cache of its own.

use anyhow::{anyhow, bail, Context, Result};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Udp,
    Tcp,
}

static NEXT_ID: AtomicU16 = AtomicU16::new(0);

fn next_id() -> u16 {
    let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos() as u16).unwrap_or(1);
    NEXT_ID.fetch_add(1, Ordering::Relaxed).wrapping_add(seed)
}

/// Build a query. `edns` is the advertised UDP size, or no OPT record.
pub fn build(name: &str, qtype: RecordType, edns: Option<u16>) -> Result<Message> {
    let mut m = Message::new();
    m.set_id(next_id()).set_message_type(MessageType::Query).set_op_code(OpCode::Query).set_recursion_desired(true);
    let n = Name::from_ascii(name).with_context(|| format!("bad name {name}"))?;
    m.add_query(Query::query(n, qtype));
    if let Some(size) = edns {
        let mut e = Edns::new();
        e.set_max_payload(size);
        m.set_edns(e);
    }
    Ok(m)
}

/// One query, one answer (or a timeout).
pub async fn query(server: SocketAddr, name: &str, qtype: RecordType, proto: Proto, edns: Option<u16>, timeout: Duration) -> Result<Message> {
    let q = build(name, qtype, edns)?;
    let wire = q.to_vec()?;
    let reply = match proto {
        Proto::Udp => exchange_udp(server, &wire, q.id(), timeout).await?,
        Proto::Tcp => exchange_tcp(server, &wire, timeout).await?,
    };
    let m = Message::from_vec(&reply).context("unparsable reply")?;
    if m.id() != q.id() {
        bail!("reply id {} does not match query id {}", m.id(), q.id());
    }
    Ok(m)
}

/// UDP with one retransmit: the first try gets `timeout`, the retry the same.
pub async fn query_udp_retry(server: SocketAddr, name: &str, qtype: RecordType, timeout: Duration) -> Result<Message> {
    match query(server, name, qtype, Proto::Udp, None, timeout).await {
        Ok(m) => Ok(m),
        Err(_) => query(server, name, qtype, Proto::Udp, None, timeout).await,
    }
}

/// Send raw bytes over UDP and return whatever comes back, if anything.
pub async fn exchange_udp(server: SocketAddr, wire: &[u8], id: u16, timeout: Duration) -> Result<Vec<u8>> {
    let local: SocketAddr = if server.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let sock = UdpSocket::bind(local).await?;
    sock.connect(server).await?;
    sock.send(wire).await?;
    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; 65535];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let n = tokio::time::timeout(left, sock.recv(&mut buf)).await.map_err(|_| anyhow!("no UDP reply from {server} within {timeout:?}"))??;
        // Ignore anything that is not an answer to this query.
        if n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == id {
            return Ok(buf[..n].to_vec());
        }
    }
}

async fn exchange_tcp(server: SocketAddr, wire: &[u8], timeout: Duration) -> Result<Vec<u8>> {
    tokio::time::timeout(timeout, async {
        let mut s = TcpStream::connect(server).await.with_context(|| format!("TCP connect to {server}"))?;
        let mut out = Vec::with_capacity(wire.len() + 2);
        out.extend_from_slice(&(wire.len() as u16).to_be_bytes());
        out.extend_from_slice(wire);
        s.write_all(&out).await?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await?;
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut buf).await?;
        Ok::<_, anyhow::Error>(buf)
    })
    .await
    .map_err(|_| anyhow!("no TCP reply from {server} within {timeout:?}"))?
}

// ── reading replies ─────────────────────────────────────────────────────────

pub fn rcode(m: &Message) -> ResponseCode {
    m.response_code()
}

/// The addresses in the answer section, sorted and without duplicates.
pub fn addrs(m: &Message) -> Vec<IpAddr> {
    let mut v: Vec<IpAddr> = m
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            Some(RData::A(a)) => Some(IpAddr::V4(a.0)),
            Some(RData::AAAA(a)) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

/// SRV answers as (port, target), sorted and without duplicates.
pub fn srvs(m: &Message) -> Vec<(u16, String)> {
    let mut v: Vec<(u16, String)> = m
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            Some(RData::SRV(s)) => Some((s.port(), lower(s.target()))),
            _ => None,
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

pub fn ptrs(m: &Message) -> Vec<String> {
    m.answers().iter().filter_map(|r| match r.data() { Some(RData::PTR(p)) => Some(lower(&p.0)), _ => None }).collect()
}

pub fn cnames(m: &Message) -> Vec<String> {
    m.answers().iter().filter_map(|r| match r.data() { Some(RData::CNAME(c)) => Some(lower(&c.0)), _ => None }).collect()
}

pub fn txts(m: &Message) -> Vec<String> {
    m.answers()
        .iter()
        .filter_map(|r| match r.data() {
            Some(RData::TXT(t)) => Some(t.txt_data().iter().map(|b| String::from_utf8_lossy(b).into_owned()).collect::<String>()),
            _ => None,
        })
        .collect()
}

pub fn has_type(records: &[hickory_proto::rr::Record], t: RecordType) -> bool {
    records.iter().any(|r| r.record_type() == t)
}

pub fn lower(n: &Name) -> String {
    n.to_ascii().to_lowercase()
}

/// `1.2.3.4` → `4.3.2.1.in-addr.arpa.`; IPv6 nibble form.
pub fn reverse(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v) => {
            let mut s = String::new();
            for b in v.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", b & 0xf, b >> 4));
            }
            s + "ip6.arpa."
        }
    }
}

/// Short text for a reply, for test details.
pub fn show(m: &Message) -> String {
    let answers: Vec<String> = m.answers().iter().map(|r| format!("{} {} ttl={}", r.record_type(), r.data().map(|d| d.to_string()).unwrap_or_default(), r.ttl())).collect();
    format!("{:?}{} [{}]", rcode(m), if m.truncated() { " TC" } else { "" }, answers.join(", "))
}

/// Ask until `ok` holds or `within` passes. Returns the last reply and how
/// long it took; a transport error counts as "not yet".
pub async fn wait_for<F>(server: SocketAddr, name: &str, qtype: RecordType, proto: Proto, within: Duration, ok: F) -> (Option<Message>, Duration, bool)
where
    F: Fn(&Message) -> bool,
{
    let start = Instant::now();
    let mut last = None;
    loop {
        if let Ok(m) = query(server, name, qtype, proto, None, Duration::from_secs(2)).await {
            if ok(&m) {
                return (Some(m), start.elapsed(), true);
            }
            last = Some(m);
        }
        if start.elapsed() >= within {
            return (last, start.elapsed(), false);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_round_trips() {
        let q = build("web.default.svc.cluster.local.", RecordType::SRV, Some(1232)).unwrap();
        let back = Message::from_vec(&q.to_vec().unwrap()).unwrap();
        assert_eq!(back.id(), q.id());
        assert_eq!(back.queries()[0].query_type(), RecordType::SRV);
        assert_eq!(back.edns().map(|e| e.max_payload()), Some(1232));
        let plain = build("a.", RecordType::A, None).unwrap();
        assert!(plain.edns().is_none());
    }

    #[test]
    fn reverse_names() {
        assert_eq!(reverse("10.96.0.10".parse().unwrap()), "10.0.96.10.in-addr.arpa.");
        assert!(reverse("::1".parse().unwrap()).starts_with("1.0.0.0."));
        assert!(reverse("::1".parse().unwrap()).ends_with(".ip6.arpa."));
    }
}
