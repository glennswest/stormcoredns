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

/// The longest a cache may hold one reply: its smallest answer TTL, or for
/// a negative reply the SOA's min(TTL, MINIMUM) (RFC 2308), as `cache`
/// computes it. A reply with neither is not cacheable.
pub fn cache_ttl(m: &Message) -> u32 {
    if let Some(t) = m.answers().iter().map(|r| r.ttl()).min() {
        return t;
    }
    m.name_servers()
        .iter()
        .find_map(|r| match r.data() {
            Some(RData::SOA(soa)) => Some(r.ttl().min(soa.minimum())),
            _ => None,
        })
        .unwrap_or(0)
}

/// Upper bound on the cache allowance, so a bogus TTL cannot stall a run.
pub const MAX_CACHE_WAIT: Duration = Duration::from_secs(300);

/// When `wait_for` gives up, given the replies so far: `within` after the
/// start, or later if a reply seen by then may be cached until later. Only
/// replies seen up to `within` count: the plugin must be right by then, and
/// a cache in front of it (stormcos runs `cache 30`, as upstream CoreDNS
/// would) gets to finish the TTL of whatever it held. A refill after that
/// is the plugin itself still answering the old way, and does not extend it.
fn extend_limit(limit: Duration, within: Duration, at: Duration, ttl: u32) -> Duration {
    if at > within {
        return limit;
    }
    let held = Duration::from_secs(u64::from(ttl)).min(MAX_CACHE_WAIT);
    limit.max(at + held + Duration::from_secs(1))
}

/// Ask until `ok` holds or `within` passes, plus the rest of the TTL of a
/// reply a cache may still be holding at `within` (see `extend_limit`).
/// Returns the last reply and how long it took; a transport error counts as
/// "not yet".
pub async fn wait_for<F>(server: SocketAddr, name: &str, qtype: RecordType, proto: Proto, within: Duration, ok: F) -> (Option<Message>, Duration, bool)
where
    F: Fn(&Message) -> bool,
{
    let start = Instant::now();
    let mut last = None;
    let mut limit = within;
    loop {
        if let Ok(m) = query(server, name, qtype, proto, None, Duration::from_secs(2)).await {
            if ok(&m) {
                return (Some(m), start.elapsed(), true);
            }
            limit = extend_limit(limit, within, start.elapsed(), cache_ttl(&m));
            last = Some(m);
        }
        if start.elapsed() >= limit {
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

    #[test]
    fn cache_allowance() {
        let s = Duration::from_secs;
        // A negative answer cached at 1 s with TTL 30 is held until 31 s.
        assert_eq!(extend_limit(s(30), s(30), s(1), 30), s(32));
        // Seen after `within`: a refill from the plugin, no extension.
        assert_eq!(extend_limit(s(30), s(30), s(31), 30), s(30));
        // Never shorter than `within`, and capped.
        assert_eq!(extend_limit(s(30), s(30), s(2), 5), s(30));
        assert_eq!(extend_limit(s(30), s(30), s(0), 86400), MAX_CACHE_WAIT + s(1));
    }

    #[test]
    fn cache_ttl_of_replies() {
        use hickory_proto::rr::rdata::{A, SOA};
        use hickory_proto::rr::Record;
        let n = Name::from_ascii("x.cluster.local.").unwrap();
        let mut pos = Message::new();
        pos.add_answer(Record::from_rdata(n.clone(), 30, RData::A(A::new(10, 0, 0, 1))));
        pos.add_answer(Record::from_rdata(n.clone(), 12, RData::A(A::new(10, 0, 0, 2))));
        assert_eq!(cache_ttl(&pos), 12);
        let mut neg = Message::new();
        let soa = SOA::new(Name::from_ascii("ns.dns.cluster.local.").unwrap(), Name::from_ascii("hostmaster.cluster.local.").unwrap(), 1, 7200, 1800, 86400, 5);
        neg.add_name_server(Record::from_rdata(Name::from_ascii("cluster.local.").unwrap(), 30, RData::SOA(soa)));
        assert_eq!(cache_ttl(&neg), 5);
        assert_eq!(cache_ttl(&Message::new()), 0);
    }
}
