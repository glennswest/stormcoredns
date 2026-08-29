//! DNS helpers shared by the server and plugins (`plugin/pkg/dnsutil`,
//! `plugin/pkg/parse`, `plugin/pkg/cidr`, `plugin/pkg/transport`).

use anyhow::{anyhow, bail, Result};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

/// EDNS0 buffer size advertised in responses and upstream queries
/// (`dns.DefaultMsgSize`).
pub const UDP_BUFFER_SIZE: u16 = 4096;
/// Minimum UDP message size.
pub const MIN_MSG_SIZE: usize = 512;
/// Maximum message size over stream transports.
pub const MAX_MSG_SIZE: usize = 65535;

/// Lowercase + trailing dot.
pub fn fqdn(s: &str) -> String {
    let mut s = s.to_ascii_lowercase();
    if !s.ends_with('.') {
        s.push('.');
    }
    s
}

/// Is `name` equal to or below `zone`? Both must be FQDNs (lowercase is
/// applied here). `.` matches everything.
pub fn is_subdomain(zone: &str, name: &str) -> bool {
    let zone = zone.to_ascii_lowercase();
    let name = name.to_ascii_lowercase();
    if zone == "." {
        return true;
    }
    if name == zone {
        return true;
    }
    if name.len() > zone.len() && name.ends_with(&zone) {
        // must be on a label boundary
        let idx = name.len() - zone.len();
        return name.as_bytes()[idx - 1] == b'.';
    }
    false
}

/// Number of labels in a FQDN string ("." has 0).
pub fn count_labels(name: &str) -> usize {
    name.trim_end_matches('.').split('.').filter(|l| !l.is_empty()).count()
}

/// Normalise a zone argument: a domain name (lowercased, made FQDN) or a
/// reverse CIDR (`10.0.0.0/8`, `2001:db8::/32`) expanded to one or more
/// `*.arpa.` zones on class/nibble boundaries.
pub fn normalize_zone(s: &str) -> Result<Vec<String>> {
    let s = s.trim();
    if s.is_empty() {
        bail!("empty zone");
    }
    if s == "." {
        return Ok(vec![".".to_string()]);
    }
    if s.contains('/') {
        let net: IpNet = s.parse().map_err(|e| anyhow!("bad reverse zone {}: {}", s, e))?;
        return Ok(reverse_zones_for(&net));
    }
    // A bare IP (e.g. from a Caddy-style host key) is a reverse /32 zone.
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(vec![reverse_name_str(ip)]);
    }
    // validate as a name
    let n = Name::from_ascii(s).map_err(|e| anyhow!("bad zone name {}: {}", s, e))?;
    let mut z = n.to_ascii().to_ascii_lowercase();
    if !z.ends_with('.') {
        z.push('.');
    }
    Ok(vec![z])
}

/// Expand a CIDR into the reverse zones that exactly cover it
/// (`cidr.Split` + `dns.ReverseAddr`).
pub fn reverse_zones_for(net: &IpNet) -> Vec<String> {
    match net {
        IpNet::V4(n) => {
            let p = n.prefix_len();
            let boundary = ((p + 7) / 8) * 8; // 8,16,24,32; 0 → 0 (whole space)
            if boundary == 0 {
                return vec!["in-addr.arpa.".to_string()];
            }
            let subnets: Vec<Ipv4Net> = n.subnets(boundary).map(|it| it.collect()).unwrap_or_else(|_| vec![*n]);
            subnets
                .into_iter()
                .map(|sn| {
                    let o = sn.network().octets();
                    let labels = (boundary / 8) as usize;
                    let mut parts: Vec<String> = o[..labels].iter().map(|b| b.to_string()).collect();
                    parts.reverse();
                    format!("{}.in-addr.arpa.", parts.join("."))
                })
                .collect()
        }
        IpNet::V6(n) => {
            let p = n.prefix_len();
            let boundary = ((p + 3) / 4) * 4;
            if boundary == 0 {
                return vec!["ip6.arpa.".to_string()];
            }
            let subnets: Vec<Ipv6Net> = n.subnets(boundary).map(|it| it.collect()).unwrap_or_else(|_| vec![*n]);
            subnets
                .into_iter()
                .map(|sn| {
                    let o = sn.network().octets();
                    let nibbles = (boundary / 4) as usize;
                    let mut parts: Vec<String> = Vec::with_capacity(nibbles);
                    for i in 0..nibbles {
                        let b = o[i / 2];
                        let nib = if i % 2 == 0 { b >> 4 } else { b & 0xf };
                        parts.push(format!("{:x}", nib));
                    }
                    parts.reverse();
                    format!("{}.ip6.arpa.", parts.join("."))
                })
                .collect()
        }
    }
}

/// `dns.ReverseAddr` as a string with trailing dot.
pub fn reverse_name_str(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            let mut parts = Vec::with_capacity(32);
            for b in o.iter().rev() {
                parts.push(format!("{:x}", b & 0xf));
                parts.push(format!("{:x}", b >> 4));
            }
            format!("{}.ip6.arpa.", parts.join("."))
        }
    }
}

pub fn reverse_name(ip: IpAddr) -> Name {
    Name::from_ascii(reverse_name_str(ip)).expect("reverse name is valid")
}

/// `dnsutil.ExtractAddressFromReverse`: the IP encoded in a full reverse
/// name, or `None` if the name is not a complete `*.arpa.` address.
pub fn extract_address_from_reverse(name: &str) -> Option<IpAddr> {
    let n = name.to_ascii_lowercase();
    if let Some(rest) = n.strip_suffix(".in-addr.arpa.") {
        let parts: Vec<&str> = rest.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        let mut o = [0u8; 4];
        for (i, p) in parts.iter().rev().enumerate() {
            o[i] = p.parse().ok()?;
        }
        return Some(IpAddr::V4(Ipv4Addr::from(o)));
    }
    if let Some(rest) = n.strip_suffix(".ip6.arpa.") {
        let parts: Vec<&str> = rest.split('.').collect();
        if parts.len() != 32 {
            return None;
        }
        let mut o = [0u8; 16];
        for (i, p) in parts.iter().rev().enumerate() {
            let v = u8::from_str_radix(p, 16).ok()?;
            if p.len() != 1 {
                return None;
            }
            if i % 2 == 0 {
                o[i / 2] |= v << 4;
            } else {
                o[i / 2] |= v;
            }
        }
        return Some(IpAddr::V6(Ipv6Addr::from(o)));
    }
    None
}

/// `dnsutil.IsReverse`: 1 for in-addr.arpa, 2 for ip6.arpa, 0 otherwise.
pub fn is_reverse(name: &str) -> u8 {
    let n = name.to_ascii_lowercase();
    if n.ends_with(".in-addr.arpa.") || n == "in-addr.arpa." {
        1
    } else if n.ends_with(".ip6.arpa.") || n == "ip6.arpa." {
        2
    } else {
        0
    }
}

/// An upstream address as parsed from a Corefile argument.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Upstream {
    pub transport: UpstreamTransport,
    pub addr: String, // host:port
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpstreamTransport {
    Dns,
    Tls,
    Https,
    Quic,
    Grpc,
}

impl UpstreamTransport {
    pub fn default_port(&self) -> u16 {
        match self {
            UpstreamTransport::Dns => 53,
            UpstreamTransport::Tls => 853,
            UpstreamTransport::Https => 443,
            UpstreamTransport::Quic => 853,
            UpstreamTransport::Grpc => 443,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            UpstreamTransport::Dns => "dns",
            UpstreamTransport::Tls => "tls",
            UpstreamTransport::Https => "https",
            UpstreamTransport::Quic => "quic",
            UpstreamTransport::Grpc => "grpc",
        }
    }
}

/// `transport.Parse` + `parse.HostPort`: `[scheme://]host[:port]` →
/// upstream with a port filled in.
pub fn parse_upstream(s: &str) -> Result<Upstream> {
    let (t, rest) = match s.find("://") {
        Some(i) => {
            let t = match &s[..i] {
                "dns" => UpstreamTransport::Dns,
                "tls" => UpstreamTransport::Tls,
                "https" => UpstreamTransport::Https,
                "quic" => UpstreamTransport::Quic,
                "grpc" => UpstreamTransport::Grpc,
                o => bail!("not a valid transport: {}", o),
            };
            (t, &s[i + 3..])
        }
        None => (UpstreamTransport::Dns, s),
    };
    let addr = host_port(rest, t.default_port())?;
    Ok(Upstream { transport: t, addr })
}

/// Add a default port to a host if it has none. Handles `[v6]:port`, bare
/// v6 addresses, and `host:port`.
pub fn host_port(s: &str, default_port: u16) -> Result<String> {
    if s.is_empty() {
        bail!("empty host");
    }
    if let Some(rest) = s.strip_prefix('[') {
        // [v6]:port or [v6]
        let end = rest.find(']').ok_or_else(|| anyhow!("bad address {}", s))?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            p.parse::<u16>().map_err(|_| anyhow!("bad port in {}", s))?
        } else if after.is_empty() {
            default_port
        } else {
            bail!("bad address {}", s);
        };
        host.parse::<Ipv6Addr>().map_err(|_| anyhow!("bad IPv6 address {}", host))?;
        return Ok(format!("[{}]:{}", host, port));
    }
    if s.parse::<Ipv6Addr>().is_ok() {
        return Ok(format!("[{}]:{}", s, default_port));
    }
    match s.rfind(':') {
        Some(i) => {
            let host = &s[..i];
            let port = s[i + 1..].parse::<u16>().map_err(|_| anyhow!("bad port in {}", s))?;
            if host.is_empty() {
                bail!("empty host in {}", s);
            }
            Ok(format!("{}:{}", host, port))
        }
        None => Ok(format!("{}:{}", s, default_port)),
    }
}

/// `parse.HostPortOrFile`: each arg is an upstream or a resolv.conf-style
/// file whose `nameserver` lines are used.
pub fn parse_host_port_or_file(args: &[String]) -> Result<Vec<Upstream>> {
    let mut out = Vec::new();
    for a in args {
        match parse_upstream(a) {
            Ok(u) if is_ip_host(&u.addr) => out.push(u),
            _ => {
                // try as file
                let text = std::fs::read_to_string(a).map_err(|_| anyhow!("not an IP address or file: {}", a))?;
                let mut found = false;
                for line in text.lines() {
                    let line = line.trim();
                    if let Some(rest) = line.strip_prefix("nameserver") {
                        let ns = rest.trim();
                        if ns.is_empty() {
                            continue;
                        }
                        if let Ok(u) = parse_upstream(ns) {
                            out.push(u);
                            found = true;
                        }
                    }
                }
                if !found {
                    bail!("no nameservers found in {}", a);
                }
            }
        }
    }
    Ok(out)
}

fn is_ip_host(hostport: &str) -> bool {
    hostport.parse::<SocketAddr>().is_ok()
}

/// Go-style duration ("5s", "1m30s", "500ms", "2h") or bare seconds.
pub fn parse_duration(s: &str) -> Result<Duration> {
    if let Ok(secs) = s.parse::<u64>() {
        return Ok(Duration::from_secs(secs));
    }
    if let Ok(f) = s.parse::<f64>() {
        return Ok(Duration::from_secs_f64(f));
    }
    humantime::parse_duration(s).map_err(|e| anyhow!("invalid duration '{}': {}", s, e))
}

/// Encode a response respecting the client's size limit; hickory sets the
/// TC bit and drops sections that do not fit (`request.Scrub`).
pub fn encode_with_limit(msg: &Message, max: usize) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    {
        let mut enc = BinEncoder::new(&mut buf);
        enc.set_max_size(max.min(MAX_MSG_SIZE) as u16);
        msg.emit(&mut enc).map_err(|e| anyhow!("encoding response: {}", e))?;
    }
    Ok(buf)
}

/// Remove exact duplicate records from a list, keeping order.
pub fn dedup(records: Vec<Record>) -> Vec<Record> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(records.len());
    for r in records {
        let key = format!("{}", r);
        if seen.insert(key) {
            out.push(r);
        }
    }
    out
}

/// `dnsutil.MinimalTTL`: the smallest TTL in the message, considering the
/// SOA minimum for negative answers.
pub fn minimal_ttl(m: &Message, negative: bool) -> Duration {
    let mut min = u32::MAX;
    let mut found = false;
    for r in m.answers().iter().chain(m.name_servers()).chain(m.additionals()) {
        if r.record_type() == RecordType::OPT {
            continue;
        }
        if negative {
            if let Some(RData::SOA(soa)) = r.data() {
                let t = r.ttl().min(soa.minimum());
                return Duration::from_secs(t as u64);
            }
        }
        found = true;
        if r.ttl() < min {
            min = r.ttl();
        }
    }
    if !found {
        return Duration::from_secs(if negative { 1800 } else { 3600 }).min(Duration::from_secs(5));
    }
    Duration::from_secs(min as u64)
}

/// True if the message has an OPT record.
pub fn has_opt(m: &Message) -> bool {
    m.edns().is_some()
}

/// Make an rcode-only error reply for `req` (server-side, no plugin).
pub fn error_reply(req: &Message, rcode: ResponseCode) -> Message {
    let mut m = Message::new();
    m.set_id(req.id());
    m.set_message_type(hickory_proto::op::MessageType::Response);
    m.set_op_code(req.op_code());
    m.set_recursion_desired(req.recursion_desired());
    m.set_response_code(rcode);
    if let Some(q) = req.queries().first() {
        m.add_query(q.clone());
    }
    if let Some(e) = req.edns() {
        let mut ne = hickory_proto::op::Edns::new();
        ne.set_max_payload(UDP_BUFFER_SIZE);
        ne.set_dnssec_ok(e.dnssec_ok());
        m.set_edns(ne);
    }
    m
}

/// `dnsutil.TrimZone`: strip `zone` from the end of `name`, returning the
/// relative part (without trailing dot) or None if not a subdomain.
pub fn trim_zone(name: &str, zone: &str) -> Option<String> {
    if !is_subdomain(zone, name) {
        return None;
    }
    if zone == "." {
        return Some(name.trim_end_matches('.').to_string());
    }
    let n = name.to_ascii_lowercase();
    let z = zone.to_ascii_lowercase();
    if n == z {
        return Some(String::new());
    }
    Some(n[..n.len() - z.len() - 1].to_string())
}

/// Join a relative label sequence and a zone into a FQDN.
pub fn join(labels: &[&str], zone: &str) -> String {
    let mut s = String::new();
    for l in labels {
        if l.is_empty() {
            continue;
        }
        s.push_str(l);
        s.push('.');
    }
    if zone == "." {
        if s.is_empty() {
            return ".".into();
        }
        return s;
    }
    s.push_str(zone.trim_start_matches('.'));
    if !s.ends_with('.') {
        s.push('.');
    }
    s
}

/// Parse a record type name ("A", "AAAA", "TYPE65").
pub fn record_type_from_str(s: &str) -> Result<RecordType> {
    RecordType::from_str(&s.to_ascii_uppercase()).map_err(|e| anyhow!("unknown record type {}: {}", s, e))
}

/// Name as a lowercase FQDN string.
pub fn name_str(n: &Name) -> String {
    let mut s = n.to_ascii().to_ascii_lowercase();
    if !s.ends_with('.') {
        s.push('.');
    }
    s
}

pub fn name_from_str(s: &str) -> Result<Name> {
    Name::from_ascii(s).map_err(|e| anyhow!("bad name {}: {}", s, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subdomains() {
        assert!(is_subdomain(".", "a.b."));
        assert!(is_subdomain("b.", "a.b."));
        assert!(is_subdomain("a.b.", "a.b."));
        assert!(!is_subdomain("ab.", "a.b."));
        assert!(!is_subdomain("xa.b.", "a.b."));
        assert!(is_subdomain("Example.ORG.", "www.example.org."));
    }

    #[test]
    fn reverse_zones() {
        assert_eq!(normalize_zone("10.0.0.0/8").unwrap(), vec!["10.in-addr.arpa."]);
        assert_eq!(normalize_zone("192.168.1.0/24").unwrap(), vec!["1.168.192.in-addr.arpa."]);
        assert_eq!(normalize_zone("10.0.0.0/15").unwrap(), vec!["0.10.in-addr.arpa.", "1.10.in-addr.arpa."]);
        assert_eq!(normalize_zone("2001:db8::/32").unwrap(), vec!["8.b.d.0.1.0.0.2.ip6.arpa."]);
        assert_eq!(reverse_name_str("192.0.2.1".parse().unwrap()), "1.2.0.192.in-addr.arpa.");
        assert_eq!(
            extract_address_from_reverse("1.2.0.192.in-addr.arpa."),
            Some("192.0.2.1".parse().unwrap())
        );
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(extract_address_from_reverse(&reverse_name_str(v6)), Some(v6));
    }

    #[test]
    fn upstreams() {
        assert_eq!(parse_upstream("8.8.8.8").unwrap().addr, "8.8.8.8:53");
        let u = parse_upstream("tls://1.1.1.1").unwrap();
        assert_eq!((u.transport, u.addr.as_str()), (UpstreamTransport::Tls, "1.1.1.1:853"));
        assert_eq!(parse_upstream("[::1]:5353").unwrap().addr, "[::1]:5353");
        assert_eq!(parse_upstream("::1").unwrap().addr, "[::1]:53");
        assert_eq!(parse_upstream("https://dns.google").unwrap().addr, "dns.google:443");
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_duration("30").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("1m30s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
    }

    #[test]
    fn trim() {
        assert_eq!(trim_zone("www.example.org.", "example.org.").unwrap(), "www");
        assert_eq!(trim_zone("example.org.", "example.org.").unwrap(), "");
        assert!(trim_zone("example.com.", "example.org.").is_none());
        assert_eq!(join(&["www"], "example.org."), "www.example.org.");
        assert_eq!(join(&[], "example.org."), "example.org.");
    }
}
