//! `plugin/pkg/replacer`: expands `{placeholders}` in log formats.

use super::{Reply, Request};
use hickory_proto::op::Message;
use std::time::Duration;

pub const COMMON_LOG_FORMAT: &str = "{remote}:{port} - {>id} \"{type} {class} {name} {proto} {size} {>do} {>bufsize}\" {rcode} {>rflags} {rsize} {duration}";
pub const COMBINED_LOG_FORMAT: &str = "{remote}:{port} - {>id} \"{type} {class} {name} {proto} {size} {>do} {>bufsize}\" {rcode} {>rflags} {rsize} {duration} \"{>opcode}\"";
pub const COMMON_LOG_EMPTY: &str = "-";

/// A parsed format: literal segments interleaved with placeholders.
#[derive(Debug, Clone)]
pub struct Replacer {
    parts: Vec<Part>,
}

#[derive(Debug, Clone)]
enum Part {
    Lit(String),
    Ph(String),
}

impl Replacer {
    pub fn new(format: &str) -> Self {
        let format = format.replace("{common}", COMMON_LOG_FORMAT).replace("{combined}", COMBINED_LOG_FORMAT);
        let mut parts = Vec::new();
        let mut lit = String::new();
        let mut rest = format.as_str();
        while let Some(i) = rest.find('{') {
            lit.push_str(&rest[..i]);
            let after = &rest[i + 1..];
            match after.find('}') {
                Some(j) => {
                    if !lit.is_empty() {
                        parts.push(Part::Lit(std::mem::take(&mut lit)));
                    }
                    parts.push(Part::Ph(after[..j].to_string()));
                    rest = &after[j + 1..];
                }
                None => {
                    lit.push('{');
                    rest = after;
                }
            }
        }
        lit.push_str(rest);
        if !lit.is_empty() {
            parts.push(Part::Lit(lit));
        }
        Replacer { parts }
    }

    pub fn replace(&self, req: &Request, reply: Option<&Reply>, err_rcode: Option<hickory_proto::op::ResponseCode>) -> String {
        let mut out = String::new();
        for p in &self.parts {
            match p {
                Part::Lit(s) => out.push_str(s),
                Part::Ph(k) => out.push_str(&placeholder(k, req, reply, err_rcode)),
            }
        }
        out
    }
}

fn flags(m: &Message) -> String {
    let h = m.header();
    let mut f = Vec::new();
    if h.message_type() == hickory_proto::op::MessageType::Response {
        f.push("qr");
    }
    if h.authoritative() {
        f.push("aa");
    }
    if h.truncated() {
        f.push("tc");
    }
    if h.recursion_desired() {
        f.push("rd");
    }
    if h.recursion_available() {
        f.push("ra");
    }
    if h.authentic_data() {
        f.push("ad");
    }
    if h.checking_disabled() {
        f.push("cd");
    }
    if m.edns().map(|e| e.dnssec_ok()).unwrap_or(false) {
        f.push("do");
    }
    f.join(",")
}

fn placeholder(k: &str, req: &Request, reply: Option<&Reply>, err_rcode: Option<hickory_proto::op::ResponseCode>) -> String {
    let msg = reply.and_then(|r| r.msg());
    match k {
        "type" => req.type_str(),
        "name" => req.name_uncached(),
        "class" => req.class_str(),
        "proto" => req.proto_str().to_string(),
        "size" => req.len().to_string(),
        "remote" => addr_str(req.ip()),
        "port" => req.port().to_string(),
        "local" => addr_str(req.local_ip()),
        "local_port" => req.local_port().to_string(),
        "when" => chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "rcode" => match (msg, reply, err_rcode) {
            (Some(m), _, _) => rcode_str(m.response_code()),
            (None, Some(r), _) => rcode_str(r.rcode()),
            (None, None, Some(rc)) => rcode_str(rc),
            _ => COMMON_LOG_EMPTY.into(),
        },
        "rsize" => msg.map(|m| m.to_vec().map(|v| v.len()).unwrap_or(0).to_string()).unwrap_or_else(|| COMMON_LOG_EMPTY.into()),
        "duration" => format_duration(req.start.elapsed()),
        ">id" => req.msg.id().to_string(),
        ">opcode" => opcode_str(req.msg.op_code()),
        ">do" => req.do_bit().to_string(),
        ">bufsize" => req.size().to_string(),
        ">rflags" => msg.map(flags).unwrap_or_else(|| COMMON_LOG_EMPTY.into()),
        "server" => req.server.clone(),
        "zone" => req.zone.clone(),
        "view" => req.view.clone(),
        _ if k.starts_with('/') => req.metadata.value(&k[1..]).unwrap_or_else(|| COMMON_LOG_EMPTY.into()),
        _ => format!("{{{}}}", k),
    }
}

fn addr_str(ip: std::net::IpAddr) -> String {
    ip.to_string()
}

pub fn rcode_str(rc: hickory_proto::op::ResponseCode) -> String {
    use hickory_proto::op::ResponseCode::*;
    match rc {
        NoError => "NOERROR".into(),
        FormErr => "FORMERR".into(),
        ServFail => "SERVFAIL".into(),
        NXDomain => "NXDOMAIN".into(),
        NotImp => "NOTIMP".into(),
        Refused => "REFUSED".into(),
        YXDomain => "YXDOMAIN".into(),
        YXRRSet => "YXRRSET".into(),
        NXRRSet => "NXRRSET".into(),
        NotAuth => "NOTAUTH".into(),
        NotZone => "NOTZONE".into(),
        BADVERS => "BADVERS".into(),
        BADSIG => "BADSIG".into(),
        BADKEY => "BADKEY".into(),
        BADTIME => "BADTIME".into(),
        BADMODE => "BADMODE".into(),
        BADNAME => "BADNAME".into(),
        BADALG => "BADALG".into(),
        BADTRUNC => "BADTRUNC".into(),
        BADCOOKIE => "BADCOOKIE".into(),
        other => format!("RCODE{}", u16::from(other)),
    }
}

/// Parse an rcode name as used in Corefiles ("NXDOMAIN", "SERVFAIL"...).
pub fn rcode_from_str(s: &str) -> Option<hickory_proto::op::ResponseCode> {
    use hickory_proto::op::ResponseCode::*;
    Some(match s.to_ascii_uppercase().as_str() {
        "NOERROR" => NoError,
        "FORMERR" => FormErr,
        "SERVFAIL" => ServFail,
        "NXDOMAIN" => NXDomain,
        "NOTIMP" => NotImp,
        "REFUSED" => Refused,
        "YXDOMAIN" => YXDomain,
        "YXRRSET" => YXRRSet,
        "NXRRSET" => NXRRSet,
        "NOTAUTH" => NotAuth,
        "NOTZONE" => NotZone,
        "BADVERS" => BADVERS,
        "BADSIG" => BADSIG,
        "BADKEY" => BADKEY,
        "BADTIME" => BADTIME,
        "BADMODE" => BADMODE,
        "BADNAME" => BADNAME,
        "BADALG" => BADALG,
        "BADTRUNC" => BADTRUNC,
        "BADCOOKIE" => BADCOOKIE,
        _ => return None,
    })
}

pub fn opcode_str(op: hickory_proto::op::OpCode) -> String {
    match op {
        hickory_proto::op::OpCode::Query => "QUERY".into(),
        hickory_proto::op::OpCode::Status => "STATUS".into(),
        hickory_proto::op::OpCode::Notify => "NOTIFY".into(),
        hickory_proto::op::OpCode::Update => "UPDATE".into(),
    }
}

/// Go-style duration formatting: `1.234567ms`, `2.5s`.
pub fn format_duration(d: Duration) -> String {
    let ns = d.as_nanos();
    if ns < 1_000 {
        format!("{}ns", ns)
    } else if ns < 1_000_000 {
        format!("{}µs", trim(ns as f64 / 1_000.0))
    } else if ns < 1_000_000_000 {
        format!("{}ms", trim(ns as f64 / 1_000_000.0))
    } else {
        format!("{}s", trim(ns as f64 / 1_000_000_000.0))
    }
}

fn trim(v: f64) -> String {
    let s = format!("{:.6}", v);
    let s = s.trim_end_matches('0');
    s.trim_end_matches('.').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::RecordType;

    #[test]
    fn common_format() {
        let req = Request::for_test("example.org.", RecordType::A);
        let reply = Reply::Msg(req.new_reply());
        let r = Replacer::new("{common}");
        let s = r.replace(&req, Some(&reply), None);
        assert!(s.starts_with("127.0.0.1:40000 - "), "{}", s);
        assert!(s.contains("\"A IN example.org. udp "), "{}", s);
        assert!(s.contains(" NOERROR qr,rd "), "{}", s);
    }

    #[test]
    fn durations() {
        assert_eq!(format_duration(Duration::from_micros(1500)), "1.5ms");
        assert_eq!(format_duration(Duration::from_secs(2)), "2s");
    }
}
