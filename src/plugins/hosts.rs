//! `hosts` — serves A/AAAA/PTR from a hosts(5) file and inline entries.
//!
//! ```text
//! hosts [FILE [ZONES...]] {
//!     [INLINE]
//!     ttl SECONDS
//!     no_reverse
//!     reload DURATION
//!     fallthrough [ZONES...]
//! }
//! ```

use crate::dnsutil;
use crate::plugin::{Controller, DnsResult, Handler, Next, Reply, Request};
use async_trait::async_trait;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{A, AAAA, PTR};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use prometheus::IntGaugeVec;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

static ENTRIES: Lazy<IntGaugeVec> = Lazy::new(|| {
    let g = IntGaugeVec::new(prometheus::Opts::new("coredns_hosts_entries", "The combined number of entries in hosts and Corefile."), &[]).unwrap();
    crate::metrics::register(Box::new(g.clone()));
    g
});
static RELOAD_TIMESTAMP: Lazy<IntGaugeVec> = Lazy::new(|| {
    let g = IntGaugeVec::new(prometheus::Opts::new("coredns_hosts_reload_timestamp_seconds", "The timestamp of the last reload of hosts file."), &[]).unwrap();
    crate::metrics::register(Box::new(g.clone()));
    g
});

#[derive(Default, Debug, Clone)]
pub struct HostsMap {
    /// name (lowercase FQDN) → addresses
    pub v4: HashMap<String, Vec<std::net::Ipv4Addr>>,
    pub v6: HashMap<String, Vec<std::net::Ipv6Addr>>,
    /// reverse name (`1.0.0.10.in-addr.arpa.`) → host names
    pub reverse: HashMap<String, Vec<String>>,
}

impl HostsMap {
    pub fn len(&self) -> usize {
        self.v4.values().map(|v| v.len()).sum::<usize>() + self.v6.values().map(|v| v.len()).sum::<usize>()
    }

    /// Parse hosts(5) text. Lines: `IP NAME [ALIAS...]`, `#` comments.
    pub fn parse(text: &str, into: &mut HostsMap) {
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(ip_s) = parts.next() else { continue };
            let Ok(ip) = ip_s.parse::<IpAddr>() else { continue };
            for host in parts {
                let name = dnsutil::fqdn(host);
                match ip {
                    IpAddr::V4(v4) => {
                        let v = into.v4.entry(name.clone()).or_default();
                        if !v.contains(&v4) {
                            v.push(v4);
                        }
                    }
                    IpAddr::V6(v6) => {
                        let v = into.v6.entry(name.clone()).or_default();
                        if !v.contains(&v6) {
                            v.push(v6);
                        }
                    }
                }
                let rev = dnsutil::reverse_name_str(ip);
                let r = into.reverse.entry(rev).or_default();
                if !r.contains(&name) {
                    r.push(name);
                }
            }
        }
    }
}

pub struct Hosts {
    zones: Vec<String>,
    path: Option<PathBuf>,
    inline: HostsMap,
    map: RwLock<HostsMap>,
    ttl: u32,
    no_reverse: bool,
    fallthrough: Option<Vec<String>>,
}

impl Hosts {
    fn load(&self) {
        let mut m = self.inline.clone();
        if let Some(p) = &self.path {
            match std::fs::read_to_string(p) {
                Ok(text) => HostsMap::parse(&text, &mut m),
                Err(e) => tracing::warn!("plugin/hosts: reading {}: {}", p.display(), e),
            }
        }
        ENTRIES.with_label_values(&[]).set(m.len() as i64);
        RELOAD_TIMESTAMP.with_label_values(&[]).set(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0));
        *self.map.write() = m;
    }
}

#[async_trait]
impl Handler for Hosts {
    fn name(&self) -> &'static str {
        "hosts"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let qname = req.name();
        if crate::plugin::zones_match(&self.zones, &qname).is_none() {
            return next.serve(req).await;
        }
        let name = req.qname();
        let map = self.map.read();
        let mut answers: Vec<Record> = Vec::new();
        let mut name_exists = false;
        match req.qtype() {
            RecordType::A => {
                if let Some(v) = map.v4.get(&qname) {
                    answers.extend(v.iter().map(|ip| Record::from_rdata(name.clone(), self.ttl, RData::A(A(*ip)))));
                }
                name_exists = map.v6.contains_key(&qname);
            }
            RecordType::AAAA => {
                if let Some(v) = map.v6.get(&qname) {
                    answers.extend(v.iter().map(|ip| Record::from_rdata(name.clone(), self.ttl, RData::AAAA(AAAA(*ip)))));
                }
                name_exists = map.v4.contains_key(&qname);
            }
            RecordType::PTR if !self.no_reverse => {
                if let Some(v) = map.reverse.get(&qname) {
                    for h in v {
                        if let Ok(n) = Name::from_ascii(h) {
                            answers.push(Record::from_rdata(name.clone(), self.ttl, RData::PTR(PTR(n))));
                        }
                    }
                }
            }
            _ => {
                name_exists = map.v4.contains_key(&qname) || map.v6.contains_key(&qname) || (!self.no_reverse && map.reverse.contains_key(&qname));
            }
        }
        drop(map);
        if answers.is_empty() {
            if let Some(ft) = &self.fallthrough {
                if crate::plugin::zones_match(ft, &qname).is_some() {
                    return next.serve(req).await;
                }
            }
            let mut m = req.new_reply();
            m.set_authoritative(true);
            if !name_exists {
                m.set_response_code(ResponseCode::NXDomain);
            }
            return Ok(Reply::Msg(m));
        }
        let mut m = req.new_reply();
        m.set_authoritative(true);
        for r in answers {
            m.add_answer(r);
        }
        Ok(Reply::Msg(m))
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/hosts: this plugin can only be used once per Server Block"));
        }
        let mut args = c.remaining_args_until_brace();
        let mut path = Some(PathBuf::from("/etc/hosts"));
        if !args.is_empty() {
            let p = args.remove(0);
            path = Some(if std::path::Path::new(&p).is_absolute() { PathBuf::from(&p) } else { c.config.root.join(&p) });
        }
        let zones = c.origins_from_args_or_server_block(&args)?;
        let mut inline = HostsMap::default();
        let mut ttl = 3600u32;
        let mut no_reverse = false;
        let mut reload = Duration::from_secs(5);
        let mut fallthrough = None;
        while c.next_block() {
            match c.val() {
                "ttl" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    ttl = a[0].parse().map_err(|_| c.errf(format!("invalid ttl {}", a[0])))?;
                }
                "no_reverse" => no_reverse = true,
                "reload" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    reload = dnsutil::parse_duration(&a[0])?;
                }
                "fallthrough" => {
                    let a = c.remaining_args();
                    fallthrough = Some(if a.is_empty() { vec![".".into()] } else { crate::plugin::normalize_zones(&a)? });
                }
                other => {
                    // inline entry: IP NAME...
                    if other.parse::<IpAddr>().is_err() {
                        return Err(c.errf(format!("unknown property '{}'", other)));
                    }
                    let mut line = vec![other.to_string()];
                    line.extend(c.remaining_args());
                    if line.len() < 2 {
                        return Err(c.errf("inline hosts entry needs at least one name"));
                    }
                    HostsMap::parse(&line.join(" "), &mut inline);
                }
            }
        }
        if let Some(p) = &path {
            if !p.exists() {
                tracing::warn!("plugin/hosts: file {} does not exist, will keep watching for it", p.display());
            }
        }
        let h = Arc::new(Hosts { zones, path, inline, map: RwLock::new(HostsMap::default()), ttl, no_reverse, fallthrough });
        h.load();
        c.add_plugin(h.clone());
        if !reload.is_zero() && h.path.is_some() {
            let hh = h.clone();
            let cancel = tokio_util::sync::CancellationToken::new();
            let stop = cancel.clone();
            c.on_startup(Box::new(move || {
                Box::pin(async move {
                    tokio::spawn(async move {
                        let p = hh.path.clone().unwrap();
                        let mut last = std::fs::metadata(&p).and_then(|m| m.modified()).ok();
                        loop {
                            tokio::select! {
                                _ = cancel.cancelled() => return,
                                _ = tokio::time::sleep(reload) => {}
                            }
                            let now = std::fs::metadata(&p).and_then(|m| m.modified()).ok();
                            if now != last {
                                last = now;
                                hh.load();
                            }
                        }
                    });
                    Ok(())
                })
            }));
            c.on_shutdown(Box::new(move || {
                Box::pin(async move {
                    stop.cancel();
                    Ok(())
                })
            }));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn inline_lookup() {
        let mut inline = HostsMap::default();
        HostsMap::parse("10.0.0.1 a.example.org alias.example.org\n# c\n::1 v6.example.org", &mut inline);
        let h = Hosts { zones: vec!["example.org.".into()], path: None, inline, map: RwLock::new(HostsMap::default()), ttl: 60, no_reverse: false, fallthrough: None };
        h.load();
        let mut req = Request::for_test("alias.example.org.", RecordType::A);
        let m = h.serve_dns(&mut req, Next::new(&[])).await.unwrap().into_msg().unwrap();
        assert_eq!(m.answers().len(), 1);
        let mut req = Request::for_test("v6.example.org.", RecordType::A);
        let m = h.serve_dns(&mut req, Next::new(&[])).await.unwrap().into_msg().unwrap();
        assert_eq!(m.response_code(), ResponseCode::NoError, "NODATA: name exists as AAAA");
        let mut req = Request::for_test("nope.example.org.", RecordType::A);
        let m = h.serve_dns(&mut req, Next::new(&[])).await.unwrap().into_msg().unwrap();
        assert_eq!(m.response_code(), ResponseCode::NXDomain);
        let mut req = Request::for_test("1.0.0.10.in-addr.arpa.", RecordType::PTR);
        let h2 = Hosts { zones: vec![".".into()], ..h };
        let m = h2.serve_dns(&mut req, Next::new(&[])).await.unwrap().into_msg().unwrap();
        assert_eq!(m.answers().len(), 2);
    }
}
