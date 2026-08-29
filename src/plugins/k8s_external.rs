//! `k8s_external` — exposes Services under an external domain using their
//! LoadBalancer ingress / externalIPs (and, with `headless`, endpoint IPs).
//!
//! ```text
//! k8s_external [ZONE...] {
//!     apex APEX
//!     ttl TTL
//!     headless
//!     fallthrough [ZONES...]
//! }
//! ```
//! Names are `<service>.<namespace>.<zone>`; SRV as `_port._proto.` prefix.
//! Reverse zones in ZONE answer PTR for external IPs.

use crate::dnsutil;
use crate::plugin::{Controller, DnsResult, ExternalService, Handler, Next, Reply, Request};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, NS, PTR, SOA, SRV};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::net::IpAddr;
use std::sync::Arc;

pub struct External {
    zones: Vec<String>,
    apex: String,
    ttl: u32,
    headless: bool,
    fallthrough: Option<Vec<String>>,
    k8s: ArcSwapOption<Arc<dyn Handler>>,
}

impl External {
    fn soa(&self, zone: &str) -> Record {
        let z = Name::from_ascii(zone).unwrap_or_else(|_| Name::root());
        let ns = Name::from_ascii(dnsutil::join(&["ns1", &self.apex], zone)).unwrap_or_else(|_| z.clone());
        let mbox = Name::from_ascii(dnsutil::join(&["hostmaster", &self.apex], zone)).unwrap_or_else(|_| z.clone());
        Record::from_rdata(z, self.ttl, RData::SOA(SOA::new(ns, mbox, chrono::Utc::now().timestamp() as u32, 7200, 1800, 86400, self.ttl)))
    }

    fn lookup(&self, ns: &str, svc: &str) -> Option<ExternalService> {
        self.k8s.load().as_ref().and_then(|h| h.external_addrs(ns, svc))
    }

    fn addrs(&self, name: &Name, ips: &[IpAddr], qtype: RecordType) -> Vec<Record> {
        ips.iter()
            .filter_map(|ip| match (ip, qtype) {
                (IpAddr::V4(v), RecordType::A | RecordType::ANY) => Some(Record::from_rdata(name.clone(), self.ttl, RData::A(A(*v)))),
                (IpAddr::V6(v), RecordType::AAAA | RecordType::ANY) => Some(Record::from_rdata(name.clone(), self.ttl, RData::AAAA(AAAA(*v)))),
                _ => None,
            })
            .collect()
    }

    /// Returns Some(message) when the name is ours, None for NXDOMAIN.
    fn serve(&self, req: &mut Request, zone: &str) -> Option<Message> {
        let qname = req.name();
        let qtype = req.qtype();
        let name = req.qname();
        let mut m = req.new_reply();
        m.set_authoritative(true);

        if dnsutil::is_reverse(zone) != 0 {
            let ip = dnsutil::extract_address_from_reverse(&qname)?;
            let (ns, svc) = self.k8s.load().as_ref().and_then(|h| h.external_reverse(ip))?;
            let fwd = self.zones.iter().find(|z| dnsutil::is_reverse(z) == 0)?;
            let target = Name::from_ascii(dnsutil::join(&[&svc, &ns], fwd)).ok()?;
            if matches!(qtype, RecordType::PTR | RecordType::ANY) {
                m.add_answer(Record::from_rdata(name, self.ttl, RData::PTR(PTR(target))));
            } else {
                m.add_name_server(self.soa(zone));
            }
            return Some(m);
        }

        let rel = dnsutil::trim_zone(&qname, zone).unwrap_or_default();
        if rel.is_empty() {
            match qtype {
                RecordType::SOA | RecordType::ANY => m.add_answer(self.soa(zone)),
                RecordType::NS => m.add_answer(Record::from_rdata(name.clone(), self.ttl, RData::NS(NS(Name::from_ascii(dnsutil::join(&["ns1", &self.apex], zone)).ok()?)))),
                _ => m.add_name_server(self.soa(zone)),
            };
            return Some(m);
        }
        let mut segs: Vec<&str> = rel.split('.').collect();
        segs.reverse();
        // apex.<zone>, ns1.apex.<zone>
        if segs[0] == self.apex {
            match segs.len() {
                1 => {
                    m.add_name_server(self.soa(zone));
                    return Some(m);
                }
                2 if segs[1] == "ns1" => {
                    let ips: Vec<IpAddr> = crate::plugins::bind::interfaces().into_iter().map(|(_, ip)| ip).filter(|ip| !ip.is_loopback()).collect();
                    for r in self.addrs(&name, &ips, qtype) {
                        m.add_answer(r);
                    }
                    if m.answers().is_empty() {
                        m.add_name_server(self.soa(zone));
                    }
                    return Some(m);
                }
                _ => return None,
            }
        }
        let (namespace, service, port, proto) = match segs.as_slice() {
            [ns] => {
                // namespace only: NODATA if any service exists there
                let _ = ns;
                m.add_name_server(self.soa(zone));
                return Some(m);
            }
            [ns, svc] => (*ns, *svc, None, None),
            [ns, svc, proto, port] if proto.starts_with('_') && port.starts_with('_') => (*ns, *svc, Some(&port[1..]), Some(&proto[1..])),
            _ => return None,
        };
        let ext = self.lookup(namespace, service)?;
        let svc_name = Name::from_ascii(dnsutil::join(&[service, namespace], zone)).ok()?;
        let mut ips = ext.ips.clone();
        if self.headless {
            ips.extend(ext.headless_ips.iter().cloned());
        }
        if ips.is_empty() && ext.hostnames.is_empty() {
            return None;
        }
        match (port, qtype) {
            (Some(p), RecordType::SRV) => {
                let mut any = false;
                for (pname, pproto, pport) in &ext.ports {
                    if (p == "*" || pname.eq_ignore_ascii_case(p)) && proto.map(|pr| pr == "*" || pproto.eq_ignore_ascii_case(pr)).unwrap_or(true) {
                        any = true;
                        m.add_answer(Record::from_rdata(name.clone(), self.ttl, RData::SRV(SRV::new(0, 100, *pport, svc_name.clone()))));
                    }
                }
                if !any {
                    return None;
                }
                for r in self.addrs(&svc_name, &ips, RecordType::ANY) {
                    m.add_additional(r);
                }
            }
            (Some(p), _) => {
                if !ext.ports.iter().any(|(pname, _, _)| p == "*" || pname.eq_ignore_ascii_case(p)) {
                    return None;
                }
                m.add_name_server(self.soa(zone));
            }
            (None, RecordType::SRV) => {
                for (_, _, pport) in &ext.ports {
                    m.add_answer(Record::from_rdata(name.clone(), self.ttl, RData::SRV(SRV::new(0, 100, *pport, svc_name.clone()))));
                }
                for r in self.addrs(&svc_name, &ips, RecordType::ANY) {
                    m.add_additional(r);
                }
            }
            (None, RecordType::A | RecordType::AAAA | RecordType::ANY | RecordType::CNAME) => {
                for r in self.addrs(&name, &ips, qtype) {
                    m.add_answer(r);
                }
                if ips.is_empty() || qtype == RecordType::CNAME {
                    for h in &ext.hostnames {
                        if let Ok(t) = Name::from_ascii(dnsutil::fqdn(h)) {
                            m.add_answer(Record::from_rdata(name.clone(), self.ttl, RData::CNAME(CNAME(t))));
                        }
                    }
                }
                if m.answers().is_empty() {
                    m.add_name_server(self.soa(zone));
                }
            }
            _ => {
                m.add_name_server(self.soa(zone));
            }
        }
        Some(m)
    }
}

#[async_trait]
impl Handler for External {
    fn name(&self) -> &'static str {
        "k8s_external"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let qname = req.name();
        let Some(zone) = crate::plugin::zones_match(&self.zones, &qname).map(|z| z.to_string()) else {
            return next.serve(req).await;
        };
        match self.serve(req, &zone) {
            Some(m) => Ok(Reply::Msg(m)),
            None => {
                if let Some(ft) = &self.fallthrough {
                    if crate::plugin::zones_match(ft, &qname).is_some() {
                        return next.serve(req).await;
                    }
                }
                let mut m = req.new_reply();
                m.set_authoritative(true);
                m.set_response_code(ResponseCode::NXDomain);
                m.add_name_server(self.soa(&zone));
                Ok(Reply::Msg(m))
            }
        }
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/k8s_external: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args_until_brace();
        let zones = c.origins_from_args_or_server_block(&args)?;
        let mut e = External { zones, apex: "dns".into(), ttl: 5, headless: false, fallthrough: None, k8s: ArcSwapOption::empty() };
        while c.next_block() {
            match c.val() {
                "apex" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    e.apex = a[0].clone();
                }
                "ttl" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    let t: u32 = a[0].parse().map_err(|_| c.errf(format!("bad ttl {}", a[0])))?;
                    if t > 3600 {
                        return Err(c.errf("ttl must be in range [0, 3600]"));
                    }
                    e.ttl = t;
                }
                "headless" => e.headless = true,
                "fallthrough" => {
                    let a = c.remaining_args();
                    e.fallthrough = Some(if a.is_empty() { vec![".".into()] } else { crate::plugin::normalize_zones(&a)? });
                }
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        let e = Arc::new(e);
        c.add_plugin(e.clone());
        let e2 = e.clone();
        crate::plugins::wire::register(c, move |cfg| match cfg.handler("kubernetes") {
            Some(h) => e2.k8s.store(Some(Arc::new(h))),
            None => tracing::error!("plugin/k8s_external: the kubernetes plugin must be enabled in the same server block"),
        });
    }
    Ok(())
}
