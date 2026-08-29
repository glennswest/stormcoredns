//! `kubernetes` — serves the cluster DNS schema (Services, headless
//! endpoints, SRV, pods, PTR, ExternalName) from a live watch of the API.
//!
//! ```text
//! kubernetes [ZONES...] {
//!     endpoint URL
//!     tls CERT KEY CACERT
//!     kubeconfig KUBECONFIG [CONTEXT]
//!     namespaces NAMESPACE...
//!     namespace_labels EXPRESSION
//!     labels EXPRESSION
//!     pods POD-MODE            # disabled | insecure | verified
//!     endpoint_pod_names
//!     ttl TTL
//!     noendpoints
//!     fallthrough [ZONES...]
//!     ignore empty_service
//! }
//! ```

pub mod store;

use crate::dnsutil;
use crate::plugin::{error, Controller, DnsResult, Handler, Next, Reply, Request};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, NS, PTR, SOA, SRV, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use store::{Endpoint, Store, Svc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PodMode {
    Disabled,
    Insecure,
    Verified,
}

pub struct Kubernetes {
    pub zones: Vec<String>,
    /// The first forward (non-arpa) zone: names are synthesised in it.
    pub primary_zone: String,
    pub store: Arc<Store>,
    pub namespaces: Vec<String>,
    pub pod_mode: PodMode,
    pub endpoint_pod_names: bool,
    pub ttl: u32,
    pub watch_endpoints: bool,
    pub fallthrough: Option<Vec<String>>,
    pub ignore_empty_service: bool,
    pub local_ips: Vec<IpAddr>,
}

/// What a query name means inside the cluster zone.
#[derive(Debug, PartialEq, Eq)]
enum Parsed {
    Apex,
    Dns,
    NsDns,
    DnsVersion,
    SvcRoot,
    NsSvcRoot { namespace: String },
    Svc { namespace: String, service: String, endpoint: Option<String>, port: Option<String>, protocol: Option<String> },
    PodRoot,
    NsPodRoot { namespace: String },
    Pod { namespace: String, pod: String },
    Invalid,
}

fn parse_name(rel: &str) -> Parsed {
    if rel.is_empty() {
        return Parsed::Apex;
    }
    let mut segs: Vec<&str> = rel.split('.').collect();
    segs.reverse();
    match segs.as_slice() {
        ["dns"] => Parsed::Dns,
        ["dns", "ns"] => Parsed::NsDns,
        ["dns-version"] => Parsed::DnsVersion,
        ["svc"] => Parsed::SvcRoot,
        ["svc", ns] => Parsed::NsSvcRoot { namespace: ns.to_string() },
        ["svc", ns, svc] => Parsed::Svc { namespace: ns.to_string(), service: svc.to_string(), endpoint: None, port: None, protocol: None },
        ["svc", ns, svc, ep] if !ep.starts_with('_') => {
            Parsed::Svc { namespace: ns.to_string(), service: svc.to_string(), endpoint: Some(ep.to_string()), port: None, protocol: None }
        }
        ["svc", ns, svc, proto, port] if proto.starts_with('_') && port.starts_with('_') => Parsed::Svc {
            namespace: ns.to_string(),
            service: svc.to_string(),
            endpoint: None,
            port: Some(port[1..].to_string()),
            protocol: Some(proto[1..].to_string()),
        },
        ["svc", ns, svc, proto, "*"] | ["svc", ns, svc, proto, "any"] if proto.starts_with('_') => Parsed::Svc {
            namespace: ns.to_string(),
            service: svc.to_string(),
            endpoint: None,
            port: Some("*".into()),
            protocol: Some(proto[1..].to_string()),
        },
        ["pod"] => Parsed::PodRoot,
        ["pod", ns] => Parsed::NsPodRoot { namespace: ns.to_string() },
        ["pod", ns, pod] => Parsed::Pod { namespace: ns.to_string(), pod: pod.to_string() },
        _ => Parsed::Invalid,
    }
}

fn is_wild(s: &str) -> bool {
    s == "*" || s == "any"
}

fn dashed(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => v.to_string().replace('.', "-"),
        IpAddr::V6(v) => v.to_string().replace(':', "-"),
    }
}

fn undash(s: &str) -> Option<IpAddr> {
    if let Ok(v4) = s.replace('-', ".").parse::<std::net::Ipv4Addr>() {
        return Some(IpAddr::V4(v4));
    }
    if let Ok(v6) = s.replace('-', ":").parse::<std::net::Ipv6Addr>() {
        return Some(IpAddr::V6(v6));
    }
    None
}

impl Kubernetes {
    fn name(&self, labels: &[&str]) -> Name {
        Name::from_ascii(dnsutil::join(labels, &self.primary_zone)).unwrap_or_else(|_| Name::root())
    }

    fn endpoint_hostname(&self, e: &Endpoint) -> String {
        if let Some(h) = &e.hostname {
            return h.clone();
        }
        if self.endpoint_pod_names {
            if let Some(p) = &e.pod_name {
                return p.clone();
            }
        }
        e.ips.first().map(|ip| dashed(*ip)).unwrap_or_default()
    }

    fn namespace_exposed(&self, ns: &str) -> bool {
        (self.namespaces.is_empty() || self.namespaces.iter().any(|n| n == ns)) && self.store.namespace_exists(ns)
    }

    fn soa(&self, zone: &str) -> Record {
        let z = Name::from_ascii(zone).unwrap_or_else(|_| Name::root());
        let ns = Name::from_ascii(dnsutil::join(&["ns", "dns"], zone)).unwrap_or_else(|_| z.clone());
        let mbox = Name::from_ascii(dnsutil::join(&["hostmaster"], zone)).unwrap_or_else(|_| z.clone());
        let serial = chrono::Utc::now().timestamp() as u32;
        Record::from_rdata(z, self.ttl, RData::SOA(SOA::new(ns, mbox, serial, 7200, 1800, 86400, self.ttl)))
    }

    fn nxdomain(&self, req: &Request, zone: &str) -> Message {
        let mut m = req.new_reply();
        m.set_authoritative(true);
        m.set_response_code(ResponseCode::NXDomain);
        m.add_name_server(self.soa(zone));
        m
    }

    fn nodata(&self, req: &Request, zone: &str) -> Message {
        let mut m = req.new_reply();
        m.set_authoritative(true);
        m.add_name_server(self.soa(zone));
        m
    }

    fn addr_records(&self, name: &Name, ips: &[IpAddr], qtype: RecordType) -> Vec<Record> {
        ips.iter()
            .filter_map(|ip| match (ip, qtype) {
                (IpAddr::V4(v), RecordType::A | RecordType::ANY) => Some(Record::from_rdata(name.clone(), self.ttl, RData::A(A(*v)))),
                (IpAddr::V6(v), RecordType::AAAA | RecordType::ANY) => Some(Record::from_rdata(name.clone(), self.ttl, RData::AAAA(AAAA(*v)))),
                _ => None,
            })
            .collect()
    }

    /// The A/AAAA records answering `ns.dns.<zone>`: the cluster IP of the
    /// service fronting this DNS pod, or the host's own addresses.
    fn ns_addrs(&self, qtype: RecordType) -> Vec<Record> {
        let name = self.name(&["ns", "dns"]);
        let mut ips: Vec<IpAddr> = Vec::new();
        for lip in &self.local_ips {
            for (ns, svc) in self.store.services_by_endpoint_ip(*lip) {
                if let Some(s) = self.store.service(&ns, &svc) {
                    ips.extend(s.cluster_ips.iter().cloned());
                }
            }
        }
        if ips.is_empty() {
            ips = self.local_ips.clone();
        }
        ips.sort();
        ips.dedup();
        self.addr_records(&name, &ips, qtype)
    }

    /// Ready endpoints of a service (all of them when publishNotReadyAddresses).
    fn ready_endpoints(&self, svc: &Svc) -> Vec<Endpoint> {
        self.store.endpoints(&svc.namespace, &svc.name).into_iter().filter(|e| e.ready || svc.publish_not_ready).collect()
    }

    /// Records for one service. Returns (answers, extras, found).
    async fn service_records(&self, req: &Request, svc: &Svc, qname: &Name, endpoint: &Option<String>, port: &Option<String>, protocol: &Option<String>, qtype: RecordType) -> Result<(Vec<Record>, Vec<Record>, bool)> {
        let svc_name = self.name(&[&svc.name, &svc.namespace, "svc"]);
        let mut answers = Vec::new();
        let mut extras = Vec::new();

        // ExternalName → CNAME (+ chase it through our own chain)
        if let Some(ext) = &svc.external_name {
            if endpoint.is_some() || port.is_some() {
                return Ok((answers, extras, false));
            }
            let target = Name::from_ascii(dnsutil::fqdn(ext)).map_err(|e| anyhow!("bad externalName {}: {}", ext, e))?;
            if matches!(qtype, RecordType::CNAME | RecordType::A | RecordType::AAAA | RecordType::ANY) {
                answers.push(Record::from_rdata(qname.clone(), self.ttl, RData::CNAME(CNAME(target.clone()))));
                if matches!(qtype, RecordType::A | RecordType::AAAA) && !dnsutil::is_subdomain(&self.primary_zone, &dnsutil::name_str(&target)) {
                    if let Ok(m) = crate::server::self_lookup(req, target, qtype).await {
                        answers.extend(m.answers().iter().cloned());
                    }
                }
            }
            return Ok((answers, extras, true));
        }

        let wants_endpoints = svc.headless || endpoint.is_some();
        if wants_endpoints {
            let eps = self.ready_endpoints(svc);
            if self.ignore_empty_service && eps.is_empty() && svc.headless {
                return Ok((answers, extras, false));
            }
            let mut found = false;
            let n = eps.len().max(1) as u16;
            for e in &eps {
                let ep_host = self.endpoint_hostname(e);
                if let Some(want) = endpoint {
                    if !is_wild(want) && !want.eq_ignore_ascii_case(&ep_host) {
                        continue;
                    }
                }
                found = true;
                let ep_name = self.name(&[&ep_host, &svc.name, &svc.namespace, "svc"]);
                match qtype {
                    RecordType::SRV => {
                        for p in &e.ports {
                            if !port_matches(p, port, protocol) {
                                continue;
                            }
                            let srv_name = if port.is_some() { qname.clone() } else { svc_name.clone() };
                            answers.push(Record::from_rdata(srv_name, self.ttl, RData::SRV(SRV::new(0, 100 / n, p.port, ep_name.clone()))));
                            extras.extend(self.addr_records(&ep_name, &e.ips, RecordType::ANY));
                        }
                    }
                    RecordType::A | RecordType::AAAA | RecordType::ANY => {
                        if port.is_none() {
                            let target = if endpoint.is_some() { qname.clone() } else { svc_name.clone() };
                            answers.extend(self.addr_records(&target, &e.ips, qtype));
                        }
                    }
                    _ => {}
                }
            }
            if endpoint.is_some() && !found {
                return Ok((answers, extras, false));
            }
            if port.is_some() && answers.is_empty() && qtype == RecordType::SRV {
                return Ok((answers, extras, false));
            }
            return Ok((answers, extras, true));
        }

        // ClusterIP service
        if self.ignore_empty_service && self.ready_endpoints(svc).is_empty() {
            return Ok((answers, extras, false));
        }
        match qtype {
            RecordType::SRV => {
                let mut any = false;
                for p in &svc.ports {
                    if !port_matches(p, port, protocol) {
                        continue;
                    }
                    any = true;
                    let srv_name = if port.is_some() { qname.clone() } else { svc_name.clone() };
                    answers.push(Record::from_rdata(srv_name, self.ttl, RData::SRV(SRV::new(0, 100, p.port, svc_name.clone()))));
                }
                if port.is_some() && !any {
                    return Ok((answers, extras, false));
                }
                extras.extend(self.addr_records(&svc_name, &svc.cluster_ips, RecordType::ANY));
            }
            RecordType::A | RecordType::AAAA | RecordType::ANY => {
                if port.is_some() {
                    return Ok((answers, extras, svc.ports.iter().any(|p| port_matches(p, port, protocol))));
                }
                answers.extend(self.addr_records(&svc_name, &svc.cluster_ips, qtype));
            }
            _ => {
                if port.is_some() {
                    return Ok((answers, extras, svc.ports.iter().any(|p| port_matches(p, port, protocol))));
                }
            }
        }
        Ok((answers, extras, true))
    }

    async fn serve_forward(&self, req: &mut Request, zone: &str) -> Result<Option<Message>> {
        let qname_str = req.name();
        let rel = dnsutil::trim_zone(&qname_str, zone).unwrap_or_default();
        let qname = req.qname();
        let qtype = req.qtype();
        let parsed = parse_name(&rel);
        let mut m = req.new_reply();
        m.set_authoritative(true);
        match parsed {
            Parsed::Apex => {
                match qtype {
                    RecordType::SOA | RecordType::ANY => m.add_answer(self.soa(zone)),
                    RecordType::NS => {
                        m.add_answer(Record::from_rdata(qname.clone(), self.ttl, RData::NS(NS(self.name(&["ns", "dns"])))));
                        for r in self.ns_addrs(RecordType::ANY) {
                            m.add_additional(r);
                        }
                        &mut m
                    }
                    _ => {
                        m.add_name_server(self.soa(zone));
                        &mut m
                    }
                };
                Ok(Some(m))
            }
            Parsed::Dns | Parsed::SvcRoot | Parsed::PodRoot => Ok(Some(self.nodata(req, zone))),
            Parsed::NsDns => {
                let recs = self.ns_addrs(qtype);
                if recs.is_empty() {
                    return Ok(Some(self.nodata(req, zone)));
                }
                for r in recs {
                    m.add_answer(r);
                }
                Ok(Some(m))
            }
            Parsed::DnsVersion => {
                if matches!(qtype, RecordType::TXT | RecordType::ANY) {
                    m.add_answer(Record::from_rdata(qname.clone(), 28800, RData::TXT(TXT::new(vec!["1.1.0".to_string()]))));
                    Ok(Some(m))
                } else {
                    Ok(Some(self.nodata(req, zone)))
                }
            }
            Parsed::NsSvcRoot { namespace } | Parsed::NsPodRoot { namespace } => {
                if is_wild(&namespace) || self.namespace_exposed(&namespace) {
                    Ok(Some(self.nodata(req, zone)))
                } else {
                    Ok(None)
                }
            }
            Parsed::Svc { namespace, service, endpoint, port, protocol } => {
                if !is_wild(&namespace) && !self.namespace_exposed(&namespace) {
                    return Ok(None);
                }
                let services: Vec<Arc<Svc>> = if is_wild(&service) {
                    let ns = if is_wild(&namespace) { "*".to_string() } else { namespace.clone() };
                    self.store.services_in(&ns).into_iter().filter(|s| self.namespace_exposed(&s.namespace)).collect()
                } else if is_wild(&namespace) {
                    self.store.services_in("*").into_iter().filter(|s| s.name == service && self.namespace_exposed(&s.namespace)).collect()
                } else {
                    self.store.service(&namespace, &service).into_iter().collect()
                };
                if services.is_empty() {
                    return Ok(None);
                }
                let mut any_found = false;
                for svc in &services {
                    let (ans, ext, found) = self.service_records(req, svc, &qname, &endpoint, &port, &protocol, qtype).await?;
                    any_found |= found;
                    for r in ans {
                        m.add_answer(r);
                    }
                    for r in ext {
                        m.add_additional(r);
                    }
                }
                if !any_found {
                    return Ok(None);
                }
                if m.answers().is_empty() {
                    return Ok(Some(self.nodata(req, zone)));
                }
                Ok(Some(m))
            }
            Parsed::Pod { namespace, pod } => {
                if self.pod_mode == PodMode::Disabled {
                    return Ok(None);
                }
                if !is_wild(&namespace) && self.namespaces.iter().any(|_| true) && !self.namespaces.iter().any(|n| *n == namespace) {
                    return Ok(None);
                }
                let Some(ip) = undash(&pod) else { return Ok(None) };
                match self.pod_mode {
                    PodMode::Insecure => {}
                    PodMode::Verified => match self.store.pod_by_ip(ip) {
                        Some(p) if is_wild(&namespace) || p.namespace == namespace => {}
                        _ => return Ok(None),
                    },
                    PodMode::Disabled => return Ok(None),
                }
                let recs = self.addr_records(&qname, &[ip], qtype);
                if recs.is_empty() {
                    return Ok(Some(self.nodata(req, zone)));
                }
                for r in recs {
                    m.add_answer(r);
                }
                Ok(Some(m))
            }
            Parsed::Invalid => Ok(None),
        }
    }

    fn serve_reverse(&self, req: &mut Request, zone: &str) -> Option<Message> {
        let qname_str = req.name();
        let ip = dnsutil::extract_address_from_reverse(&qname_str)?;
        let mut targets: Vec<Name> = Vec::new();
        if let Some(svc) = self.store.service_by_ip(ip) {
            if self.namespace_exposed(&svc.namespace) {
                targets.push(self.name(&[&svc.name, &svc.namespace, "svc"]));
            }
        }
        if targets.is_empty() {
            for (ns, name) in self.store.services_by_endpoint_ip(ip) {
                if !self.namespace_exposed(&ns) {
                    continue;
                }
                let Some(svc) = self.store.service(&ns, &name) else { continue };
                for e in self.ready_endpoints(&svc) {
                    if e.ips.contains(&ip) {
                        targets.push(self.name(&[&self.endpoint_hostname(&e), &svc.name, &svc.namespace, "svc"]));
                    }
                }
            }
        }
        if targets.is_empty() {
            return None;
        }
        let mut m = req.new_reply();
        m.set_authoritative(true);
        if matches!(req.qtype(), RecordType::PTR | RecordType::ANY) {
            for t in targets {
                m.add_answer(Record::from_rdata(req.qname(), self.ttl, RData::PTR(PTR(t))));
            }
        } else {
            m.add_name_server(self.soa(zone));
        }
        Some(m)
    }
}

fn port_matches(p: &store::Port, port: &Option<String>, protocol: &Option<String>) -> bool {
    match (port, protocol) {
        (None, _) => true,
        (Some(port), proto) => {
            let port_ok = is_wild(port) || p.name.eq_ignore_ascii_case(port);
            let proto_ok = match proto {
                Some(pr) => is_wild(pr) || p.protocol.eq_ignore_ascii_case(pr),
                None => true,
            };
            port_ok && proto_ok
        }
    }
}

pub struct KubernetesHandler(pub Arc<Kubernetes>);

#[async_trait]
impl Handler for KubernetesHandler {
    fn name(&self) -> &'static str {
        "kubernetes"
    }

    fn ready(&self) -> Option<bool> {
        Some(self.0.store.synced(self.0.pod_mode == PodMode::Verified, self.0.watch_endpoints))
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let k = &self.0;
        let name = req.name();
        let Some(zone) = crate::plugin::zones_match(&k.zones, &name).map(|z| z.to_string()) else {
            return next.serve(req).await;
        };
        if req.qclass() != hickory_proto::rr::DNSClass::IN {
            return next.serve(req).await;
        }
        let result = if dnsutil::is_reverse(&zone) != 0 {
            Ok(k.serve_reverse(req, &zone))
        } else {
            k.serve_forward(req, &zone).await
        };
        match result {
            Ok(Some(m)) => Ok(Reply::Msg(m)),
            Ok(None) => {
                if let Some(ft) = &k.fallthrough {
                    if crate::plugin::zones_match(ft, &name).is_some() {
                        return next.serve(req).await;
                    }
                }
                Ok(Reply::Msg(k.nxdomain(req, &zone)))
            }
            Err(e) => Err(error("kubernetes", e)),
        }
    }
}

// ------------------------------------------------------------------ setup

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/kubernetes: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args_until_brace();
        let zones = c.origins_from_args_or_server_block(&args)?;
        let primary_zone = zones.iter().find(|z| dnsutil::is_reverse(z) == 0).cloned().unwrap_or_else(|| zones[0].clone());
        let mut endpoint: Option<String> = None;
        let mut tls: Option<(String, String, String)> = None;
        let mut kubeconfig: Option<(String, Option<String>)> = None;
        let mut k = Kubernetes {
            zones,
            primary_zone,
            store: Store::new(),
            namespaces: Vec::new(),
            pod_mode: PodMode::Disabled,
            endpoint_pod_names: false,
            ttl: 5,
            watch_endpoints: true,
            fallthrough: None,
            ignore_empty_service: false,
            local_ips: crate::plugins::bind::interfaces().into_iter().map(|(_, ip)| ip).filter(|ip| !ip.is_loopback()).collect(),
        };
        let mut labels: Option<String> = None;
        let mut namespace_labels: Option<String> = None;
        while c.next_block() {
            match c.val() {
                "endpoint" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    endpoint = Some(a[0].clone());
                }
                "tls" => {
                    let a = c.remaining_args();
                    if a.len() != 3 {
                        return Err(c.arg_err());
                    }
                    tls = Some((a[0].clone(), a[1].clone(), a[2].clone()));
                }
                "kubeconfig" => {
                    let a = c.remaining_args();
                    match a.len() {
                        1 => kubeconfig = Some((a[0].clone(), None)),
                        2 => kubeconfig = Some((a[0].clone(), Some(a[1].clone()))),
                        _ => return Err(c.arg_err()),
                    }
                }
                "namespaces" => {
                    let a = c.remaining_args();
                    if a.is_empty() {
                        return Err(c.arg_err());
                    }
                    k.namespaces = a;
                }
                "namespace_labels" => {
                    let a = c.remaining_args();
                    if a.is_empty() {
                        return Err(c.arg_err());
                    }
                    namespace_labels = Some(a.join(" "));
                }
                "labels" => {
                    let a = c.remaining_args();
                    if a.is_empty() {
                        return Err(c.arg_err());
                    }
                    labels = Some(a.join(" "));
                }
                "pods" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    k.pod_mode = match a[0].as_str() {
                        "disabled" => PodMode::Disabled,
                        "insecure" => PodMode::Insecure,
                        "verified" => PodMode::Verified,
                        o => return Err(c.errf(format!("wrong value for pods: {}", o))),
                    };
                }
                "endpoint_pod_names" => {
                    if c.next_arg() {
                        return Err(c.arg_err());
                    }
                    k.endpoint_pod_names = true;
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
                    k.ttl = t;
                }
                "noendpoints" => k.watch_endpoints = false,
                "fallthrough" => {
                    let a = c.remaining_args();
                    k.fallthrough = Some(if a.is_empty() { vec![".".into()] } else { crate::plugin::normalize_zones(&a)? });
                }
                "ignore" => {
                    let a = c.remaining_args();
                    if a.len() != 1 || a[0] != "empty_service" {
                        return Err(c.errf("ignore: only 'empty_service' is supported"));
                    }
                    k.ignore_empty_service = true;
                }
                "multicluster" => {
                    let _ = c.remaining_args();
                    return Err(c.errf("multicluster is not supported"));
                }
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        let k = Arc::new(k);
        c.add_plugin(Arc::new(KubernetesHandler(k.clone())));
        let root = c.config.root.clone();
        let watch_opts = store::WatchOptions {
            namespaces: k.namespaces.clone(),
            label_selector: labels,
            namespace_label_selector: namespace_labels,
            watch_pods: k.pod_mode == PodMode::Verified,
            watch_endpoints: k.watch_endpoints,
        };
        c.on_startup(Box::new(move || {
            Box::pin(async move {
                let client = make_client(endpoint, tls, kubeconfig, &root).await?;
                store::start(client, k.store.clone(), watch_opts).await
            })
        }));
    }
    Ok(())
}

async fn make_client(endpoint: Option<String>, tls: Option<(String, String, String)>, kubeconfig: Option<(String, Option<String>)>, root: &std::path::Path) -> Result<kube::Client> {
    let resolve = |p: &str| if std::path::Path::new(p).is_absolute() { std::path::PathBuf::from(p) } else { root.join(p) };
    let config = if let Some((file, ctx)) = kubeconfig {
        let kc = kube::config::Kubeconfig::read_from(resolve(&file)).map_err(|e| anyhow!("kubeconfig {}: {}", file, e))?;
        let opts = kube::config::KubeConfigOptions { context: ctx, ..Default::default() };
        kube::Config::from_custom_kubeconfig(kc, &opts).await.map_err(|e| anyhow!("kubeconfig: {}", e))?
    } else if let Some(url) = endpoint {
        let uri: http::Uri = url.parse().map_err(|e| anyhow!("endpoint {}: {}", url, e))?;
        let mut cfg = kube::Config::new(uri);
        if let Some((cert, key, ca)) = tls {
            cfg.root_cert = Some(vec![std::fs::read(resolve(&ca)).map_err(|e| anyhow!("reading {}: {}", ca, e))?]);
            cfg.auth_info.client_certificate = Some(resolve(&cert));
            cfg.auth_info.client_key = Some(resolve(&key));
        } else if url.starts_with("https://") {
            tracing::warn!("plugin/kubernetes: endpoint {} without tls: accepting any server certificate", url);
            cfg.accept_invalid_certs = true;
        }
        cfg
    } else {
        kube::Config::infer().await.map_err(|e| anyhow!("kubernetes: no in-cluster or kubeconfig configuration: {}", e))?
    };
    kube::Client::try_from(config).map_err(|e| anyhow!("kubernetes client: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use store::testing;

    fn k8s() -> Arc<Kubernetes> {
        let store = Store::new();
        testing::add_service(&store, "default", "web", &["10.96.0.10"], &[("http", "TCP", 80), ("https", "TCP", 443)], false, None);
        testing::add_service(&store, "default", "hl", &[], &[("db", "TCP", 5432)], true, None);
        testing::add_endpoints(
            &store,
            "default",
            "hl",
            vec![
                Endpoint { ips: vec!["10.244.0.5".parse().unwrap()], hostname: Some("pg-0".into()), pod_name: Some("pg-0".into()), ready: true, ports: vec![store::Port { name: "db".into(), protocol: "TCP".into(), port: 5432 }] },
                Endpoint { ips: vec!["10.244.0.6".parse().unwrap()], hostname: None, pod_name: Some("pg-1".into()), ready: false, ports: vec![] },
            ],
        );
        testing::add_service(&store, "default", "ext", &[], &[], false, Some("example.org"));
        testing::add_pod(&store, "default", "p1", "10.244.1.9");
        store.services_synced.store(true, std::sync::atomic::Ordering::Relaxed);
        Arc::new(Kubernetes {
            zones: vec!["cluster.local.".into(), "in-addr.arpa.".into()],
            primary_zone: "cluster.local.".into(),
            store,
            namespaces: vec![],
            pod_mode: PodMode::Verified,
            endpoint_pod_names: false,
            ttl: 5,
            watch_endpoints: true,
            fallthrough: None,
            ignore_empty_service: false,
            local_ips: vec![],
        })
    }

    async fn q(k: &Arc<Kubernetes>, name: &str, t: RecordType) -> Message {
        let mut req = Request::for_test(name, t);
        KubernetesHandler(k.clone()).serve_dns(&mut req, Next::new(&[])).await.unwrap().into_msg().unwrap()
    }

    #[tokio::test]
    async fn cluster_ip_service() {
        let k = k8s();
        let m = q(&k, "web.default.svc.cluster.local.", RecordType::A).await;
        assert_eq!(m.response_code(), ResponseCode::NoError);
        assert_eq!(m.answers().len(), 1);
        assert!(matches!(m.answers()[0].data(), Some(RData::A(a)) if a.0 == std::net::Ipv4Addr::new(10, 96, 0, 10)));
        assert!(m.authoritative());
        // AAAA → NODATA with SOA
        let m = q(&k, "web.default.svc.cluster.local.", RecordType::AAAA).await;
        assert_eq!(m.response_code(), ResponseCode::NoError);
        assert!(m.answers().is_empty());
        assert_eq!(m.name_servers()[0].record_type(), RecordType::SOA);
    }

    #[tokio::test]
    async fn srv_records() {
        let k = k8s();
        let m = q(&k, "_http._tcp.web.default.svc.cluster.local.", RecordType::SRV).await;
        assert_eq!(m.answers().len(), 1);
        assert!(matches!(m.answers()[0].data(), Some(RData::SRV(s)) if s.port() == 80));
        assert_eq!(m.additionals().len(), 1);
        let m = q(&k, "_nope._tcp.web.default.svc.cluster.local.", RecordType::SRV).await;
        assert_eq!(m.response_code(), ResponseCode::NXDomain);
        let m = q(&k, "web.default.svc.cluster.local.", RecordType::SRV).await;
        assert_eq!(m.answers().len(), 2);
    }

    #[tokio::test]
    async fn headless_and_endpoints() {
        let k = k8s();
        let m = q(&k, "hl.default.svc.cluster.local.", RecordType::A).await;
        assert_eq!(m.answers().len(), 1, "only the ready endpoint");
        let m = q(&k, "pg-0.hl.default.svc.cluster.local.", RecordType::A).await;
        assert_eq!(m.answers().len(), 1);
        assert_eq!(m.answers()[0].name().to_ascii(), "pg-0.hl.default.svc.cluster.local.");
        let m = q(&k, "_db._tcp.hl.default.svc.cluster.local.", RecordType::SRV).await;
        assert_eq!(m.answers().len(), 1);
        assert!(matches!(m.answers()[0].data(), Some(RData::SRV(s)) if s.target().to_ascii() == "pg-0.hl.default.svc.cluster.local."));
    }

    #[tokio::test]
    async fn nxdomain_and_nodata() {
        let k = k8s();
        let m = q(&k, "nope.default.svc.cluster.local.", RecordType::A).await;
        assert_eq!(m.response_code(), ResponseCode::NXDomain);
        let m = q(&k, "web.nons.svc.cluster.local.", RecordType::A).await;
        assert_eq!(m.response_code(), ResponseCode::NXDomain);
        let m = q(&k, "default.svc.cluster.local.", RecordType::A).await;
        assert_eq!(m.response_code(), ResponseCode::NoError);
        assert!(m.answers().is_empty());
        let m = q(&k, "cluster.local.", RecordType::SOA).await;
        assert_eq!(m.answers()[0].record_type(), RecordType::SOA);
    }

    #[tokio::test]
    async fn pods_and_ptr() {
        let k = k8s();
        let m = q(&k, "10-244-1-9.default.pod.cluster.local.", RecordType::A).await;
        assert_eq!(m.answers().len(), 1);
        let m = q(&k, "10-244-1-99.default.pod.cluster.local.", RecordType::A).await;
        assert_eq!(m.response_code(), ResponseCode::NXDomain, "verified mode rejects unknown pod IPs");
        let m = q(&k, "10.0.96.10.in-addr.arpa.", RecordType::PTR).await;
        assert!(matches!(m.answers()[0].data(), Some(RData::PTR(p)) if p.0.to_ascii() == "web.default.svc.cluster.local."));
        let m = q(&k, "5.0.244.10.in-addr.arpa.", RecordType::PTR).await;
        assert!(matches!(m.answers()[0].data(), Some(RData::PTR(p)) if p.0.to_ascii() == "pg-0.hl.default.svc.cluster.local."));
    }

    #[tokio::test]
    async fn external_name() {
        let k = k8s();
        let m = q(&k, "ext.default.svc.cluster.local.", RecordType::CNAME).await;
        assert!(matches!(m.answers()[0].data(), Some(RData::CNAME(c)) if c.0.to_ascii() == "example.org."));
    }

    #[test]
    fn parse_names() {
        assert_eq!(parse_name(""), Parsed::Apex);
        assert_eq!(parse_name("svc"), Parsed::SvcRoot);
        assert!(matches!(parse_name("web.default.svc"), Parsed::Svc { endpoint: None, port: None, .. }));
        assert!(matches!(parse_name("_http._tcp.web.default.svc"), Parsed::Svc { port: Some(p), protocol: Some(pr), .. } if p == "http" && pr == "tcp"));
        assert!(matches!(parse_name("ep.web.default.svc"), Parsed::Svc { endpoint: Some(e), .. } if e == "ep"));
        assert!(matches!(parse_name("1-2-3-4.default.pod"), Parsed::Pod { .. }));
        assert_eq!(parse_name("a.b.c.d.e.f"), Parsed::Invalid);
    }
}
