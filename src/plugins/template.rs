//! `template` — synthesise answers from Go-template style RR strings.
//!
//! ```text
//! template CLASS TYPE [ZONE...] {
//!     match REGEX...
//!     answer RR
//!     additional RR
//!     authority RR
//!     rcode CODE
//!     ederror CODE [REASON]
//!     fallthrough [ZONES...]
//! }
//! ```
//! As in CoreDNS: a query in the zone whose class/type match but whose
//! name misses every regex gets SERVFAIL unless `fallthrough` covers it;
//! CNAME answers to A/AAAA queries are resolved through the server.
//! Supported template fields: `{{ .Name }}`, `{{ .Zone }}`, `{{ .Class }}`,
//! `{{ .Type }}`, `{{ .Remote }}`, `{{ .Message.Id }}`, `{{ index .Match N }}`,
//! `{{ .Group.NAME }}`, `{{ .Meta "label" }}`.

use crate::dnsutil;
use crate::plugin::replacer::rcode_from_str;
use crate::plugin::{error, Controller, DnsResult, Handler, Next, Reply, Request};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use hickory_proto::op::{Edns, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::txt::Parser;
use once_cell::sync::Lazy;
use prometheus::IntCounterVec;
use regex::Regex;
use std::sync::Arc;

static MATCHES: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(prometheus::Opts::new("coredns_template_matches_total", "Counter of template regex matches."), &["server", "zone", "view", "class", "type"]).unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});
static FAILURES: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(prometheus::Opts::new("coredns_template_template_failures_total", "Counter of go template failures."), &["server", "zone", "view", "class", "type", "section", "template"]).unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});
static RR_FAILURES: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(prometheus::Opts::new("coredns_template_rr_failures_total", "Counter of mis-templated RRs."), &["server", "zone", "view", "class", "type", "section", "template"]).unwrap();
    crate::metrics::register(Box::new(c.clone()));
    c
});

#[derive(Debug, Clone)]
pub struct Template {
    pub zones: Vec<String>,
    pub class: Option<DNSClass>, // None = ANY
    pub qtype: Option<RecordType>,
    pub regex: Vec<Regex>,
    pub answer: Vec<String>,
    pub additional: Vec<String>,
    pub authority: Vec<String>,
    pub rcode: ResponseCode,
    pub fallthrough: Option<Vec<String>>,
    /// `ederror CODE [REASON]`: an Extended DNS Error added to the reply.
    pub ederror: Option<(u16, String)>,
}

/// Values available to a template.
struct Data<'a> {
    req: &'a Request,
    zone: &'a str,
    name: String,
    matches: Vec<String>,
    groups: Vec<(String, String)>,
}

/// Expand `{{ ... }}` actions. Unknown actions render empty.
fn render(tpl: &str, d: &Data<'_>) -> Result<String> {
    let mut out = String::new();
    let mut rest = tpl;
    while let Some(i) = rest.find("{{") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 2..];
        let j = after.find("}}").ok_or_else(|| anyhow!("unterminated template action in {}", tpl))?;
        let action = after[..j].trim();
        out.push_str(&eval_action(action, d)?);
        rest = &after[j + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

fn eval_action(action: &str, d: &Data<'_>) -> Result<String> {
    let parts: Vec<&str> = action.split_whitespace().collect();
    match parts.as_slice() {
        [".Name"] | [".Question.Name"] => Ok(d.name.clone()),
        [".Zone"] => Ok(d.zone.to_string()),
        [".Class"] => Ok(d.req.class_str()),
        [".Type"] => Ok(d.req.type_str()),
        [".Remote"] => Ok(d.req.ip().to_string()),
        [".Message.Id"] => Ok(d.req.msg.id().to_string()),
        ["index", ".Match", n] => {
            let i: usize = n.parse().map_err(|_| anyhow!("bad match index {}", n))?;
            d.matches.get(i).cloned().ok_or_else(|| anyhow!("match index {} out of range", i))
        }
        [".Meta", label] => Ok(d.req.metadata.value(label.trim_matches('"')).unwrap_or_default()),
        [g] if g.starts_with(".Group.") => {
            let key = &g[".Group.".len()..];
            Ok(d.groups.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()).unwrap_or_default())
        }
        ["index", ".Group", key] => {
            let key = key.trim_matches('"');
            Ok(d.groups.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()).unwrap_or_default())
        }
        _ => Err(anyhow!("unsupported template action {{{{ {} }}}}", action)),
    }
}

fn parse_rr(text: &str, zone: &str) -> Result<Vec<Record>> {
    let origin = Name::from_ascii(zone).ok();
    let input = format!("$TTL 3600\n{}\n", text);
    let (_, sets) = Parser::new(input, None, origin).parse().map_err(|e| anyhow!("parsing RR '{}': {}", text, e))?;
    let mut out = Vec::new();
    for (_, set) in sets {
        for r in set.records_without_rrsigs() {
            out.push(r.clone());
        }
    }
    Ok(out)
}

pub struct TemplateHandler {
    templates: Vec<Template>,
}

impl Template {
    // a query of class/type ANY matches every template, as in CoreDNS
    fn class_matches(&self, c: DNSClass) -> bool {
        c == DNSClass::ANY || self.class.map(|x| x == c).unwrap_or(true)
    }
    fn type_matches(&self, t: RecordType) -> bool {
        t == RecordType::ANY || self.qtype.map(|x| x == t).unwrap_or(true)
    }
    fn falls_through(&self, name: &str) -> bool {
        self.fallthrough.as_ref().map(|ft| crate::plugin::zones_match(ft, name).is_some()).unwrap_or(false)
    }
    fn zone_match<'z>(&'z self, name: &str) -> Option<&'z str> {
        crate::plugin::zones_match(&self.zones, name)
    }
}

#[async_trait]
impl Handler for TemplateHandler {
    fn name(&self) -> &'static str {
        "template"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let name = req.name();
        for t in &self.templates {
            let Some(zone) = t.zone_match(&name) else { continue };
            if !t.class_matches(req.qclass()) || !t.type_matches(req.qtype()) {
                continue;
            }
            // regex match (none = match all)
            let mut matches = Vec::new();
            let mut groups = Vec::new();
            let mut matched = t.regex.is_empty();
            for re in &t.regex {
                if let Some(caps) = re.captures(&name) {
                    matched = true;
                    for i in 0..caps.len() {
                        matches.push(caps.get(i).map(|m| m.as_str().to_string()).unwrap_or_default());
                    }
                    for gname in re.capture_names().flatten() {
                        if let Some(m) = caps.name(gname) {
                            groups.push((gname.to_string(), m.as_str().to_string()));
                        }
                    }
                    break;
                }
            }
            if !matched {
                // as in CoreDNS: a regex miss is SERVFAIL unless fallthrough covers the name
                if t.falls_through(&name) {
                    continue;
                }
                return Ok(Reply::Rcode(ResponseCode::ServFail));
            }
            let class_s = t.class.map(|c| c.to_string()).unwrap_or_else(|| "ANY".into());
            let type_s = t.qtype.map(|c| c.to_string()).unwrap_or_else(|| "ANY".into());
            MATCHES.with_label_values(&[&req.server, &req.zone, &req.view, &class_s, &type_s]).inc();
            if t.rcode == ResponseCode::ServFail {
                return Ok(Reply::Rcode(ResponseCode::ServFail));
            }
            let data = Data { req, zone, name: name.clone(), matches, groups };
            let mut m = req.new_reply();
            m.set_authoritative(true);
            m.set_response_code(t.rcode);
            let mut chased: Vec<Record> = Vec::new();
            for (section, tpls) in [("answer", &t.answer), ("additional", &t.additional), ("authority", &t.authority)] {
                for tpl in tpls {
                    let rendered = match render(tpl, &data) {
                        Ok(r) => r,
                        Err(e) => {
                            FAILURES.with_label_values(&[&req.server, &req.zone, &req.view, &class_s, &type_s, section, tpl]).inc();
                            return Err(error("template", e).with_rcode(ResponseCode::ServFail));
                        }
                    };
                    let recs = match parse_rr(&rendered, zone) {
                        Ok(r) => r,
                        Err(e) => {
                            RR_FAILURES.with_label_values(&[&req.server, &req.zone, &req.view, &class_s, &type_s, section, tpl]).inc();
                            return Err(error("template", e).with_rcode(ResponseCode::ServFail));
                        }
                    };
                    for r in recs {
                        match section {
                            "answer" => {
                                // CNAME answers to A/AAAA are resolved through the server, as CoreDNS's upstream does
                                if matches!(req.qtype(), RecordType::A | RecordType::AAAA) {
                                    if let Some(RData::CNAME(c)) = r.data() {
                                        if let Ok(up) = crate::server::self_lookup(req, c.0.clone(), req.qtype()).await {
                                            if up.truncated() {
                                                m.set_truncated(true);
                                            }
                                            chased.extend(up.answers().iter().cloned());
                                        }
                                    }
                                }
                                m.add_answer(r);
                                for c in chased.drain(..) {
                                    m.add_answer(c);
                                }
                            }
                            "additional" => {
                                m.add_additional(r);
                            }
                            _ => {
                                m.add_name_server(r);
                            }
                        }
                    }
                }
            }
            if let Some((code, reason)) = &t.ederror {
                let mut e = m.extensions().clone().unwrap_or_else(Edns::new);
                e.set_max_payload(4096);
                e.set_dnssec_ok(true);
                let mut data = code.to_be_bytes().to_vec();
                data.extend_from_slice(reason.as_bytes());
                e.options_mut().insert(EdnsOption::Unknown(15, data));
                m.set_edns(e);
            }
            return Ok(Reply::Msg(m));
        }
        next.serve(req).await
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut templates = Vec::new();
    while c.next() {
        let args = c.remaining_args_until_brace();
        if args.len() < 2 {
            return Err(c.arg_err());
        }
        let class = match args[0].to_ascii_uppercase().as_str() {
            "ANY" => None,
            cl => Some(cl.parse::<DNSClass>().map_err(|e| c.errf(format!("invalid query class {}: {}", cl, e)))?),
        };
        let qtype = match args[1].to_ascii_uppercase().as_str() {
            "ANY" => None,
            t => Some(dnsutil::record_type_from_str(t).map_err(|e| c.errf(e))?),
        };
        let zones = c.origins_from_args_or_server_block(&args[2..])?;
        let mut t = Template { zones, class, qtype, regex: Vec::new(), answer: Vec::new(), additional: Vec::new(), authority: Vec::new(), rcode: ResponseCode::NoError, fallthrough: None, ederror: None };
        while c.next_block() {
            match c.val() {
                "match" => {
                    for r in c.remaining_args() {
                        // compiled as given (case-sensitive, like Go); query names are lowercased
                        t.regex.push(Regex::new(&r).map_err(|e| c.errf(format!("invalid regex {}: {}", r, e)))?);
                    }
                }
                "answer" => t.answer.extend(c.remaining_args()),
                "additional" => t.additional.extend(c.remaining_args()),
                "authority" => t.authority.extend(c.remaining_args()),
                "rcode" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    t.rcode = rcode_from_str(&a[0]).ok_or_else(|| c.errf(format!("unknown rcode {}", a[0])))?;
                }
                "fallthrough" => {
                    let a = c.remaining_args();
                    t.fallthrough = Some(if a.is_empty() { vec![".".into()] } else { crate::plugin::normalize_zones(&a)? });
                }
                "upstream" => {
                    let _ = c.remaining_args();
                }
                "ederror" => {
                    let a = c.remaining_args();
                    if a.is_empty() || a.len() > 2 {
                        return Err(c.arg_err());
                    }
                    let code: u16 = a[0].parse().map_err(|_| c.errf(format!("error parsing extended DNS error code {}", a[0])))?;
                    t.ederror = Some((code, a.get(1).cloned().unwrap_or_default()));
                }
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        if t.answer.is_empty() && t.additional.is_empty() && t.authority.is_empty() && t.rcode == ResponseCode::NoError {
            return Err(c.errf("template has no sections and no rcode"));
        }
        templates.push(t);
    }
    c.add_plugin(Arc::new(TemplateHandler { templates }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn renders_answer() {
        let t = Template {
            zones: vec!["example.".into()],
            class: Some(DNSClass::IN),
            qtype: Some(RecordType::A),
            regex: vec![Regex::new(r"^ip-(?P<a>\d+)-(?P<b>\d+)-(?P<c>\d+)-(?P<d>\d+)\.example\.$").unwrap()],
            answer: vec!["{{ .Name }} 60 IN A {{ .Group.a }}.{{ .Group.b }}.{{ .Group.c }}.{{ .Group.d }}".into()],
            additional: vec![],
            authority: vec![],
            rcode: ResponseCode::NoError,
            fallthrough: None,
            ederror: None,
        };
        let h = TemplateHandler { templates: vec![t] };
        let mut req = Request::for_test("ip-10-1-2-3.example.", RecordType::A);
        let m = h.serve_dns(&mut req, Next::new(&[])).await.unwrap().into_msg().unwrap();
        assert_eq!(m.answers().len(), 1);
        assert_eq!(m.answers()[0].ttl(), 60);
        assert!(matches!(m.answers()[0].data(), Some(hickory_proto::rr::RData::A(a)) if a.0 == std::net::Ipv4Addr::new(10, 1, 2, 3)));
    }

    #[tokio::test]
    async fn nxdomain_with_soa() {
        let t = Template {
            zones: vec!["invalid.".into()],
            class: None,
            qtype: None,
            regex: vec![],
            answer: vec![],
            additional: vec![],
            authority: vec!["invalid. 60 IN SOA ns.invalid. hostmaster.invalid. (1 60 60 60 60)".into()],
            rcode: ResponseCode::NXDomain,
            fallthrough: None,
            ederror: None,
        };
        let h = TemplateHandler { templates: vec![t] };
        let mut req = Request::for_test("foo.invalid.", RecordType::AAAA);
        let m = h.serve_dns(&mut req, Next::new(&[])).await.unwrap().into_msg().unwrap();
        assert_eq!(m.response_code(), ResponseCode::NXDomain);
        assert_eq!(m.name_servers().len(), 1);
    }

    #[tokio::test]
    async fn regex_miss_is_servfail_unless_fallthrough() {
        let mk = |ft: Option<Vec<String>>| Template {
            zones: vec!["example.".into()],
            class: None,
            qtype: None,
            regex: vec![Regex::new(r"^ok\.example\.$").unwrap()],
            answer: vec!["{{ .Name }} 60 IN A 192.0.2.1".into()],
            additional: vec![],
            authority: vec![],
            rcode: ResponseCode::NoError,
            fallthrough: ft,
            ederror: Some((17, "nope".into())),
        };
        let h = TemplateHandler { templates: vec![mk(None)] };
        let mut req = Request::for_test("other.example.", RecordType::A);
        assert!(matches!(h.serve_dns(&mut req, Next::new(&[])).await.unwrap(), Reply::Rcode(ResponseCode::ServFail)));
        let h = TemplateHandler { templates: vec![mk(Some(vec![".".into()]))] };
        let mut req = Request::for_test("other.example.", RecordType::A);
        assert!(h.serve_dns(&mut req, Next::new(&[])).await.is_err(), "falls through to the (empty) chain");
        // a match carries the EDE
        let mut req = Request::for_test("ok.example.", RecordType::A);
        let m = h.serve_dns(&mut req, Next::new(&[])).await.unwrap().into_msg().unwrap();
        let ede = m.extensions().as_ref().unwrap().options().get(hickory_proto::rr::rdata::opt::EdnsCode::from(15)).cloned();
        assert_eq!(ede, Some(EdnsOption::Unknown(15, b"\x00\x11nope".to_vec())));
    }
}
