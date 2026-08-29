//! `rewrite` — rewrite queries (name, type, class, EDNS0 options) and
//! responses (answer names, TTL, rcode, CNAME targets).
//!
//! ```text
//! rewrite [continue|stop] name [exact|prefix|suffix|substring|regex] FROM TO [answer auto | answer name FROM TO | answer value FROM TO]
//! rewrite [continue|stop] type FROM TO
//! rewrite [continue|stop] class FROM TO
//! rewrite [continue|stop] ttl [exact|prefix|suffix|substring|regex] NAME TTL[-TTL]
//! rewrite [continue|stop] rcode [exact|prefix|suffix|substring|regex] NAME FROM TO
//! rewrite [continue|stop] cname [exact|prefix|suffix|substring|regex] FROM TO
//! rewrite [continue|stop] edns0 local set|append|replace CODE DATA
//! rewrite [continue|stop] edns0 nsid set|append|replace
//! rewrite [continue|stop] edns0 subnet set|append|replace V4-BITS V6-BITS
//! ```

use crate::dnsutil;
use crate::plugin::replacer::rcode_from_str;
use crate::plugin::{Controller, DnsResult, Handler, Next, Request};
use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use hickory_proto::op::{Edns, Message, ResponseCode};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_proto::rr::rdata::CNAME;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use regex::Regex;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum Matcher {
    Exact(String),
    Prefix(String),
    Suffix(String),
    Substring(String),
    Regex(Regex),
}

impl Matcher {
    fn parse(kind: &str, pat: &str) -> Result<Matcher> {
        Ok(match kind {
            "exact" => Matcher::Exact(dnsutil::fqdn(pat)),
            "prefix" => Matcher::Prefix(pat.to_ascii_lowercase()),
            "suffix" => Matcher::Suffix(dnsutil::fqdn(pat).trim_start_matches('.').to_string().to_ascii_lowercase()),
            "substring" => Matcher::Substring(pat.to_ascii_lowercase()),
            "regex" => Matcher::Regex(Regex::new(&format!("(?i)^{}$", pat.trim_start_matches('^').trim_end_matches('$'))).map_err(|e| anyhow!("bad regex {}: {}", pat, e))?),
            o => bail!("unknown name match type {}", o),
        })
    }

    fn matches(&self, name: &str) -> bool {
        let n = name.to_ascii_lowercase();
        match self {
            Matcher::Exact(e) => n == *e,
            Matcher::Prefix(p) => n.starts_with(p),
            Matcher::Suffix(s) => n.ends_with(s),
            Matcher::Substring(s) => n.contains(s),
            Matcher::Regex(r) => r.is_match(&n),
        }
    }

    /// Apply the rewrite `to` for a matching name.
    fn rewrite(&self, name: &str, to: &str) -> Option<String> {
        let n = name.to_ascii_lowercase();
        match self {
            Matcher::Exact(e) => (n == *e).then(|| dnsutil::fqdn(to)),
            Matcher::Prefix(p) => n.strip_prefix(p.as_str()).map(|rest| dnsutil::fqdn(&format!("{}{}", to, rest))),
            Matcher::Suffix(s) => n.strip_suffix(s.as_str()).map(|head| dnsutil::fqdn(&format!("{}{}", head, to.trim_start_matches('.')))),
            Matcher::Substring(s) => n.contains(s.as_str()).then(|| dnsutil::fqdn(&n.replace(s.as_str(), to))),
            Matcher::Regex(r) => {
                let caps = r.captures(&n)?;
                let mut out = to.to_string();
                for i in 0..caps.len() {
                    if let Some(m) = caps.get(i) {
                        out = out.replace(&format!("{{{}}}", i), m.as_str());
                    }
                }
                // Go-style ${1} references too
                for i in 0..caps.len() {
                    if let Some(m) = caps.get(i) {
                        out = out.replace(&format!("${{{}}}", i), m.as_str()).replace(&format!("${}", i), m.as_str());
                    }
                }
                Some(dnsutil::fqdn(&out))
            }
        }
    }

    /// The inverse rewrite for `answer auto`.
    fn inverse(&self, to: &str) -> Option<(Matcher, String)> {
        match self {
            Matcher::Exact(e) => Some((Matcher::Exact(dnsutil::fqdn(to)), e.clone())),
            Matcher::Prefix(p) => Some((Matcher::Prefix(to.to_ascii_lowercase()), p.clone())),
            Matcher::Suffix(s) => Some((Matcher::Suffix(dnsutil::fqdn(to).trim_start_matches('.').to_ascii_lowercase()), s.clone())),
            Matcher::Substring(s) => Some((Matcher::Substring(to.to_ascii_lowercase()), s.clone())),
            Matcher::Regex(_) => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum AnswerRule {
    /// Rewrite answer names matching the rewritten query name back.
    Auto,
    Name(Matcher, String),
    Value(Matcher, String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edns0Action {
    Set,
    Append,
    Replace,
}

impl Edns0Action {
    fn parse(s: &str) -> Result<Edns0Action> {
        Ok(match s {
            "set" => Edns0Action::Set,
            "append" => Edns0Action::Append,
            "replace" => Edns0Action::Replace,
            o => bail!("invalid action: {}", o),
        })
    }
}

#[derive(Debug, Clone)]
pub enum Rule {
    Name { m: Matcher, to: String, answers: Vec<AnswerRule> },
    Type { from: RecordType, to: RecordType },
    Class { from: DNSClass, to: DNSClass },
    Ttl { m: Matcher, min: u32, max: u32 },
    Rcode { m: Matcher, from: ResponseCode, to: ResponseCode },
    Cname { m: Matcher, to: String },
    Edns0Local { action: Edns0Action, code: u16, data: Vec<u8>, var: Option<String> },
    Edns0Nsid { action: Edns0Action },
    Edns0Subnet { action: Edns0Action, v4: u8, v6: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Stop,
    Continue,
}

pub struct Rewrite {
    rules: Vec<(Mode, Rule)>,
}

/// State recorded while rewriting a request so the response can be undone.
#[derive(Default)]
struct Undo {
    orig_name: Option<Name>,
    orig_type: Option<RecordType>,
    orig_class: Option<DNSClass>,
    answer_rules: Vec<(AnswerRule, Matcher, String)>,
    ttl: Vec<(Matcher, u32, u32)>,
    rcode: Vec<(Matcher, ResponseCode, ResponseCode)>,
    cname: Vec<(Matcher, String)>,
}

fn expand_var(var: &str, req: &Request) -> String {
    match var {
        "{qname}" => req.name_uncached(),
        "{qtype}" => req.type_str(),
        "{client_ip}" => req.ip().to_string(),
        "{client_port}" => req.port().to_string(),
        "{protocol}" => req.proto_str().to_string(),
        "{server_ip}" => req.local_ip().to_string(),
        "{server_port}" => req.local_port().to_string(),
        o => o.to_string(),
    }
}

fn apply_edns0(req: &mut Request, action: Edns0Action, code: u16, data: Vec<u8>) {
    let e = req.msg.extensions_mut().get_or_insert_with(|| {
        let mut e = Edns::new();
        e.set_max_payload(dnsutil::UDP_BUFFER_SIZE);
        e
    });
    let ecode = EdnsCode::from(code);
    let exists = e.option(ecode).is_some();
    match action {
        Edns0Action::Set => {
            e.options_mut().insert(EdnsOption::Unknown(code, data));
        }
        Edns0Action::Append => {
            if !exists {
                e.options_mut().insert(EdnsOption::Unknown(code, data));
            }
        }
        Edns0Action::Replace => {
            if exists {
                e.options_mut().insert(EdnsOption::Unknown(code, data));
            }
        }
    }
}

impl Rewrite {
    fn apply_request(&self, req: &mut Request) -> Undo {
        let mut undo = Undo::default();
        for (mode, rule) in &self.rules {
            let matched = match rule {
                Rule::Name { m, to, answers } => {
                    let name = req.name_uncached();
                    match m.rewrite(&name, to) {
                        Some(new) if new != name => {
                            if let Ok(n) = Name::from_ascii(&new) {
                                if undo.orig_name.is_none() {
                                    undo.orig_name = Some(req.qname());
                                }
                                let mut q = req.msg.take_queries();
                                if let Some(first) = q.first_mut() {
                                    first.set_name(n);
                                }
                                for qq in q {
                                    req.msg.add_query(qq);
                                }
                                req.clear_name_cache();
                                for a in answers {
                                    undo.answer_rules.push((a.clone(), m.clone(), to.clone()));
                                }
                                true
                            } else {
                                false
                            }
                        }
                        _ => false,
                    }
                }
                Rule::Type { from, to } => {
                    if req.qtype() == *from {
                        if undo.orig_type.is_none() {
                            undo.orig_type = Some(*from);
                        }
                        let mut q = req.msg.take_queries();
                        if let Some(first) = q.first_mut() {
                            first.set_query_type(*to);
                        }
                        for qq in q {
                            req.msg.add_query(qq);
                        }
                        true
                    } else {
                        false
                    }
                }
                Rule::Class { from, to } => {
                    if req.qclass() == *from {
                        if undo.orig_class.is_none() {
                            undo.orig_class = Some(*from);
                        }
                        let mut q = req.msg.take_queries();
                        if let Some(first) = q.first_mut() {
                            first.set_query_class(*to);
                        }
                        for qq in q {
                            req.msg.add_query(qq);
                        }
                        true
                    } else {
                        false
                    }
                }
                Rule::Ttl { m, min, max } => {
                    if m.matches(&req.name_uncached()) {
                        undo.ttl.push((m.clone(), *min, *max));
                        true
                    } else {
                        false
                    }
                }
                Rule::Rcode { m, from, to } => {
                    if m.matches(&req.name_uncached()) {
                        undo.rcode.push((m.clone(), *from, *to));
                        true
                    } else {
                        false
                    }
                }
                Rule::Cname { m, to } => {
                    undo.cname.push((m.clone(), to.clone()));
                    false
                }
                Rule::Edns0Local { action, code, data, var } => {
                    let data = match var {
                        Some(v) => expand_var(v, req).into_bytes(),
                        None => data.clone(),
                    };
                    apply_edns0(req, *action, *code, data);
                    true
                }
                Rule::Edns0Nsid { action } => {
                    apply_edns0(req, *action, u16::from(EdnsCode::NSID), Vec::new());
                    true
                }
                Rule::Edns0Subnet { action, v4, v6 } => {
                    let ip = req.ip();
                    let (addr, bits) = match ip {
                        IpAddr::V4(a) => {
                            let mask = if *v4 == 0 { 0 } else { u32::MAX << (32 - *v4 as u32) };
                            (IpAddr::V4(std::net::Ipv4Addr::from(u32::from(a) & mask)), *v4)
                        }
                        IpAddr::V6(a) => {
                            let mask = if *v6 == 0 { 0 } else { u128::MAX << (128 - *v6 as u32) };
                            (IpAddr::V6(std::net::Ipv6Addr::from(u128::from(a) & mask)), *v6)
                        }
                    };
                    let e = req.msg.extensions_mut().get_or_insert_with(|| {
                        let mut e = Edns::new();
                        e.set_max_payload(dnsutil::UDP_BUFFER_SIZE);
                        e
                    });
                    let exists = e.option(EdnsCode::Subnet).is_some();
                    let want = match action {
                        Edns0Action::Set => true,
                        Edns0Action::Append => !exists,
                        Edns0Action::Replace => exists,
                    };
                    if want {
                        e.options_mut().insert(EdnsOption::Subnet(ClientSubnet::new(addr, bits, 0)));
                    }
                    true
                }
            };
            if matched && *mode == Mode::Stop {
                break;
            }
        }
        undo
    }

    async fn apply_response(&self, req: &Request, undo: &Undo, m: &mut Message) {
        // restore the question
        let orig_name = undo.orig_name.clone();
        let mut q = m.take_queries();
        if let Some(first) = q.first_mut() {
            if let Some(n) = &orig_name {
                first.set_name(n.clone());
            }
            if let Some(t) = undo.orig_type {
                first.set_query_type(t);
            }
            if let Some(c) = undo.orig_class {
                first.set_query_class(c);
            }
        }
        for qq in q {
            m.add_query(qq);
        }
        // answer name rewriting
        if !undo.answer_rules.is_empty() {
            let new_qname = req.name_uncached();
            let mut answers = m.take_answers();
            for (rule, matcher, to) in &undo.answer_rules {
                for r in answers.iter_mut() {
                    let rname = dnsutil::name_str(r.name());
                    match rule {
                        AnswerRule::Auto => {
                            if rname == new_qname {
                                if let Some(o) = &orig_name {
                                    r.set_name(o.clone());
                                }
                            } else if let Some((inv, back)) = matcher.inverse(to) {
                                if let Some(n) = inv.rewrite(&rname, &back) {
                                    if let Ok(nn) = Name::from_ascii(&n) {
                                        r.set_name(nn);
                                    }
                                }
                            }
                        }
                        AnswerRule::Name(am, ato) => {
                            if let Some(n) = am.rewrite(&rname, ato) {
                                if let Ok(nn) = Name::from_ascii(&n) {
                                    r.set_name(nn);
                                }
                            }
                        }
                        AnswerRule::Value(vm, vto) => {
                            let target = match r.data() {
                                Some(RData::CNAME(c)) => Some(dnsutil::name_str(&c.0)),
                                Some(RData::PTR(p)) => Some(dnsutil::name_str(&p.0)),
                                _ => None,
                            };
                            if let Some(t) = target {
                                if let Some(n) = vm.rewrite(&t, vto) {
                                    if let Ok(nn) = Name::from_ascii(&n) {
                                        match r.data_mut() {
                                            Some(RData::CNAME(c)) => c.0 = nn,
                                            Some(RData::PTR(p)) => p.0 = nn,
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            m.insert_answers(answers);
        }
        // ttl
        for (matcher, min, max) in &undo.ttl {
            let mut answers = m.take_answers();
            for r in answers.iter_mut() {
                if matcher.matches(&dnsutil::name_str(r.name())) {
                    let t = r.ttl().clamp(*min, *max);
                    r.set_ttl(t);
                }
            }
            m.insert_answers(answers);
        }
        // rcode
        for (_, from, to) in &undo.rcode {
            if m.response_code() == *from {
                m.set_response_code(*to);
            }
        }
        // cname target rewrite + re-resolution
        for (matcher, to) in &undo.cname {
            let mut answers = m.take_answers();
            let mut chased: Vec<Record> = Vec::new();
            let mut changed = false;
            for r in answers.iter_mut() {
                if let Some(RData::CNAME(c)) = r.data() {
                    let t = dnsutil::name_str(&c.0);
                    if let Some(n) = matcher.rewrite(&t, to) {
                        if let Ok(nn) = Name::from_ascii(&n) {
                            *r = Record::from_rdata(r.name().clone(), r.ttl(), RData::CNAME(CNAME(nn.clone())));
                            changed = true;
                            if let Ok(res) = crate::server::self_lookup(req, nn, req.qtype()).await {
                                chased.extend(res.answers().iter().cloned());
                            }
                        }
                    }
                }
            }
            if changed {
                // keep only the rewritten CNAMEs, then the chased records
                answers.retain(|r| r.record_type() == RecordType::CNAME);
                answers.extend(chased);
            }
            m.insert_answers(answers);
        }
    }
}

#[async_trait]
impl Handler for Rewrite {
    fn name(&self) -> &'static str {
        "rewrite"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let undo = self.apply_request(req);
        let mut r = next.serve(req).await?;
        if let Some(m) = r.msg_mut() {
            self.apply_response(req, &undo, m).await;
        }
        // hand the request back with its original question so later
        // observers (log, metrics) see what the client asked
        if let Some(n) = undo.orig_name {
            let mut q = req.msg.take_queries();
            if let Some(first) = q.first_mut() {
                first.set_name(n);
            }
            for qq in q {
                req.msg.add_query(qq);
            }
            req.clear_name_cache();
        }
        Ok(r)
    }
}

fn parse_edns0_data(s: &str) -> Result<(Vec<u8>, Option<String>)> {
    if s.starts_with('{') && s.ends_with('}') {
        return Ok((Vec::new(), Some(s.to_string())));
    }
    if let Some(h) = s.strip_prefix("0x") {
        return Ok((hex::decode(h).map_err(|e| anyhow!("bad hex data {}: {}", s, e))?, None));
    }
    Ok((s.as_bytes().to_vec(), None))
}

fn parse_rule(c: &Controller<'_>, args: &[String], block: &[Vec<String>]) -> Result<(Mode, Rule)> {
    let mut args = args.to_vec();
    let mut mode = Mode::Stop;
    if let Some(first) = args.first() {
        if first == "continue" {
            mode = Mode::Continue;
            args.remove(0);
        } else if first == "stop" {
            args.remove(0);
        }
    }
    if args.is_empty() {
        return Err(c.errf("rewrite rule needs a field"));
    }
    let field = args.remove(0);
    let rule = match field.as_str() {
        "name" => {
            // name [kind] FROM TO [answer ...]
            let (kind, rest) = match args.first().map(|s| s.as_str()) {
                Some("exact") | Some("prefix") | Some("suffix") | Some("substring") | Some("regex") => (args[0].clone(), &args[1..]),
                _ => ("exact".to_string(), &args[..]),
            };
            if rest.len() < 2 {
                return Err(c.errf("name rule needs FROM and TO"));
            }
            let m = Matcher::parse(&kind, &rest[0])?;
            let to = rest[1].clone();
            let mut answers = Vec::new();
            let mut extra: Vec<Vec<String>> = Vec::new();
            if rest.len() > 2 {
                extra.push(rest[2..].to_vec());
            }
            extra.extend(block.iter().cloned());
            for line in extra {
                if line.first().map(|s| s.as_str()) != Some("answer") {
                    return Err(c.errf(format!("unexpected '{}' in name rule", line.join(" "))));
                }
                match line.get(1).map(|s| s.as_str()) {
                    Some("auto") => answers.push(AnswerRule::Auto),
                    Some("name") | Some("value") => {
                        let which = line[1].clone();
                        let (akind, arest) = match line.get(2).map(|s| s.as_str()) {
                            Some("exact") | Some("prefix") | Some("suffix") | Some("substring") | Some("regex") => (line[2].clone(), &line[3..]),
                            _ => (kind.clone(), &line[2..]),
                        };
                        if arest.len() != 2 {
                            return Err(c.errf("answer rule needs FROM and TO"));
                        }
                        let am = Matcher::parse(&akind, &arest[0])?;
                        if which == "name" {
                            answers.push(AnswerRule::Name(am, arest[1].clone()));
                        } else {
                            answers.push(AnswerRule::Value(am, arest[1].clone()));
                        }
                    }
                    _ => return Err(c.errf("answer needs auto, name or value")),
                }
            }
            Rule::Name { m, to, answers }
        }
        "type" => {
            if args.len() != 2 {
                return Err(c.errf("type rule needs FROM and TO"));
            }
            Rule::Type { from: dnsutil::record_type_from_str(&args[0])?, to: dnsutil::record_type_from_str(&args[1])? }
        }
        "class" => {
            if args.len() != 2 {
                return Err(c.errf("class rule needs FROM and TO"));
            }
            let pc = |s: &str| -> Result<DNSClass> { s.to_ascii_uppercase().parse::<DNSClass>().map_err(|e| anyhow!("bad class {}: {}", s, e)) };
            Rule::Class { from: pc(&args[0])?, to: pc(&args[1])? }
        }
        "ttl" => {
            let (kind, rest) = match args.first().map(|s| s.as_str()) {
                Some("exact") | Some("prefix") | Some("suffix") | Some("substring") | Some("regex") => (args[0].clone(), &args[1..]),
                _ => ("exact".to_string(), &args[..]),
            };
            if rest.len() != 2 {
                return Err(c.errf("ttl rule needs NAME and TTL"));
            }
            let m = Matcher::parse(&kind, &rest[0])?;
            let (min, max) = match rest[1].split_once('-') {
                Some((a, b)) => (a.parse::<u32>()?, b.parse::<u32>()?),
                None => {
                    let t: u32 = rest[1].parse()?;
                    (t, t)
                }
            };
            Rule::Ttl { m, min, max }
        }
        "rcode" => {
            let (kind, rest) = match args.first().map(|s| s.as_str()) {
                Some("exact") | Some("prefix") | Some("suffix") | Some("substring") | Some("regex") => (args[0].clone(), &args[1..]),
                _ => ("exact".to_string(), &args[..]),
            };
            if rest.len() != 3 {
                return Err(c.errf("rcode rule needs NAME FROM TO"));
            }
            let m = Matcher::parse(&kind, &rest[0])?;
            let pr = |s: &str| rcode_from_str(s).ok_or_else(|| anyhow!("unknown rcode {}", s));
            Rule::Rcode { m, from: pr(&rest[1])?, to: pr(&rest[2])? }
        }
        "cname" => {
            let (kind, rest) = match args.first().map(|s| s.as_str()) {
                Some("exact") | Some("prefix") | Some("suffix") | Some("substring") | Some("regex") => (args[0].clone(), &args[1..]),
                _ => ("exact".to_string(), &args[..]),
            };
            if rest.len() != 2 {
                return Err(c.errf("cname rule needs FROM and TO"));
            }
            Rule::Cname { m: Matcher::parse(&kind, &rest[0])?, to: rest[1].clone() }
        }
        "edns0" => {
            if args.is_empty() {
                return Err(c.errf("edns0 rule needs a type"));
            }
            match args[0].as_str() {
                "local" => {
                    if args.len() != 4 {
                        return Err(c.errf("edns0 local needs ACTION CODE DATA"));
                    }
                    let action = Edns0Action::parse(&args[1])?;
                    let code: u16 = if let Some(h) = args[2].strip_prefix("0x") { u16::from_str_radix(h, 16)? } else { args[2].parse()? };
                    let (data, var) = parse_edns0_data(&args[3])?;
                    Rule::Edns0Local { action, code, data, var }
                }
                "nsid" => {
                    if args.len() != 2 {
                        return Err(c.errf("edns0 nsid needs ACTION"));
                    }
                    Rule::Edns0Nsid { action: Edns0Action::parse(&args[1])? }
                }
                "subnet" => {
                    if args.len() != 4 {
                        return Err(c.errf("edns0 subnet needs ACTION V4-BITS V6-BITS"));
                    }
                    let v4: u8 = args[2].parse()?;
                    let v6: u8 = args[3].parse()?;
                    if v4 > 32 || v6 > 128 {
                        return Err(c.errf("bad subnet mask bits"));
                    }
                    Rule::Edns0Subnet { action: Edns0Action::parse(&args[1])?, v4, v6 }
                }
                o => return Err(c.errf(format!("unknown edns0 type {}", o))),
            }
        }
        o => return Err(c.errf(format!("invalid rule type \"{}\"", o))),
    };
    Ok((mode, rule))
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut rules = Vec::new();
    while c.next() {
        let args = c.remaining_args_until_brace();
        let mut block: Vec<Vec<String>> = Vec::new();
        while c.next_block() {
            let mut line = vec![c.val().to_string()];
            line.extend(c.remaining_args());
            block.push(line);
        }
        if args.is_empty() {
            return Err(c.arg_err());
        }
        rules.push(parse_rule(c, &args, &block)?);
    }
    c.add_plugin(Arc::new(Rewrite { rules }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::Reply;
    use hickory_proto::rr::rdata::A;

    struct Echo;
    #[async_trait]
    impl Handler for Echo {
        fn name(&self) -> &'static str {
            "echo"
        }
        async fn serve_dns(&self, req: &mut Request, _next: Next<'_>) -> DnsResult {
            let mut m = req.new_reply();
            m.add_answer(Record::from_rdata(req.qname(), 30, RData::A(A::new(1, 2, 3, 4))));
            Ok(Reply::Msg(m))
        }
    }

    #[tokio::test]
    async fn suffix_with_auto_answer() {
        let rw = Rewrite {
            rules: vec![(Mode::Stop, Rule::Name { m: Matcher::parse("suffix", ".old.example.").unwrap(), to: ".new.example.".into(), answers: vec![AnswerRule::Auto] })],
        };
        let chain: Vec<Arc<dyn Handler>> = vec![Arc::new(rw), Arc::new(Echo)];
        let mut req = Request::for_test("www.old.example.", RecordType::A);
        let m = Next::new(&chain).serve(&mut req).await.unwrap().into_msg().unwrap();
        assert_eq!(m.queries()[0].name().to_ascii(), "www.old.example.");
        assert_eq!(m.answers()[0].name().to_ascii(), "www.old.example.");
        assert_eq!(req.name(), "www.old.example.");
    }

    #[test]
    fn regex_rewrite() {
        let m = Matcher::parse("regex", "(.*)\\.example\\.org").unwrap();
        assert_eq!(m.rewrite("www.example.org.", "{1}.example.net").unwrap(), "www.example.net.");
        let m = Matcher::parse("exact", "a.example.org").unwrap();
        assert_eq!(m.rewrite("A.EXAMPLE.ORG.", "b.example.org").unwrap(), "b.example.org.");
        assert!(m.rewrite("c.example.org.", "b").is_none());
    }
}
