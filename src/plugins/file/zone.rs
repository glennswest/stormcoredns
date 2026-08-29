//! In-memory authoritative zone with RFC 1034 lookup semantics: exact
//! match, CNAME chasing, wildcards, delegations with glue, empty
//! non-terminals, NXDOMAIN/NODATA with SOA, and DNSSEC records (RRSIG,
//! NSEC, DS) passed through when the zone file is signed.

use crate::dnsutil;
use crate::plugin::Request;
use anyhow::{anyhow, bail, Result};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::txt::Parser;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

#[derive(Default, Debug, Clone)]
pub struct NameData {
    pub rrsets: HashMap<RecordType, Vec<Record>>,
    /// RRSIGs keyed by the type they cover.
    pub rrsigs: HashMap<RecordType, Vec<Record>>,
}

impl NameData {
    fn is_empty(&self) -> bool {
        self.rrsets.is_empty()
    }
    fn has(&self, t: RecordType) -> bool {
        self.rrsets.get(&t).map(|v| !v.is_empty()).unwrap_or(false)
    }
}

#[derive(Debug, Clone)]
pub struct Zone {
    /// Lowercase FQDN.
    pub origin: String,
    pub origin_name: Name,
    /// Owner name (lowercase FQDN) → data.
    pub names: BTreeMap<String, NameData>,
    /// Names that own NSEC records, in canonical order, for negative proofs.
    nsec_chain: Vec<Name>,
    pub serial: u32,
    pub signed: bool,
    /// Source path, if loaded from a file.
    pub path: Option<PathBuf>,
}

impl Zone {
    pub fn parse(text: &str, origin: &str, path: Option<PathBuf>) -> Result<Zone> {
        let origin_fq = dnsutil::fqdn(origin);
        let origin_name = Name::from_ascii(&origin_fq).map_err(|e| anyhow!("bad origin {}: {}", origin, e))?;
        let (_, sets) = Parser::new(text, path.clone(), Some(origin_name.clone()))
            .parse()
            .map_err(|e| anyhow!("parsing zone {}: {}", origin_fq, e))?;
        let mut records = Vec::new();
        for (_, set) in sets {
            for r in set.records_without_rrsigs() {
                records.push(r.clone());
            }
            for r in set.rrsigs() {
                records.push(r.clone());
            }
        }
        let mut z = Zone::from_records(&origin_fq, records)?;
        z.path = path;
        Ok(z)
    }

    pub fn from_records(origin: &str, records: impl IntoIterator<Item = Record>) -> Result<Zone> {
        let origin = dnsutil::fqdn(origin);
        let origin_name = Name::from_ascii(&origin).map_err(|e| anyhow!("bad origin {}: {}", origin, e))?;
        let mut names: BTreeMap<String, NameData> = BTreeMap::new();
        let mut signed = false;
        for r in records {
            let owner = dnsutil::name_str(r.name());
            if !dnsutil::is_subdomain(&origin, &owner) {
                tracing::warn!("zone {}: ignoring out-of-zone record for {}", origin, owner);
                continue;
            }
            let nd = names.entry(owner).or_default();
            match r.data() {
                Some(RData::DNSSEC(hickory_proto::rr::dnssec::rdata::DNSSECRData::RRSIG(sig))) => {
                    signed = true;
                    nd.rrsigs.entry(sig.type_covered()).or_default().push(r);
                }
                _ => {
                    let t = r.record_type();
                    let set = nd.rrsets.entry(t).or_default();
                    if !set.iter().any(|x| x.data() == r.data()) {
                        set.push(r);
                    }
                }
            }
        }
        let serial = names
            .get(&origin)
            .and_then(|nd| nd.rrsets.get(&RecordType::SOA))
            .and_then(|v| v.first())
            .and_then(|r| match r.data() {
                Some(RData::SOA(s)) => Some(s.serial()),
                _ => None,
            })
            .ok_or_else(|| anyhow!("zone {}: no SOA record at the apex", origin))?;
        let mut nsec_chain: Vec<Name> = names
            .iter()
            .filter(|(_, nd)| nd.has(RecordType::NSEC))
            .filter_map(|(n, _)| Name::from_ascii(n).ok())
            .collect();
        nsec_chain.sort();
        Ok(Zone { origin, origin_name, names, nsec_chain, serial, signed, path: None })
    }

    pub fn soa(&self) -> Option<&Record> {
        self.names.get(&self.origin).and_then(|nd| nd.rrsets.get(&RecordType::SOA)).and_then(|v| v.first())
    }

    /// Every record in the zone, SOA first (for AXFR).
    pub fn all_records(&self) -> Vec<Record> {
        let mut out = Vec::new();
        if let Some(soa) = self.soa() {
            out.push(soa.clone());
        }
        for (name, nd) in &self.names {
            for (t, set) in &nd.rrsets {
                if *t == RecordType::SOA && *name == self.origin {
                    continue;
                }
                out.extend(set.iter().cloned());
            }
            for set in nd.rrsigs.values() {
                out.extend(set.iter().cloned());
            }
        }
        out
    }

    pub fn len(&self) -> usize {
        self.names.values().map(|nd| nd.rrsets.values().map(|v| v.len()).sum::<usize>()).sum()
    }

    // ------------------------------------------------------------ lookup

    fn with_sigs(&self, nd: &NameData, t: RecordType, do_bit: bool, out: &mut Vec<Record>) {
        if let Some(set) = nd.rrsets.get(&t) {
            out.extend(set.iter().cloned());
            if do_bit {
                if let Some(sigs) = nd.rrsigs.get(&t) {
                    out.extend(sigs.iter().cloned());
                }
            }
        }
    }

    /// SOA (and its RRSIG) for the authority section of negative answers,
    /// TTL clamped to the SOA minimum (RFC 2308).
    fn negative_soa(&self, do_bit: bool) -> Vec<Record> {
        let mut out = Vec::new();
        if let Some(nd) = self.names.get(&self.origin) {
            if let Some(soa) = nd.rrsets.get(&RecordType::SOA).and_then(|v| v.first()) {
                let mut s = soa.clone();
                if let Some(RData::SOA(d)) = s.data() {
                    let ttl = s.ttl().min(d.minimum());
                    s.set_ttl(ttl);
                }
                out.push(s);
                if do_bit {
                    if let Some(sigs) = nd.rrsigs.get(&RecordType::SOA) {
                        out.extend(sigs.iter().cloned());
                    }
                }
            }
        }
        out
    }

    /// The NSEC record (and RRSIG) covering `name`, or proving it exists.
    fn nsec_for(&self, name: &Name, out: &mut Vec<Record>) {
        if self.nsec_chain.is_empty() {
            return;
        }
        let idx = match self.nsec_chain.binary_search_by(|n| n.cmp(name)) {
            Ok(i) => i,
            Err(0) => self.nsec_chain.len() - 1, // before the first: covered by the last (wraps)
            Err(i) => i - 1,
        };
        let owner = dnsutil::name_str(&self.nsec_chain[idx]);
        if let Some(nd) = self.names.get(&owner) {
            self.with_sigs(nd, RecordType::NSEC, true, out);
        }
    }

    /// Glue: A/AAAA for NS/SRV/MX targets inside the zone.
    fn additional(&self, records: &[Record], do_bit: bool, out: &mut Vec<Record>) {
        for r in records {
            let target = match r.data() {
                Some(RData::NS(ns)) => Some(&ns.0),
                Some(RData::SRV(srv)) => Some(srv.target()),
                Some(RData::MX(mx)) => Some(mx.exchange()),
                _ => None,
            };
            let Some(t) = target else { continue };
            let tn = dnsutil::name_str(t);
            if let Some(nd) = self.names.get(&tn) {
                self.with_sigs(nd, RecordType::A, do_bit, out);
                self.with_sigs(nd, RecordType::AAAA, do_bit, out);
            }
        }
    }

    /// Find a delegation point at or above `qname` (below the apex).
    fn delegation(&self, qname: &str, qtype: RecordType) -> Option<(String, &NameData)> {
        let rel = dnsutil::trim_zone(qname, &self.origin)?;
        if rel.is_empty() {
            return None;
        }
        let labels: Vec<&str> = rel.split('.').collect();
        // ancestors from the apex side down
        for i in (0..labels.len()).rev() {
            let candidate = dnsutil::join(&labels[i..], &self.origin);
            if let Some(nd) = self.names.get(&candidate) {
                if nd.has(RecordType::NS) {
                    // a DS query for the delegation name is answered by us (the parent)
                    if candidate == qname && qtype == RecordType::DS {
                        return None;
                    }
                    return Some((candidate, nd));
                }
            }
        }
        None
    }

    /// Answer `req`. `chase_external` allows resolving CNAME targets that
    /// live outside the zone through the server's own chain.
    pub async fn lookup(&self, req: &Request, chase_external: bool) -> Message {
        let do_bit = req.do_bit();
        let qname = req.name_uncached();
        let qtype = req.qtype();
        let mut m = req.new_reply();
        m.set_authoritative(true);

        // referral
        if let Some((dname, nd)) = self.delegation(&qname, qtype) {
            m.set_authoritative(false);
            let mut ns = Vec::new();
            self.with_sigs(nd, RecordType::NS, false, &mut ns);
            if do_bit {
                if nd.has(RecordType::DS) {
                    self.with_sigs(nd, RecordType::DS, true, &mut ns);
                } else if let Ok(n) = Name::from_ascii(&dname) {
                    self.nsec_for(&n, &mut ns);
                }
            }
            let mut extra = Vec::new();
            self.additional(&ns, do_bit, &mut extra);
            for r in ns {
                m.add_name_server(r);
            }
            for r in extra {
                m.add_additional(r);
            }
            return m;
        }

        let mut answers: Vec<Record> = Vec::new();
        let mut current = qname.clone();
        let mut synthesized: Option<Name> = None; // wildcard expansion owner
        let mut hops = 0;
        loop {
            hops += 1;
            if hops > 8 {
                break;
            }
            let (nd, wildcard) = match self.names.get(&current) {
                Some(nd) => (nd, false),
                None => match self.wildcard_for(&current) {
                    Some(nd) => (nd, true),
                    None => {
                        if answers.is_empty() {
                            return self.negative(req, &current, do_bit);
                        }
                        break;
                    }
                },
            };
            let owner = if wildcard {
                let n = Name::from_ascii(&current).unwrap_or_else(|_| Name::root());
                synthesized = Some(n.clone());
                Some(n)
            } else {
                None
            };
            // CNAME chase
            if qtype != RecordType::CNAME && nd.has(RecordType::CNAME) {
                let mut cn = Vec::new();
                self.with_sigs(nd, RecordType::CNAME, do_bit, &mut cn);
                rename(&mut cn, owner.as_ref());
                let target = cn.iter().find_map(|r| match r.data() {
                    Some(RData::CNAME(c)) => Some(dnsutil::name_str(&c.0)),
                    _ => None,
                });
                answers.extend(cn);
                match target {
                    Some(t) if dnsutil::is_subdomain(&self.origin, &t) => {
                        current = t;
                        continue;
                    }
                    Some(t) if chase_external => {
                        if let Ok(tn) = Name::from_ascii(&t) {
                            if let Ok(r) = crate::server::self_lookup(req, tn, qtype).await {
                                answers.extend(r.answers().iter().cloned());
                            }
                        }
                        break;
                    }
                    _ => break,
                }
            }
            let mut found = Vec::new();
            if qtype == RecordType::ANY {
                for t in nd.rrsets.keys() {
                    self.with_sigs(nd, *t, do_bit, &mut found);
                }
            } else {
                self.with_sigs(nd, qtype, do_bit, &mut found);
            }
            if found.is_empty() {
                if answers.is_empty() {
                    // NODATA
                    for r in self.negative_soa(do_bit) {
                        m.add_name_server(r);
                    }
                    if do_bit {
                        let mut nsec = Vec::new();
                        if let Some(w) = &synthesized {
                            self.nsec_for(w, &mut nsec);
                            // also prove the wildcard was used
                            if let Some(wn) = self.wildcard_name(&current) {
                                self.nsec_for(&wn, &mut nsec);
                            }
                        } else if let Ok(n) = Name::from_ascii(&current) {
                            self.nsec_for(&n, &mut nsec);
                        }
                        for r in nsec {
                            m.add_name_server(r);
                        }
                    }
                    return m;
                }
                break;
            }
            rename(&mut found, owner.as_ref());
            answers.extend(found);
            break;
        }
        let mut extra = Vec::new();
        self.additional(&answers, do_bit, &mut extra);
        if let Some(w) = &synthesized {
            if do_bit {
                // wildcard proof: NSEC showing the exact name does not exist
                let mut nsec = Vec::new();
                self.nsec_for(w, &mut nsec);
                for r in nsec {
                    m.add_name_server(r);
                }
            }
        }
        if qtype == RecordType::NS && qname == self.origin {
            // apex NS: nothing more to add
        }
        for r in answers {
            m.add_answer(r);
        }
        for r in extra {
            m.add_additional(r);
        }
        m
    }

    /// The closest enclosing wildcard for `name`, if any.
    fn wildcard_for(&self, name: &str) -> Option<&NameData> {
        let wn = self.wildcard_name_str(name)?;
        self.names.get(&wn)
    }

    fn wildcard_name_str(&self, name: &str) -> Option<String> {
        let rel = dnsutil::trim_zone(name, &self.origin)?;
        if rel.is_empty() {
            return None;
        }
        let labels: Vec<&str> = rel.split('.').collect();
        for i in 1..=labels.len() {
            let mut parts = vec!["*"];
            parts.extend_from_slice(&labels[i..]);
            let cand = dnsutil::join(&parts, &self.origin);
            if self.names.contains_key(&cand) {
                return Some(cand);
            }
        }
        None
    }

    fn wildcard_name(&self, name: &str) -> Option<Name> {
        self.wildcard_name_str(name).and_then(|s| Name::from_ascii(s).ok())
    }

    /// NXDOMAIN, or NODATA for an empty non-terminal.
    fn negative(&self, req: &Request, name: &str, do_bit: bool) -> Message {
        let mut m = req.new_reply();
        m.set_authoritative(true);
        let suffix = format!(".{}", name);
        let ent = self.names.keys().any(|k| k.ends_with(&suffix));
        if !ent {
            m.set_response_code(ResponseCode::NXDomain);
        }
        for r in self.negative_soa(do_bit) {
            m.add_name_server(r);
        }
        if do_bit {
            let mut nsec = Vec::new();
            if let Ok(n) = Name::from_ascii(name) {
                self.nsec_for(&n, &mut nsec);
                // closest encloser / wildcard non-existence
                if !ent {
                    if let Some(rel) = dnsutil::trim_zone(name, &self.origin) {
                        let labels: Vec<&str> = rel.split('.').collect();
                        if labels.len() > 1 {
                            let mut parts = vec!["*"];
                            parts.extend_from_slice(&labels[1..]);
                            if let Ok(w) = Name::from_ascii(dnsutil::join(&parts, &self.origin)) {
                                self.nsec_for(&w, &mut nsec);
                            }
                        }
                    }
                }
            }
            let mut seen = std::collections::HashSet::new();
            for r in nsec {
                if seen.insert(format!("{}", r)) {
                    m.add_name_server(r);
                }
            }
        }
        m
    }
}

fn rename(records: &mut [Record], owner: Option<&Name>) {
    if let Some(o) = owner {
        for r in records.iter_mut() {
            r.set_name(o.clone());
        }
    }
}

/// Serial from a zone file's SOA without parsing the whole file (used
/// by `file` reload checks); falls back to a full parse on failure.
pub fn quick_serial(text: &str, origin: &str) -> Option<u32> {
    Zone::parse(text, origin, None).ok().map(|z| z.serial)
}

#[allow(dead_code)]
fn unused_bail() -> Result<()> {
    bail!("unused")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::RecordType;

    const ZONE: &str = r#"
$TTL 3600
$ORIGIN example.org.
@       IN SOA  ns1.example.org. hostmaster.example.org. (2024010101 7200 3600 1209600 300)
@       IN NS   ns1.example.org.
ns1     IN A    192.0.2.1
www     IN A    192.0.2.10
www     IN AAAA 2001:db8::10
alias   IN CNAME www
ext     IN CNAME www.example.net.
*.wild  IN A    192.0.2.99
sub     IN NS   ns.sub.example.org.
ns.sub  IN A    192.0.2.50
a.b.c   IN TXT  "deep"
mail    IN MX   10 www
"#;

    fn zone() -> Zone {
        Zone::parse(ZONE, "example.org.", None).unwrap()
    }

    async fn q(z: &Zone, name: &str, t: RecordType) -> Message {
        let req = Request::for_test(name, t);
        z.lookup(&req, false).await
    }

    #[tokio::test]
    async fn exact_and_nodata() {
        let z = zone();
        let m = q(&z, "www.example.org.", RecordType::A).await;
        assert_eq!(m.answers().len(), 1);
        assert!(m.authoritative());
        let m = q(&z, "www.example.org.", RecordType::MX).await;
        assert_eq!(m.response_code(), ResponseCode::NoError);
        assert!(m.answers().is_empty());
        assert_eq!(m.name_servers()[0].record_type(), RecordType::SOA);
        assert_eq!(m.name_servers()[0].ttl(), 300, "SOA ttl clamped to minimum");
    }

    #[tokio::test]
    async fn cname_chain() {
        let z = zone();
        let m = q(&z, "alias.example.org.", RecordType::A).await;
        assert_eq!(m.answers().len(), 2);
        assert_eq!(m.answers()[0].record_type(), RecordType::CNAME);
        assert_eq!(m.answers()[1].record_type(), RecordType::A);
        let m = q(&z, "ext.example.org.", RecordType::A).await;
        assert_eq!(m.answers().len(), 1, "external target not chased without upstream");
    }

    #[tokio::test]
    async fn wildcard_and_ent() {
        let z = zone();
        let m = q(&z, "foo.wild.example.org.", RecordType::A).await;
        assert_eq!(m.answers().len(), 1);
        assert_eq!(m.answers()[0].name().to_ascii(), "foo.wild.example.org.");
        let m = q(&z, "b.c.example.org.", RecordType::A).await;
        assert_eq!(m.response_code(), ResponseCode::NoError, "empty non-terminal is NODATA");
        let m = q(&z, "nope.example.org.", RecordType::A).await;
        assert_eq!(m.response_code(), ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn delegation_with_glue() {
        let z = zone();
        let m = q(&z, "host.sub.example.org.", RecordType::A).await;
        assert!(!m.authoritative());
        assert_eq!(m.name_servers()[0].record_type(), RecordType::NS);
        assert_eq!(m.additionals().len(), 1);
        let m = q(&z, "mail.example.org.", RecordType::MX).await;
        assert_eq!(m.additionals().len(), 2, "MX glue A+AAAA");
    }

    #[test]
    fn axfr_order() {
        let z = zone();
        let all = z.all_records();
        assert_eq!(all[0].record_type(), RecordType::SOA);
        assert_eq!(all.iter().filter(|r| r.record_type() == RecordType::SOA).count(), 1);
        assert_eq!(z.serial, 2024010101);
    }
}
