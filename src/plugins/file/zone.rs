//! In-memory authoritative zone with RFC 1034 lookup semantics: exact
//! match, CNAME chasing, wildcards (RFC 4592: only from the closest
//! encloser), DNAME (RFC 6672), delegations with glue, empty
//! non-terminals, NXDOMAIN/NODATA with SOA, and DNSSEC records (RRSIG,
//! NSEC or NSEC3, DS) passed through when the zone file is signed.

use crate::dnsutil;
use crate::plugin::Request;
use anyhow::{anyhow, bail, Result};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::dnssec::rdata::DNSSECRData;
use hickory_proto::rr::dnssec::Nsec3HashAlgorithm;
use hickory_proto::rr::rdata::{CNAME, NULL};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable};
use hickory_proto::serialize::txt::Parser;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;

/// DNAME (RFC 6672). hickory 0.24 has no type for it, so DNAME records
/// are kept as type 39 with the target in wire form.
pub const DNAME: RecordType = RecordType::Unknown(39);

#[derive(Default, Debug, Clone)]
pub struct NameData {
    pub rrsets: HashMap<RecordType, Vec<Record>>,
    /// RRSIGs keyed by the type they cover.
    pub rrsigs: HashMap<RecordType, Vec<Record>>,
}

impl NameData {
    fn has(&self, t: RecordType) -> bool {
        self.rrsets.get(&t).map(|v| !v.is_empty()).unwrap_or(false)
    }
}

/// The NSEC3 chain of a pre-signed zone (RFC 5155).
#[derive(Debug, Clone)]
struct Nsec3Chain {
    alg: Nsec3HashAlgorithm,
    salt: Vec<u8>,
    iterations: u16,
    /// (hash of the original owner, NSEC3 owner name), sorted by hash.
    chain: Vec<(Vec<u8>, String)>,
}

#[derive(Debug, Clone)]
pub struct Zone {
    /// Lowercase FQDN.
    pub origin: String,
    pub origin_name: Name,
    /// Owner name (lowercase FQDN) → data.
    pub names: BTreeMap<String, NameData>,
    /// Every name that exists: owners and their ancestors up to the apex
    /// (so empty non-terminals too). Used to find the closest encloser.
    nodes: HashSet<String>,
    /// Names that own NSEC records, in canonical order, for negative proofs.
    nsec_chain: Vec<Name>,
    nsec3: Option<Nsec3Chain>,
    pub serial: u32,
    pub signed: bool,
    /// Source path, if loaded from a file.
    pub path: Option<PathBuf>,
}

impl Zone {
    pub fn parse(text: &str, origin: &str, path: Option<PathBuf>) -> Result<Zone> {
        let origin_fq = dnsutil::fqdn(origin);
        let origin_name = Name::from_ascii(&origin_fq).map_err(|e| anyhow!("bad origin {}: {}", origin, e))?;
        let text = dname_as_aname(text).map_err(|e| anyhow!("parsing zone {}: {}", origin_fq, e))?;
        let (_, sets) = Parser::new(text.as_ref(), path.clone(), Some(origin_name.clone()))
            .parse()
            .map_err(|e| anyhow!("parsing zone {}: {}", origin_fq, e))?;
        let mut records = Vec::new();
        for (_, set) in sets {
            for r in set.records_without_rrsigs() {
                records.push(aname_to_dname(r.clone())?);
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
                Some(RData::DNSSEC(DNSSECRData::RRSIG(sig))) => {
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
        let mut nodes = HashSet::new();
        for owner in names.keys() {
            let mut n = owner.clone();
            while nodes.insert(n.clone()) && n != origin {
                n = parent(&n).to_string();
            }
        }
        let mut nsec_chain: Vec<Name> = names
            .iter()
            .filter(|(_, nd)| nd.has(RecordType::NSEC))
            .filter_map(|(n, _)| Name::from_ascii(n).ok())
            .collect();
        nsec_chain.sort();
        let nsec3 = nsec3_chain(&origin, &names);
        Ok(Zone { origin, origin_name, names, nodes, nsec_chain, nsec3, serial, signed, path: None })
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

    /// Find a delegation point at or above `qname` (below the apex). A
    /// DNAME above the cut occludes it.
    fn delegation(&self, qname: &str, qtype: RecordType) -> Option<(String, &NameData)> {
        let rel = dnsutil::trim_zone(qname, &self.origin)?;
        if rel.is_empty() {
            return None;
        }
        if self.names.get(&self.origin).map(|nd| nd.has(DNAME)).unwrap_or(false) {
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
                if candidate != qname && nd.has(DNAME) {
                    return None;
                }
            }
        }
        None
    }

    /// The DNAME owner that redirects `name`: the highest proper ancestor
    /// of `name` (the apex included) that owns a DNAME.
    fn dname_for(&self, name: &str) -> Option<(String, &NameData)> {
        let rel = dnsutil::trim_zone(name, &self.origin)?;
        if rel.is_empty() {
            return None;
        }
        if let Some(nd) = self.names.get(&self.origin) {
            if nd.has(DNAME) {
                return Some((self.origin.clone(), nd));
            }
        }
        let labels: Vec<&str> = rel.split('.').collect();
        for i in (1..labels.len()).rev() {
            let candidate = dnsutil::join(&labels[i..], &self.origin);
            if let Some(nd) = self.names.get(&candidate) {
                if nd.has(DNAME) {
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
                } else {
                    self.prove_nodata(&dname, &mut ns);
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
        // wildcard expansion: (query name it answered, closest encloser)
        let mut synthesized: Option<(String, String)> = None;
        let mut hops = 0;
        loop {
            hops += 1;
            if hops > 8 {
                break;
            }
            // DNAME substitution (RFC 6672 2.2)
            let mut target = None;
            if let Some((downer, dnd)) = self.dname_for(&current) {
                let mut dn = Vec::new();
                self.with_sigs(dnd, DNAME, do_bit, &mut dn);
                let Some((dtarget, ttl)) = dn.iter().find_map(|r| dname_target(r).map(|t| (dnsutil::name_str(&t), r.ttl()))) else {
                    break;
                };
                answers.extend(dn);
                let prefix = &current[..current.len() - if downer == "." { 0 } else { downer.len() }];
                let new = if dtarget == "." { prefix.to_string() } else { format!("{}{}", prefix, dtarget) };
                // a name over 255 octets on the wire cannot be synthesized
                let synth = if new.len() + 1 > 255 { None } else { Name::from_ascii(&new).ok() };
                let Some(new_name) = synth else {
                    m.set_response_code(ResponseCode::YXDomain);
                    for r in answers {
                        m.add_answer(r);
                    }
                    return m;
                };
                if let Ok(owner) = Name::from_ascii(&current) {
                    answers.push(Record::from_rdata(owner, ttl, RData::CNAME(CNAME(new_name))));
                }
                if qtype == RecordType::CNAME {
                    break;
                }
                target = Some(new);
            }
            if target.is_none() {
                let (nd, wildcard) = match self.names.get(&current) {
                    Some(nd) => (nd, false),
                    None => match self.wildcard_for(&current) {
                        Some((ce, nd)) => {
                            synthesized = Some((current.clone(), ce));
                            (nd, true)
                        }
                        None => {
                            if answers.is_empty() {
                                return self.negative(req, &current, do_bit);
                            }
                            break;
                        }
                    },
                };
                let owner = if wildcard { Some(Name::from_ascii(&current).unwrap_or_else(|_| Name::root())) } else { None };
                if qtype != RecordType::CNAME && nd.has(RecordType::CNAME) {
                    let mut cn = Vec::new();
                    self.with_sigs(nd, RecordType::CNAME, do_bit, &mut cn);
                    rename(&mut cn, owner.as_ref());
                    target = cn.iter().find_map(|r| match r.data() {
                        Some(RData::CNAME(c)) => Some(dnsutil::name_str(&c.0)),
                        _ => None,
                    });
                    answers.extend(cn);
                    if target.is_none() {
                        break;
                    }
                } else {
                    let mut found = Vec::new();
                    if qtype == RecordType::ANY {
                        for t in nd.rrsets.keys() {
                            self.with_sigs(nd, *t, do_bit, &mut found);
                        }
                    } else {
                        self.with_sigs(nd, qtype, do_bit, &mut found);
                    }
                    if found.is_empty() && answers.is_empty() {
                        // NODATA
                        for r in self.negative_soa(do_bit) {
                            m.add_name_server(r);
                        }
                        if do_bit {
                            let mut proof = Vec::new();
                            match &synthesized {
                                Some((name, ce)) => self.prove_wildcard_nodata(name, ce, &mut proof),
                                None => self.prove_nodata(&current, &mut proof),
                            }
                            add_authority(&mut m, proof);
                        }
                        return m;
                    }
                    rename(&mut found, owner.as_ref());
                    answers.extend(found);
                    break;
                }
            }
            // follow the CNAME (given or synthesized)
            match target {
                Some(t) if dnsutil::is_subdomain(&self.origin, &t) => {
                    current = t;
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
        let mut extra = Vec::new();
        self.additional(&answers, do_bit, &mut extra);
        if let Some((name, ce)) = &synthesized {
            if do_bit {
                // wildcard proof: the exact name does not exist
                let mut proof = Vec::new();
                self.prove_wildcard_answer(name, ce, &mut proof);
                add_authority(&mut m, proof);
            }
        }
        for r in answers {
            m.add_answer(r);
        }
        for r in extra {
            m.add_additional(r);
        }
        m
    }

    /// The closest encloser of a name that does not exist: its nearest
    /// ancestor that does (an empty non-terminal counts).
    fn closest_encloser(&self, name: &str) -> String {
        let mut n = name;
        while n != self.origin && n != "." {
            n = parent(n);
            if self.nodes.contains(n) {
                return n.to_string();
            }
        }
        self.origin.clone()
    }

    /// The wildcard that synthesizes `name` (RFC 4592): `*.<closest
    /// encloser>`, only when `name` does not exist. Returns the closest
    /// encloser and the wildcard's data.
    fn wildcard_for(&self, name: &str) -> Option<(String, &NameData)> {
        if self.nodes.contains(name) || !dnsutil::is_subdomain(&self.origin, name) {
            return None;
        }
        let ce = self.closest_encloser(name);
        let nd = self.names.get(&wildcard_of(&ce))?;
        Some((ce, nd))
    }

    /// NXDOMAIN, or NODATA for an empty non-terminal.
    fn negative(&self, req: &Request, name: &str, do_bit: bool) -> Message {
        let mut m = req.new_reply();
        m.set_authoritative(true);
        let ent = self.nodes.contains(name);
        if !ent {
            m.set_response_code(ResponseCode::NXDomain);
        }
        for r in self.negative_soa(do_bit) {
            m.add_name_server(r);
        }
        if do_bit {
            let mut proof = Vec::new();
            if ent {
                self.prove_nodata(name, &mut proof);
            } else {
                let ce = self.closest_encloser(name);
                self.prove_nxdomain(name, &ce, &mut proof);
            }
            add_authority(&mut m, proof);
        }
        m
    }

    // ------------------------------------------------------ denial proofs
    // NSEC per RFC 4035 3.1.3, NSEC3 per RFC 5155 7.2. Nothing is added
    // when the zone has neither chain.

    /// `name` does not exist and no wildcard at its closest encloser `ce`.
    fn prove_nxdomain(&self, name: &str, ce: &str, out: &mut Vec<Record>) {
        if self.nsec3.is_some() {
            self.nsec3_match(ce, out);
            self.nsec3_cover(&next_closer(name, ce), out);
            self.nsec3_cover(&wildcard_of(ce), out);
        } else {
            self.nsec_name(name, out);
            self.nsec_name(&wildcard_of(ce), out);
        }
    }

    /// `name` exists (or is an empty non-terminal) without the type asked.
    fn prove_nodata(&self, name: &str, out: &mut Vec<Record>) {
        if self.nsec3.is_some() {
            if !self.nsec3_match(name, out) {
                // opt-out (RFC 5155 7.2.4): closest provable encloser + next closer
                let mut ce = parent(name);
                while ce != self.origin && ce != "." && !self.nsec3_hash_exists(ce) {
                    ce = parent(ce);
                }
                self.nsec3_match(ce, out);
                self.nsec3_cover(&next_closer(name, ce), out);
            }
        } else {
            self.nsec_name(name, out);
        }
    }

    /// A wildcard answered `name`: prove `name` itself does not exist.
    fn prove_wildcard_answer(&self, name: &str, ce: &str, out: &mut Vec<Record>) {
        if self.nsec3.is_some() {
            self.nsec3_cover(&next_closer(name, ce), out);
        } else {
            self.nsec_name(name, out);
        }
    }

    /// A wildcard matched `name` but has no data of the type asked.
    fn prove_wildcard_nodata(&self, name: &str, ce: &str, out: &mut Vec<Record>) {
        if self.nsec3.is_some() {
            self.nsec3_match(ce, out);
            self.nsec3_cover(&next_closer(name, ce), out);
            self.nsec3_match(&wildcard_of(ce), out);
        } else {
            self.nsec_name(name, out);
            self.nsec_name(&wildcard_of(ce), out);
        }
    }

    fn nsec_name(&self, name: &str, out: &mut Vec<Record>) {
        if let Ok(n) = Name::from_ascii(name) {
            self.nsec_for(&n, out);
        }
    }

    fn nsec3_hash(&self, name: &str) -> Option<Vec<u8>> {
        let c = self.nsec3.as_ref()?;
        let n = Name::from_ascii(name).ok()?;
        c.alg.hash(&c.salt, &n, c.iterations).ok().map(|d| d.as_ref().to_vec())
    }

    fn nsec3_hash_exists(&self, name: &str) -> bool {
        match (self.nsec3.as_ref(), self.nsec3_hash(name)) {
            (Some(c), Some(h)) => c.chain.binary_search_by(|(x, _)| x.cmp(&h)).is_ok(),
            _ => false,
        }
    }

    fn nsec3_push(&self, owner: &str, out: &mut Vec<Record>) {
        if let Some(nd) = self.names.get(owner) {
            self.with_sigs(nd, RecordType::NSEC3, true, out);
        }
    }

    /// The NSEC3 whose owner is the hash of `name`; false if there is none.
    fn nsec3_match(&self, name: &str, out: &mut Vec<Record>) -> bool {
        let (Some(c), Some(h)) = (self.nsec3.as_ref(), self.nsec3_hash(name)) else { return false };
        match c.chain.binary_search_by(|(x, _)| x.cmp(&h)) {
            Ok(i) => {
                self.nsec3_push(&c.chain[i].1, out);
                true
            }
            Err(_) => false,
        }
    }

    /// The NSEC3 whose hash interval covers the hash of `name`.
    fn nsec3_cover(&self, name: &str, out: &mut Vec<Record>) {
        let (Some(c), Some(h)) = (self.nsec3.as_ref(), self.nsec3_hash(name)) else { return };
        if c.chain.is_empty() {
            return;
        }
        let i = match c.chain.binary_search_by(|(x, _)| x.cmp(&h)) {
            Ok(i) => i,
            Err(0) => c.chain.len() - 1, // before the first: covered by the last (wraps)
            Err(i) => i - 1,
        };
        self.nsec3_push(&c.chain[i].1, out);
    }
}

/// Authority records, each once.
fn add_authority(m: &mut Message, records: Vec<Record>) {
    let mut seen = HashSet::new();
    for r in records {
        if seen.insert(format!("{}", r)) {
            m.add_name_server(r);
        }
    }
}

/// The parent of a lowercase FQDN ("." for a TLD or the root).
fn parent(name: &str) -> &str {
    match name.find('.') {
        Some(i) if i + 1 < name.len() => &name[i + 1..],
        _ => ".",
    }
}

fn wildcard_of(name: &str) -> String {
    if name == "." {
        "*.".into()
    } else {
        format!("*.{}", name)
    }
}

/// The ancestor of `name` one label below its closest encloser `ce`.
fn next_closer(name: &str, ce: &str) -> String {
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').filter(|l| !l.is_empty()).collect();
    let keep = dnsutil::count_labels(ce) + 1;
    if keep > labels.len() {
        return name.to_string();
    }
    format!("{}.", labels[labels.len() - keep..].join("."))
}

fn rename(records: &mut [Record], owner: Option<&Name>) {
    if let Some(o) = owner {
        for r in records.iter_mut() {
            r.set_name(o.clone());
        }
    }
}

/// The target of a DNAME record.
pub fn dname_target(r: &Record) -> Option<Name> {
    match r.data() {
        Some(RData::Unknown { code, rdata }) if *code == DNAME => {
            let mut d = BinDecoder::new(rdata.anything());
            Name::read(&mut d).ok()
        }
        _ => None,
    }
}

/// Decode base32hex (RFC 4648, no padding, either case).
fn base32hex(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c.to_ascii_uppercase() {
            b @ b'0'..=b'9' => b - b'0',
            b @ b'A'..=b'V' => b - b'A' + 10,
            _ => return None,
        };
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// The NSEC3 chain, with its parameters from the apex NSEC3PARAM (or the
/// first NSEC3 when there is none).
fn nsec3_chain(origin: &str, names: &BTreeMap<String, NameData>) -> Option<Nsec3Chain> {
    let param = names
        .get(origin)
        .and_then(|nd| nd.rrsets.get(&RecordType::NSEC3PARAM))
        .and_then(|v| v.first())
        .and_then(|r| match r.data() {
            Some(RData::DNSSEC(DNSSECRData::NSEC3PARAM(p))) => Some((p.hash_algorithm(), p.salt().to_vec(), p.iterations())),
            _ => None,
        });
    let mut first = None;
    let mut chain = Vec::new();
    for (owner, nd) in names {
        let Some(r) = nd.rrsets.get(&RecordType::NSEC3).and_then(|v| v.first()) else { continue };
        let Some(RData::DNSSEC(DNSSECRData::NSEC3(n))) = r.data() else { continue };
        if first.is_none() {
            first = Some((n.hash_algorithm(), n.salt().to_vec(), n.iterations()));
        }
        let label = owner.split('.').next().unwrap_or_default();
        match base32hex(label) {
            Some(h) => chain.push((h, owner.clone())),
            None => tracing::warn!("zone {}: NSEC3 owner {} is not a base32hex hash", origin, owner),
        }
    }
    if chain.is_empty() {
        return None;
    }
    let (alg, salt, iterations) = param.or(first)?;
    chain.sort();
    Some(Nsec3Chain { alg, salt, iterations, chain })
}

/// Turn the ANAME stand-in `dname_as_aname` made back into a DNAME.
fn aname_to_dname(r: Record) -> Result<Record> {
    let Some(RData::ANAME(a)) = r.data() else { return Ok(r) };
    let wire = a.0.to_bytes().map_err(|e| anyhow!("DNAME target {}: {}", a.0, e))?;
    let mut d = Record::from_rdata(r.name().clone(), r.ttl(), RData::Unknown { code: DNAME, rdata: NULL::with(wire) });
    d.set_dns_class(r.dns_class());
    Ok(d)
}

/// hickory's zone parser knows ANAME but not DNAME, and both take one
/// domain name as RDATA. Rewrite the type field of DNAME records to ANAME
/// so the parser resolves the target (relative names, `$ORIGIN`) and
/// `aname_to_dname` turns them back. A real ANAME is refused, as CoreDNS
/// does (it is not a standard type).
fn dname_as_aname(text: &str) -> Result<Cow<'_, str>> {
    let mut edits: Vec<usize> = Vec::new(); // byte offsets of "DNAME" type tokens
    let mut depth = 0i32;
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let base = offset;
        offset += line.len();
        // tokens outside quotes and comments, with their byte offsets
        let mut tokens: Vec<(usize, &str)> = Vec::new();
        let bytes = line.as_bytes();
        let mut i = 0;
        let start_depth = depth;
        while i < bytes.len() {
            match bytes[i] {
                b';' => break,
                b'"' => {
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'"' {
                        if bytes[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                    tokens.push((i, "\"")); // a quoted string is rdata, never a type
                    i += 1;
                }
                b'(' => {
                    depth += 1;
                    i += 1;
                }
                b')' => {
                    depth -= 1;
                    i += 1;
                }
                c if c.is_ascii_whitespace() => i += 1,
                _ => {
                    let s = i;
                    while i < bytes.len() && !bytes[i].is_ascii_whitespace() && !matches!(bytes[i], b'(' | b')' | b';' | b'"') {
                        if bytes[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                    let e = i.min(bytes.len());
                    tokens.push((s, &line[s..e]));
                }
            }
        }
        // a continuation line, a directive or an empty line has no type field
        if start_depth > 0 || tokens.is_empty() || tokens[0].1.starts_with('$') {
            continue;
        }
        let mut idx = if line.starts_with(|c: char| c == ' ' || c == '\t') { 0 } else { 1 };
        for _ in 0..2 {
            match tokens.get(idx) {
                Some((_, t)) if t.starts_with(|c: char| c.is_ascii_digit()) || ["IN", "CH", "HS", "CS"].iter().any(|k| t.eq_ignore_ascii_case(k)) => idx += 1,
                _ => break,
            }
        }
        match tokens.get(idx) {
            Some((p, t)) if t.eq_ignore_ascii_case("DNAME") => edits.push(base + p),
            Some((_, t)) if t.eq_ignore_ascii_case("ANAME") => bail!("unknown RR type ANAME"),
            _ => {}
        }
    }
    if edits.is_empty() {
        return Ok(Cow::Borrowed(text));
    }
    let mut out = text.to_string();
    for p in edits {
        out.replace_range(p..p + 5, "ANAME");
    }
    Ok(Cow::Owned(out))
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

    // ------------------------------------------- #13: RFC 4592 wildcards

    const WILD: &str = r#"
$TTL 3600
$ORIGIN example.org.
@       IN SOA  ns1.example.org. hostmaster.example.org. 1 7200 3600 1209600 300
@       IN NS   ns1.example.org.
ns1     IN A    192.0.2.1
*       IN TXT  "top"
a.b.c   IN TXT  "deep"
*.wild  IN A    192.0.2.99
"#;

    #[tokio::test]
    async fn wildcard_only_from_closest_encloser() {
        let z = Zone::parse(WILD, "example.org.", None).unwrap();
        // closest encloser of x.b.c is the empty non-terminal b.c; there is no *.b.c
        let m = q(&z, "x.b.c.example.org.", RecordType::TXT).await;
        assert_eq!(m.response_code(), ResponseCode::NXDomain);
        assert!(m.answers().is_empty());
        let m = q(&z, "b.c.example.org.", RecordType::TXT).await;
        assert_eq!(m.response_code(), ResponseCode::NoError);
        assert!(m.answers().is_empty(), "empty non-terminal is NODATA, not the wildcard");
        // the apex wildcard covers names whose closest encloser is the apex
        let m = q(&z, "other.example.org.", RecordType::TXT).await;
        assert_eq!(m.answers().len(), 1);
        assert_eq!(m.answers()[0].name().to_ascii(), "other.example.org.");
        let m = q(&z, "y.x.example.org.", RecordType::TXT).await;
        assert_eq!(m.answers().len(), 1);
        // *.wild covers more than one label below wild
        let m = q(&z, "deep.foo.wild.example.org.", RecordType::A).await;
        assert_eq!(m.answers().len(), 1);
        assert_eq!(m.answers()[0].name().to_ascii(), "deep.foo.wild.example.org.");
        // the closest encloser c.example.org exists, so *.example.org does not apply below it
        let m = q(&z, "z.c.example.org.", RecordType::TXT).await;
        assert_eq!(m.response_code(), ResponseCode::NXDomain);
    }

    // ------------------------------------------------------ #13: DNAME

    fn long_label(c: char) -> String {
        std::iter::repeat(c).take(60).collect()
    }

    fn dname_zone() -> Zone {
        let text = format!(
            r#"
$TTL 3600
$ORIGIN example.org.
@       IN SOA  ns1.example.org. hostmaster.example.org. (
                1 7200 3600 1209600 300 )
@       IN NS   ns1.example.org.
ns1     IN A    192.0.2.1
legacy  300 IN DNAME modern
        IN TXT  "DNAME"
www.modern IN A 192.0.2.7
ext     DNAME   example.net.
long    IN dname {a}.{b}.{c}.example.net.
dname   IN A    192.0.2.8
"#,
            a = long_label('a'),
            b = long_label('b'),
            c = long_label('c')
        );
        Zone::parse(&text, "example.org.", None).unwrap()
    }

    #[tokio::test]
    async fn dname_substitution() {
        let z = dname_zone();
        let m = q(&z, "www.legacy.example.org.", RecordType::A).await;
        assert_eq!(m.response_code(), ResponseCode::NoError);
        let a = m.answers();
        assert_eq!(a.len(), 3, "{:?}", a);
        assert_eq!(a[0].record_type(), DNAME);
        assert_eq!(a[0].name().to_ascii(), "legacy.example.org.");
        assert_eq!(dname_target(&a[0]).unwrap().to_ascii(), "modern.example.org.");
        assert_eq!(a[1].record_type(), RecordType::CNAME);
        assert_eq!(a[1].name().to_ascii(), "www.legacy.example.org.");
        assert_eq!(a[1].ttl(), 300, "synthesized CNAME takes the DNAME's TTL");
        match a[1].data() {
            Some(RData::CNAME(c)) => assert_eq!(c.0.to_ascii(), "www.modern.example.org."),
            o => panic!("{:?}", o),
        }
        assert_eq!(a[2].record_type(), RecordType::A);
        // out-of-zone target: DNAME + CNAME, not chased without the server
        let m = q(&z, "a.b.ext.example.org.", RecordType::A).await;
        assert_eq!(m.answers().len(), 2);
        match m.answers()[1].data() {
            Some(RData::CNAME(c)) => assert_eq!(c.0.to_ascii(), "a.b.example.net."),
            o => panic!("{:?}", o),
        }
        // the owner itself is not redirected
        let m = q(&z, "legacy.example.org.", DNAME).await;
        assert_eq!(m.answers().len(), 1);
        let m = q(&z, "legacy.example.org.", RecordType::A).await;
        assert!(m.answers().is_empty());
        assert_eq!(m.response_code(), ResponseCode::NoError);
        let m = q(&z, "legacy.example.org.", RecordType::TXT).await;
        assert_eq!(m.answers().len(), 1, "TXT \"DNAME\" kept as TXT");
        // an owner called "dname" is not a type
        let m = q(&z, "dname.example.org.", RecordType::A).await;
        assert_eq!(m.answers().len(), 1);
    }

    #[tokio::test]
    async fn dname_too_long_is_yxdomain() {
        let z = dname_zone();
        let name = format!("{}.long.example.org.", long_label('x'));
        let m = q(&z, &name, RecordType::A).await;
        assert_eq!(m.response_code(), ResponseCode::YXDomain);
        assert_eq!(m.answers().len(), 1);
        assert_eq!(m.answers()[0].record_type(), DNAME);
    }

    #[test]
    fn dname_in_axfr_and_wire() {
        let z = dname_zone();
        let all = z.all_records();
        let d: Vec<_> = all.iter().filter(|r| r.record_type() == DNAME).collect();
        assert_eq!(d.len(), 3);
        // round trip through the wire as an unknown type (what secondary sees)
        let mut m = Message::new();
        for r in &d {
            m.add_answer((*r).clone());
        }
        let back = Message::from_vec(&m.to_vec().unwrap()).unwrap();
        let z2 = Zone::from_records("example.org.", z.all_records()).unwrap();
        assert_eq!(z2.all_records().iter().filter(|r| r.record_type() == DNAME).count(), 3);
        for r in back.answers() {
            assert_eq!(r.record_type(), DNAME);
            assert!(dname_target(r).is_some());
        }
    }

    #[test]
    fn aname_is_refused() {
        let text = "$ORIGIN example.org.\n@ IN SOA ns1 h 1 2 3 4 5\nx IN ANAME y\n";
        assert!(Zone::parse(text, "example.org.", None).is_err());
    }

    #[test]
    fn hickory_rejects_dnssec_records_in_zone_files() {
        // hickory 0.24's text parser refuses NSEC/RRSIG/NSEC3 (filed as its
        // own issue): signed zones reach Zone through secondary/from_records
        let text = "$ORIGIN example.org.\n@ IN SOA ns1 h 1 2 3 4 5\n@ IN NSEC www A NS SOA NSEC RRSIG\n";
        assert!(Zone::parse(text, "example.org.", None).is_err());
    }

    // ------------------------------------------------------ #13: NSEC3

    use hickory_proto::rr::dnssec::rdata::{NSEC3, NSEC3PARAM};
    use hickory_proto::rr::rdata::{A, SOA, TXT};

    fn b32hex(b: &[u8]) -> String {
        const A: &[u8] = b"0123456789abcdefghijklmnopqrstuv";
        let (mut acc, mut bits, mut s) = (0u32, 0u32, String::new());
        for &x in b {
            acc = (acc << 8) | x as u32;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                s.push(A[((acc >> bits) & 31) as usize] as char);
            }
            acc &= (1 << bits) - 1;
        }
        if bits > 0 {
            s.push(A[((acc << (5 - bits)) & 31) as usize] as char);
        }
        s
    }

    fn h(name: &str, salt: &[u8]) -> Vec<u8> {
        Nsec3HashAlgorithm::SHA1.hash(salt, &Name::from_ascii(name).unwrap(), 1).unwrap().as_ref().to_vec()
    }

    /// example.org with www (A), a.b (TXT, so b is an ENT) and *.w (A),
    /// with an NSEC3 chain (1 iteration, salt ab).
    fn nsec3_zone() -> Zone {
        let n = |s: &str| Name::from_ascii(s).unwrap();
        let salt = vec![0xab];
        let mut recs = vec![
            Record::from_rdata(n("example.org."), 3600, RData::SOA(SOA::new(n("ns1.example.org."), n("h.example.org."), 1, 2, 3, 4, 300))),
            Record::from_rdata(n("www.example.org."), 3600, RData::A(A::new(192, 0, 2, 1))),
            Record::from_rdata(n("a.b.example.org."), 3600, RData::TXT(TXT::new(vec!["x".into()]))),
            Record::from_rdata(n("*.w.example.org."), 3600, RData::A(A::new(192, 0, 2, 9))),
            Record::from_rdata(
                n("example.org."),
                0,
                RData::DNSSEC(DNSSECRData::NSEC3PARAM(NSEC3PARAM::new(Nsec3HashAlgorithm::SHA1, false, 1, salt.clone()))),
            ),
        ];
        let owners = ["example.org.", "www.example.org.", "b.example.org.", "a.b.example.org.", "w.example.org.", "*.w.example.org."];
        let mut hashes: Vec<Vec<u8>> = owners.iter().map(|o| h(o, &salt)).collect();
        hashes.sort();
        for (i, hh) in hashes.iter().enumerate() {
            let next = hashes[(i + 1) % hashes.len()].clone();
            let rd = NSEC3::new(Nsec3HashAlgorithm::SHA1, false, 1, salt.clone(), next, vec![RecordType::A]);
            recs.push(Record::from_rdata(n(&format!("{}.example.org.", b32hex(hh))), 300, RData::DNSSEC(DNSSECRData::NSEC3(rd))));
        }
        Zone::from_records("example.org.", recs).unwrap()
    }

    async fn q_do(z: &Zone, name: &str, t: RecordType) -> Message {
        let mut req = Request::for_test(name, t);
        req.msg.extensions_mut().get_or_insert_with(hickory_proto::op::Edns::new).set_dnssec_ok(true);
        z.lookup(&req, false).await
    }

    fn nsec3_owners(m: &Message) -> Vec<String> {
        m.name_servers().iter().filter(|r| r.record_type() == RecordType::NSEC3).map(|r| dnsutil::name_str(r.name())).collect()
    }

    fn hash_owner(name: &str) -> String {
        format!("{}.example.org.", b32hex(&h(name, &[0xab])))
    }

    /// The NSEC3 owned by `owner` covers `name`'s hash (strictly between, wrapping).
    fn covers(z: &Zone, owner: &str, name: &str) -> bool {
        let c = z.nsec3.as_ref().unwrap();
        let i = c.chain.iter().position(|(_, o)| o == owner).unwrap();
        let (lo, hi) = (&c.chain[i].0, &c.chain[(i + 1) % c.chain.len()].0);
        let x = h(name, &[0xab]);
        if lo < hi {
            lo < &x && &x < hi
        } else {
            &x > lo || &x < hi
        }
    }

    #[test]
    fn base32hex_round_trip() {
        let x = h("www.example.org.", &[0xab]);
        assert_eq!(base32hex(&b32hex(&x)).unwrap(), x);
        assert_eq!(base32hex(&b32hex(&x).to_uppercase()).unwrap(), x);
    }

    #[tokio::test]
    async fn nsec3_nxdomain_proof() {
        let z = nsec3_zone();
        assert_eq!(z.nsec3.as_ref().unwrap().chain.len(), 6);
        let m = q_do(&z, "nope.example.org.", RecordType::A).await;
        assert_eq!(m.response_code(), ResponseCode::NXDomain);
        let owners = nsec3_owners(&m);
        // closest encloser (apex) matched, next closer and *.apex covered
        assert!(owners.contains(&hash_owner("example.org.")), "{:?}", owners);
        assert!(owners.iter().any(|o| covers(&z, o, "nope.example.org.")));
        assert!(owners.iter().any(|o| covers(&z, o, "*.example.org.")));
        // below the ENT: closest encloser b, next closer x.b
        let m = q_do(&z, "y.x.b.example.org.", RecordType::A).await;
        assert_eq!(m.response_code(), ResponseCode::NXDomain);
        let owners = nsec3_owners(&m);
        assert!(owners.contains(&hash_owner("b.example.org.")));
        assert!(owners.iter().any(|o| covers(&z, o, "x.b.example.org.")));
        assert!(owners.iter().any(|o| covers(&z, o, "*.b.example.org.")));
    }

    #[tokio::test]
    async fn nsec3_nodata_and_wildcard_proofs() {
        let z = nsec3_zone();
        let m = q_do(&z, "www.example.org.", RecordType::TXT).await;
        assert_eq!(m.response_code(), ResponseCode::NoError);
        assert_eq!(nsec3_owners(&m), vec![hash_owner("www.example.org.")]);
        // empty non-terminal
        let m = q_do(&z, "b.example.org.", RecordType::A).await;
        assert_eq!(nsec3_owners(&m), vec![hash_owner("b.example.org.")]);
        // wildcard answer: next closer covered
        let m = q_do(&z, "x.w.example.org.", RecordType::A).await;
        assert_eq!(m.answers().len(), 1);
        let owners = nsec3_owners(&m);
        assert_eq!(owners.len(), 1);
        assert!(covers(&z, &owners[0], "x.w.example.org."));
        // wildcard NODATA: closest encloser + wildcard matched, next closer covered
        let m = q_do(&z, "x.w.example.org.", RecordType::TXT).await;
        assert!(m.answers().is_empty());
        let owners = nsec3_owners(&m);
        assert!(owners.contains(&hash_owner("w.example.org.")));
        assert!(owners.contains(&hash_owner("*.w.example.org.")));
        assert!(owners.iter().any(|o| covers(&z, o, "x.w.example.org.")));
        // no DO bit: no proofs
        let m = q(&z, "nope.example.org.", RecordType::A).await;
        assert!(nsec3_owners(&m).is_empty());
    }
}
