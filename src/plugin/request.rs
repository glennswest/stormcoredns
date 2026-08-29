//! `request.Request`: a DNS query plus everything the server knows about
//! how it arrived, with the helpers CoreDNS plugins expect.

use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
    Grpc,
}

impl Proto {
    /// The label used in metrics / logs: "udp", "tcp", "tcp-tls", "https", "quic", "grpc".
    pub fn as_str(&self) -> &'static str {
        match self {
            Proto::Udp => "udp",
            Proto::Tcp => "tcp",
            Proto::Tls => "tcp-tls",
            Proto::Https => "https",
            Proto::Quic => "quic",
            Proto::Grpc => "grpc",
        }
    }
    /// Stream transports have no 512-byte limit.
    pub fn is_stream(&self) -> bool {
        !matches!(self, Proto::Udp)
    }
}

/// Per-request metadata (`metadata.Provider`): label → lazily evaluated value.
#[derive(Default, Clone)]
pub struct Metadata {
    values: HashMap<String, Arc<dyn Fn() -> String + Send + Sync>>,
}

impl Metadata {
    pub fn set_value(&mut self, label: impl Into<String>, f: impl Fn() -> String + Send + Sync + 'static) {
        self.values.insert(label.into(), Arc::new(f));
    }
    pub fn set_static(&mut self, label: impl Into<String>, v: impl Into<String>) {
        let v: String = v.into();
        self.values.insert(label.into(), Arc::new(move || v.clone()));
    }
    pub fn value_func(&self, label: &str) -> Option<Arc<dyn Fn() -> String + Send + Sync>> {
        self.values.get(label).cloned()
    }
    pub fn value(&self, label: &str) -> Option<String> {
        self.values.get(label).map(|f| f())
    }
    pub fn labels(&self) -> Vec<String> {
        self.values.keys().cloned().collect()
    }
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl std::fmt::Debug for Metadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.values.keys()).finish()
    }
}

/// A typed bag for cross-plugin state (what CoreDNS stashes in `context.Context`).
#[derive(Default)]
pub struct Extensions {
    map: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl Extensions {
    pub fn insert<T: Any + Send + Sync>(&mut self, v: T) {
        self.map.insert(TypeId::of::<T>(), Box::new(v));
    }
    pub fn get<T: Any + Send + Sync>(&self) -> Option<&T> {
        self.map.get(&TypeId::of::<T>()).and_then(|b| b.downcast_ref())
    }
    pub fn get_mut<T: Any + Send + Sync>(&mut self) -> Option<&mut T> {
        self.map.get_mut(&TypeId::of::<T>()).and_then(|b| b.downcast_mut())
    }
    pub fn remove<T: Any + Send + Sync>(&mut self) -> Option<T> {
        self.map.remove(&TypeId::of::<T>()).and_then(|b| b.downcast().ok()).map(|b| *b)
    }
}

/// Information about the HTTP request carrying a DoH query.
#[derive(Debug, Clone, Default)]
pub struct HttpInfo {
    pub method: String,
    pub path: String,
    pub host: String,
    pub user_agent: String,
}

pub struct Request {
    /// The query. Plugins such as `rewrite` mutate it in place.
    pub msg: Message,
    pub remote: SocketAddr,
    pub local: SocketAddr,
    pub proto: Proto,
    pub start: Instant,
    /// Server identifier for metrics labels, e.g. `dns://:53`.
    pub server: String,
    /// The server-block zone this request was dispatched to.
    pub zone: String,
    /// The `view` name of the config that took the request ("" if none).
    pub view: String,
    pub metadata: Metadata,
    pub ext: Extensions,
    /// Absolute deadline set by the `cancel` plugin.
    pub deadline: Option<Instant>,
    pub tls_server_name: Option<String>,
    pub http: Option<HttpInfo>,
    /// Client-provided TSIG name that verified OK (set by `tsig`).
    pub tsig_verified: Option<Name>,
    /// Nesting depth of in-process self lookups (`server::self_lookup`).
    pub lookup_depth: u8,
    /// Cached lowercase qname.
    name_cache: Option<String>,
}

impl Request {
    pub fn new(msg: Message, remote: SocketAddr, local: SocketAddr, proto: Proto) -> Self {
        // dual-stack sockets report IPv4 peers as ::ffff:a.b.c.d; CoreDNS
        // (Go) reports them as IPv4, so unmap for family/ACL/logging parity
        let remote = SocketAddr::new(remote.ip().to_canonical(), remote.port());
        let local = SocketAddr::new(local.ip().to_canonical(), local.port());
        Request {
            msg,
            remote,
            local,
            proto,
            start: Instant::now(),
            server: String::new(),
            zone: String::new(),
            view: String::new(),
            metadata: Metadata::default(),
            ext: Extensions::default(),
            deadline: None,
            tls_server_name: None,
            http: None,
            tsig_verified: None,
            lookup_depth: 0,
            name_cache: None,
        }
    }

    /// Test helper: a UDP request from 127.0.0.1 for `name`/`qtype`.
    pub fn for_test(name: &str, qtype: RecordType) -> Self {
        let mut m = Message::new();
        m.set_id(rand::random());
        m.set_recursion_desired(true);
        m.add_query(hickory_proto::op::Query::query(Name::from_ascii(name).unwrap(), qtype));
        Request::new(
            m,
            "127.0.0.1:40000".parse().unwrap(),
            "127.0.0.1:53".parse().unwrap(),
            Proto::Udp,
        )
    }

    /// Lowercased FQDN of the (first) question; "." if there is none.
    pub fn name(&mut self) -> String {
        if let Some(n) = &self.name_cache {
            return n.clone();
        }
        let n = self.name_uncached();
        self.name_cache = Some(n.clone());
        n
    }

    /// Same as `name()` but does not require `&mut`.
    pub fn name_uncached(&self) -> String {
        match self.msg.queries().first() {
            Some(q) => {
                let mut s = q.name().to_ascii().to_lowercase();
                if !s.ends_with('.') {
                    s.push('.');
                }
                s
            }
            None => ".".to_string(),
        }
    }

    /// Invalidate the cached name (call after rewriting the question).
    pub fn clear_name_cache(&mut self) {
        self.name_cache = None;
    }

    pub fn qname(&self) -> Name {
        self.msg.queries().first().map(|q| q.name().clone()).unwrap_or_else(Name::root)
    }

    pub fn qtype(&self) -> RecordType {
        self.msg.queries().first().map(|q| q.query_type()).unwrap_or(RecordType::ZERO)
    }

    pub fn qclass(&self) -> DNSClass {
        self.msg.queries().first().map(|q| q.query_class()).unwrap_or(DNSClass::IN)
    }

    pub fn ip(&self) -> IpAddr {
        self.remote.ip()
    }

    pub fn port(&self) -> u16 {
        self.remote.port()
    }

    pub fn local_ip(&self) -> IpAddr {
        self.local.ip()
    }

    pub fn local_port(&self) -> u16 {
        self.local.port()
    }

    /// 1 for IPv4, 2 for IPv6.
    pub fn family(&self) -> u8 {
        match self.remote.ip() {
            IpAddr::V4(_) => 1,
            IpAddr::V6(_) => 2,
        }
    }

    pub fn do_bit(&self) -> bool {
        self.msg.edns().map(|e| e.dnssec_ok()).unwrap_or(false)
    }

    pub fn has_edns(&self) -> bool {
        self.msg.edns().is_some()
    }

    /// The maximum response size the client can take: the EDNS0 buffer size
    /// for UDP (min 512), or 65535 for stream transports.
    pub fn size(&self) -> usize {
        if self.proto.is_stream() {
            return 65535;
        }
        match self.msg.edns() {
            Some(e) => {
                let s = e.max_payload();
                if s < 512 {
                    512
                } else {
                    s as usize
                }
            }
            None => 512,
        }
    }

    /// Wire size of the query (approximate: re-encoded).
    pub fn len(&self) -> usize {
        self.msg.to_vec().map(|v| v.len()).unwrap_or(0)
    }

    /// "udp", "tcp", "tcp-tls", "https", "quic", "grpc".
    pub fn proto_str(&self) -> &'static str {
        self.proto.as_str()
    }

    /// "IN", "CH", ...
    pub fn class_str(&self) -> String {
        self.qclass().to_string()
    }

    pub fn type_str(&self) -> String {
        self.qtype().to_string()
    }

    /// Does `reply` belong to this query (same id and question)?
    pub fn matches(&self, reply: &Message) -> bool {
        if reply.id() != self.msg.id() {
            return false;
        }
        if reply.message_type() != MessageType::Response {
            return false;
        }
        match (self.msg.queries().first(), reply.queries().first()) {
            (Some(q), Some(r)) => {
                q.query_type() == r.query_type()
                    && q.query_class() == r.query_class()
                    && q.name().to_ascii().eq_ignore_ascii_case(&r.name().to_ascii())
            }
            (None, None) => true,
            _ => false,
        }
    }

    /// A fresh response message for this query: id, question, opcode and RD
    /// copied, EDNS0 mirrored (`m.SetReply(r)` + `SetEdns0`).
    pub fn new_reply(&self) -> Message {
        let mut m = Message::new();
        m.set_id(self.msg.id());
        m.set_message_type(MessageType::Response);
        m.set_op_code(self.msg.op_code());
        m.set_recursion_desired(self.msg.recursion_desired());
        m.set_checking_disabled(self.msg.checking_disabled());
        m.set_response_code(ResponseCode::NoError);
        if let Some(q) = self.msg.queries().first() {
            m.add_query(q.clone());
        }
        self.set_edns0(&mut m);
        m
    }

    /// Mirror the query's EDNS0 OPT into a response (`request.Request.SetEdns0`
    /// style): the response carries an OPT of our size, with DO copied.
    pub fn set_edns0(&self, m: &mut Message) {
        if let Some(q) = self.msg.edns() {
            let mut e = Edns::new();
            e.set_max_payload(crate::dnsutil::UDP_BUFFER_SIZE);
            e.set_dnssec_ok(q.dnssec_ok());
            e.set_version(0);
            m.set_edns(e);
        }
    }

    /// Make an error response with the given rcode (`request.Request.ErrorResponse`).
    pub fn error_response(&self, rcode: ResponseCode) -> Message {
        let mut m = self.new_reply();
        m.set_response_code(rcode);
        m
    }

    pub fn op_code(&self) -> OpCode {
        self.msg.op_code()
    }

    /// Returns true if the deadline set by `cancel` has passed.
    pub fn is_cancelled(&self) -> bool {
        self.deadline.map(|d| Instant::now() >= d).unwrap_or(false)
    }

    /// Clone the parts of the request a plugin needs to re-issue it (for
    /// upstream lookups): the message and addressing.
    pub fn shallow_clone(&self) -> Request {
        let mut r = Request::new(self.msg.clone(), self.remote, self.local, self.proto);
        r.start = self.start;
        r.server = self.server.clone();
        r.zone = self.zone.clone();
        r.view = self.view.clone();
        r.metadata = self.metadata.clone();
        r.deadline = self.deadline;
        r.tls_server_name = self.tls_server_name.clone();
        r.http = self.http.clone();
        r.tsig_verified = self.tsig_verified.clone();
        r.lookup_depth = self.lookup_depth;
        r
    }

    /// A new request for `name`/`qtype` that inherits this request's
    /// transport context (used by plugins that look up other names, e.g.
    /// `kubernetes` for CNAME targets, `autopath`).
    pub fn new_with_question(&self, name: Name, qtype: RecordType) -> Request {
        let mut m = Message::new();
        m.set_id(rand::random());
        m.set_recursion_desired(true);
        m.add_query(hickory_proto::op::Query::query(name, qtype));
        if let Some(e) = self.msg.edns() {
            let mut ne = Edns::new();
            ne.set_max_payload(e.max_payload());
            ne.set_dnssec_ok(e.dnssec_ok());
            m.set_edns(ne);
        }
        let mut r = Request::new(m, self.remote, self.local, self.proto);
        r.server = self.server.clone();
        r.zone = self.zone.clone();
        r.view = self.view.clone();
        r.deadline = self.deadline;
        r.lookup_depth = self.lookup_depth;
        r
    }
}
