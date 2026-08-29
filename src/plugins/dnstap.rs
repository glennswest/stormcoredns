//! `dnstap SOCKET [full] { identity ID; version V; extra E; skipverify }`
//! — streams CLIENT_QUERY / CLIENT_RESPONSE dnstap messages over Frame
//! Streams to a unix socket, `tcp://host:port` or `tls://host:port`.
//! `full` includes the wire-format DNS messages.

use crate::plugin::{Controller, DnsResult, Handler, Next, Proto, Reply, Request};
use async_trait::async_trait;
use prost::Message as ProstMessage;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

// --------------------------------------------------------------- protobuf

#[derive(Clone, PartialEq, ProstMessage)]
pub struct DnstapMessage {
    #[prost(uint32, tag = "1")]
    pub r#type: u32,
    #[prost(uint32, optional, tag = "2")]
    pub socket_family: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub socket_protocol: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub query_address: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "5")]
    pub response_address: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "6")]
    pub query_port: Option<u32>,
    #[prost(uint32, optional, tag = "7")]
    pub response_port: Option<u32>,
    #[prost(uint64, optional, tag = "8")]
    pub query_time_sec: Option<u64>,
    #[prost(fixed32, optional, tag = "9")]
    pub query_time_nsec: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "10")]
    pub query_message: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "11")]
    pub query_zone: Option<Vec<u8>>,
    #[prost(uint64, optional, tag = "12")]
    pub response_time_sec: Option<u64>,
    #[prost(fixed32, optional, tag = "13")]
    pub response_time_nsec: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "14")]
    pub response_message: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, ProstMessage)]
pub struct Dnstap {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub identity: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub version: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub extra: Option<Vec<u8>>,
    #[prost(message, optional, tag = "14")]
    pub message: Option<DnstapMessage>,
    #[prost(uint32, tag = "15")]
    pub r#type: u32,
}

const TYPE_MESSAGE: u32 = 1;
const CLIENT_QUERY: u32 = 5;
const CLIENT_RESPONSE: u32 = 6;
const CONTENT_TYPE: &[u8] = b"protobuf:dnstap.Dnstap";

// frame streams control frame types
const FS_ACCEPT: u32 = 1;
const FS_START: u32 = 2;
const FS_STOP: u32 = 3;
const FS_READY: u32 = 4;

fn socket_family(ip: IpAddr) -> u32 {
    match ip {
        IpAddr::V4(_) => 1,
        IpAddr::V6(_) => 2,
    }
}
fn socket_protocol(p: Proto) -> u32 {
    match p {
        Proto::Udp => 1,
        Proto::Tcp => 2,
        Proto::Tls => 3,
        Proto::Https => 4,
        Proto::Grpc => 2,
        Proto::Quic => 7,
    }
}
fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v) => v.octets().to_vec(),
        IpAddr::V6(v) => v.octets().to_vec(),
    }
}

// --------------------------------------------------------------- writer

#[derive(Clone)]
pub enum Endpoint {
    Unix(String),
    Tcp(SocketAddr),
    Tls(SocketAddr, bool),
}

async fn control(w: &mut (dyn tokio::io::AsyncWrite + Unpin + Send), ctype: u32, with_content: bool) -> std::io::Result<()> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&ctype.to_be_bytes());
    if with_content {
        frame.extend_from_slice(&1u32.to_be_bytes()); // field: content type
        frame.extend_from_slice(&(CONTENT_TYPE.len() as u32).to_be_bytes());
        frame.extend_from_slice(CONTENT_TYPE);
    }
    w.write_all(&0u32.to_be_bytes()).await?;
    w.write_all(&(frame.len() as u32).to_be_bytes()).await?;
    w.write_all(&frame).await
}

async fn read_control(r: &mut (dyn tokio::io::AsyncRead + Unpin + Send)) -> std::io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b).await?;
    if u32::from_be_bytes(b) != 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "expected control frame"));
    }
    r.read_exact(&mut b).await?;
    let len = u32::from_be_bytes(b) as usize;
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    if body.len() < 4 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "short control frame"));
    }
    Ok(u32::from_be_bytes([body[0], body[1], body[2], body[3]]))
}

async fn session<S>(mut stream: S, rx: &mut mpsc::Receiver<Vec<u8>>) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    // bi-directional handshake: READY → ACCEPT, START
    control(&mut stream, FS_READY, true).await?;
    let t = tokio::time::timeout(Duration::from_secs(5), read_control(&mut stream)).await.map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "no ACCEPT"))??;
    if t != FS_ACCEPT {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "expected ACCEPT"));
    }
    control(&mut stream, FS_START, true).await?;
    while let Some(frame) = rx.recv().await {
        stream.write_all(&(frame.len() as u32).to_be_bytes()).await?;
        stream.write_all(&frame).await?;
    }
    control(&mut stream, FS_STOP, false).await?;
    Ok(())
}

async fn writer(endpoint: Endpoint, mut rx: mpsc::Receiver<Vec<u8>>) {
    loop {
        let res = match &endpoint {
            Endpoint::Unix(p) => match tokio::net::UnixStream::connect(p).await {
                Ok(s) => session(s, &mut rx).await,
                Err(e) => Err(e),
            },
            Endpoint::Tcp(a) => match tokio::net::TcpStream::connect(a).await {
                Ok(s) => session(s, &mut rx).await,
                Err(e) => Err(e),
            },
            Endpoint::Tls(a, skipverify) => match tokio::net::TcpStream::connect(a).await {
                Ok(s) => match crate::server::tls::client_config(None, None, *skipverify) {
                    Ok(cfg) => {
                        let conn = tokio_rustls::TlsConnector::from(cfg);
                        let sni = rustls::pki_types::ServerName::IpAddress(a.ip().into());
                        match conn.connect(sni, s).await {
                            Ok(t) => session(t, &mut rx).await,
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
                },
                Err(e) => Err(e),
            },
        };
        match res {
            Ok(()) => return, // channel closed: shutdown
            Err(e) => {
                tracing::warn!("plugin/dnstap: connection failed: {}; retrying", e);
                // drain a little so we do not buffer forever while down
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

// --------------------------------------------------------------- plugin

pub struct DnstapHandler {
    tx: mpsc::Sender<Vec<u8>>,
    full: bool,
    identity: Vec<u8>,
    version: Vec<u8>,
    extra: Option<Vec<u8>>,
}

impl DnstapHandler {
    fn tap(&self, mut m: DnstapMessage) {
        let d = Dnstap { identity: Some(self.identity.clone()), version: Some(self.version.clone()), extra: self.extra.clone(), message: Some(std::mem::take(&mut m)), r#type: TYPE_MESSAGE };
        let mut buf = Vec::with_capacity(d.encoded_len());
        if d.encode(&mut buf).is_ok() {
            let _ = self.tx.try_send(buf);
        }
    }
}

fn now() -> (u64, u32) {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (d.as_secs(), d.subsec_nanos())
}

#[async_trait]
impl Handler for DnstapHandler {
    fn name(&self) -> &'static str {
        "dnstap"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let (qs, qn) = now();
        let base = DnstapMessage {
            r#type: CLIENT_QUERY,
            socket_family: Some(socket_family(req.ip())),
            socket_protocol: Some(socket_protocol(req.proto)),
            query_address: Some(ip_bytes(req.ip())),
            response_address: Some(ip_bytes(req.local_ip())),
            query_port: Some(req.port() as u32),
            response_port: Some(req.local_port() as u32),
            query_time_sec: Some(qs),
            query_time_nsec: Some(qn),
            query_message: if self.full { req.raw.as_ref().map(|r| r.as_ref().clone()).or_else(|| req.msg.to_vec().ok()) } else { None },
            query_zone: None,
            response_time_sec: None,
            response_time_nsec: None,
            response_message: None,
        };
        self.tap(base.clone());
        let r = next.serve(req).await;
        if let Ok(Reply::Msg(m)) = &r {
            let (rs, rn) = now();
            let mut resp = base;
            resp.r#type = CLIENT_RESPONSE;
            resp.query_message = None;
            resp.response_time_sec = Some(rs);
            resp.response_time_nsec = Some(rn);
            resp.response_message = if self.full { m.to_vec().ok() } else { None };
            self.tap(resp);
        }
        r
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    while c.next() {
        let mut args = c.remaining_args_until_brace();
        if args.is_empty() {
            return Err(c.arg_err());
        }
        let socket = args.remove(0);
        let mut full = false;
        if let Some(f) = args.first() {
            if f == "full" {
                full = true;
                args.remove(0);
            }
        }
        if !args.is_empty() {
            return Err(c.arg_err());
        }
        let mut identity = hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or_else(|_| "localhost".into()).into_bytes();
        let mut version = format!("stormcoredns-{}", crate::VERSION).into_bytes();
        let mut extra = None;
        let mut skipverify = false;
        while c.next_block() {
            match c.val() {
                "identity" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    identity = a[0].clone().into_bytes();
                }
                "version" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    version = a[0].clone().into_bytes();
                }
                "extra" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    extra = Some(a[0].clone().into_bytes());
                }
                "skipverify" => skipverify = true,
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        let endpoint = if let Some(rest) = socket.strip_prefix("tcp://") {
            Endpoint::Tcp(crate::dnsutil::host_port(rest, 6000)?.parse().map_err(|_| c.errf(format!("bad tcp endpoint {}", socket)))?)
        } else if let Some(rest) = socket.strip_prefix("tls://") {
            Endpoint::Tls(crate::dnsutil::host_port(rest, 6000)?.parse().map_err(|_| c.errf(format!("bad tls endpoint {}", socket)))?, skipverify)
        } else {
            Endpoint::Unix(socket.strip_prefix("unix://").unwrap_or(&socket).to_string())
        };
        let (tx, rx) = mpsc::channel::<Vec<u8>>(10000);
        c.add_plugin(Arc::new(DnstapHandler { tx, full, identity, version, extra }));
        c.on_startup(Box::new(move || {
            Box::pin(async move {
                tokio::spawn(writer(endpoint, rx));
                Ok(())
            })
        }));
    }
    Ok(())
}
