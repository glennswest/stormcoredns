//! DNS over HTTPS (RFC 8484) listener. Serves `/dns-query` with GET
//! (`?dns=<base64url>`) and POST (`application/dns-message`). Runs plain
//! HTTP when no `tls` plugin is configured (behind a TLS-terminating proxy).

use super::Server;
use crate::plugin::{HttpInfo, Proto};
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

pub const DOH_PATH: &str = "/dns-query";
pub const MIME: &str = "application/dns-message";
/// The largest DNS message (RFC 1035 4.2.2's 16-bit length). A POST body past
/// it is refused while it is read, before it is buffered (finding 79d70052c48c).
pub const MAX_MESSAGE: usize = 65535;

pub async fn run_https(srv: Arc<Server>, listener: TcpListener, cancel: CancellationToken) {
    let acceptor = srv.tls.clone().map(TlsAcceptor::from);
    if acceptor.is_none() {
        tracing::warn!("{}: no tls plugin configured, serving plain HTTP", srv.label);
    }
    loop {
        let (stream, remote) = tokio::select! {
            _ = cancel.cancelled() => return,
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!("{}: https accept: {}", srv.label, e);
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    continue;
                }
            },
        };
        let local = stream.local_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        let srv = srv.clone();
        let acceptor = acceptor.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            match acceptor {
                // `timeouts read` bounds the handshake, as Go's ReadTimeout does
                Some(acc) => match tokio::time::timeout(srv.read_timeout, acc.accept(stream)).await.unwrap_or_else(|_| Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "handshake timeout"))) {
                    Ok(tls) => {
                        let sni = tls.get_ref().1.server_name().map(|s| s.to_string());
                        serve_conn(srv, TokioIo::new(tls), remote, local, sni, cancel).await
                    }
                    Err(e) => tracing::debug!("{}: tls handshake from {}: {}", srv.label, remote, e),
                },
                None => serve_conn(srv, TokioIo::new(stream), remote, local, None, cancel).await,
            }
        });
    }
}

async fn serve_conn<I>(srv: Arc<Server>, io: I, remote: SocketAddr, local: SocketAddr, sni: Option<String>, cancel: CancellationToken)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let idle = srv.idle_timeout;
    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
        let srv = srv.clone();
        let sni = sni.clone();
        async move { Ok::<_, std::convert::Infallible>(handle(srv, req, remote, local, sni).await) }
    });
    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    // `timeouts idle`: how long a connection may wait for the next request's headers
    builder.http1().timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(idle);
    let conn = builder.serve_connection(io, svc);
    tokio::pin!(conn);
    tokio::select! {
        _ = cancel.cancelled() => { conn.as_mut().graceful_shutdown(); let _ = conn.await; }
        r = &mut conn => { if let Err(e) = r { tracing::debug!("https connection from {}: {}", remote, e); } }
    }
}

fn status(srv: &Server, code: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    crate::metrics::HTTPS_RESPONSES.with_label_values(&[&srv.label, code.as_str()]).inc();
    Response::builder().status(code).header("content-type", "text/plain").body(Full::new(Bytes::from_static(body.as_bytes()))).unwrap()
}

async fn handle(srv: Arc<Server>, req: Request<Incoming>, remote: SocketAddr, local: SocketAddr, sni: Option<String>) -> Response<Full<Bytes>> {
    let path = req.uri().path().to_string();
    if path != DOH_PATH {
        return status(&srv, StatusCode::NOT_FOUND, "not found");
    }
    let method = req.method().clone();
    let info = HttpInfo {
        method: method.to_string(),
        path: path.clone(),
        host: req.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or("").to_string(),
        user_agent: req.headers().get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("").to_string(),
    };
    let query: Vec<u8> = match method {
        hyper::Method::GET => {
            let q = req.uri().query().unwrap_or("");
            let mut dns = None;
            for kv in q.split('&') {
                if let Some(v) = kv.strip_prefix("dns=") {
                    dns = Some(v.to_string());
                }
            }
            let Some(v) = dns else { return status(&srv, StatusCode::BAD_REQUEST, "missing dns parameter") };
            match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(v.trim_end_matches('=')) {
                Ok(b) => b,
                Err(_) => return status(&srv, StatusCode::BAD_REQUEST, "bad dns parameter"),
            }
        }
        hyper::Method::POST => {
            let ct = req.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
            if !ct.starts_with(MIME) {
                return status(&srv, StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported media type");
            }
            // a declared length past the limit is refused before reading any of it
            let declared = req.headers().get(hyper::header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<u64>().ok());
            if declared.is_some_and(|n| n > MAX_MESSAGE as u64) {
                return status(&srv, StatusCode::BAD_REQUEST, "bad message size");
            }
            // and a chunked (or lying) body stops as soon as it passes the limit
            match tokio::time::timeout(srv.read_timeout, Limited::new(req.into_body(), MAX_MESSAGE).collect()).await {
                Ok(Ok(c)) => c.to_bytes().to_vec(),
                Ok(Err(e)) if e.downcast_ref::<LengthLimitError>().is_some() => return status(&srv, StatusCode::BAD_REQUEST, "bad message size"),
                Ok(Err(_)) => return status(&srv, StatusCode::BAD_REQUEST, "bad body"),
                Err(_) => return status(&srv, StatusCode::REQUEST_TIMEOUT, "read timeout"),
            }
        }
        _ => return status(&srv, StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
    };
    if query.len() > MAX_MESSAGE || query.len() < 12 {
        return status(&srv, StatusCode::BAD_REQUEST, "bad message size");
    }
    // Use the X-Forwarded-For remote when behind a proxy? CoreDNS does not; neither do we.
    // `timeouts write` bounds producing the answer, as Go's WriteTimeout does
    let resp = match tokio::time::timeout(srv.write_timeout, srv.serve_bytes(&query, remote, local, Proto::Https, Some(info), sni)).await {
        Ok(r) => r,
        Err(_) => return status(&srv, StatusCode::SERVICE_UNAVAILABLE, "write timeout"),
    };
    match resp {
        Some(bytes) => {
            // cache-control from the minimal TTL in the answer
            let ttl = hickory_proto::op::Message::from_vec(&bytes)
                .map(|m| crate::dnsutil::minimal_ttl(&m, m.metadata.response_code == hickory_proto::op::ResponseCode::NXDomain).as_secs())
                .unwrap_or(0);
            crate::metrics::HTTPS_RESPONSES.with_label_values(&[&srv.label, "200"]).inc();
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", MIME)
                .header("cache-control", format!("max-age={}", ttl))
                .body(Full::new(Bytes::from(bytes)))
                .unwrap()
        }
        None => status(&srv, StatusCode::BAD_REQUEST, "bad request"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::config::Transport;
    use std::collections::HashMap;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A plain-HTTP DoH listener on 127.0.0.1 with no zones; `read` is long so
    /// that only the size limit can answer a request that never ends.
    async fn doh() -> (SocketAddr, CancellationToken) {
        let srv = Arc::new(Server {
            label: "https://:0".into(),
            transport: Transport::Https,
            addrs: vec![],
            zones: HashMap::new(),
            tls: None,
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(30),
            num_sockets: 1,
            graceful_timeout: Duration::from_secs(1),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        tokio::spawn(run_https(srv, listener, cancel.clone()));
        (addr, cancel)
    }

    /// Reads until the status line is in; "" when the server closed first.
    async fn status_line(rd: &mut (impl AsyncReadExt + Unpin)) -> String {
        let mut got = Vec::new();
        let mut buf = [0u8; 1024];
        while !got.windows(2).any(|w| w == b"\r\n") {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        String::from_utf8_lossy(&got).lines().next().unwrap_or("").to_string()
    }

    fn post_head(extra: &str) -> String {
        format!("POST {} HTTP/1.1\r\nhost: t\r\ncontent-type: {}\r\n{}\r\n", DOH_PATH, MIME, extra)
    }

    #[tokio::test]
    async fn post_body_past_the_limit_is_refused_while_read() {
        let (addr, cancel) = doh().await;

        // a declared length past 65535: refused with no body sent at all
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        c.write_all(post_head("content-length: 100000000\r\n").as_bytes()).await.unwrap();
        let line = tokio::time::timeout(Duration::from_secs(5), status_line(&mut c)).await.expect("answered before the body");
        assert!(line.starts_with("HTTP/1.1 400"), "declared length: {line}");

        // a chunked body that never ends: refused once it passes the limit,
        // long before read_timeout (30 s), with the rest never read
        let c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut rd, mut wr) = c.into_split();
        let writer = tokio::spawn(async move {
            let mut sent = 0usize;
            if wr.write_all(post_head("transfer-encoding: chunked\r\n").as_bytes()).await.is_err() {
                return sent;
            }
            let chunk = format!("4000\r\n{}\r\n", "a".repeat(0x4000));
            // up to 8 MiB, then stall without the last chunk
            while sent < 8 << 20 {
                if wr.write_all(chunk.as_bytes()).await.is_err() {
                    break;
                }
                sent += 0x4000;
            }
            std::future::pending::<()>().await;
            sent
        });
        let line = tokio::time::timeout(Duration::from_secs(10), status_line(&mut rd)).await.expect("answered before read_timeout");
        assert!(line.starts_with("HTTP/1.1 400"), "chunked: {line}");
        writer.abort();

        // a real query still gets through
        let mut m = hickory_proto::op::Message::new(0, MessageType::Query, OpCode::Query);
        m.add_query(hickory_proto::op::Query::query("example.org.".parse().unwrap(), hickory_proto::rr::RecordType::A));
        let q = m.to_vec().unwrap();
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        c.write_all(post_head(&format!("content-length: {}\r\n", q.len())).as_bytes()).await.unwrap();
        c.write_all(&q).await.unwrap();
        let line = tokio::time::timeout(Duration::from_secs(5), status_line(&mut c)).await.unwrap();
        assert!(line.starts_with("HTTP/1.1 200"), "small query: {line}");
        cancel.cancel();
    }
}
