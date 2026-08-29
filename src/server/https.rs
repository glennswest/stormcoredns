//! DNS over HTTPS (RFC 8484) listener. Serves `/dns-query` with GET
//! (`?dns=<base64url>`) and POST (`application/dns-message`). Runs plain
//! HTTP when no `tls` plugin is configured (behind a TLS-terminating proxy).

use super::Server;
use crate::plugin::{HttpInfo, Proto};
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
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
                Some(acc) => match acc.accept(stream).await {
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
    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
        let srv = srv.clone();
        let sni = sni.clone();
        async move { Ok::<_, std::convert::Infallible>(handle(srv, req, remote, local, sni).await) }
    });
    let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
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
            match req.into_body().collect().await {
                Ok(c) => c.to_bytes().to_vec(),
                Err(_) => return status(&srv, StatusCode::BAD_REQUEST, "bad body"),
            }
        }
        _ => return status(&srv, StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
    };
    if query.len() > 65535 || query.len() < 12 {
        return status(&srv, StatusCode::BAD_REQUEST, "bad message size");
    }
    // Use the X-Forwarded-For remote when behind a proxy? CoreDNS does not; neither do we.
    let resp = srv.serve_bytes(&query, remote, local, Proto::Https, Some(info), sni).await;
    match resp {
        Some(bytes) => {
            // cache-control from the minimal TTL in the answer
            let ttl = hickory_proto::op::Message::from_vec(&bytes)
                .map(|m| crate::dnsutil::minimal_ttl(&m, m.response_code() == hickory_proto::op::ResponseCode::NXDomain).as_secs())
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
