//! Tiny HTTP server helper for the `health`, `ready`, `prometheus` and
//! `pprof` endpoints. Binds with SO_REUSEPORT so a reloading instance can
//! start its endpoint before the old one stops.

use anyhow::Result;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::future::Future;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

pub type HttpResponse = Response<Full<Bytes>>;

/// Normalise `:8080` / `localhost:8080` / `127.0.0.1:8080` bind strings.
pub fn normalize_addr(addr: &str) -> String {
    if addr.starts_with(':') {
        addr.to_string()
    } else if let Some(rest) = addr.strip_prefix("localhost") {
        format!("127.0.0.1{}", rest)
    } else {
        addr.to_string()
    }
}

pub async fn serve<F, Fut>(addr: &str, cancel: CancellationToken, handler: F) -> Result<()>
where
    F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = HttpResponse> + Send + 'static,
{
    let std_listener = super::bind_tcp(&normalize_addr(addr))?;
    let listener = TcpListener::from_std(std_listener)?;
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        loop {
            let (stream, _) = tokio::select! {
                _ = cancel.cancelled() => return,
                r = listener.accept() => match r { Ok(v) => v, Err(_) => continue },
            };
            let h = handler.clone();
            let c = cancel.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req| {
                    let h = h.clone();
                    async move { Ok::<_, std::convert::Infallible>(h(req).await) }
                });
                let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                let conn = builder.serve_connection(TokioIo::new(stream), svc);
                tokio::pin!(conn);
                tokio::select! {
                    _ = c.cancelled() => { conn.as_mut().graceful_shutdown(); let _ = conn.await; }
                    _ = &mut conn => {}
                }
            });
        }
    });
    Ok(())
}

pub fn text(status: u16, body: impl Into<Bytes>) -> HttpResponse {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(body.into()))
        .unwrap()
}

pub fn with_type(status: u16, content_type: &str, body: impl Into<Bytes>) -> HttpResponse {
    Response::builder().status(status).header("content-type", content_type).body(Full::new(body.into())).unwrap()
}

/// Process-wide registry of HTTP endpoints (health, ready, prometheus,
/// pprof) keyed by bind address. Handles reloads: the new instance's
/// endpoint replaces the old one at startup, and the old instance's
/// shutdown does not tear down the replacement.
#[derive(Default, Clone)]
pub struct Endpoints {
    inner: Arc<parking_lot::Mutex<Vec<(String, u64, CancellationToken)>>>,
    next_id: Arc<std::sync::atomic::AtomicU64>,
}

impl Endpoints {
    /// Register startup/shutdown hooks on `c` that serve `handler` at `addr`.
    pub fn install<F, Fut>(&self, c: &mut crate::plugin::Controller<'_>, addr: &str, handler: F)
    where
        F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = HttpResponse> + Send + 'static,
    {
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let cancel = CancellationToken::new();
        let addr = normalize_addr(addr);
        let (inner_s, inner_d) = (self.inner.clone(), self.inner.clone());
        let (addr_s, cancel_s) = (addr.clone(), cancel.clone());
        c.on_startup(Box::new(move || {
            Box::pin(async move {
                {
                    let mut list = inner_s.lock();
                    // replace an endpoint left by the previous instance
                    list.retain(|(a, _, tok)| {
                        if *a == addr_s {
                            tok.cancel();
                            false
                        } else {
                            true
                        }
                    });
                    list.push((addr_s.clone(), id, cancel_s.clone()));
                }
                serve(&addr_s, cancel_s, handler).await
            })
        }));
        c.on_shutdown(Box::new(move || {
            Box::pin(async move {
                let mut list = inner_d.lock();
                list.retain(|(_, i, tok)| {
                    if *i == id {
                        tok.cancel();
                        false
                    } else {
                        true
                    }
                });
                Ok(())
            })
        }));
        let _ = cancel;
    }
}
