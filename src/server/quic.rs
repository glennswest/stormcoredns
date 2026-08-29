//! DNS over QUIC (RFC 9250) listener: one query per bidirectional stream,
//! 2-byte length prefix, ALPN `doq`.

use super::Server;
use crate::plugin::Proto;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

const DOQ_NO_ERROR: u32 = 0x0;
const DOQ_PROTOCOL_ERROR: u32 = 0x2;
const MAX_STREAMS: u32 = 256;

pub async fn run_quic(srv: Arc<Server>, sock: std::net::UdpSocket, cancel: CancellationToken) {
    let Some(tls) = srv.tls.clone() else {
        tracing::error!("{}: no TLS configuration (add the tls plugin)", srv.label);
        return;
    };
    let mut tls = (*tls).clone();
    tls.alpn_protocols = vec![b"doq".to_vec()];
    let crypto = match quinn::crypto::rustls::QuicServerConfig::try_from(tls) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("{}: quic tls config: {}", srv.label, e);
            return;
        }
    };
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(MAX_STREAMS.into());
    transport.max_concurrent_uni_streams(0u32.into());
    transport.max_idle_timeout(Some(quinn::IdleTimeout::try_from(srv.idle_timeout).unwrap_or(quinn::IdleTimeout::from(quinn::VarInt::from_u32(10_000)))));
    server_config.transport_config(Arc::new(transport));
    let endpoint = match quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(server_config), sock, Arc::new(quinn::TokioRuntime)) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("{}: quic endpoint: {}", srv.label, e);
            return;
        }
    };
    let local = endpoint.local_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
    loop {
        let incoming = tokio::select! {
            _ = cancel.cancelled() => { endpoint.close(quinn::VarInt::from_u32(DOQ_NO_ERROR), b"shutdown"); return; }
            i = endpoint.accept() => match i { Some(i) => i, None => return },
        };
        let srv = srv.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!("{}: quic handshake: {}", srv.label, e);
                    return;
                }
            };
            let remote = conn.remote_address();
            let sni = conn
                .handshake_data()
                .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .and_then(|d| d.server_name);
            loop {
                let (send, recv) = tokio::select! {
                    _ = cancel.cancelled() => { conn.close(quinn::VarInt::from_u32(DOQ_NO_ERROR), b"shutdown"); return; }
                    r = conn.accept_bi() => match r {
                        Ok(s) => s,
                        Err(quinn::ConnectionError::ApplicationClosed(_)) | Err(quinn::ConnectionError::LocallyClosed) => return,
                        Err(e) => { tracing::debug!("{}: quic accept_bi from {}: {}", srv.label, remote, e); return; }
                    },
                };
                let srv = srv.clone();
                let conn = conn.clone();
                let sni = sni.clone();
                tokio::spawn(async move {
                    handle_stream(srv, conn, send, recv, remote, local, sni).await;
                });
            }
        });
    }
}

async fn handle_stream(
    srv: Arc<Server>,
    conn: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    remote: std::net::SocketAddr,
    local: std::net::SocketAddr,
    sni: Option<String>,
) {
    let data = match tokio::time::timeout(srv.read_timeout, recv.read_to_end(65535 + 2)).await {
        Ok(Ok(d)) => d,
        _ => {
            conn.close(quinn::VarInt::from_u32(DOQ_PROTOCOL_ERROR), b"read");
            crate::metrics::QUIC_RESPONSES.with_label_values(&[&srv.label, "0x2"]).inc();
            return;
        }
    };
    if data.len() < 2 {
        conn.close(quinn::VarInt::from_u32(DOQ_PROTOCOL_ERROR), b"short");
        crate::metrics::QUIC_RESPONSES.with_label_values(&[&srv.label, "0x2"]).inc();
        return;
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() != len + 2 {
        conn.close(quinn::VarInt::from_u32(DOQ_PROTOCOL_ERROR), b"length");
        crate::metrics::QUIC_RESPONSES.with_label_values(&[&srv.label, "0x2"]).inc();
        return;
    }
    // RFC 9250 §4.2.1: the message id must be 0
    if data[2] != 0 || data[3] != 0 {
        conn.close(quinn::VarInt::from_u32(DOQ_PROTOCOL_ERROR), b"id");
        crate::metrics::QUIC_RESPONSES.with_label_values(&[&srv.label, "0x2"]).inc();
        return;
    }
    if let Some(resp) = srv.serve_bytes(&data[2..], remote, local, Proto::Quic, None, sni).await {
        let mut out = Vec::with_capacity(resp.len() + 2);
        out.extend_from_slice(&(resp.len() as u16).to_be_bytes());
        out.extend_from_slice(&resp);
        if send.write_all(&out).await.is_ok() {
            let _ = send.finish();
            crate::metrics::QUIC_RESPONSES.with_label_values(&[&srv.label, "0x0"]).inc();
        }
    }
}
