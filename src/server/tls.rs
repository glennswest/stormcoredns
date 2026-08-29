//! DNS over TLS (RFC 7858) listener and TLS config loading shared by the
//! `tls` plugin and upstream clients.

use super::Server;
use crate::plugin::Proto;
use anyhow::{anyhow, bail, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

pub async fn run_tls(srv: Arc<Server>, listener: TcpListener, cancel: CancellationToken) {
    let cfg = match &srv.tls {
        Some(c) => c.clone(),
        None => {
            tracing::error!("{}: no TLS configuration (add the tls plugin)", srv.label);
            return;
        }
    };
    let acceptor = TlsAcceptor::from(cfg);
    loop {
        let (stream, remote) = tokio::select! {
            _ = cancel.cancelled() => return,
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!("{}: tls accept: {}", srv.label, e);
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    continue;
                }
            },
        };
        let local = stream.local_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        let acceptor = acceptor.clone();
        let srv = srv.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            let hs = tokio::time::timeout(std::time::Duration::from_secs(10), acceptor.accept(stream)).await;
            match hs {
                Ok(Ok(tls)) => {
                    let sni = tls.get_ref().1.server_name().map(|s| s.to_string());
                    srv.serve_stream(tls, remote, local, Proto::Tls, sni, cancel).await;
                }
                Ok(Err(e)) => tracing::debug!("{}: tls handshake from {}: {}", srv.label, remote, e),
                Err(_) => tracing::debug!("{}: tls handshake from {} timed out", srv.label, remote),
            }
        });
    }
}

pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let f = std::fs::File::open(path).with_context(|| format!("opening certificate {}", path.display()))?;
    let mut rd = BufReader::new(f);
    let certs: Vec<_> = rustls_pemfile::certs(&mut rd).collect::<std::result::Result<_, _>>()?;
    if certs.is_empty() {
        bail!("no certificates found in {}", path.display());
    }
    Ok(certs)
}

pub fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let f = std::fs::File::open(path).with_context(|| format!("opening key {}", path.display()))?;
    let mut rd = BufReader::new(f);
    rustls_pemfile::private_key(&mut rd)?.ok_or_else(|| anyhow!("no private key found in {}", path.display()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth {
    Nocert,
    Request,
    Require,
    Verify,
    RequireAndVerify,
}

impl ClientAuth {
    pub fn parse(s: &str) -> Option<ClientAuth> {
        match s {
            "nocert" => Some(ClientAuth::Nocert),
            "request" => Some(ClientAuth::Request),
            "require" => Some(ClientAuth::Require),
            "verify_if_given" => Some(ClientAuth::Verify),
            "require_and_verify" => Some(ClientAuth::RequireAndVerify),
            _ => None,
        }
    }
}

/// Build a server TLS config from cert/key files, an optional CA bundle
/// for client verification, and the client-auth policy (`tls` plugin).
pub fn server_config(cert: &Path, key: &Path, ca: Option<&Path>, client_auth: ClientAuth) -> Result<Arc<rustls::ServerConfig>> {
    let certs = load_certs(cert)?;
    let key = load_key(key)?;
    let builder = rustls::ServerConfig::builder();
    let builder = match (ca, client_auth) {
        (_, ClientAuth::Nocert) | (None, _) => builder.with_no_client_auth(),
        (Some(ca), auth) => {
            let mut roots = rustls::RootCertStore::empty();
            for c in load_certs(ca)? {
                roots.add(c)?;
            }
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots));
            let verifier = match auth {
                ClientAuth::Request | ClientAuth::Verify => verifier.allow_unauthenticated().build()?,
                _ => verifier.build()?,
            };
            builder.with_client_cert_verifier(verifier)
        }
    };
    let mut cfg = builder.with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"dot".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec(), b"doq".to_vec()];
    Ok(Arc::new(cfg))
}

/// Client TLS config: system roots (or a CA file), optional client cert.
pub fn client_config(ca: Option<&Path>, client_cert: Option<(&Path, &Path)>, insecure: bool) -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    match ca {
        Some(p) => {
            for c in load_certs(p)? {
                roots.add(c)?;
            }
        }
        None => {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            if let Ok(native) = rustls_native_certs::load_native_certs().certs.into_iter().map(Ok::<_, anyhow::Error>).collect::<Result<Vec<_>>>() {
                for c in native {
                    let _ = roots.add(c);
                }
            }
        }
    }
    let builder = rustls::ClientConfig::builder();
    let builder = if insecure {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify)).into()
    } else {
        builder.with_root_certificates(roots)
    };
    let cfg = match client_cert {
        Some((c, k)) => builder.with_client_auth_cert(load_certs(c)?, load_key(k)?)?,
        None => builder.with_no_client_auth(),
    };
    Ok(Arc::new(cfg))
}

/// Certificate verifier that accepts anything (`tls` with no CA and
/// `insecure`); only for testing.
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// Install the ring crypto provider as the process default (idempotent).
pub fn init_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
