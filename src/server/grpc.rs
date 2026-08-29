//! DNS over gRPC: the `coredns.dns.DnsService/Query` service CoreDNS
//! speaks (server side here; the `grpc` plugin is the client).

use super::Server;
use crate::plugin::Proto;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

pub mod pb {
    tonic::include_proto!("coredns.dns");
}

use pb::dns_service_server::{DnsService, DnsServiceServer};
use pb::DnsPacket;

pub struct GrpcDns {
    srv: Arc<Server>,
}

#[tonic::async_trait]
impl DnsService for GrpcDns {
    async fn query(&self, request: Request<DnsPacket>) -> Result<Response<DnsPacket>, Status> {
        let remote = request.remote_addr().unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
        let local = request.local_addr().unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
        let msg = request.into_inner().msg;
        match self.srv.serve_bytes(&msg, remote, local, Proto::Grpc, None, None).await {
            Some(resp) => Ok(Response::new(DnsPacket { msg: resp })),
            None => Err(Status::invalid_argument("malformed DNS message")),
        }
    }
}

pub async fn run_grpc(srv: Arc<Server>, listener: TcpListener, cancel: CancellationToken) {
    let acceptor = srv.tls.clone().map(TlsAcceptor::from);
    if acceptor.is_none() {
        tracing::warn!("{}: no tls plugin configured, serving plaintext gRPC", srv.label);
    }
    let service = DnsServiceServer::new(GrpcDns { srv: srv.clone() });
    let label = srv.label.clone();
    match acceptor {
        None => {
            let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
            let shutdown = cancel.clone();
            if let Err(e) = tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(incoming, async move { shutdown.cancelled().await })
                .await
            {
                tracing::error!("{}: grpc server: {}", label, e);
            }
        }
        Some(acc) => {
            // accept + TLS-wrap ourselves so the rustls config from the tls
            // plugin (client auth etc.) is honoured
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, std::io::Error>>(64);
            let accept_cancel = cancel.clone();
            let accept_label = label.clone();
            tokio::spawn(async move {
                loop {
                    let (stream, remote) = tokio::select! {
                        _ = accept_cancel.cancelled() => return,
                        r = listener.accept() => match r {
                            Ok(v) => v,
                            Err(e) => { tracing::debug!("{}: grpc accept: {}", accept_label, e); continue; }
                        },
                    };
                    let acc = acc.clone();
                    let tx = tx.clone();
                    let l = accept_label.clone();
                    tokio::spawn(async move {
                        let _ = stream.set_nodelay(true);
                        match acc.accept(stream).await {
                            Ok(tls) => {
                                let _ = tx.send(Ok(tls)).await;
                            }
                            Err(e) => tracing::debug!("{}: grpc tls handshake from {}: {}", l, remote, e),
                        }
                    });
                }
            });
            let incoming = tokio_stream::wrappers::ReceiverStream::new(rx);
            let shutdown = cancel.clone();
            if let Err(e) = tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(incoming, async move { shutdown.cancelled().await })
                .await
            {
                tracing::error!("{}: grpc server: {}", label, e);
            }
        }
    }
}
