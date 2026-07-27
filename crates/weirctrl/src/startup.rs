use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::{Router, extract::Request, routing::get};
use hyper::{body::Incoming, service};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier};
use rustls_pki_types::PrivatePkcs8KeyDer;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower_service::Service;

use crate::pki::CertificateAuthority;

pub struct Application {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    router: Router,
}

impl Application {
    pub async fn build(addr: SocketAddr, mesh_name: &str) -> Result<Self> {
        let ca = CertificateAuthority::generate(mesh_name)?;
        let (server_cert, server_key) = ca.issue_server_cert(&format!("{mesh_name}.ctrl"))?;

        let mut roots = RootCertStore::empty();
        roots.add(ca.ca_cert().der().clone())?;

        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .allow_unauthenticated()
            .build()?;

        let key_der = PrivatePkcs8KeyDer::from(server_key.serialize_der());
        let tls_config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![server_cert], key_der.into())?;

        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let listener = TcpListener::bind(addr).await?;

        Ok(Self {
            listener,
            acceptor,
            router: build_router(),
        })
    }

    pub async fn serve_https(self) -> ! {
        loop {
            let acceptor = self.acceptor.clone();
            let router = self.router.clone();

            let (tcp_stream, _) = match self.listener.accept().await {
                Ok(stream) => stream,
                Err(err) => {
                    tracing::error!("accepting tcp connection: {err}");
                    continue;
                }
            };

            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(tcp_stream).await {
                    Ok(stream) => stream,
                    Err(err) => {
                        tracing::error!("tls handshake failed: {err}");
                        return;
                    }
                };

                let svc =
                    service::service_fn(move |req: Request<Incoming>| router.clone().call(req));

                if let Err(err) = Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(TokioIo::new(tls_stream), svc)
                    .await
                {
                    tracing::error!("connection error: {err}");
                }
            });
        }
    }
}

fn build_router() -> Router {
    Router::new().route("/enroll", get(|| async { "hello world" }))
}
