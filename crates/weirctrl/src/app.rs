use std::sync::Arc;
use std::{net::SocketAddr, path::Path};

use anyhow::Result;
use axum::{Router, extract::Request};
use hyper::{body::Incoming, service};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier};
use rustls_pki_types::PrivatePkcs8KeyDer;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tower_service::Service;

use crate::{pki::CertificateAuthority, routes};

#[derive(Clone)]
pub struct AppContext {
    pub ca: Arc<CertificateAuthority>,
}

pub struct App {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    router: Router,
}

impl App {
    pub async fn build(addr: SocketAddr, cert_path: &Path, san: &str) -> Result<Self> {
        let ca = CertificateAuthority::init(cert_path, san).await?;
        let (server_cert, server_key) = ca.issue_server_cert(san)?;

        let mut roots = RootCertStore::empty();
        roots.add(ca.ca_cert_der().clone())?;

        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .allow_unauthenticated()
            .build()?;

        let key_der = PrivatePkcs8KeyDer::from(server_key.serialize_der());
        let mut tls_config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![server_cert.der().clone()], key_der.into())?;

        tls_config.alpn_protocols = vec!["h2".into(), "http/1.1".into()];

        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let listener = TcpListener::bind(addr).await?;
        let app_context = AppContext { ca: Arc::new(ca) };

        Ok(Self {
            listener,
            acceptor,
            router: routes::build_router(app_context),
        })
    }

    pub async fn serve_https(self) -> ! {
        loop {
            let acceptor = self.acceptor.clone();
            let router = self.router.clone();

            let (conn, _) = match self.listener.accept().await {
                Ok(stream) => stream,
                Err(err) => {
                    tracing::error!("accepting tcp connection: {err}");
                    continue;
                }
            };

            tokio::spawn(handle_connection(conn, acceptor, router));
        }
    }
}

async fn handle_connection(conn: TcpStream, acceptor: TlsAcceptor, app: Router) {
    let tls_stream = match acceptor.accept(conn).await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::error!("tls handshake failed: {err}");
            return;
        }
    };

    let svc = service::service_fn(move |req: Request<Incoming>| app.clone().call(req));

    if let Err(err) = Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(TokioIo::new(tls_stream), svc)
        .await
    {
        tracing::error!("connection error: {err}");
    }
}
