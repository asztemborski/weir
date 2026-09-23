use std::sync::Arc;
use std::time::Duration;
use tokio::time;

use anyhow::Result;
use axum::Router;
use hyper_util::service::TowerToHyperService;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier};
use rustls_pki_types::PrivatePkcs8KeyDer;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::pki::CertificateAuthority;
use crate::routes;

const SHUTDODWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct AppContext {
    pub cert_auth: Arc<CertificateAuthority>,
}

pub struct App {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    router: Router,
}

impl App {
    pub fn new(
        listener: TcpListener,
        tls_config: ServerConfig,
        cert_auth: CertificateAuthority,
    ) -> Self {
        let app_context = AppContext {
            cert_auth: Arc::new(cert_auth),
        };

        Self {
            listener,
            acceptor: TlsAcceptor::from(Arc::new(tls_config)),
            router: routes::build_router(app_context),
        }
    }

    pub async fn serve_https(self, cancellation_token: CancellationToken) {
        let tracker = TaskTracker::new();

        loop {
            let acceptor = self.acceptor.clone();
            let router = self.router.clone();

            tokio::select! {
                () = cancellation_token.cancelled() => {
                    tracing::info!(info = "shutdown singnal received, stopping https server");
                    break;
                },
                Ok((conn, _)) = self.listener.accept() => {
                    tracker.spawn(handle_connection(conn, acceptor, router));
                },
            }
        }

        let _ = time::timeout(SHUTDODWN_TIMEOUT, tracker.wait()).await;
    }
}

pub fn build_tls_config(cert_auth: &CertificateAuthority) -> Result<ServerConfig> {
    let (server_cert, server_key) = cert_auth.issue_server_cert()?;

    let mut roots = RootCertStore::empty();
    roots.add(cert_auth.ca_cert_der().clone())?;

    let cert_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated()
        .build()?;

    let key_der = PrivatePkcs8KeyDer::from(server_key.serialize_der());
    let mut tls_config = ServerConfig::builder()
        .with_client_cert_verifier(cert_verifier)
        .with_single_cert(vec![server_cert.der().clone()], key_der.into())?;

    tls_config.alpn_protocols = vec!["h2".into(), "http/1.1".into()];

    Ok(tls_config)
}

async fn handle_connection(conn: TcpStream, acceptor: TlsAcceptor, app: Router) {
    let tls_stream = match acceptor.accept(conn).await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::warn!(warning = "tls handshake failed", %err);
            return;
        }
    };

    let svc = TowerToHyperService::new(app);
    if let Err(err) = Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(TokioIo::new(tls_stream), svc)
        .await
    {
        tracing::warn!(warning = "connection error", %err);
    }
}
