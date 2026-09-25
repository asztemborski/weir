use std::{net::SocketAddr, path::PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tokio::signal;
use tokio_util::sync::CancellationToken;

use crate::{app::App, pki::CertificateAuthority};

mod app;
mod pki;
mod routes;

#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    CertGen {
        #[arg(short, long, env = "WEIRCTRL_SAN")]
        san: String,

        #[arg(short, long, env = "WEIRCTRL_CERT_DIR")]
        cert_dir: PathBuf,
    },

    Serve {
        #[arg(short, long, env = "WEIRCTRL_ADDR")]
        addr: SocketAddr,

        #[arg(short, long, env = "WEIRCTRL_CERT_DIR")]
        cert_dir: PathBuf,
    },
}

async fn wait_for_shutdown_signal(cancellation_token: CancellationToken) {
    if let Err(err) = signal::ctrl_c().await {
        tracing::warn!(warning = "failed to listen for ctrl_c signal", %err);
        return;
    }
    cancellation_token.cancel();
}

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = tracing_subscriber::FmtSubscriber::new();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();
    match args.command {
        Command::CertGen { san, cert_dir } => {
            CertificateAuthority::generate_and_save(&cert_dir, &san).await?;
        }

        Command::Serve { addr, cert_dir } => {
            let cancellation_token = CancellationToken::new();
            tokio::spawn(wait_for_shutdown_signal(cancellation_token.clone()));

            let cert_auth = CertificateAuthority::from_cert_dir(&cert_dir).await?;

            let tls_config = app::build_tls_config(&cert_auth)?;
            let listener = TcpListener::bind(addr).await?;

            let app = App::new(listener, tls_config, cert_auth);
            app.serve_https(cancellation_token).await;
        }
    }
    Ok(())
}
