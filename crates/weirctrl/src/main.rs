use std::{net::SocketAddr, path::PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::app::App;

mod app;
mod pki;
mod routes;

#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Serve {
        #[arg(short, long, env = "WEIRCTRL_ADDR")]
        addr: SocketAddr,

        #[arg(short, long, env = "WEIRCTRL_SAN")]
        san: String,

        #[arg(short, long, env = "WEIRCTRL_CERT_DIR")]
        cert_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = tracing_subscriber::FmtSubscriber::new();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();
    match args.command {
        Command::Serve {
            addr,
            san,
            cert_dir,
        } => {
            let app = App::build(addr, &cert_dir, &san).await?;
            app.serve_https().await
        }
    }
}
