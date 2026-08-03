use std::net::SocketAddr;

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
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = tracing_subscriber::FmtSubscriber::new();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();
    match args.command {
        Command::Serve { addr, san } => {
            let app = App::build(addr, &san).await?;
            app.serve_https().await
        }
    }
}
