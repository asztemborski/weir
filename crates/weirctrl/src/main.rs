use std::net::SocketAddr;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::startup::Application;

mod pki;
mod startup;

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

        #[arg(short, long, env = "WEIRCTRL_NAME")]
        mesh_name: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = tracing_subscriber::FmtSubscriber::new();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();
    match args.command {
        Command::Serve { addr, mesh_name } => {
            let app = Application::build(addr, &mesh_name).await?;
            app.serve_https().await
        }
    }
}
