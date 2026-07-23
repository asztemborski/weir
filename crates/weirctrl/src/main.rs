use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use tokio::net::TcpListener;

mod startup;

#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Serve { addr: SocketAddr },
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    match args.command {
        Command::Serve { addr } => {
            let listener = TcpListener::bind(addr).await.unwrap();
            startup::run_server(listener).await.unwrap();
        }
    }
}
