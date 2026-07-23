use anyhow::{Ok, Result};
use axum::{Router, routing::get};
use tokio::net::TcpListener;

pub async fn run_server(listener: TcpListener) -> Result<()> {
    let app = Router::new().route("/", get(|| async { "hello world" }));

    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
