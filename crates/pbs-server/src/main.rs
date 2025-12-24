use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!("PBS Cloud Server starting...");

    // TODO: Load config
    // TODO: Initialize storage backend
    // TODO: Start HTTP/2 server

    tracing::info!("Server shutdown");
    Ok(())
}
