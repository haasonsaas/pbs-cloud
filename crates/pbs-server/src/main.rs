use std::sync::Arc;
use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use pbs_server::{ServerConfig, server::{ServerState, run_server}};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,pbs_server=debug".into()),
        )
        .init();

    tracing::info!("PBS Cloud Server v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration from environment or defaults
    let config = load_config()?;

    tracing::info!("Storage backend: {:?}", config.storage);
    tracing::info!("Listen address: {}", config.listen_addr);

    // Create server state
    let state = Arc::new(ServerState::from_config(config).await?);

    // Start the server
    run_server(state).await?;

    Ok(())
}

fn load_config() -> Result<ServerConfig> {
    let mut config = ServerConfig::default();

    // Override from environment variables
    if let Ok(addr) = std::env::var("PBS_LISTEN_ADDR") {
        config.listen_addr = addr;
    }

    if let Ok(bucket) = std::env::var("PBS_S3_BUCKET") {
        let region = std::env::var("PBS_S3_REGION").ok();
        let endpoint = std::env::var("PBS_S3_ENDPOINT").ok();
        let prefix = std::env::var("PBS_S3_PREFIX").ok();

        config.storage = pbs_server::config::StorageConfig::S3 {
            bucket,
            region,
            endpoint,
            prefix,
        };
    } else if let Ok(path) = std::env::var("PBS_DATA_DIR") {
        config.storage = pbs_server::config::StorageConfig::Local { path };
    }

    if let Ok(tenant) = std::env::var("PBS_DEFAULT_TENANT") {
        config.tenants.default_tenant = tenant;
    }

    Ok(config)
}
