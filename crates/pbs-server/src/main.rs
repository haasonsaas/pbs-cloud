use anyhow::Result;
use std::sync::Arc;
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use pbs_server::{
    server::{run_server, ServerState},
    ServerConfig,
};

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

    // Start the server with graceful shutdown
    let state_for_shutdown = state.clone();
    tokio::select! {
        result = run_server(state) => {
            if let Err(e) = result {
                tracing::error!("Server error: {}", e);
            }
        }
        _ = shutdown_signal() => {
            tracing::info!("Shutdown signal received, saving state...");
            if let Err(e) = state_for_shutdown.save_state().await {
                tracing::error!("Failed to save state on shutdown: {}", e);
            }
            tracing::info!("Shutdown complete");
        }
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

fn load_config() -> Result<ServerConfig> {
    let mut config = ServerConfig::default();

    // Override from environment variables
    if let Ok(addr) = std::env::var("PBS_LISTEN_ADDR") {
        config.listen_addr = addr;
    }

    // Storage configuration
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
        config.storage = pbs_server::config::StorageConfig::Local { path: path.clone() };
        // Also use as persistence directory if not set separately
        if config.data_dir.is_none() {
            config.data_dir = Some(path);
        }
    }

    // Persistence directory (can be separate from storage)
    if let Ok(dir) = std::env::var("PBS_PERSISTENCE_DIR") {
        config.data_dir = Some(dir);
    }

    // Tenant configuration
    if let Ok(tenant) = std::env::var("PBS_DEFAULT_TENANT") {
        config.tenants.default_tenant = tenant;
    }

    // TLS configuration
    if std::env::var("PBS_TLS_DISABLED").is_ok() {
        config.tls = Some(pbs_server::tls::TlsConfig::disabled());
    } else if let (Ok(cert), Ok(key)) =
        (std::env::var("PBS_TLS_CERT"), std::env::var("PBS_TLS_KEY"))
    {
        config.tls = Some(pbs_server::tls::TlsConfig::with_certs(&cert, &key));
    }

    // GC configuration
    if std::env::var("PBS_GC_DISABLED").is_ok() {
        config.gc.enabled = false;
    }
    if let Ok(hours) = std::env::var("PBS_GC_INTERVAL_HOURS") {
        if let Ok(h) = hours.parse::<u64>() {
            config.gc.interval_hours = h;
        }
    }

    // WORM configuration
    if let Ok(enabled) = std::env::var("PBS_WORM_ENABLED") {
        config.worm.enabled = enabled == "1" || enabled.eq_ignore_ascii_case("true");
    }

    if let Ok(days) = std::env::var("PBS_WORM_RETENTION_DAYS") {
        config.worm.enabled = true;
        config.worm.default_retention_days = Some(days.parse()?);
    }

    if let Ok(allow) = std::env::var("PBS_WORM_ALLOW_OVERRIDE") {
        config.worm.allow_override = allow == "1" || allow.eq_ignore_ascii_case("true");
    }

    if let Ok(secret) = std::env::var("PBS_WEBHOOK_RECEIVER_SECRET") {
        if !secret.is_empty() {
            config.webhook_receiver_secret = Some(secret);
        }
    }

    if let Ok(key) = std::env::var("PBS_ENCRYPTION_KEY") {
        if !key.is_empty() {
            config.encryption_key = Some(key);
        }
    }

    if let Ok(path) = std::env::var("PBS_ENCRYPTION_KEY_FILE") {
        if !path.is_empty() {
            let key = std::fs::read_to_string(&path)?;
            let key = key.trim().to_string();
            if !key.is_empty() {
                config.encryption_key = Some(key);
            }
        }
    }

    Ok(config)
}
