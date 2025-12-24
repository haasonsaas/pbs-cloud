//! Server configuration

use serde::{Deserialize, Serialize};

use crate::rate_limit::RateLimitConfig;
use crate::tls::TlsConfig;

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Listen address
    pub listen_addr: String,
    /// Data directory for persistence
    pub data_dir: Option<String>,
    /// TLS configuration
    #[serde(skip)]
    pub tls: Option<TlsConfig>,
    /// Rate limiting configuration
    #[serde(skip)]
    pub rate_limit: Option<RateLimitConfig>,
    /// Storage backend configuration
    pub storage: StorageConfig,
    /// Tenant configuration
    pub tenants: TenantsConfig,
    /// Garbage collection configuration
    #[serde(default)]
    pub gc: GcConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8007".to_string(),
            data_dir: None,
            tls: Some(TlsConfig::self_signed()),
            rate_limit: Some(RateLimitConfig::default()),
            storage: StorageConfig::default(),
            tenants: TenantsConfig::default(),
            gc: GcConfig::default(),
        }
    }
}

impl ServerConfig {
    /// Create config with local storage
    pub fn local(path: &str) -> Self {
        Self {
            storage: StorageConfig::Local { path: path.to_string() },
            ..Default::default()
        }
    }

    /// Create config with S3 storage
    pub fn s3(bucket: &str, region: &str) -> Self {
        Self {
            storage: StorageConfig::S3 {
                bucket: bucket.to_string(),
                region: Some(region.to_string()),
                endpoint: None,
                prefix: None,
            },
            ..Default::default()
        }
    }

    /// Set data directory for persistence
    pub fn with_data_dir(mut self, path: &str) -> Self {
        self.data_dir = Some(path.to_string());
        self
    }

    /// Disable TLS (for development)
    pub fn without_tls(mut self) -> Self {
        self.tls = Some(TlsConfig::disabled());
        self
    }

    /// Set TLS certificate paths
    pub fn with_tls(mut self, cert_path: &str, key_path: &str) -> Self {
        self.tls = Some(TlsConfig::with_certs(cert_path, key_path));
        self
    }

    /// Disable rate limiting
    pub fn without_rate_limit(mut self) -> Self {
        self.rate_limit = Some(RateLimitConfig::disabled());
        self
    }
}

/// Storage backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum StorageConfig {
    /// Local filesystem
    #[serde(rename = "local")]
    Local { path: String },
    /// S3-compatible storage
    #[serde(rename = "s3")]
    S3 {
        bucket: String,
        region: Option<String>,
        endpoint: Option<String>,
        prefix: Option<String>,
    },
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self::Local {
            path: "/var/lib/pbs-cloud".to_string(),
        }
    }
}

/// Multi-tenant configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantsConfig {
    /// Enable multi-tenancy
    pub enabled: bool,
    /// Default tenant ID for single-tenant mode
    pub default_tenant: String,
}

impl Default for TenantsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_tenant: "default".to_string(),
        }
    }
}

/// Garbage collection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcConfig {
    /// Enable scheduled GC (runs every gc_interval_hours)
    pub enabled: bool,
    /// Interval in hours between automatic GC runs
    pub interval_hours: u64,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_hours: 24, // Run GC once per day by default
        }
    }
}
