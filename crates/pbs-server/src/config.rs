//! Server configuration

use serde::{Deserialize, Serialize};

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Listen address
    pub listen_addr: String,
    /// TLS certificate path
    pub tls_cert: Option<String>,
    /// TLS key path
    pub tls_key: Option<String>,
    /// Storage backend configuration
    pub storage: StorageConfig,
    /// Tenant configuration
    pub tenants: TenantsConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8007".to_string(),
            tls_cert: None,
            tls_key: None,
            storage: StorageConfig::default(),
            tenants: TenantsConfig::default(),
        }
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
