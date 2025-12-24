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
    /// Additional datastores (besides default)
    #[serde(default)]
    pub datastores: Vec<String>,
    /// Garbage collection configuration
    #[serde(default)]
    pub gc: GcConfig,
    /// Verification scheduling configuration
    #[serde(default)]
    pub verify: VerifyConfig,
    /// WORM/immutability configuration
    #[serde(default)]
    pub worm: WormConfig,
    /// Task tracking configuration
    #[serde(default)]
    pub tasks: TaskConfig,
    /// Shared secret for inbound webhook verification
    pub webhook_receiver_secret: Option<String>,
    /// Optional encryption key (hex, 32 bytes)
    pub encryption_key: Option<String>,
    /// Expose Prometheus metrics without auth
    #[serde(default)]
    pub metrics_public: bool,
    /// Serve the root status dashboard
    #[serde(default)]
    pub dashboard_enabled: bool,
    /// Print the root token to logs on first boot
    #[serde(default = "default_print_root_token")]
    pub print_root_token: bool,
    /// Optional file to write the initial root token to
    pub root_token_file: Option<String>,
}

fn default_print_root_token() -> bool {
    true
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
            datastores: Vec::new(),
            gc: GcConfig::default(),
            verify: VerifyConfig::default(),
            worm: WormConfig::default(),
            tasks: TaskConfig::default(),
            webhook_receiver_secret: None,
            encryption_key: None,
            metrics_public: false,
            dashboard_enabled: false,
            print_root_token: true,
            root_token_file: None,
        }
    }
}

impl ServerConfig {
    /// Create config with local storage
    pub fn local(path: &str) -> Self {
        Self {
            storage: StorageConfig::Local {
                path: path.to_string(),
            },
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

/// Verification scheduling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyConfig {
    /// Enable scheduled verification runs (runs every verify_interval_hours)
    pub enabled: bool,
    /// Interval in hours between automatic verification runs
    pub interval_hours: u64,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_hours: 24,
        }
    }
}

/// WORM/immutability configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WormConfig {
    /// Enable WORM protection
    pub enabled: bool,
    /// Default retention days (if enabled)
    pub default_retention_days: Option<u64>,
    /// Allow per-backup override
    pub allow_override: bool,
}

/// Task tracking configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskConfig {
    /// Maximum number of log lines stored per task
    pub log_max_lines: usize,
}

impl Default for TaskConfig {
    fn default() -> Self {
        Self {
            log_max_lines: 1000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert_eq!(config.listen_addr, "0.0.0.0:8007");
        assert!(config.tls.is_some());
        assert!(config.rate_limit.is_some());
        assert!(!config.metrics_public);
        assert!(!config.dashboard_enabled);
        assert!(config.print_root_token);
    }

    #[test]
    fn test_local_config() {
        let config = ServerConfig::local("/data/backups");
        assert!(matches!(config.storage, StorageConfig::Local { path } if path == "/data/backups"));
    }

    #[test]
    fn test_s3_config() {
        let config = ServerConfig::s3("my-bucket", "us-west-2");
        match &config.storage {
            StorageConfig::S3 { bucket, region, .. } => {
                assert_eq!(bucket, "my-bucket");
                assert_eq!(region, &Some("us-west-2".to_string()));
            }
            _ => panic!("Expected S3 storage config"),
        }
    }

    #[test]
    fn test_config_builders() {
        let config = ServerConfig::default()
            .with_data_dir("/var/data")
            .without_tls()
            .without_rate_limit();

        assert_eq!(config.data_dir, Some("/var/data".to_string()));
    }

    #[test]
    fn test_gc_config_default() {
        let gc = GcConfig::default();
        assert!(gc.enabled);
        assert_eq!(gc.interval_hours, 24);
    }

    #[test]
    fn test_verify_config_default() {
        let verify = VerifyConfig::default();
        assert!(!verify.enabled);
        assert_eq!(verify.interval_hours, 24);
    }

    #[test]
    fn test_tenants_config_default() {
        let tenants = TenantsConfig::default();
        assert!(!tenants.enabled);
        assert_eq!(tenants.default_tenant, "default");
    }

    #[test]
    fn test_tasks_config_default() {
        let tasks = TaskConfig::default();
        assert_eq!(tasks.log_max_lines, 1000);
    }

    #[test]
    fn test_storage_config_serialization() {
        let local = StorageConfig::Local {
            path: "/data".to_string(),
        };
        let json = serde_json::to_string(&local).unwrap();
        assert!(json.contains("local"));
        assert!(json.contains("/data"));

        let s3 = StorageConfig::S3 {
            bucket: "test".to_string(),
            region: Some("us-east-1".to_string()),
            endpoint: None,
            prefix: None,
        };
        let json = serde_json::to_string(&s3).unwrap();
        assert!(json.contains("s3"));
        assert!(json.contains("test"));
    }
}
