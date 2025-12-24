//! PBS-compatible HTTP/2 backup server
//!
//! This crate implements the PBS backup protocol over HTTP/2,
//! enabling compatibility with the stock proxmox-backup-client.
//!
//! ## Features
//!
//! - **HTTP/2 Streaming Protocol**: Full support for PBS backup/restore protocol
//! - **TLS/HTTPS**: Secure connections with rustls, including self-signed certs
//! - **Persistence**: Users, tokens, and tenants saved to disk
//! - **Rate Limiting**: Per-IP and per-tenant rate limiting
//! - **Prometheus Metrics**: Export metrics at /metrics endpoint
//! - **Multi-tenancy**: Full tenant isolation with quota support

pub mod api;
pub mod auth;
pub mod billing;
pub mod config;
pub mod metrics;
pub mod persistence;
pub mod protocol;
pub mod rate_limit;
pub mod server;
pub mod session;
pub mod streaming;
pub mod tenant;
pub mod tls;
pub mod validation;

pub use auth::{AuthContext, AuthManager, Permission, User, ApiToken};
pub use billing::{BillingManager, UsageEvent, UsageEventType, WebhookConfig};
pub use config::ServerConfig;
pub use metrics::{Metrics, MetricsConfig};
pub use persistence::{PersistenceConfig, PersistenceManager};
pub use rate_limit::{RateLimitConfig, RateLimiter_, RateLimitResult};
pub use session::{BackupSession, ReaderSession, SessionManager};
pub use streaming::{BackupProtocolHandler, ReaderProtocolHandler};
pub use tenant::{Tenant, TenantManager};
pub use tls::TlsConfig;
