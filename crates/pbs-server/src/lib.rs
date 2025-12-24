//! PBS-compatible HTTP/2 backup server
//!
//! This crate implements the PBS backup protocol over HTTP/2,
//! enabling compatibility with the stock proxmox-backup-client.

pub mod api;
pub mod auth;
pub mod billing;
pub mod config;
pub mod protocol;
pub mod server;
pub mod session;
pub mod tenant;

pub use auth::{AuthContext, AuthManager, Permission, User, ApiToken};
pub use billing::{BillingManager, UsageEvent, UsageEventType, WebhookConfig};
pub use config::ServerConfig;
pub use session::{BackupSession, ReaderSession, SessionManager};
pub use tenant::{Tenant, TenantManager};
