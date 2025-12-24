//! Audit logging for administrative operations
//!
//! Provides structured logging for security-relevant events including:
//! - User/token/tenant creation and deletion
//! - Authentication attempts
//! - Permission changes
//! - Administrative actions

use chrono::{DateTime, Utc};
use serde::Serialize;
use tracing::{info, warn};

/// Audit event types
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    // Authentication events
    AuthSuccess,
    AuthFailure,

    // User management
    UserCreated,
    UserDeleted,
    UserDeactivated,
    UserPermissionChanged,

    // Token management
    TokenCreated,
    TokenDeleted,
    TokenRevoked,

    // Tenant management
    TenantCreated,
    TenantDeleted,
    TenantDeactivated,
    TenantQuotaChanged,

    // Admin operations
    GcStarted,
    GcCompleted,
    PruneExecuted,

    // Backup operations
    BackupStarted,
    BackupCompleted,
    BackupFailed,
    RestoreStarted,
    RestoreCompleted,
}

/// Audit event details
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Event type
    pub event_type: AuditEventType,
    /// Actor (user who performed the action)
    pub actor: Option<String>,
    /// Actor's tenant ID
    pub actor_tenant: Option<String>,
    /// Target resource ID (user_id, token_id, tenant_id, etc.)
    pub target_id: Option<String>,
    /// Target resource type
    pub target_type: Option<String>,
    /// Additional details
    pub details: Option<String>,
    /// Client IP address
    pub client_ip: Option<String>,
    /// Success/failure
    pub success: bool,
}

impl AuditEvent {
    /// Create a new audit event
    pub fn new(event_type: AuditEventType) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type,
            actor: None,
            actor_tenant: None,
            target_id: None,
            target_type: None,
            details: None,
            client_ip: None,
            success: true,
        }
    }

    /// Set the actor
    pub fn actor(mut self, username: &str, tenant_id: &str) -> Self {
        self.actor = Some(username.to_string());
        self.actor_tenant = Some(tenant_id.to_string());
        self
    }

    /// Set the target
    pub fn target(mut self, target_type: &str, target_id: &str) -> Self {
        self.target_type = Some(target_type.to_string());
        self.target_id = Some(target_id.to_string());
        self
    }

    /// Set details
    pub fn details(mut self, details: &str) -> Self {
        self.details = Some(details.to_string());
        self
    }

    /// Set client IP
    pub fn client_ip(mut self, ip: &str) -> Self {
        self.client_ip = Some(ip.to_string());
        self
    }

    /// Mark as failed
    pub fn failed(mut self) -> Self {
        self.success = false;
        self
    }

    /// Log the event
    pub fn log(self) {
        let json = serde_json::to_string(&self).unwrap_or_else(|_| format!("{:?}", self));

        if self.success {
            info!(
                target: "audit",
                event_type = ?self.event_type,
                actor = ?self.actor,
                target_id = ?self.target_id,
                "AUDIT: {}", json
            );
        } else {
            warn!(
                target: "audit",
                event_type = ?self.event_type,
                actor = ?self.actor,
                target_id = ?self.target_id,
                "AUDIT_FAIL: {}", json
            );
        }
    }
}

/// Helper functions for common audit events
pub fn log_user_created(actor_username: &str, actor_tenant: &str, new_user_id: &str, new_username: &str) {
    AuditEvent::new(AuditEventType::UserCreated)
        .actor(actor_username, actor_tenant)
        .target("user", new_user_id)
        .details(&format!("Created user: {}", new_username))
        .log();
}

pub fn log_user_deleted(actor_username: &str, actor_tenant: &str, deleted_user_id: &str, deleted_username: &str) {
    AuditEvent::new(AuditEventType::UserDeleted)
        .actor(actor_username, actor_tenant)
        .target("user", deleted_user_id)
        .details(&format!("Deleted user: {}", deleted_username))
        .log();
}

pub fn log_token_created(actor_username: &str, actor_tenant: &str, token_id: &str, token_name: &str) {
    AuditEvent::new(AuditEventType::TokenCreated)
        .actor(actor_username, actor_tenant)
        .target("token", token_id)
        .details(&format!("Created token: {}", token_name))
        .log();
}

pub fn log_token_deleted(actor_username: &str, actor_tenant: &str, token_id: &str) {
    AuditEvent::new(AuditEventType::TokenDeleted)
        .actor(actor_username, actor_tenant)
        .target("token", token_id)
        .log();
}

pub fn log_tenant_created(actor_username: &str, actor_tenant: &str, new_tenant_id: &str, tenant_name: &str) {
    AuditEvent::new(AuditEventType::TenantCreated)
        .actor(actor_username, actor_tenant)
        .target("tenant", new_tenant_id)
        .details(&format!("Created tenant: {}", tenant_name))
        .log();
}

pub fn log_tenant_deleted(actor_username: &str, actor_tenant: &str, deleted_tenant_id: &str, tenant_name: &str) {
    AuditEvent::new(AuditEventType::TenantDeleted)
        .actor(actor_username, actor_tenant)
        .target("tenant", deleted_tenant_id)
        .details(&format!("Deleted tenant: {}", tenant_name))
        .log();
}

pub fn log_auth_success(username: &str, tenant_id: &str, client_ip: Option<&str>) {
    let mut event = AuditEvent::new(AuditEventType::AuthSuccess)
        .actor(username, tenant_id);

    if let Some(ip) = client_ip {
        event = event.client_ip(ip);
    }

    event.log();
}

pub fn log_auth_failure(username: Option<&str>, client_ip: Option<&str>, reason: &str) {
    let mut event = AuditEvent::new(AuditEventType::AuthFailure)
        .failed()
        .details(reason);

    if let Some(user) = username {
        event.actor = Some(user.to_string());
    }

    if let Some(ip) = client_ip {
        event = event.client_ip(ip);
    }

    event.log();
}

pub fn log_gc_started(actor_username: &str, actor_tenant: &str, dry_run: bool) {
    AuditEvent::new(AuditEventType::GcStarted)
        .actor(actor_username, actor_tenant)
        .details(&format!("dry_run={}", dry_run))
        .log();
}

pub fn log_gc_completed(actor_username: &str, actor_tenant: &str, chunks_deleted: u64, bytes_freed: u64) {
    AuditEvent::new(AuditEventType::GcCompleted)
        .actor(actor_username, actor_tenant)
        .details(&format!("chunks_deleted={}, bytes_freed={}", chunks_deleted, bytes_freed))
        .log();
}

pub fn log_prune_executed(actor_username: &str, actor_tenant: &str, snapshots_removed: usize) {
    AuditEvent::new(AuditEventType::PruneExecuted)
        .actor(actor_username, actor_tenant)
        .details(&format!("snapshots_removed={}", snapshots_removed))
        .log();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(AuditEventType::UserCreated)
            .actor("admin", "default")
            .target("user", "user-123")
            .details("Created new user");

        assert!(event.success);
        assert_eq!(event.actor, Some("admin".to_string()));
        assert_eq!(event.actor_tenant, Some("default".to_string()));
        assert_eq!(event.target_type, Some("user".to_string()));
        assert_eq!(event.target_id, Some("user-123".to_string()));
    }

    #[test]
    fn test_audit_event_failed() {
        let event = AuditEvent::new(AuditEventType::AuthFailure).failed();
        assert!(!event.success);
    }

    #[test]
    fn test_audit_event_serialization() {
        let event = AuditEvent::new(AuditEventType::TokenCreated)
            .actor("user", "tenant1")
            .target("token", "tok-abc");

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("token_created"));
        assert!(json.contains("user"));
        assert!(json.contains("tenant1"));
    }

    #[test]
    fn test_event_type_variants() {
        // Ensure all event types can be created
        let types = [
            AuditEventType::AuthSuccess,
            AuditEventType::AuthFailure,
            AuditEventType::UserCreated,
            AuditEventType::UserDeleted,
            AuditEventType::TokenCreated,
            AuditEventType::TenantCreated,
            AuditEventType::GcStarted,
            AuditEventType::BackupStarted,
        ];

        for event_type in types {
            let event = AuditEvent::new(event_type);
            assert!(event.success);
        }
    }
}
