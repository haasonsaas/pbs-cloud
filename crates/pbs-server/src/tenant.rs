//! Multi-tenant management
//!
//! Each tenant has isolated datastores and can be billed separately.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Tenant information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    /// Unique tenant ID
    pub id: String,
    /// Tenant name
    pub name: String,
    /// Creation time
    pub created_at: DateTime<Utc>,
    /// Whether the tenant is active
    pub active: bool,
    /// Quota in bytes (None = unlimited)
    pub quota_bytes: Option<u64>,
    /// Usage in bytes
    pub used_bytes: u64,
    /// Custom metadata
    pub metadata: HashMap<String, String>,
}

impl Tenant {
    /// Create a new tenant
    pub fn new(name: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            created_at: Utc::now(),
            active: true,
            quota_bytes: None,
            used_bytes: 0,
            metadata: HashMap::new(),
        }
    }

    /// Check if tenant is over quota
    pub fn is_over_quota(&self) -> bool {
        match self.quota_bytes {
            Some(quota) => self.used_bytes >= quota,
            None => false,
        }
    }

    /// Get remaining quota
    pub fn remaining_quota(&self) -> Option<u64> {
        self.quota_bytes.map(|q| q.saturating_sub(self.used_bytes))
    }
}

/// Usage record for billing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecord {
    /// Tenant ID
    pub tenant_id: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Storage used (bytes)
    pub storage_bytes: u64,
    /// Egress (bytes downloaded)
    pub egress_bytes: u64,
    /// API requests
    pub api_requests: u64,
}

/// Tenant manager
pub struct TenantManager {
    tenants: RwLock<HashMap<String, Tenant>>,
}

impl TenantManager {
    /// Create a new tenant manager
    pub fn new() -> Self {
        Self {
            tenants: RwLock::new(HashMap::new()),
        }
    }

    /// Create a tenant
    pub async fn create_tenant(&self, name: &str) -> Tenant {
        let tenant = Tenant::new(name);
        let mut tenants = self.tenants.write().await;
        tenants.insert(tenant.id.clone(), tenant.clone());
        tenant
    }

    /// Get a tenant by ID
    pub async fn get_tenant(&self, id: &str) -> Option<Tenant> {
        let tenants = self.tenants.read().await;
        tenants.get(id).cloned()
    }

    /// List all tenants
    pub async fn list_tenants(&self) -> Vec<Tenant> {
        let tenants = self.tenants.read().await;
        tenants.values().cloned().collect()
    }

    /// Update tenant usage
    pub async fn update_usage(&self, tenant_id: &str, bytes: i64) -> Option<Tenant> {
        let mut tenants = self.tenants.write().await;
        if let Some(tenant) = tenants.get_mut(tenant_id) {
            if bytes >= 0 {
                tenant.used_bytes = tenant.used_bytes.saturating_add(bytes as u64);
            } else {
                tenant.used_bytes = tenant.used_bytes.saturating_sub((-bytes) as u64);
            }
            return Some(tenant.clone());
        }
        None
    }

    /// Set tenant quota
    pub async fn set_quota(&self, tenant_id: &str, quota: Option<u64>) -> Option<Tenant> {
        let mut tenants = self.tenants.write().await;
        if let Some(tenant) = tenants.get_mut(tenant_id) {
            tenant.quota_bytes = quota;
            return Some(tenant.clone());
        }
        None
    }

    /// Deactivate a tenant
    pub async fn deactivate_tenant(&self, tenant_id: &str) -> Option<Tenant> {
        let mut tenants = self.tenants.write().await;
        if let Some(tenant) = tenants.get_mut(tenant_id) {
            tenant.active = false;
            return Some(tenant.clone());
        }
        None
    }

    /// Delete a tenant permanently
    /// Returns the deleted tenant if found
    pub async fn delete_tenant(&self, tenant_id: &str) -> Option<Tenant> {
        let mut tenants = self.tenants.write().await;
        tenants.remove(tenant_id)
    }
}

impl Default for TenantManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TenantManager {
    /// Restore a tenant from persistence (for loading from disk)
    pub async fn restore_tenant(&self, tenant: Tenant) {
        let mut tenants = self.tenants.write().await;
        tenants.insert(tenant.id.clone(), tenant);
    }

    /// Get the number of tenants
    pub async fn tenant_count(&self) -> usize {
        self.tenants.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tenant_lifecycle() {
        let manager = TenantManager::new();

        // Create tenant
        let tenant = manager.create_tenant("Test Tenant").await;
        assert!(tenant.active);
        assert_eq!(tenant.used_bytes, 0);

        // Get tenant
        let fetched = manager.get_tenant(&tenant.id).await.unwrap();
        assert_eq!(fetched.name, "Test Tenant");

        // Update usage
        manager.update_usage(&tenant.id, 1000).await;
        let updated = manager.get_tenant(&tenant.id).await.unwrap();
        assert_eq!(updated.used_bytes, 1000);

        // Set quota
        manager.set_quota(&tenant.id, Some(2000)).await;
        let with_quota = manager.get_tenant(&tenant.id).await.unwrap();
        assert_eq!(with_quota.remaining_quota(), Some(1000));
        assert!(!with_quota.is_over_quota());
    }

    #[tokio::test]
    async fn test_quota_enforcement() {
        let manager = TenantManager::new();

        // Create tenant with quota
        let tenant = manager.create_tenant("Quota Test").await;
        manager.set_quota(&tenant.id, Some(1000)).await;

        // Initially not over quota
        let t = manager.get_tenant(&tenant.id).await.unwrap();
        assert!(!t.is_over_quota());
        assert_eq!(t.remaining_quota(), Some(1000));

        // Update usage to exactly quota
        manager.update_usage(&tenant.id, 1000).await;
        let t = manager.get_tenant(&tenant.id).await.unwrap();
        assert!(t.is_over_quota());
        assert_eq!(t.remaining_quota(), Some(0));

        // Unlimited quota (None) is never over quota
        let unlimited = manager.create_tenant("Unlimited").await;
        manager.update_usage(&unlimited.id, 999999999).await;
        let u = manager.get_tenant(&unlimited.id).await.unwrap();
        assert!(!u.is_over_quota());
        assert_eq!(u.remaining_quota(), None);
    }
}
