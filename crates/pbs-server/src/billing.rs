//! Billing integration
//!
//! Tracks usage and sends events to billing systems via webhooks.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, instrument, warn};

/// Usage event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageEventType {
    /// Backup created
    BackupCreated,
    /// Backup deleted
    BackupDeleted,
    /// Data restored
    DataRestored,
    /// Storage usage updated
    StorageUpdated,
    /// API request
    ApiRequest,
}

/// A usage event for billing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageEvent {
    /// Event ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Event type
    pub event_type: UsageEventType,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Bytes involved (uploaded, downloaded, stored)
    pub bytes: u64,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl UsageEvent {
    /// Create a new usage event
    pub fn new(tenant_id: &str, event_type: UsageEventType, bytes: u64) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            event_type,
            timestamp: Utc::now(),
            bytes,
            metadata: HashMap::new(),
        }
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL
    pub url: String,
    /// Secret for signing requests (HMAC-SHA256)
    pub secret: Option<String>,
    /// Custom headers
    pub headers: HashMap<String, String>,
    /// Retry count
    pub max_retries: u32,
    /// Events to send (None = all)
    pub event_filter: Option<Vec<UsageEventType>>,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            secret: None,
            headers: HashMap::new(),
            max_retries: 3,
            event_filter: None,
        }
    }
}

/// Usage statistics for a tenant
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TenantUsage {
    /// Total storage used (bytes)
    pub storage_bytes: u64,
    /// Total data uploaded (bytes)
    pub upload_bytes: u64,
    /// Total data downloaded (bytes)
    pub download_bytes: u64,
    /// Number of backups
    pub backup_count: u64,
    /// Number of API requests
    pub api_requests: u64,
    /// Last updated
    pub updated_at: Option<DateTime<Utc>>,
}

/// Billing manager
pub struct BillingManager {
    /// Tenant usage stats
    usage: RwLock<HashMap<String, TenantUsage>>,
    /// Webhook configurations
    webhooks: RwLock<Vec<WebhookConfig>>,
    /// Event queue sender
    event_tx: mpsc::Sender<UsageEvent>,
    /// HTTP client for webhooks
    client: reqwest::Client,
}

impl BillingManager {
    /// Create a new billing manager
    pub fn new() -> (Self, mpsc::Receiver<UsageEvent>) {
        let (event_tx, event_rx) = mpsc::channel(1000);

        let manager = Self {
            usage: RwLock::new(HashMap::new()),
            webhooks: RwLock::new(Vec::new()),
            event_tx,
            client: reqwest::Client::new(),
        };

        (manager, event_rx)
    }

    /// Add a webhook
    pub async fn add_webhook(&self, config: WebhookConfig) {
        let mut webhooks = self.webhooks.write().await;
        webhooks.push(config);
    }

    /// Remove webhooks for a URL
    pub async fn remove_webhook(&self, url: &str) {
        let mut webhooks = self.webhooks.write().await;
        webhooks.retain(|w| w.url != url);
    }

    /// List webhooks
    pub async fn list_webhooks(&self) -> Vec<WebhookConfig> {
        let webhooks = self.webhooks.read().await;
        webhooks.clone()
    }

    /// Record a usage event
    #[instrument(skip(self))]
    pub async fn record_event(&self, event: UsageEvent) {
        // Update local usage stats
        {
            let mut usage = self.usage.write().await;
            let tenant_usage = usage.entry(event.tenant_id.clone()).or_default();

            match event.event_type {
                UsageEventType::BackupCreated => {
                    tenant_usage.upload_bytes += event.bytes;
                    tenant_usage.backup_count += 1;
                }
                UsageEventType::BackupDeleted => {
                    tenant_usage.backup_count = tenant_usage.backup_count.saturating_sub(1);
                }
                UsageEventType::DataRestored => {
                    tenant_usage.download_bytes += event.bytes;
                }
                UsageEventType::StorageUpdated => {
                    tenant_usage.storage_bytes = event.bytes;
                }
                UsageEventType::ApiRequest => {
                    tenant_usage.api_requests += 1;
                }
            }

            tenant_usage.updated_at = Some(Utc::now());
        }

        // Queue event for webhook delivery
        if let Err(e) = self.event_tx.send(event.clone()).await {
            warn!("Failed to queue usage event: {}", e);
        }
    }

    /// Run the webhook dispatcher loop
    pub async fn run_dispatcher(self: Arc<Self>, mut rx: mpsc::Receiver<UsageEvent>) {
        while let Some(event) = rx.recv().await {
            self.dispatch_webhooks(&event).await;
        }
    }

    /// Get usage for a tenant
    pub async fn get_usage(&self, tenant_id: &str) -> Option<TenantUsage> {
        let usage = self.usage.read().await;
        usage.get(tenant_id).cloned()
    }

    /// Get all tenant usage
    pub async fn get_all_usage(&self) -> HashMap<String, TenantUsage> {
        let usage = self.usage.read().await;
        usage.clone()
    }

    /// Dispatch event to webhooks
    async fn dispatch_webhooks(&self, event: &UsageEvent) {
        let webhooks = self.webhooks.read().await;

        for webhook in webhooks.iter() {
            // Check event filter
            if let Some(filter) = &webhook.event_filter {
                if !filter.contains(&event.event_type) {
                    continue;
                }
            }

            // Send with retries
            for attempt in 0..=webhook.max_retries {
                match self.send_webhook(webhook, event).await {
                    Ok(()) => {
                        info!("Webhook delivered to {}", webhook.url);
                        break;
                    }
                    Err(e) => {
                        if attempt < webhook.max_retries {
                            warn!(
                                "Webhook to {} failed (attempt {}/{}): {}",
                                webhook.url,
                                attempt + 1,
                                webhook.max_retries,
                                e
                            );
                            tokio::time::sleep(tokio::time::Duration::from_millis(
                                100 * 2u64.pow(attempt),
                            ))
                            .await;
                        } else {
                            error!(
                                "Webhook to {} failed after {} attempts: {}",
                                webhook.url,
                                webhook.max_retries + 1,
                                e
                            );
                        }
                    }
                }
            }
        }
    }

    /// Send a webhook request
    async fn send_webhook(&self, config: &WebhookConfig, event: &UsageEvent) -> Result<(), String> {
        let payload = serde_json::to_string(event).map_err(|e| e.to_string())?;

        let mut request = self
            .client
            .post(&config.url)
            .header("Content-Type", "application/json")
            .body(payload.clone());

        // Add custom headers
        for (key, value) in &config.headers {
            request = request.header(key, value);
        }

        // Add signature if secret is configured
        if let Some(secret) = &config.secret {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;

            type HmacSha256 = Hmac<Sha256>;

            let mut mac =
                HmacSha256::new_from_slice(secret.as_bytes()).map_err(|e| e.to_string())?;
            mac.update(payload.as_bytes());
            let signature = hex::encode(mac.finalize().into_bytes());

            request = request.header("X-Signature-256", format!("sha256={}", signature));
        }

        let response = request
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("HTTP {}", response.status()))
        }
    }

    /// Generate usage report for a time period
    pub async fn generate_report(
        &self,
        tenant_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> UsageReport {
        let usage = self.get_usage(tenant_id).await.unwrap_or_default();

        UsageReport {
            tenant_id: tenant_id.to_string(),
            period_start: start,
            period_end: end,
            storage_bytes: usage.storage_bytes,
            upload_bytes: usage.upload_bytes,
            download_bytes: usage.download_bytes,
            backup_count: usage.backup_count,
            api_requests: usage.api_requests,
        }
    }
}

impl Default for BillingManager {
    fn default() -> Self {
        Self::new().0
    }
}

/// Usage report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageReport {
    /// Tenant ID
    pub tenant_id: String,
    /// Period start
    pub period_start: DateTime<Utc>,
    /// Period end
    pub period_end: DateTime<Utc>,
    /// Storage bytes (average or peak)
    pub storage_bytes: u64,
    /// Upload bytes
    pub upload_bytes: u64,
    /// Download bytes
    pub download_bytes: u64,
    /// Backup count
    pub backup_count: u64,
    /// API requests
    pub api_requests: u64,
}

impl UsageReport {
    /// Calculate estimated cost for the report period (storage prorated by time)
    pub fn estimate_cost(&self, rates: &BillingRates) -> f64 {
        let storage_gb = self.storage_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        let egress_gb = self.download_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        let period_secs = (self.period_end - self.period_start).num_seconds().max(0) as f64;
        let month_secs = 30.0 * 24.0 * 3600.0;
        let month_fraction = if month_secs > 0.0 {
            period_secs / month_secs
        } else {
            0.0
        };

        storage_gb * rates.storage_per_gb * month_fraction
            + egress_gb * rates.egress_per_gb
            + (self.api_requests as f64 / 1000.0) * rates.api_per_1k
    }
}

/// Billing rates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingRates {
    /// Cost per GB of storage per month
    pub storage_per_gb: f64,
    /// Cost per GB of egress
    pub egress_per_gb: f64,
    /// Cost per 1000 API requests
    pub api_per_1k: f64,
}

impl Default for BillingRates {
    fn default() -> Self {
        Self {
            storage_per_gb: 0.02, // $0.02/GB/month (like S3)
            egress_per_gb: 0.09,  // $0.09/GB egress
            api_per_1k: 0.004,    // $0.004 per 1000 requests
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_usage_tracking() {
        let (manager, _rx) = BillingManager::new();

        let event = UsageEvent::new("tenant1", UsageEventType::BackupCreated, 1024 * 1024);
        manager.record_event(event).await;

        let usage = manager.get_usage("tenant1").await.unwrap();
        assert_eq!(usage.upload_bytes, 1024 * 1024);
        assert_eq!(usage.backup_count, 1);
    }

    #[tokio::test]
    async fn test_usage_report() {
        let (manager, _rx) = BillingManager::new();

        // Record some events
        manager
            .record_event(UsageEvent::new(
                "tenant1",
                UsageEventType::BackupCreated,
                10 * 1024 * 1024 * 1024,
            ))
            .await;
        manager
            .record_event(UsageEvent::new(
                "tenant1",
                UsageEventType::StorageUpdated,
                10 * 1024 * 1024 * 1024,
            ))
            .await;
        manager
            .record_event(UsageEvent::new(
                "tenant1",
                UsageEventType::DataRestored,
                1024 * 1024 * 1024,
            ))
            .await;

        let report = manager
            .generate_report(
                "tenant1",
                Utc::now() - chrono::Duration::days(30),
                Utc::now(),
            )
            .await;

        let cost = report.estimate_cost(&BillingRates::default());
        assert!(cost > 0.0);
    }

    #[test]
    fn test_event_serialization() {
        let event = UsageEvent::new("tenant1", UsageEventType::BackupCreated, 1024)
            .with_metadata("backup_id", "100")
            .with_metadata("backup_type", "vm");

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("backup_created"));
        assert!(json.contains("tenant1"));
    }
}
