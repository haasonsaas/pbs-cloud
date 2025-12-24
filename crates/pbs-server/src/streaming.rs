//! HTTP/2 streaming backup protocol implementation
//!
//! Implements the PBS backup/restore protocol for streaming data transfer.

use pbs_core::{Chunk, ChunkDigest};
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};

use crate::auth::AuthContext;
use crate::billing::{UsageEvent, UsageEventType};
use crate::config::WormConfig;
use crate::protocol::{ApiError, BackupParams};
use crate::server::ServerState;

/// Handle backup protocol requests within a session
pub struct BackupProtocolHandler {
    state: Arc<ServerState>,
}

impl BackupProtocolHandler {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }

    /// Start a new backup session
    #[instrument(skip(self, ctx, params))]
    pub async fn start_backup(
        &self,
        ctx: &AuthContext,
        params: BackupParams,
    ) -> Result<String, ApiError> {
        info!(
            "Starting backup session: {}/{}/{}",
            params.backup_type, params.backup_id, params.backup_time
        );

        // Verify tenant is active
        let tenant = self
            .state
            .tenants
            .get_tenant(&ctx.user.tenant_id)
            .await
            .ok_or_else(|| ApiError::not_found("Tenant not found"))?;

        if !tenant.active {
            return Err(ApiError::new(403, "Tenant is not active"));
        }

        // Check quota - reject new backups if tenant is over quota
        if tenant.is_over_quota() {
            return Err(ApiError::new(
                507, // HTTP 507 Insufficient Storage
                &format!(
                    "Quota exceeded: {} bytes used of {} bytes allowed",
                    tenant.used_bytes,
                    tenant.quota_bytes.unwrap_or(0)
                ),
            ));
        }

        let store = params.store.as_deref().unwrap_or("default");
        let datastore = self
            .state
            .get_datastore(store)
            .ok_or_else(|| ApiError::not_found("Datastore not found"))?;
        let session_id = self
            .state
            .sessions
            .create_backup_session(&ctx.user.tenant_id, params.clone(), datastore)
            .await;

        if let Some(retain_until) = compute_retain_until(&self.state.config.worm, &params) {
            let _ = self
                .state
                .sessions
                .with_backup_session_verified(&session_id, &ctx.user.tenant_id, |session| {
                    session.set_retain_until(retain_until);
                    Ok(())
                })
                .await;
        }

        // Record backup event
        self.state
            .billing
            .record_event(UsageEvent::new(
                &ctx.user.tenant_id,
                UsageEventType::BackupCreated,
                0,
            ))
            .await;

        info!("Created backup session: {}", session_id);
        Ok(session_id)
    }

    /// Upload a fixed-size chunk
    #[instrument(skip(self, data), fields(session_id = %session_id, digest = %digest))]
    pub async fn upload_fixed_chunk(
        &self,
        session_id: &str,
        tenant_id: &str,
        digest: ChunkDigest,
        data: Vec<u8>,
    ) -> Result<bool, ApiError> {
        let datastore = self
            .state
            .sessions
            .with_backup_session_verified(session_id, tenant_id, |session| Ok(session.datastore()))
            .await?;

        // Check if chunk already exists (deduplication)
        let exists = datastore
            .chunk_exists(&digest)
            .await
            .map_err(|e| ApiError::internal(&e.to_string()))?;

        if exists {
            debug!("Chunk {} already exists, skipping upload", digest);
            return Ok(false);
        }

        // Create and store the chunk
        let chunk = Chunk::new(data).map_err(|e| ApiError::bad_request(&e.to_string()))?;

        // Verify digest matches
        if chunk.digest() != &digest {
            return Err(ApiError::bad_request("Chunk digest mismatch"));
        }

        let stored = datastore
            .store_chunk(&chunk)
            .await
            .map_err(|e| ApiError::internal(&e.to_string()))?;

        // Mark chunk as uploaded in session
        self.state
            .sessions
            .with_backup_session_verified(session_id, tenant_id, |session| {
                session.mark_chunk_uploaded(digest);
                Ok(())
            })
            .await?;

        Ok(stored)
    }

    /// Upload a raw chunk blob (already encoded as DataBlob)
    #[instrument(skip(self, data), fields(session_id = %session_id, digest = %digest, size = data.len()))]
    pub async fn upload_chunk_blob(
        &self,
        session_id: &str,
        tenant_id: &str,
        digest: ChunkDigest,
        data: bytes::Bytes,
    ) -> Result<bool, ApiError> {
        let datastore = self
            .state
            .sessions
            .with_backup_session_verified(session_id, tenant_id, |session| Ok(session.datastore()))
            .await?;
        let stored = datastore
            .store_chunk_blob(&digest, data)
            .await
            .map_err(|e| ApiError::internal(&e.to_string()))?;

        self.state
            .sessions
            .with_backup_session_verified(session_id, tenant_id, |session| {
                session.mark_chunk_uploaded(digest);
                Ok(())
            })
            .await?;

        Ok(stored)
    }

    /// Upload a dynamic-size chunk
    #[instrument(skip(self, data), fields(session_id = %session_id, digest = %digest))]
    pub async fn upload_dynamic_chunk(
        &self,
        session_id: &str,
        tenant_id: &str,
        digest: ChunkDigest,
        data: Vec<u8>,
    ) -> Result<bool, ApiError> {
        // Dynamic chunks are stored the same as fixed chunks
        self.upload_fixed_chunk(session_id, tenant_id, digest, data)
            .await
    }

    /// Create a fixed index
    pub async fn create_fixed_index(
        &self,
        session_id: &str,
        tenant_id: &str,
        name: &str,
        chunk_size: u64,
    ) -> Result<(), ApiError> {
        self.state
            .sessions
            .with_backup_session_verified(session_id, tenant_id, |session| {
                session.create_fixed_index(name, chunk_size);
                Ok(())
            })
            .await
    }

    /// Append to a fixed index
    pub async fn append_fixed_index(
        &self,
        session_id: &str,
        tenant_id: &str,
        name: &str,
        digest: ChunkDigest,
        size: u64,
    ) -> Result<(), ApiError> {
        self.state
            .sessions
            .with_backup_session_verified(session_id, tenant_id, |session| {
                session.append_fixed_index(name, digest, size)
            })
            .await
    }

    /// Close a fixed index
    pub async fn close_fixed_index(
        &self,
        session_id: &str,
        tenant_id: &str,
        name: &str,
    ) -> Result<(u64, ChunkDigest), ApiError> {
        let (datastore, path, index, size, digest) = self
            .state
            .sessions
            .with_backup_session_verified(session_id, tenant_id, |session| {
                let index = session.close_fixed_index(name)?;
                let data = index.to_bytes();
                let digest = ChunkDigest::from_data(&data);
                let path = format!("{}/{}", session.snapshot_path(), name);
                session.closed_indexes.insert(name.to_string());
                Ok((session.datastore(), path, index, data.len() as u64, digest))
            })
            .await?;

        datastore
            .store_fixed_index(&path, &index)
            .await
            .map_err(|e| ApiError::internal(&e.to_string()))?;

        Ok((size, digest))
    }

    /// Create a dynamic index
    pub async fn create_dynamic_index(
        &self,
        session_id: &str,
        tenant_id: &str,
        name: &str,
    ) -> Result<(), ApiError> {
        self.state
            .sessions
            .with_backup_session_verified(session_id, tenant_id, |session| {
                session.create_dynamic_index(name);
                Ok(())
            })
            .await
    }

    /// Append to a dynamic index
    pub async fn append_dynamic_index(
        &self,
        session_id: &str,
        tenant_id: &str,
        name: &str,
        digest: ChunkDigest,
        offset: u64,
        size: u64,
    ) -> Result<(), ApiError> {
        self.state
            .sessions
            .with_backup_session_verified(session_id, tenant_id, |session| {
                session.append_dynamic_index(name, digest, offset, size)
            })
            .await
    }

    /// Close a dynamic index
    pub async fn close_dynamic_index(
        &self,
        session_id: &str,
        tenant_id: &str,
        name: &str,
    ) -> Result<(u64, ChunkDigest), ApiError> {
        let (datastore, path, index, size, digest) = self
            .state
            .sessions
            .with_backup_session_verified(session_id, tenant_id, |session| {
                let index = session.close_dynamic_index(name)?;
                let data = index.to_bytes();
                let digest = ChunkDigest::from_data(&data);
                let path = format!("{}/{}", session.snapshot_path(), name);
                session.closed_indexes.insert(name.to_string());
                Ok((session.datastore(), path, index, data.len() as u64, digest))
            })
            .await?;

        datastore
            .store_dynamic_index(&path, &index)
            .await
            .map_err(|e| ApiError::internal(&e.to_string()))?;

        Ok((size, digest))
    }

    /// Upload a blob
    pub async fn upload_blob(
        &self,
        session_id: &str,
        tenant_id: &str,
        name: &str,
        data: Vec<u8>,
    ) -> Result<(), ApiError> {
        self.state
            .sessions
            .with_backup_session_verified(session_id, tenant_id, |session| {
                session.store_blob(name, data);
                Ok(())
            })
            .await
    }

    /// Finish the backup session
    #[instrument(skip(self))]
    pub async fn finish_backup(
        &self,
        session_id: &str,
        tenant_id: &str,
    ) -> Result<FinishResult, ApiError> {
        info!("Finishing backup session: {}", session_id);

        // Remove the session first so we own it
        let mut session = self
            .state
            .sessions
            .remove_backup_session(session_id)
            .await
            .ok_or_else(|| ApiError::not_found("Session not found"))?;

        // Finish the backup
        let manifest = session.finish().await?;

        // Calculate total size
        let total_bytes: u64 = manifest.files.iter().map(|f| f.size).sum();

        // Update billing
        self.state
            .billing
            .record_event(UsageEvent::new(
                tenant_id,
                UsageEventType::StorageUpdated,
                total_bytes,
            ))
            .await;

        // Update tenant usage
        self.state
            .tenants
            .update_usage(tenant_id, total_bytes as i64)
            .await;

        info!(
            "Backup completed: {} files, {} bytes",
            manifest.files.len(),
            total_bytes
        );

        let manifest_json = manifest
            .to_json()
            .map_err(|e| ApiError::internal(&format!("Failed to serialize manifest: {}", e)))?;

        Ok(FinishResult {
            manifest_digest: ChunkDigest::from_data(manifest_json.as_bytes()),
            total_bytes,
            chunk_count: manifest.files.len(),
        })
    }

    /// Abort a backup session
    pub async fn abort_backup(&self, session_id: &str) -> Result<(), ApiError> {
        warn!("Aborting backup session: {}", session_id);
        self.state.sessions.remove_backup_session(session_id).await;
        Ok(())
    }

    /// Check known chunks (for deduplication)
    pub async fn check_known_chunks(
        &self,
        session_id: &str,
        tenant_id: &str,
        digests: &[ChunkDigest],
    ) -> Result<Vec<bool>, ApiError> {
        let datastore = self
            .state
            .sessions
            .with_backup_session_verified(session_id, tenant_id, |session| Ok(session.datastore()))
            .await?;
        let mut results = Vec::with_capacity(digests.len());

        for digest in digests {
            let exists = datastore
                .chunk_exists(digest)
                .await
                .map_err(|e| ApiError::internal(&e.to_string()))?;
            results.push(exists);
        }

        Ok(results)
    }
}

fn compute_retain_until(config: &WormConfig, params: &BackupParams) -> Option<String> {
    if !config.enabled {
        return None;
    }

    if config.allow_override {
        if let Some(retain_until) = &params.retain_until {
            if chrono::DateTime::parse_from_rfc3339(retain_until).is_ok() {
                return Some(retain_until.clone());
            }
            if let Ok(epoch) = retain_until.parse::<i64>() {
                if let Some(dt) = chrono::DateTime::<chrono::Utc>::from_timestamp(epoch, 0) {
                    return Some(dt.format("%Y-%m-%dT%H:%M:%SZ").to_string());
                }
            }
        }

        if let Some(days) = params.retention_days {
            let until = chrono::Utc::now() + chrono::Duration::days(days as i64);
            return Some(until.format("%Y-%m-%dT%H:%M:%SZ").to_string());
        }
    }

    if let Some(days) = config.default_retention_days {
        let until = chrono::Utc::now() + chrono::Duration::days(days as i64);
        return Some(until.format("%Y-%m-%dT%H:%M:%SZ").to_string());
    }

    None
}

/// Result of finishing a backup
#[derive(Debug)]
pub struct FinishResult {
    pub manifest_digest: ChunkDigest,
    pub total_bytes: u64,
    pub chunk_count: usize,
}

/// Handle restore/reader protocol requests
pub struct ReaderProtocolHandler {
    state: Arc<ServerState>,
}

impl ReaderProtocolHandler {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }

    /// Start a new reader session
    #[instrument(skip(self, ctx))]
    pub async fn start_reader(
        &self,
        ctx: &AuthContext,
        backup_type: &str,
        backup_id: &str,
        backup_time: &str,
        namespace: Option<String>,
        store: Option<String>,
    ) -> Result<String, ApiError> {
        info!(
            "Starting reader session: {}/{}/{}",
            backup_type, backup_id, backup_time
        );

        // Verify tenant is active
        let tenant = self
            .state
            .tenants
            .get_tenant(&ctx.user.tenant_id)
            .await
            .ok_or_else(|| ApiError::not_found("Tenant not found"))?;

        if !tenant.active {
            return Err(ApiError::new(403, "Tenant is not active"));
        }

        let store_name = store.as_deref().unwrap_or("default");
        let datastore = self
            .state
            .get_datastore(store_name)
            .ok_or_else(|| ApiError::not_found("Datastore not found"))?;
        let session_id = self
            .state
            .sessions
            .create_reader_session(
                &ctx.user.tenant_id,
                backup_type,
                backup_id,
                backup_time,
                namespace,
                datastore,
            )
            .await;

        info!("Created reader session: {}", session_id);
        Ok(session_id)
    }

    /// Download a chunk
    #[instrument(skip(self), fields(session_id = %session_id, digest = %digest))]
    pub async fn download_chunk(
        &self,
        session_id: &str,
        digest: &ChunkDigest,
        tenant_id: &str,
    ) -> Result<Vec<u8>, ApiError> {
        // Verify reader session ownership
        self.state
            .sessions
            .verify_reader_session_ownership(session_id, tenant_id)
            .await?;

        // Read chunk directly from datastore
        let datastore = self
            .state
            .sessions
            .with_reader_session_async(session_id, |session| {
                std::future::ready(Ok(session.datastore()))
            })
            .await?;
        let chunk = datastore
            .read_chunk(digest)
            .await
            .map_err(|e| ApiError::not_found(&e.to_string()))?;
        let data = chunk.into_data();

        // Record download for billing
        self.state
            .billing
            .record_event(UsageEvent::new(
                tenant_id,
                UsageEventType::DataRestored,
                data.len() as u64,
            ))
            .await;

        Ok(data)
    }

    /// Read a fixed index
    pub async fn read_fixed_index(
        &self,
        session_id: &str,
        tenant_id: &str,
        name: &str,
    ) -> Result<Vec<u8>, ApiError> {
        let index = self
            .state
            .sessions
            .reader_read_fixed_index(session_id, tenant_id, name)
            .await?;
        Ok(index.to_bytes())
    }

    /// Read a dynamic index
    pub async fn read_dynamic_index(
        &self,
        session_id: &str,
        tenant_id: &str,
        name: &str,
    ) -> Result<Vec<u8>, ApiError> {
        let index = self
            .state
            .sessions
            .reader_read_dynamic_index(session_id, tenant_id, name)
            .await?;
        Ok(index.to_bytes())
    }

    /// Read a blob
    pub async fn read_blob(
        &self,
        session_id: &str,
        tenant_id: &str,
        name: &str,
    ) -> Result<Vec<u8>, ApiError> {
        self.state
            .sessions
            .reader_read_blob(session_id, tenant_id, name)
            .await
    }

    /// Read the manifest
    pub async fn read_manifest(
        &self,
        session_id: &str,
        tenant_id: &str,
    ) -> Result<String, ApiError> {
        let manifest = self
            .state
            .sessions
            .reader_load_manifest(session_id, tenant_id)
            .await?;
        manifest
            .to_json()
            .map_err(|e| ApiError::internal(&e.to_string()))
    }

    /// Close a reader session
    pub async fn close_reader(&self, session_id: &str) -> Result<(), ApiError> {
        info!("Closing reader session: {}", session_id);
        self.state.sessions.remove_reader_session(session_id).await;
        Ok(())
    }
}

/// Parse chunk upload request
#[derive(Debug, serde::Deserialize)]
pub struct ChunkUploadRequest {
    pub digest: String,
    #[serde(default)]
    pub encoded_size: u64,
}

/// Parse index operation request
#[derive(Debug, serde::Deserialize)]
pub struct IndexRequest {
    #[serde(default)]
    pub chunk_size: u64,
}

/// Parse index append request
#[derive(Debug, serde::Deserialize)]
pub struct IndexAppendRequest {
    pub digest: String,
    pub offset: u64,
    pub size: u64,
}

/// Response for known chunks query
#[derive(Debug, serde::Serialize)]
pub struct KnownChunksResponse {
    pub known: Vec<bool>,
}

/// Response for finish backup
#[derive(Debug, serde::Serialize)]
pub struct FinishBackupResponse {
    pub manifest_digest: String,
    pub total_bytes: u64,
    pub chunk_count: usize,
}

impl From<FinishResult> for FinishBackupResponse {
    fn from(result: FinishResult) -> Self {
        Self {
            manifest_digest: result.manifest_digest.to_hex(),
            total_bytes: result.total_bytes,
            chunk_count: result.chunk_count,
        }
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    // Integration tests would go here, requiring a full server setup
}
