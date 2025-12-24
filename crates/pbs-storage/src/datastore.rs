//! Datastore - High-level backup storage interface
//!
//! A datastore manages backups for a single tenant/namespace.
//! It handles backup snapshots, chunk deduplication, and garbage collection.

use std::sync::Arc;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use pbs_core::{
    BackupManifest, Chunk, ChunkDigest, CryptoConfig, DataBlob, DynamicIndex, FixedIndex,
};
use tracing::{info, instrument};

use crate::backend::StorageBackend;
use crate::error::{StorageError, StorageResult};

/// A datastore managing backups
pub struct Datastore {
    /// Datastore name/ID
    name: String,
    /// Storage backend
    backend: Arc<dyn StorageBackend>,
    /// Crypto configuration
    crypto: CryptoConfig,
}

impl Datastore {
    /// Create a new datastore
    pub fn new(name: &str, backend: Arc<dyn StorageBackend>, crypto: CryptoConfig) -> Self {
        Self {
            name: name.to_string(),
            backend,
            crypto,
        }
    }

    /// Get datastore name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the storage backend
    pub fn backend(&self) -> Arc<dyn StorageBackend> {
        self.backend.clone()
    }

    /// Store a chunk (with deduplication)
    #[instrument(skip(self, chunk), fields(datastore = %self.name, digest = %chunk.digest()))]
    pub async fn store_chunk(&self, chunk: &Chunk) -> StorageResult<bool> {
        let digest = chunk.digest();

        // Create data blob (compressed, optionally encrypted)
        let blob = DataBlob::encode(chunk.data(), &self.crypto, true).map_err(StorageError::Core)?;

        let data = Bytes::from(blob.to_bytes());
        self.backend.write_chunk(digest, data).await
    }

    /// Store a raw chunk blob (already encoded as DataBlob)
    #[instrument(skip(self, data), fields(datastore = %self.name, digest = %digest, size = data.len()))]
    pub async fn store_chunk_blob(&self, digest: &ChunkDigest, data: Bytes) -> StorageResult<bool> {
        self.backend.write_chunk(digest, data).await
    }

    /// Read a chunk
    #[instrument(skip(self), fields(datastore = %self.name, digest = %digest))]
    pub async fn read_chunk(&self, digest: &ChunkDigest) -> StorageResult<Chunk> {
        let data = self.backend.read_chunk(digest).await?;
        let blob = DataBlob::from_bytes(&data).map_err(StorageError::Core)?;
        let raw_data = blob.decode(&self.crypto).map_err(StorageError::Core)?;
        Chunk::new(raw_data).map_err(StorageError::Core)
    }

    /// Read a raw chunk blob (DataBlob bytes)
    #[instrument(skip(self), fields(datastore = %self.name, digest = %digest))]
    pub async fn read_chunk_blob(&self, digest: &ChunkDigest) -> StorageResult<Bytes> {
        self.backend.read_chunk(digest).await
    }

    /// Check if a chunk exists
    pub async fn chunk_exists(&self, digest: &ChunkDigest) -> StorageResult<bool> {
        self.backend.chunk_exists(digest).await
    }

    /// Store a fixed index
    #[instrument(skip(self, index), fields(datastore = %self.name, path = %path))]
    pub async fn store_fixed_index(&self, path: &str, index: &FixedIndex) -> StorageResult<()> {
        let data = index.to_bytes();
        self.backend.write_file(path, Bytes::from(data)).await
    }

    /// Read a fixed index
    #[instrument(skip(self), fields(datastore = %self.name, path = %path))]
    pub async fn read_fixed_index(&self, path: &str) -> StorageResult<FixedIndex> {
        let data = self.backend.read_file(path).await?;
        FixedIndex::from_bytes(&data).map_err(StorageError::Core)
    }

    /// Store a dynamic index
    #[instrument(skip(self, index), fields(datastore = %self.name, path = %path))]
    pub async fn store_dynamic_index(
        &self,
        path: &str,
        index: &DynamicIndex,
    ) -> StorageResult<()> {
        let data = index.to_bytes();
        self.backend.write_file(path, Bytes::from(data)).await
    }

    /// Read a dynamic index
    #[instrument(skip(self), fields(datastore = %self.name, path = %path))]
    pub async fn read_dynamic_index(&self, path: &str) -> StorageResult<DynamicIndex> {
        let data = self.backend.read_file(path).await?;
        DynamicIndex::from_bytes(&data).map_err(StorageError::Core)
    }

    /// Store a blob file
    #[instrument(skip(self, data), fields(datastore = %self.name, path = %path, size = data.len()))]
    pub async fn store_blob(&self, path: &str, data: &[u8]) -> StorageResult<()> {
        self.backend
            .write_file(path, Bytes::from(data.to_vec()))
            .await
    }

    /// Read a blob file
    #[instrument(skip(self), fields(datastore = %self.name, path = %path))]
    pub async fn read_blob(&self, path: &str) -> StorageResult<Vec<u8>> {
        let data = self.backend.read_file(path).await?;
        Ok(data.to_vec())
    }

    /// Store a backup manifest
    #[instrument(skip(self, manifest), fields(datastore = %self.name))]
    pub async fn store_manifest(&self, manifest: &BackupManifest) -> StorageResult<()> {
        let path = format!("{}/index.json.blob", manifest.snapshot_path());
        let json = manifest.to_json().map_err(StorageError::Core)?;
        let blob = DataBlob::encode(json.as_bytes(), &self.crypto, true)
            .map_err(StorageError::Core)?;
        self.backend
            .write_file(&path, Bytes::from(blob.to_bytes()))
            .await
    }

    /// Read a backup manifest
    #[instrument(skip(self), fields(datastore = %self.name, path = %path))]
    pub async fn read_manifest(&self, path: &str) -> StorageResult<BackupManifest> {
        let data = self.backend.read_file(path).await?;
        let blob = DataBlob::from_bytes(&data).map_err(StorageError::Core)?;
        let raw = blob.decode(&self.crypto).map_err(StorageError::Core)?;
        let json =
            String::from_utf8(raw).map_err(|e| StorageError::Backend(e.to_string()))?;
        BackupManifest::from_json(&json).map_err(StorageError::Core)
    }

    /// List backup groups (type/id combinations)
    pub async fn list_backup_groups(&self) -> StorageResult<Vec<BackupGroup>> {
        let files = self.backend.list_files("").await?;
        let mut groups = std::collections::HashSet::new();

        for file in files {
            // Parse: {type}/{id}/{timestamp}/...
            let parts: Vec<&str> = file.split('/').collect();
            if parts.len() >= 2 {
                groups.insert((parts[0].to_string(), parts[1].to_string()));
            }
        }

        Ok(groups
            .into_iter()
            .map(|(backup_type, backup_id)| BackupGroup {
                backup_type,
                backup_id,
            })
            .collect())
    }

    /// List snapshots in a backup group
    pub async fn list_snapshots(
        &self,
        backup_type: &str,
        backup_id: &str,
    ) -> StorageResult<Vec<String>> {
        let prefix = format!("{}/{}/", backup_type, backup_id);
        let files = self.backend.list_files(&prefix).await?;

        let mut snapshots = std::collections::HashSet::new();
        for file in files {
            // Extract timestamp from path
            if let Some(rest) = file.strip_prefix(&prefix) {
                if let Some(timestamp) = rest.split('/').next() {
                    snapshots.insert(timestamp.to_string());
                }
            }
        }

        let mut result: Vec<_> = snapshots.into_iter().collect();
        result.sort();
        Ok(result)
    }

    /// Delete a snapshot
    #[instrument(skip(self), fields(datastore = %self.name))]
    pub async fn delete_snapshot(
        &self,
        backup_type: &str,
        backup_id: &str,
        timestamp: &str,
    ) -> StorageResult<()> {
        let manifest_path = format!("{}/{}/{}/index.json.blob", backup_type, backup_id, timestamp);
        if let Ok(manifest) = self.read_manifest(&manifest_path).await {
            if let Some(until) = retention_until(&manifest) {
                if until > Utc::now() {
                    return Err(StorageError::SnapshotProtected(until.to_rfc3339()));
                }
            }
        }

        let prefix = format!("{}/{}/{}/", backup_type, backup_id, timestamp);
        let files = self.backend.list_files(&prefix).await?;

        for file in files {
            self.backend.delete_file(&file).await?;
        }

        info!(
            "Deleted snapshot {}/{}/{}",
            backup_type, backup_id, timestamp
        );
        Ok(())
    }
}

fn retention_until(manifest: &BackupManifest) -> Option<DateTime<Utc>> {
    let value = manifest.unprotected.as_ref()?;
    let obj = value.as_object()?;
    let until = obj.get("worm_retain_until")?.as_str()?;
    DateTime::parse_from_rfc3339(until)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// A backup group (type + ID)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BackupGroup {
    pub backup_type: String,
    pub backup_id: String,
}

impl BackupGroup {
    pub fn path(&self) -> String {
        format!("{}/{}", self.backup_type, self.backup_id)
    }
}
