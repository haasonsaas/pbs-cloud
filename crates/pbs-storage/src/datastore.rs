//! Datastore - High-level backup storage interface
//!
//! A datastore manages backups for a single tenant/namespace.
//! It handles backup snapshots, chunk deduplication, and garbage collection.

use std::sync::Arc;
use bytes::Bytes;
use pbs_core::{
    BackupManifest, Chunk, ChunkDigest, DataBlob, DynamicIndex, FixedIndex,
    CryptoConfig,
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
    pub fn new(
        name: &str,
        backend: Arc<dyn StorageBackend>,
        crypto: CryptoConfig,
    ) -> Self {
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
        let blob = DataBlob::encode(chunk.data(), &self.crypto, true)
            .map_err(|e| StorageError::Core(e))?;

        let data = Bytes::from(blob.to_bytes());
        self.backend.write_chunk(digest, data).await
    }

    /// Read a chunk
    #[instrument(skip(self), fields(datastore = %self.name, digest = %digest))]
    pub async fn read_chunk(&self, digest: &ChunkDigest) -> StorageResult<Chunk> {
        let data = self.backend.read_chunk(digest).await?;
        let blob = DataBlob::from_bytes(&data).map_err(|e| StorageError::Core(e))?;
        let raw_data = blob.decode(&self.crypto).map_err(|e| StorageError::Core(e))?;
        Chunk::new(raw_data).map_err(|e| StorageError::Core(e))
    }

    /// Check if a chunk exists
    pub async fn chunk_exists(&self, digest: &ChunkDigest) -> StorageResult<bool> {
        self.backend.chunk_exists(digest).await
    }

    /// Store a fixed index
    #[instrument(skip(self, index), fields(datastore = %self.name, path = %path))]
    pub async fn store_fixed_index(&self, path: &str, index: &FixedIndex) -> StorageResult<()> {
        let data = index.to_bytes();
        let blob = DataBlob::encode(&data, &self.crypto, true)
            .map_err(|e| StorageError::Core(e))?;
        self.backend
            .write_file(path, Bytes::from(blob.to_bytes()))
            .await
    }

    /// Read a fixed index
    #[instrument(skip(self), fields(datastore = %self.name, path = %path))]
    pub async fn read_fixed_index(&self, path: &str) -> StorageResult<FixedIndex> {
        let data = self.backend.read_file(path).await?;
        let blob = DataBlob::from_bytes(&data).map_err(|e| StorageError::Core(e))?;
        let raw_data = blob.decode(&self.crypto).map_err(|e| StorageError::Core(e))?;
        FixedIndex::from_bytes(&raw_data).map_err(|e| StorageError::Core(e))
    }

    /// Store a dynamic index
    #[instrument(skip(self, index), fields(datastore = %self.name, path = %path))]
    pub async fn store_dynamic_index(
        &self,
        path: &str,
        index: &DynamicIndex,
    ) -> StorageResult<()> {
        let data = index.to_bytes();
        let blob = DataBlob::encode(&data, &self.crypto, true)
            .map_err(|e| StorageError::Core(e))?;
        self.backend
            .write_file(path, Bytes::from(blob.to_bytes()))
            .await
    }

    /// Read a dynamic index
    #[instrument(skip(self), fields(datastore = %self.name, path = %path))]
    pub async fn read_dynamic_index(&self, path: &str) -> StorageResult<DynamicIndex> {
        let data = self.backend.read_file(path).await?;
        let blob = DataBlob::from_bytes(&data).map_err(|e| StorageError::Core(e))?;
        let raw_data = blob.decode(&self.crypto).map_err(|e| StorageError::Core(e))?;
        DynamicIndex::from_bytes(&raw_data).map_err(|e| StorageError::Core(e))
    }

    /// Store a blob file
    #[instrument(skip(self, data), fields(datastore = %self.name, path = %path, size = data.len()))]
    pub async fn store_blob(&self, path: &str, data: &[u8]) -> StorageResult<()> {
        let blob = DataBlob::encode(data, &self.crypto, true)
            .map_err(|e| StorageError::Core(e))?;
        self.backend
            .write_file(path, Bytes::from(blob.to_bytes()))
            .await
    }

    /// Read a blob file
    #[instrument(skip(self), fields(datastore = %self.name, path = %path))]
    pub async fn read_blob(&self, path: &str) -> StorageResult<Vec<u8>> {
        let data = self.backend.read_file(path).await?;
        let blob = DataBlob::from_bytes(&data).map_err(|e| StorageError::Core(e))?;
        blob.decode(&self.crypto).map_err(|e| StorageError::Core(e))
    }

    /// Store a backup manifest
    #[instrument(skip(self, manifest), fields(datastore = %self.name))]
    pub async fn store_manifest(&self, manifest: &BackupManifest) -> StorageResult<()> {
        let path = format!("{}/index.json", manifest.snapshot_path());
        let json = manifest.to_json().map_err(|e| StorageError::Core(e))?;
        self.backend
            .write_file(&path, Bytes::from(json.into_bytes()))
            .await
    }

    /// Read a backup manifest
    #[instrument(skip(self), fields(datastore = %self.name, path = %path))]
    pub async fn read_manifest(&self, path: &str) -> StorageResult<BackupManifest> {
        let data = self.backend.read_file(path).await?;
        let json = String::from_utf8(data.to_vec())
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        BackupManifest::from_json(&json).map_err(|e| StorageError::Core(e))
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
