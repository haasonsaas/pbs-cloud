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

const GROUP_OWNER_FILE: &str = "owner";
const LEGACY_GROUP_OWNER_FILE: &str = "owner.json";

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

    /// Get the crypto configuration
    pub fn crypto_config(&self) -> CryptoConfig {
        self.crypto.clone()
    }

    /// Store a chunk (with deduplication)
    #[instrument(skip(self, chunk), fields(datastore = %self.name, digest = %chunk.digest()))]
    pub async fn store_chunk(&self, chunk: &Chunk) -> StorageResult<bool> {
        let digest = chunk.digest();

        // Create data blob (compressed, optionally encrypted)
        let blob =
            DataBlob::encode(chunk.data(), &self.crypto, true).map_err(StorageError::Core)?;

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
    pub async fn store_dynamic_index(&self, path: &str, index: &DynamicIndex) -> StorageResult<()> {
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
        self.store_manifest_at(&manifest.snapshot_path(), manifest)
            .await
    }

    /// Store a backup manifest at a specific snapshot path
    #[instrument(skip(self, manifest), fields(datastore = %self.name, path = %snapshot_path))]
    pub async fn store_manifest_at(
        &self,
        snapshot_path: &str,
        manifest: &BackupManifest,
    ) -> StorageResult<()> {
        let path = format!("{}/index.json.blob", snapshot_path);
        let json = manifest.to_json().map_err(StorageError::Core)?;
        let blob =
            DataBlob::encode(json.as_bytes(), &self.crypto, true).map_err(StorageError::Core)?;
        self.backend
            .write_file(&path, Bytes::from(blob.to_bytes()))
            .await
    }

    /// Read a backup manifest
    #[instrument(skip(self), fields(datastore = %self.name, path = %path))]
    pub async fn read_manifest(&self, path: &str) -> StorageResult<BackupManifest> {
        let data = self.backend.read_file(path).await?;
        if let Ok(blob) = DataBlob::from_bytes(&data) {
            let raw = blob.decode(&self.crypto).map_err(StorageError::Core)?;
            let json = String::from_utf8(raw).map_err(|e| StorageError::Backend(e.to_string()))?;
            return BackupManifest::from_json(&json).map_err(StorageError::Core);
        }

        let json =
            String::from_utf8(data.to_vec()).map_err(|e| StorageError::Backend(e.to_string()))?;
        BackupManifest::from_json(&json).map_err(StorageError::Core)
    }

    /// Read a backup manifest, trying both blob and legacy JSON filenames
    pub async fn read_manifest_any(&self, snapshot_path: &str) -> StorageResult<BackupManifest> {
        let blob_path = format!("{}/index.json.blob", snapshot_path);
        match self.read_manifest(&blob_path).await {
            Ok(manifest) => Ok(manifest),
            Err(StorageError::BlobNotFound(_)) => {
                let json_path = format!("{}/index.json", snapshot_path);
                self.read_manifest(&json_path).await
            }
            Err(err) => Err(err),
        }
    }

    /// List backup groups (type/id combinations)
    pub async fn list_backup_groups(&self) -> StorageResult<Vec<BackupGroup>> {
        let files = self.backend.list_files("").await?;
        let mut groups = std::collections::HashSet::new();

        for file in files {
            // Parse: {type}/{id}/{timestamp}/...
            if let Some(group) = parse_backup_group(&file) {
                groups.insert(group);
            }
        }

        Ok(groups.into_iter().collect())
    }

    /// List snapshots in a backup group
    pub async fn list_snapshots(
        &self,
        namespace: Option<&str>,
        backup_type: &str,
        backup_id: &str,
    ) -> StorageResult<Vec<String>> {
        let prefix = format!(
            "{}{}/{}/",
            namespace_prefix(namespace),
            backup_type,
            backup_id
        );
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
        namespace: Option<&str>,
        backup_type: &str,
        backup_id: &str,
        timestamp: &str,
    ) -> StorageResult<()> {
        let snapshot_path = format!(
            "{}{}/{}/{}",
            namespace_prefix(namespace),
            backup_type,
            backup_id,
            timestamp
        );
        if let Ok(manifest) = self.read_manifest_any(&snapshot_path).await {
            if manifest_protected(&manifest) {
                if let Some(until) = retention_until(&manifest) {
                    return Err(StorageError::SnapshotProtected(until.to_rfc3339()));
                }
                return Err(StorageError::SnapshotProtected("protected".to_string()));
            }
        }

        let prefix = format!("{}/", snapshot_path);
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

    /// Read the owner for a backup group (if stored).
    pub async fn read_group_owner(&self, group: &BackupGroup) -> StorageResult<Option<String>> {
        let path = format!("{}/{}", group.path(), GROUP_OWNER_FILE);
        let legacy_path = format!("{}/{}", group.path(), LEGACY_GROUP_OWNER_FILE);
        match self.backend.read_file(&path).await {
            Ok(data) => {
                let text = String::from_utf8(data.to_vec())
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
                let owner = text.trim().to_string();
                if owner.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(owner))
                }
            }
            Err(StorageError::BlobNotFound(_)) => {
                match self.backend.read_file(&legacy_path).await {
                    Ok(data) => {
                        let text = String::from_utf8(data.to_vec())
                            .map_err(|e| StorageError::Backend(e.to_string()))?;
                        let owner = text.trim().to_string();
                        if owner.is_empty() {
                            Ok(None)
                        } else {
                            Ok(Some(owner))
                        }
                    }
                    Err(StorageError::BlobNotFound(_)) => Ok(None),
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        }
    }

    /// Store the owner for a backup group.
    pub async fn store_group_owner(&self, group: &BackupGroup, owner: &str) -> StorageResult<()> {
        let path = format!("{}/{}", group.path(), GROUP_OWNER_FILE);
        self.backend
            .write_file(&path, Bytes::from(owner.to_string().into_bytes()))
            .await
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

fn manifest_protected(manifest: &BackupManifest) -> bool {
    let protected = manifest
        .unprotected
        .as_ref()
        .and_then(|v| v.get("protected"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if protected {
        return true;
    }
    if let Some(until) = retention_until(manifest) {
        return until > Utc::now();
    }
    false
}

/// A backup group (type + ID)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BackupGroup {
    pub namespace: Option<String>,
    pub backup_type: String,
    pub backup_id: String,
}

impl BackupGroup {
    pub fn path(&self) -> String {
        format!(
            "{}{}/{}",
            namespace_prefix(self.namespace.as_deref()),
            self.backup_type,
            self.backup_id
        )
    }
}

fn namespace_prefix(namespace: Option<&str>) -> String {
    let ns = match namespace {
        Some(ns) if !ns.is_empty() => ns,
        _ => return String::new(),
    };
    let mut prefix = String::new();
    for part in ns.split('/') {
        if part.is_empty() {
            continue;
        }
        prefix.push_str("ns/");
        prefix.push_str(part);
        prefix.push('/');
    }
    prefix
}

fn parse_backup_group(path: &str) -> Option<BackupGroup> {
    let parts: Vec<&str> = path.split('/').collect();
    let mut idx = 0;
    let mut ns_parts = Vec::new();

    while idx + 1 < parts.len() && parts[idx] == "ns" {
        ns_parts.push(parts[idx + 1].to_string());
        idx += 2;
    }

    if parts.len() < idx + 2 {
        return None;
    }

    let backup_type = parts[idx];
    let backup_id = parts[idx + 1];

    if backup_type.is_empty() || backup_id.is_empty() {
        return None;
    }

    let namespace = if ns_parts.is_empty() {
        None
    } else {
        Some(ns_parts.join("/"))
    };

    Some(BackupGroup {
        namespace,
        backup_type: backup_type.to_string(),
        backup_id: backup_id.to_string(),
    })
}
