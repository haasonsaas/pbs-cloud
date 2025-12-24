//! Backup and restore session management
//!
//! Manages active backup/restore sessions with proper state tracking.

use chrono::{DateTime, Utc};
use pbs_core::{BackupManifest, ChunkDigest, DynamicIndex, FileType, FixedIndex};
use pbs_storage::Datastore;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::protocol::{ApiError, BackupParams};

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

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session is active and accepting data
    Active,
    /// Session is being finalized
    Finishing,
    /// Session completed successfully
    Completed,
    /// Session was aborted
    Aborted,
}

/// A backup session
#[derive(Clone)]
pub struct BackupSession {
    /// Session ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Backup parameters
    pub params: BackupParams,
    /// Session state
    pub state: SessionState,
    /// Creation time
    pub created_at: DateTime<Utc>,
    /// Last activity time
    pub last_activity: DateTime<Utc>,
    /// Known chunks from previous backup (for dedup)
    pub known_chunks: HashMap<ChunkDigest, bool>,
    /// Uploaded chunks in this session
    pub uploaded_chunks: Vec<ChunkDigest>,
    /// Fixed indexes being built
    pub fixed_indexes: HashMap<String, FixedIndexBuilder>,
    /// Dynamic indexes being built
    pub dynamic_indexes: HashMap<String, DynamicIndexBuilder>,
    /// Index writers by ID (H2 protocol)
    pub writers: HashMap<u64, IndexWriter>,
    /// Next writer ID
    pub next_writer_id: u64,
    /// Indexes already persisted at close
    pub closed_indexes: HashSet<String>,
    /// Uploaded blobs
    pub blobs: HashMap<String, Vec<u8>>,
    /// Retention timestamp (RFC3339)
    pub retain_until: Option<String>,
    /// Reference to datastore
    datastore: Arc<Datastore>,
}

impl BackupSession {
    /// Create a new backup session
    pub fn new(
        id: String,
        tenant_id: String,
        params: BackupParams,
        datastore: Arc<Datastore>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id,
            tenant_id,
            params,
            state: SessionState::Active,
            created_at: now,
            last_activity: now,
            known_chunks: HashMap::new(),
            uploaded_chunks: Vec::new(),
            fixed_indexes: HashMap::new(),
            dynamic_indexes: HashMap::new(),
            blobs: HashMap::new(),
            writers: HashMap::new(),
            next_writer_id: 1,
            closed_indexes: HashSet::new(),
            retain_until: None,
            datastore,
        }
    }

    /// Get snapshot path
    pub fn snapshot_path(&self) -> String {
        let ns_prefix = namespace_prefix(self.params.namespace.as_deref());
        let time = if self.params.backup_time.chars().all(|c| c.is_ascii_digit()) {
            self.params
                .backup_time
                .parse::<i64>()
                .ok()
                .and_then(|epoch| chrono::DateTime::<Utc>::from_timestamp(epoch, 0))
                .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_else(|| self.params.backup_time.clone())
        } else {
            self.params.backup_time.clone()
        };
        let base = format!(
            "{}/{}/{}",
            self.params.backup_type, self.params.backup_id, time
        );
        if ns_prefix.is_empty() {
            base
        } else {
            format!("{}{}", ns_prefix, base)
        }
    }

    pub fn datastore(&self) -> Arc<Datastore> {
        self.datastore.clone()
    }

    /// Update last activity
    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Check if a chunk is known (exists on server)
    pub fn is_chunk_known(&self, digest: &ChunkDigest) -> bool {
        self.known_chunks.get(digest).copied().unwrap_or(false)
    }

    /// Mark a chunk as uploaded
    pub fn mark_chunk_uploaded(&mut self, digest: ChunkDigest) {
        self.uploaded_chunks.push(digest);
        self.known_chunks.insert(digest, true);
        self.touch();
    }

    /// Create a new fixed index
    pub fn create_fixed_index(&mut self, name: &str, chunk_size: u64) {
        self.fixed_indexes
            .insert(name.to_string(), FixedIndexBuilder::new(chunk_size));
        self.touch();
    }

    pub fn create_fixed_index_with_id(&mut self, name: &str, chunk_size: u64) -> u64 {
        self.create_fixed_index(name, chunk_size);
        let wid = self.next_writer_id;
        self.next_writer_id = self.next_writer_id.saturating_add(1);
        self.writers.insert(
            wid,
            IndexWriter {
                name: name.to_string(),
                kind: IndexKind::Fixed,
            },
        );
        wid
    }

    /// Append to a fixed index
    pub fn append_fixed_index(
        &mut self,
        name: &str,
        digest: ChunkDigest,
        size: u64,
    ) -> Result<(), ApiError> {
        let builder = self
            .fixed_indexes
            .get_mut(name)
            .ok_or_else(|| ApiError::not_found(&format!("Fixed index '{}' not found", name)))?;
        builder.push(digest, Some(size));
        self.touch();
        Ok(())
    }

    /// Close a fixed index
    pub fn close_fixed_index(&mut self, name: &str) -> Result<FixedIndex, ApiError> {
        let builder = self
            .fixed_indexes
            .get(name)
            .cloned()
            .ok_or_else(|| ApiError::not_found(&format!("Fixed index '{}' not found", name)))?;
        self.touch();
        Ok(builder.build())
    }

    /// Create a new dynamic index
    pub fn create_dynamic_index(&mut self, name: &str) {
        self.dynamic_indexes
            .insert(name.to_string(), DynamicIndexBuilder::new());
        self.touch();
    }

    pub fn create_dynamic_index_with_id(&mut self, name: &str) -> u64 {
        self.create_dynamic_index(name);
        let wid = self.next_writer_id;
        self.next_writer_id = self.next_writer_id.saturating_add(1);
        self.writers.insert(
            wid,
            IndexWriter {
                name: name.to_string(),
                kind: IndexKind::Dynamic,
            },
        );
        wid
    }

    /// Append to a dynamic index
    pub fn append_dynamic_index(
        &mut self,
        name: &str,
        digest: ChunkDigest,
        offset: u64,
        size: u64,
    ) -> Result<(), ApiError> {
        let builder = self
            .dynamic_indexes
            .get_mut(name)
            .ok_or_else(|| ApiError::not_found(&format!("Dynamic index '{}' not found", name)))?;
        builder.push(digest, offset, Some(size));
        self.touch();
        Ok(())
    }

    /// Close a dynamic index
    pub fn close_dynamic_index(&mut self, name: &str) -> Result<DynamicIndex, ApiError> {
        let builder =
            self.dynamic_indexes.get(name).cloned().ok_or_else(|| {
                ApiError::not_found(&format!("Dynamic index '{}' not found", name))
            })?;
        self.touch();
        builder.build()
    }

    pub fn append_fixed_index_by_id(
        &mut self,
        wid: u64,
        digest: ChunkDigest,
        size: Option<u64>,
    ) -> Result<(), ApiError> {
        let writer = self
            .writers
            .get(&wid)
            .ok_or_else(|| ApiError::not_found("Writer not found"))?;
        if writer.kind != IndexKind::Fixed {
            return Err(ApiError::bad_request("Writer is not fixed index"));
        }
        let builder = self
            .fixed_indexes
            .get_mut(&writer.name)
            .ok_or_else(|| ApiError::not_found("Fixed index not found"))?;
        builder.push(digest, size);
        self.touch();
        Ok(())
    }

    pub fn append_dynamic_index_by_id(
        &mut self,
        wid: u64,
        digest: ChunkDigest,
        offset: u64,
        size: Option<u64>,
    ) -> Result<(), ApiError> {
        let writer = self
            .writers
            .get(&wid)
            .ok_or_else(|| ApiError::not_found("Writer not found"))?;
        if writer.kind != IndexKind::Dynamic {
            return Err(ApiError::bad_request("Writer is not dynamic index"));
        }
        let builder = self
            .dynamic_indexes
            .get_mut(&writer.name)
            .ok_or_else(|| ApiError::not_found("Dynamic index not found"))?;
        builder.push(digest, offset, size);
        self.touch();
        Ok(())
    }

    pub fn set_index_total_size(&mut self, wid: u64, size: u64) -> Result<(), ApiError> {
        let writer = self
            .writers
            .get(&wid)
            .ok_or_else(|| ApiError::not_found("Writer not found"))?;
        match writer.kind {
            IndexKind::Fixed => {
                let builder = self
                    .fixed_indexes
                    .get_mut(&writer.name)
                    .ok_or_else(|| ApiError::not_found("Fixed index not found"))?;
                builder.set_total_size(size);
            }
            IndexKind::Dynamic => {
                let builder = self
                    .dynamic_indexes
                    .get_mut(&writer.name)
                    .ok_or_else(|| ApiError::not_found("Dynamic index not found"))?;
                builder.set_total_size(size);
            }
        }
        self.touch();
        Ok(())
    }

    pub fn close_index_by_id(&mut self, wid: u64) -> Result<(String, IndexKind), ApiError> {
        let writer = self
            .writers
            .remove(&wid)
            .ok_or_else(|| ApiError::not_found("Writer not found"))?;
        Ok((writer.name, writer.kind))
    }

    pub async fn finalize_index_by_id(
        &mut self,
        wid: u64,
        total_size: u64,
        chunk_count: usize,
        expected_csum: [u8; 32],
    ) -> Result<(), ApiError> {
        let writer = self
            .writers
            .get(&wid)
            .cloned()
            .ok_or_else(|| ApiError::not_found("Writer not found"))?;

        match writer.kind {
            IndexKind::Fixed => {
                let builder = self
                    .fixed_indexes
                    .get_mut(&writer.name)
                    .ok_or_else(|| ApiError::not_found("Fixed index not found"))?;
                builder.set_total_size(total_size);
                if builder.chunk_count() != chunk_count {
                    return Err(ApiError::bad_request("Chunk count mismatch"));
                }
                let csum = builder.upload_csum();
                if csum != expected_csum {
                    return Err(ApiError::bad_request("Checksum mismatch"));
                }
                let index = builder.clone().build();
                let path = format!("{}/{}", self.snapshot_path(), writer.name);
                self.datastore
                    .store_fixed_index(&path, &index)
                    .await
                    .map_err(|e| ApiError::internal(&e.to_string()))?;
            }
            IndexKind::Dynamic => {
                let builder = self
                    .dynamic_indexes
                    .get_mut(&writer.name)
                    .ok_or_else(|| ApiError::not_found("Dynamic index not found"))?;
                builder.set_total_size(total_size);
                if builder.chunk_count() != chunk_count {
                    return Err(ApiError::bad_request("Chunk count mismatch"));
                }
                let csum = builder.upload_csum()?;
                if csum != expected_csum {
                    return Err(ApiError::bad_request("Checksum mismatch"));
                }
                let index = builder.clone().build()?;
                let path = format!("{}/{}", self.snapshot_path(), writer.name);
                self.datastore
                    .store_dynamic_index(&path, &index)
                    .await
                    .map_err(|e| ApiError::internal(&e.to_string()))?;
            }
        }

        self.closed_indexes.insert(writer.name.clone());
        self.writers.remove(&wid);
        self.touch();
        Ok(())
    }

    /// Store a blob
    pub fn store_blob(&mut self, name: &str, data: Vec<u8>) {
        self.blobs.insert(name.to_string(), data);
        self.touch();
    }

    pub fn set_retain_until(&mut self, until: String) {
        self.retain_until = Some(until);
        self.touch();
    }

    /// Finalize the backup session
    pub async fn finish(&mut self) -> Result<BackupManifest, ApiError> {
        if self.state != SessionState::Active {
            return Err(ApiError::bad_request("Session is not active"));
        }

        self.state = SessionState::Finishing;

        // Create manifest
        let mut manifest = BackupManifest::new(&self.params.backup_type, &self.params.backup_id);
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&self.params.backup_time) {
            manifest.backup_time = dt.with_timezone(&Utc);
        } else if let Ok(epoch) = self.params.backup_time.parse::<i64>() {
            if let Some(dt) = chrono::DateTime::<Utc>::from_timestamp(epoch, 0) {
                manifest.backup_time = dt;
            }
        }

        // Store remaining fixed indexes
        for (name, builder) in std::mem::take(&mut self.fixed_indexes) {
            let index = builder.build();
            let path = format!("{}/{}", self.snapshot_path(), name);
            let data = index.to_bytes();

            if !self.closed_indexes.contains(&name) {
                self.datastore
                    .store_fixed_index(&path, &index)
                    .await
                    .map_err(|e| ApiError::internal(&e.to_string()))?;
            }

            manifest.add_file(&name, FileType::Fidx, data.len() as u64, &data);
        }

        // Store remaining dynamic indexes
        for (name, builder) in std::mem::take(&mut self.dynamic_indexes) {
            let index = builder.build()?;
            let path = format!("{}/{}", self.snapshot_path(), name);
            let data = index.to_bytes();

            if !self.closed_indexes.contains(&name) {
                self.datastore
                    .store_dynamic_index(&path, &index)
                    .await
                    .map_err(|e| ApiError::internal(&e.to_string()))?;
            }

            manifest.add_file(&name, FileType::Didx, data.len() as u64, &data);
        }

        // Store blobs
        for (name, data) in std::mem::take(&mut self.blobs) {
            let path = format!("{}/{}", self.snapshot_path(), name);

            self.datastore
                .store_blob(&path, &data)
                .await
                .map_err(|e| ApiError::internal(&e.to_string()))?;

            manifest.add_file(&name, FileType::Blob, data.len() as u64, &data);
        }

        // Store manifest
        if let Some(until) = &self.retain_until {
            let mut value = manifest
                .unprotected
                .take()
                .unwrap_or_else(|| serde_json::json!({}));
            if let Some(obj) = value.as_object_mut() {
                obj.insert(
                    "worm_retain_until".to_string(),
                    serde_json::Value::String(until.clone()),
                );
            } else {
                value = serde_json::json!({ "worm_retain_until": until });
            }
            manifest.unprotected = Some(value);
        }
        self.datastore
            .store_manifest_at(&self.snapshot_path(), &manifest)
            .await
            .map_err(|e| ApiError::internal(&e.to_string()))?;

        self.state = SessionState::Completed;
        Ok(manifest)
    }

    /// Abort the session
    pub fn abort(&mut self) {
        self.state = SessionState::Aborted;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexKind {
    Fixed,
    Dynamic,
}

#[derive(Debug, Clone)]
pub struct IndexWriter {
    pub name: String,
    pub kind: IndexKind,
}

/// Builder for fixed indexes
#[derive(Clone)]
pub struct FixedIndexBuilder {
    chunk_size: u64,
    digests: Vec<ChunkDigest>,
    size_accum: u64,
    total_size: Option<u64>,
}

impl FixedIndexBuilder {
    pub fn new(chunk_size: u64) -> Self {
        Self {
            chunk_size,
            digests: Vec::new(),
            size_accum: 0,
            total_size: None,
        }
    }

    pub fn push(&mut self, digest: ChunkDigest, size: Option<u64>) {
        self.digests.push(digest);
        if let Some(size) = size {
            self.size_accum = self.size_accum.saturating_add(size);
        }
    }

    pub fn set_total_size(&mut self, size: u64) {
        self.total_size = Some(size);
    }

    pub fn build(self) -> FixedIndex {
        let mut index = FixedIndex::new(self.chunk_size);
        for digest in self.digests {
            index.digests.push(digest);
        }
        index.size = self.total_size.unwrap_or(self.size_accum);
        index
    }

    pub fn chunk_count(&self) -> usize {
        self.digests.len()
    }

    pub fn upload_csum(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for digest in &self.digests {
            hasher.update(digest.as_bytes());
        }
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

/// Builder for dynamic indexes
#[derive(Clone)]
pub struct DynamicIndexBuilder {
    entries: Vec<(u64, ChunkDigest, Option<u64>)>,
    total_size: Option<u64>,
}

impl DynamicIndexBuilder {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            total_size: None,
        }
    }

    pub fn push(&mut self, digest: ChunkDigest, offset: u64, size: Option<u64>) {
        self.entries.push((offset, digest, size));
    }

    pub fn set_total_size(&mut self, size: u64) {
        self.total_size = Some(size);
    }

    pub fn build(self) -> Result<DynamicIndex, ApiError> {
        let mut index = DynamicIndex::new();
        let mut entries = self.entries;
        entries.sort_by_key(|(offset, _, _)| *offset);

        for i in 0..entries.len() {
            let (offset, digest, size_opt) = entries[i];
            let size = if let Some(size) = size_opt {
                size
            } else {
                let next_offset = entries.get(i + 1).map(|e| e.0);
                match (next_offset, self.total_size) {
                    (Some(next), _) => next.saturating_sub(offset),
                    (None, Some(total)) => total.saturating_sub(offset),
                    _ => {
                        return Err(ApiError::bad_request(
                            "Dynamic index size missing and total size not provided",
                        ));
                    }
                }
            };
            index.push(digest, offset, size);
        }

        Ok(index)
    }

    pub fn chunk_count(&self) -> usize {
        self.entries.len()
    }

    pub fn upload_csum(&self) -> Result<[u8; 32], ApiError> {
        let mut entries = self.entries.clone();
        entries.sort_by_key(|(offset, _, _)| *offset);

        let mut hasher = Sha256::new();
        for i in 0..entries.len() {
            let (offset, digest, size_opt) = entries[i];
            let size = if let Some(size) = size_opt {
                size
            } else {
                let next_offset = entries.get(i + 1).map(|e| e.0);
                match (next_offset, self.total_size) {
                    (Some(next), _) => next.saturating_sub(offset),
                    (None, Some(total)) => total.saturating_sub(offset),
                    _ => {
                        return Err(ApiError::bad_request(
                            "Dynamic index size missing and total size not provided",
                        ));
                    }
                }
            };
            let chunk_end = offset.saturating_add(size);
            hasher.update(chunk_end.to_le_bytes());
            hasher.update(digest.as_bytes());
        }

        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        Ok(out)
    }
}

impl Default for DynamicIndexBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A restore/reader session
#[derive(Clone)]
pub struct ReaderSession {
    /// Session ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Backup type
    pub backup_type: String,
    /// Backup ID
    pub backup_id: String,
    /// Backup time
    pub backup_time: String,
    /// Optional namespace
    pub namespace: Option<String>,
    /// Session state
    pub state: SessionState,
    /// Creation time
    pub created_at: DateTime<Utc>,
    /// Last activity time
    pub last_activity: DateTime<Utc>,
    /// Cached manifest
    pub manifest: Option<BackupManifest>,
    /// Reference to datastore
    datastore: Arc<Datastore>,
}

impl ReaderSession {
    /// Create a new reader session
    pub fn new(
        id: String,
        tenant_id: String,
        backup_type: String,
        backup_id: String,
        backup_time: String,
        namespace: Option<String>,
        datastore: Arc<Datastore>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id,
            tenant_id,
            backup_type,
            backup_id,
            backup_time,
            namespace,
            state: SessionState::Active,
            created_at: now,
            last_activity: now,
            manifest: None,
            datastore,
        }
    }

    /// Get snapshot path
    pub fn snapshot_path(&self) -> String {
        let ns_prefix = namespace_prefix(self.namespace.as_deref());
        let base = format!(
            "{}/{}/{}",
            self.backup_type, self.backup_id, self.backup_time
        );
        if ns_prefix.is_empty() {
            base
        } else {
            format!("{}{}", ns_prefix, base)
        }
    }

    pub fn datastore(&self) -> Arc<Datastore> {
        self.datastore.clone()
    }

    /// Update last activity
    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Load the manifest
    pub async fn load_manifest(&mut self) -> Result<&BackupManifest, ApiError> {
        if self.manifest.is_none() {
            let snapshot_path = self.snapshot_path();
            let manifest = self
                .datastore
                .read_manifest_any(&snapshot_path)
                .await
                .map_err(|e| ApiError::not_found(&e.to_string()))?;
            self.manifest = Some(manifest);
        }
        self.touch();
        // Safe: we just set manifest above if it was None
        Ok(self.manifest.as_ref().expect("manifest was just loaded"))
    }

    /// Read a chunk
    pub async fn read_chunk(&mut self, digest: &ChunkDigest) -> Result<Vec<u8>, ApiError> {
        self.touch();
        let chunk = self
            .datastore
            .read_chunk(digest)
            .await
            .map_err(|e| ApiError::not_found(&e.to_string()))?;
        Ok(chunk.into_data())
    }

    /// Read a fixed index
    pub async fn read_fixed_index(&mut self, name: &str) -> Result<FixedIndex, ApiError> {
        self.touch();
        let path = format!("{}/{}", self.snapshot_path(), name);
        self.datastore
            .read_fixed_index(&path)
            .await
            .map_err(|e| ApiError::not_found(&e.to_string()))
    }

    /// Read a dynamic index
    pub async fn read_dynamic_index(&mut self, name: &str) -> Result<DynamicIndex, ApiError> {
        self.touch();
        let path = format!("{}/{}", self.snapshot_path(), name);
        self.datastore
            .read_dynamic_index(&path)
            .await
            .map_err(|e| ApiError::not_found(&e.to_string()))
    }

    /// Read a blob
    pub async fn read_blob(&mut self, name: &str) -> Result<Vec<u8>, ApiError> {
        self.touch();
        let path = format!("{}/{}", self.snapshot_path(), name);
        self.datastore
            .read_blob(&path)
            .await
            .map_err(|e| ApiError::not_found(&e.to_string()))
    }

    /// Close the session
    pub fn close(&mut self) {
        self.state = SessionState::Completed;
    }
}

/// Session manager
pub struct SessionManager {
    backup_sessions: RwLock<HashMap<String, BackupSession>>,
    reader_sessions: RwLock<HashMap<String, ReaderSession>>,
    /// Session timeout in seconds
    timeout_secs: u64,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            backup_sessions: RwLock::new(HashMap::new()),
            reader_sessions: RwLock::new(HashMap::new()),
            timeout_secs,
        }
    }

    /// Create a backup session
    pub async fn create_backup_session(
        &self,
        tenant_id: &str,
        params: BackupParams,
        datastore: Arc<Datastore>,
    ) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let session = BackupSession::new(id.clone(), tenant_id.to_string(), params, datastore);

        let mut sessions = self.backup_sessions.write().await;
        sessions.insert(id.clone(), session);
        id
    }

    /// Get a backup session
    pub async fn get_backup_session(&self, id: &str) -> Option<BackupSession> {
        let sessions = self.backup_sessions.read().await;
        sessions.get(id).cloned()
    }

    /// Execute an operation on a backup session
    pub async fn with_backup_session<F, R>(&self, id: &str, f: F) -> Result<R, ApiError>
    where
        F: FnOnce(&mut BackupSession) -> Result<R, ApiError>,
    {
        let mut sessions = self.backup_sessions.write().await;
        let session = sessions
            .get_mut(id)
            .ok_or_else(|| ApiError::not_found("Session not found"))?;

        if session.state != SessionState::Active {
            return Err(ApiError::bad_request("Session is not active"));
        }

        f(session)
    }

    /// Execute an operation on a backup session with tenant ownership verification
    pub async fn with_backup_session_verified<F, R>(
        &self,
        id: &str,
        tenant_id: &str,
        f: F,
    ) -> Result<R, ApiError>
    where
        F: FnOnce(&mut BackupSession) -> Result<R, ApiError>,
    {
        let mut sessions = self.backup_sessions.write().await;
        let session = sessions
            .get_mut(id)
            .ok_or_else(|| ApiError::not_found("Session not found"))?;

        // Verify tenant ownership
        if session.tenant_id != tenant_id {
            return Err(ApiError::new(
                403,
                "Access denied: session belongs to different tenant",
            ));
        }

        if session.state != SessionState::Active {
            return Err(ApiError::bad_request("Session is not active"));
        }

        f(session)
    }

    /// Verify session exists and belongs to the given tenant
    pub async fn verify_session_ownership(
        &self,
        id: &str,
        tenant_id: &str,
    ) -> Result<(), ApiError> {
        let sessions = self.backup_sessions.read().await;
        let session = sessions
            .get(id)
            .ok_or_else(|| ApiError::not_found("Session not found"))?;

        if session.tenant_id != tenant_id {
            return Err(ApiError::new(
                403,
                "Access denied: session belongs to different tenant",
            ));
        }

        Ok(())
    }

    /// Execute an async operation on a backup session
    pub async fn with_backup_session_async<F, R>(&self, id: &str, f: F) -> Result<R, ApiError>
    where
        F: for<'a> FnOnce(
            &'a mut BackupSession,
        )
            -> Pin<Box<dyn Future<Output = Result<R, ApiError>> + Send + 'a>>,
    {
        let mut sessions = self.backup_sessions.write().await;
        let session = sessions
            .get_mut(id)
            .ok_or_else(|| ApiError::not_found("Session not found"))?;

        f(session).await
    }

    /// Remove a backup session
    pub async fn remove_backup_session(&self, id: &str) -> Option<BackupSession> {
        let mut sessions = self.backup_sessions.write().await;
        sessions.remove(id)
    }

    /// Create a reader session
    pub async fn create_reader_session(
        &self,
        tenant_id: &str,
        backup_type: &str,
        backup_id: &str,
        backup_time: &str,
        namespace: Option<String>,
        datastore: Arc<Datastore>,
    ) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let session = ReaderSession::new(
            id.clone(),
            tenant_id.to_string(),
            backup_type.to_string(),
            backup_id.to_string(),
            backup_time.to_string(),
            namespace,
            datastore,
        );

        let mut sessions = self.reader_sessions.write().await;
        sessions.insert(id.clone(), session);
        id
    }

    /// Execute an async operation on a reader session
    pub async fn with_reader_session_async<F, Fut, R>(&self, id: &str, f: F) -> Result<R, ApiError>
    where
        F: FnOnce(&mut ReaderSession) -> Fut,
        Fut: std::future::Future<Output = Result<R, ApiError>>,
    {
        let mut sessions = self.reader_sessions.write().await;
        let session = sessions
            .get_mut(id)
            .ok_or_else(|| ApiError::not_found("Session not found"))?;

        f(session).await
    }

    /// Verify reader session exists and belongs to the given tenant
    pub async fn verify_reader_session_ownership(
        &self,
        id: &str,
        tenant_id: &str,
    ) -> Result<(), ApiError> {
        let sessions = self.reader_sessions.read().await;
        let session = sessions
            .get(id)
            .ok_or_else(|| ApiError::not_found("Session not found"))?;

        if session.tenant_id != tenant_id {
            return Err(ApiError::new(
                403,
                "Access denied: session belongs to different tenant",
            ));
        }

        Ok(())
    }

    /// Remove a reader session
    pub async fn remove_reader_session(&self, id: &str) -> Option<ReaderSession> {
        let mut sessions = self.reader_sessions.write().await;
        sessions.remove(id)
    }

    /// Read a fixed index from a reader session (with ownership verification)
    pub async fn reader_read_fixed_index(
        &self,
        id: &str,
        tenant_id: &str,
        name: &str,
    ) -> Result<FixedIndex, ApiError> {
        // Get session info and datastore reference
        let (snapshot_path, datastore) = {
            let mut sessions = self.reader_sessions.write().await;
            let session = sessions
                .get_mut(id)
                .ok_or_else(|| ApiError::not_found("Session not found"))?;

            if session.tenant_id != tenant_id {
                return Err(ApiError::new(
                    403,
                    "Access denied: session belongs to different tenant",
                ));
            }

            session.touch();
            (session.snapshot_path(), session.datastore.clone())
        };

        let path = format!("{}/{}", snapshot_path, name);
        datastore
            .read_fixed_index(&path)
            .await
            .map_err(|e| ApiError::not_found(&e.to_string()))
    }

    /// Read a dynamic index from a reader session (with ownership verification)
    pub async fn reader_read_dynamic_index(
        &self,
        id: &str,
        tenant_id: &str,
        name: &str,
    ) -> Result<DynamicIndex, ApiError> {
        let (snapshot_path, datastore) = {
            let mut sessions = self.reader_sessions.write().await;
            let session = sessions
                .get_mut(id)
                .ok_or_else(|| ApiError::not_found("Session not found"))?;

            if session.tenant_id != tenant_id {
                return Err(ApiError::new(
                    403,
                    "Access denied: session belongs to different tenant",
                ));
            }

            session.touch();
            (session.snapshot_path(), session.datastore.clone())
        };

        let path = format!("{}/{}", snapshot_path, name);
        datastore
            .read_dynamic_index(&path)
            .await
            .map_err(|e| ApiError::not_found(&e.to_string()))
    }

    /// Read a blob from a reader session (with ownership verification)
    pub async fn reader_read_blob(
        &self,
        id: &str,
        tenant_id: &str,
        name: &str,
    ) -> Result<Vec<u8>, ApiError> {
        let (snapshot_path, datastore) = {
            let mut sessions = self.reader_sessions.write().await;
            let session = sessions
                .get_mut(id)
                .ok_or_else(|| ApiError::not_found("Session not found"))?;

            if session.tenant_id != tenant_id {
                return Err(ApiError::new(
                    403,
                    "Access denied: session belongs to different tenant",
                ));
            }

            session.touch();
            (session.snapshot_path(), session.datastore.clone())
        };

        let path = format!("{}/{}", snapshot_path, name);
        datastore
            .read_blob(&path)
            .await
            .map_err(|e| ApiError::not_found(&e.to_string()))
    }

    /// Load manifest from a reader session (with ownership verification)
    pub async fn reader_load_manifest(
        &self,
        id: &str,
        tenant_id: &str,
    ) -> Result<BackupManifest, ApiError> {
        // First check if we already have it cached
        {
            let sessions = self.reader_sessions.read().await;
            if let Some(session) = sessions.get(id) {
                if session.tenant_id != tenant_id {
                    return Err(ApiError::new(
                        403,
                        "Access denied: session belongs to different tenant",
                    ));
                }
                if let Some(manifest) = &session.manifest {
                    return Ok(manifest.clone());
                }
            } else {
                return Err(ApiError::not_found("Session not found"));
            }
        }

        // Need to load it
        let (snapshot_path, datastore) = {
            let sessions = self.reader_sessions.read().await;
            let session = sessions
                .get(id)
                .ok_or_else(|| ApiError::not_found("Session not found"))?;
            (session.snapshot_path(), session.datastore.clone())
        };

        let manifest = datastore
            .read_manifest_any(&snapshot_path)
            .await
            .map_err(|e| ApiError::not_found(&e.to_string()))?;

        // Cache it
        {
            let mut sessions = self.reader_sessions.write().await;
            if let Some(session) = sessions.get_mut(id) {
                session.touch();
                session.manifest = Some(manifest.clone());
            }
        }

        Ok(manifest)
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired(&self) {
        let now = Utc::now();
        let timeout = chrono::Duration::seconds(self.timeout_secs as i64);

        // Cleanup backup sessions
        {
            let mut sessions = self.backup_sessions.write().await;
            sessions
                .retain(|_, session| now.signed_duration_since(session.last_activity) < timeout);
        }

        // Cleanup reader sessions
        {
            let mut sessions = self.reader_sessions.write().await;
            sessions
                .retain(|_, session| now.signed_duration_since(session.last_activity) < timeout);
        }
    }

    /// Get session count
    pub async fn session_count(&self) -> (usize, usize) {
        let backup_count = self.backup_sessions.read().await.len();
        let reader_count = self.reader_sessions.read().await.len();
        (backup_count, reader_count)
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new(3600) // 1 hour timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pbs_storage::LocalBackend;
    use tempfile::TempDir;

    async fn create_test_datastore() -> Arc<Datastore> {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalBackend::new_lazy(temp_dir.path()).await.unwrap();
        let crypto = pbs_core::CryptoConfig::default(); // Unencrypted
        Arc::new(Datastore::new("test", Arc::new(backend), crypto))
    }

    fn test_backup_params() -> crate::protocol::BackupParams {
        crate::protocol::BackupParams {
            backup_type: "vm".to_string(),
            backup_id: "100".to_string(),
            backup_time: "2024-01-01T00:00:00Z".to_string(),
            namespace: None,
            store: None,
            encrypt: false,
            retain_until: None,
            retention_days: None,
        }
    }

    #[tokio::test]
    async fn test_session_ownership_verification() {
        let manager = SessionManager::new(3600);
        let datastore = create_test_datastore().await;

        // Create a session for tenant1
        let params = test_backup_params();

        let session_id = manager
            .create_backup_session("tenant1", params, datastore)
            .await;

        // Verify tenant1 can access the session
        let result = manager
            .verify_session_ownership(&session_id, "tenant1")
            .await;
        assert!(result.is_ok());

        // Verify tenant2 cannot access the session
        let result = manager
            .verify_session_ownership(&session_id, "tenant2")
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status, 403);
        assert!(err.message.contains("different tenant"));
    }

    #[tokio::test]
    async fn test_reader_session_ownership_verification() {
        let manager = SessionManager::new(3600);
        let datastore = create_test_datastore().await;

        // Create a reader session for tenant1
        let session_id = manager
            .create_reader_session(
                "tenant1",
                "vm",
                "100",
                "2024-01-01T00:00:00Z",
                None,
                datastore,
            )
            .await;

        // Verify tenant1 can access the session
        let result = manager
            .verify_reader_session_ownership(&session_id, "tenant1")
            .await;
        assert!(result.is_ok());

        // Verify tenant2 cannot access the session
        let result = manager
            .verify_reader_session_ownership(&session_id, "tenant2")
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status, 403);
    }

    #[tokio::test]
    async fn test_verified_session_access() {
        let manager = SessionManager::new(3600);
        let datastore = create_test_datastore().await;

        let params = test_backup_params();

        let session_id = manager
            .create_backup_session("tenant1", params, datastore)
            .await;

        // Tenant1 can modify the session
        let result = manager
            .with_backup_session_verified(&session_id, "tenant1", |session| {
                assert_eq!(session.tenant_id, "tenant1");
                Ok(())
            })
            .await;
        assert!(result.is_ok());

        // Tenant2 cannot modify the session
        let result = manager
            .with_backup_session_verified(&session_id, "tenant2", |_session| Ok(()))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_nonexistent_session() {
        let manager = SessionManager::new(3600);

        // Verify ownership of nonexistent session fails with 404
        let result = manager
            .verify_session_ownership("nonexistent", "tenant1")
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status, 404);

        // Reader session
        let result = manager
            .verify_reader_session_ownership("nonexistent", "tenant1")
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status, 404);
    }

    #[tokio::test]
    async fn test_session_cleanup() {
        let manager = SessionManager::new(1); // 1 second timeout for testing
        let datastore = create_test_datastore().await;

        let params = test_backup_params();

        let session_id = manager
            .create_backup_session("tenant1", params, datastore.clone())
            .await;

        // Session exists
        assert!(manager
            .verify_session_ownership(&session_id, "tenant1")
            .await
            .is_ok());

        // Wait for expiration
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Cleanup
        manager.cleanup_expired().await;

        // Session should be gone
        assert!(manager
            .verify_session_ownership(&session_id, "tenant1")
            .await
            .is_err());
    }
}
