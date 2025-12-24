//! Backup and restore session management
//!
//! Manages active backup/restore sessions with proper state tracking.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use pbs_core::{ChunkDigest, FixedIndex, DynamicIndex, BackupManifest, FileType};
use pbs_storage::Datastore;

use crate::protocol::{BackupParams, ApiError};

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
    /// Uploaded blobs
    pub blobs: HashMap<String, Vec<u8>>,
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
            datastore,
        }
    }

    /// Get snapshot path
    pub fn snapshot_path(&self) -> String {
        format!(
            "{}/{}/{}",
            self.params.backup_type, self.params.backup_id, self.params.backup_time
        )
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
        self.fixed_indexes.insert(
            name.to_string(),
            FixedIndexBuilder::new(chunk_size),
        );
        self.touch();
    }

    /// Append to a fixed index
    pub fn append_fixed_index(&mut self, name: &str, digest: ChunkDigest, size: u64) -> Result<(), ApiError> {
        let builder = self.fixed_indexes.get_mut(name)
            .ok_or_else(|| ApiError::not_found(&format!("Fixed index '{}' not found", name)))?;
        builder.push(digest, size);
        self.touch();
        Ok(())
    }

    /// Close a fixed index
    pub fn close_fixed_index(&mut self, name: &str) -> Result<FixedIndex, ApiError> {
        let builder = self.fixed_indexes.remove(name)
            .ok_or_else(|| ApiError::not_found(&format!("Fixed index '{}' not found", name)))?;
        self.touch();
        Ok(builder.build())
    }

    /// Create a new dynamic index
    pub fn create_dynamic_index(&mut self, name: &str) {
        self.dynamic_indexes.insert(
            name.to_string(),
            DynamicIndexBuilder::new(),
        );
        self.touch();
    }

    /// Append to a dynamic index
    pub fn append_dynamic_index(
        &mut self,
        name: &str,
        digest: ChunkDigest,
        offset: u64,
        size: u64,
    ) -> Result<(), ApiError> {
        let builder = self.dynamic_indexes.get_mut(name)
            .ok_or_else(|| ApiError::not_found(&format!("Dynamic index '{}' not found", name)))?;
        builder.push(digest, offset, size);
        self.touch();
        Ok(())
    }

    /// Close a dynamic index
    pub fn close_dynamic_index(&mut self, name: &str) -> Result<DynamicIndex, ApiError> {
        let builder = self.dynamic_indexes.remove(name)
            .ok_or_else(|| ApiError::not_found(&format!("Dynamic index '{}' not found", name)))?;
        self.touch();
        Ok(builder.build())
    }

    /// Store a blob
    pub fn store_blob(&mut self, name: &str, data: Vec<u8>) {
        self.blobs.insert(name.to_string(), data);
        self.touch();
    }

    /// Finalize the backup session
    pub async fn finish(&mut self) -> Result<BackupManifest, ApiError> {
        if self.state != SessionState::Active {
            return Err(ApiError::bad_request("Session is not active"));
        }

        self.state = SessionState::Finishing;

        // Create manifest
        let mut manifest = BackupManifest::new(
            &self.params.backup_type,
            &self.params.backup_id,
        );

        // Store remaining fixed indexes
        for (name, builder) in std::mem::take(&mut self.fixed_indexes) {
            let index = builder.build();
            let path = format!("{}/{}", self.snapshot_path(), name);
            let data = index.to_bytes();

            self.datastore.store_fixed_index(&path, &index).await
                .map_err(|e| ApiError::internal(&e.to_string()))?;

            manifest.add_file(&name, FileType::Fidx, data.len() as u64, &data);
        }

        // Store remaining dynamic indexes
        for (name, builder) in std::mem::take(&mut self.dynamic_indexes) {
            let index = builder.build();
            let path = format!("{}/{}", self.snapshot_path(), name);
            let data = index.to_bytes();

            self.datastore.store_dynamic_index(&path, &index).await
                .map_err(|e| ApiError::internal(&e.to_string()))?;

            manifest.add_file(&name, FileType::Didx, data.len() as u64, &data);
        }

        // Store blobs
        for (name, data) in std::mem::take(&mut self.blobs) {
            let path = format!("{}/{}", self.snapshot_path(), name);

            self.datastore.store_blob(&path, &data).await
                .map_err(|e| ApiError::internal(&e.to_string()))?;

            manifest.add_file(&name, FileType::Blob, data.len() as u64, &data);
        }

        // Store manifest
        self.datastore.store_manifest(&manifest).await
            .map_err(|e| ApiError::internal(&e.to_string()))?;

        self.state = SessionState::Completed;
        Ok(manifest)
    }

    /// Abort the session
    pub fn abort(&mut self) {
        self.state = SessionState::Aborted;
    }
}

/// Builder for fixed indexes
pub struct FixedIndexBuilder {
    index: FixedIndex,
}

impl FixedIndexBuilder {
    pub fn new(chunk_size: u64) -> Self {
        Self {
            index: FixedIndex::new(chunk_size),
        }
    }

    pub fn push(&mut self, digest: ChunkDigest, size: u64) {
        self.index.push(digest, size);
    }

    pub fn build(self) -> FixedIndex {
        self.index
    }
}

/// Builder for dynamic indexes
pub struct DynamicIndexBuilder {
    index: DynamicIndex,
}

impl DynamicIndexBuilder {
    pub fn new() -> Self {
        Self {
            index: DynamicIndex::new(),
        }
    }

    pub fn push(&mut self, digest: ChunkDigest, offset: u64, size: u64) {
        self.index.push(digest, offset, size);
    }

    pub fn build(self) -> DynamicIndex {
        self.index
    }
}

impl Default for DynamicIndexBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A restore/reader session
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
        datastore: Arc<Datastore>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id,
            tenant_id,
            backup_type,
            backup_id,
            backup_time,
            state: SessionState::Active,
            created_at: now,
            last_activity: now,
            manifest: None,
            datastore,
        }
    }

    /// Get snapshot path
    pub fn snapshot_path(&self) -> String {
        format!("{}/{}/{}", self.backup_type, self.backup_id, self.backup_time)
    }

    /// Update last activity
    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Load the manifest
    pub async fn load_manifest(&mut self) -> Result<&BackupManifest, ApiError> {
        if self.manifest.is_none() {
            let path = format!("{}/index.json", self.snapshot_path());
            let manifest = self.datastore.read_manifest(&path).await
                .map_err(|e| ApiError::not_found(&e.to_string()))?;
            self.manifest = Some(manifest);
        }
        self.touch();
        Ok(self.manifest.as_ref().unwrap())
    }

    /// Read a chunk
    pub async fn read_chunk(&mut self, digest: &ChunkDigest) -> Result<Vec<u8>, ApiError> {
        self.touch();
        let chunk = self.datastore.read_chunk(digest).await
            .map_err(|e| ApiError::not_found(&e.to_string()))?;
        Ok(chunk.into_data())
    }

    /// Read a fixed index
    pub async fn read_fixed_index(&mut self, name: &str) -> Result<FixedIndex, ApiError> {
        self.touch();
        let path = format!("{}/{}", self.snapshot_path(), name);
        self.datastore.read_fixed_index(&path).await
            .map_err(|e| ApiError::not_found(&e.to_string()))
    }

    /// Read a dynamic index
    pub async fn read_dynamic_index(&mut self, name: &str) -> Result<DynamicIndex, ApiError> {
        self.touch();
        let path = format!("{}/{}", self.snapshot_path(), name);
        self.datastore.read_dynamic_index(&path).await
            .map_err(|e| ApiError::not_found(&e.to_string()))
    }

    /// Read a blob
    pub async fn read_blob(&mut self, name: &str) -> Result<Vec<u8>, ApiError> {
        self.touch();
        let path = format!("{}/{}", self.snapshot_path(), name);
        self.datastore.read_blob(&path).await
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
        let session = BackupSession::new(
            id.clone(),
            tenant_id.to_string(),
            params,
            datastore,
        );

        let mut sessions = self.backup_sessions.write().await;
        sessions.insert(id.clone(), session);
        id
    }

    /// Get a backup session
    pub async fn get_backup_session(&self, id: &str) -> Option<BackupSession> {
        let sessions = self.backup_sessions.read().await;
        // We can't return a reference due to RwLock, so we need a different approach
        // For now, return None - we'll refactor this
        None
    }

    /// Execute an operation on a backup session
    pub async fn with_backup_session<F, R>(&self, id: &str, f: F) -> Result<R, ApiError>
    where
        F: FnOnce(&mut BackupSession) -> Result<R, ApiError>,
    {
        let mut sessions = self.backup_sessions.write().await;
        let session = sessions.get_mut(id)
            .ok_or_else(|| ApiError::not_found("Session not found"))?;

        if session.state != SessionState::Active {
            return Err(ApiError::bad_request("Session is not active"));
        }

        f(session)
    }

    /// Execute an async operation on a backup session
    pub async fn with_backup_session_async<F, Fut, R>(&self, id: &str, f: F) -> Result<R, ApiError>
    where
        F: FnOnce(&mut BackupSession) -> Fut,
        Fut: std::future::Future<Output = Result<R, ApiError>>,
    {
        let mut sessions = self.backup_sessions.write().await;
        let session = sessions.get_mut(id)
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
        datastore: Arc<Datastore>,
    ) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let session = ReaderSession::new(
            id.clone(),
            tenant_id.to_string(),
            backup_type.to_string(),
            backup_id.to_string(),
            backup_time.to_string(),
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
        let session = sessions.get_mut(id)
            .ok_or_else(|| ApiError::not_found("Session not found"))?;

        f(session).await
    }

    /// Remove a reader session
    pub async fn remove_reader_session(&self, id: &str) -> Option<ReaderSession> {
        let mut sessions = self.reader_sessions.write().await;
        sessions.remove(id)
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired(&self) {
        let now = Utc::now();
        let timeout = chrono::Duration::seconds(self.timeout_secs as i64);

        // Cleanup backup sessions
        {
            let mut sessions = self.backup_sessions.write().await;
            sessions.retain(|_, session| {
                now.signed_duration_since(session.last_activity) < timeout
            });
        }

        // Cleanup reader sessions
        {
            let mut sessions = self.reader_sessions.write().await;
            sessions.retain(|_, session| {
                now.signed_duration_since(session.last_activity) < timeout
            });
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
