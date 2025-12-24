//! PBS backup protocol implementation
//!
//! Implements the HTTP/2 upgrade protocol for backups:
//! GET /api2/json/backup with UPGRADE: proxmox-backup-protocol-v1

use serde::{Deserialize, Serialize};

/// Protocol upgrade header value
pub const PROTOCOL_HEADER: &str = "proxmox-backup-protocol-v1";

/// Backup request parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupParams {
    /// Backup type (vm, ct, host)
    pub backup_type: String,
    /// Backup ID
    pub backup_id: String,
    /// Backup timestamp (ISO 8601)
    pub backup_time: String,
    /// Whether to use encrypted chunks
    pub encrypt: bool,
}

/// Backup session state
#[derive(Debug)]
pub struct BackupSession {
    /// Session ID
    pub id: String,
    /// Backup parameters
    pub params: BackupParams,
    /// Known chunks (for dedup)
    pub known_chunks: Vec<pbs_core::ChunkDigest>,
    /// Whether the session is active
    pub active: bool,
}

impl BackupSession {
    /// Create a new backup session
    pub fn new(params: BackupParams) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            params,
            known_chunks: Vec::new(),
            active: true,
        }
    }

    /// Mark session as finished
    pub fn finish(&mut self) {
        self.active = false;
    }

    /// Get snapshot path
    pub fn snapshot_path(&self) -> String {
        format!(
            "{}/{}/{}",
            self.params.backup_type, self.params.backup_id, self.params.backup_time
        )
    }
}

/// Reader session state (for restores)
#[derive(Debug)]
pub struct ReaderSession {
    /// Session ID
    pub id: String,
    /// Backup type
    pub backup_type: String,
    /// Backup ID
    pub backup_id: String,
    /// Backup timestamp
    pub backup_time: String,
    /// Whether the session is active
    pub active: bool,
}

impl ReaderSession {
    /// Create a new reader session
    pub fn new(backup_type: &str, backup_id: &str, backup_time: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            backup_type: backup_type.to_string(),
            backup_id: backup_id.to_string(),
            backup_time: backup_time.to_string(),
            active: true,
        }
    }

    /// Get snapshot path
    pub fn snapshot_path(&self) -> String {
        format!(
            "{}/{}/{}",
            self.backup_type, self.backup_id, self.backup_time
        )
    }
}

/// API response wrapper
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Response data
    pub data: T,
}

impl<T> ApiResponse<T> {
    pub fn new(data: T) -> Self {
        Self { data }
    }
}

/// Error response
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiError {
    /// Error message
    pub message: String,
    /// HTTP status code
    #[serde(skip)]
    pub status: u16,
}

impl ApiError {
    pub fn new(status: u16, message: &str) -> Self {
        Self {
            message: message.to_string(),
            status,
        }
    }

    pub fn bad_request(message: &str) -> Self {
        Self::new(400, message)
    }

    pub fn unauthorized(message: &str) -> Self {
        Self::new(401, message)
    }

    pub fn not_found(message: &str) -> Self {
        Self::new(404, message)
    }

    pub fn internal(message: &str) -> Self {
        Self::new(500, message)
    }
}
