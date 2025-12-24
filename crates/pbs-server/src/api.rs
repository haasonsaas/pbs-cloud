//! REST API types
//!
//! Data types for PBS-compatible REST API endpoints.

use serde::{Deserialize, Serialize};

/// Datastore status
#[derive(Debug, Serialize, Deserialize)]
pub struct DatastoreStatus {
    /// Datastore name
    pub name: String,
    /// Total space in bytes
    pub total: u64,
    /// Used space in bytes
    pub used: u64,
    /// Available space in bytes
    pub avail: u64,
}

/// Backup group info
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupGroupInfo {
    /// Backup type
    pub backup_type: String,
    /// Backup ID
    pub backup_id: String,
    /// Number of snapshots
    pub snapshot_count: u64,
    /// Last backup time
    pub last_backup: Option<String>,
}

/// Snapshot info
#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotInfo {
    /// Backup type
    pub backup_type: String,
    /// Backup ID
    pub backup_id: String,
    /// Backup time
    pub backup_time: String,
    /// Total size in bytes
    pub size: u64,
    /// Whether backup is protected
    pub protected: bool,
    /// Comment
    pub comment: Option<String>,
}

/// File info in a snapshot
#[derive(Debug, Serialize, Deserialize)]
pub struct FileInfo {
    /// File name
    pub filename: String,
    /// File size
    pub size: u64,
    /// MIME type
    pub crypt_mode: String,
}
