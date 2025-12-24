//! REST API handlers
//!
//! Implements PBS-compatible REST API endpoints.

use serde::{Deserialize, Serialize};

use crate::protocol::{ApiResponse, ApiError};

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

// API route definitions

/// List datastores
pub async fn list_datastores() -> Result<ApiResponse<Vec<DatastoreStatus>>, ApiError> {
    // TODO: Implement
    Ok(ApiResponse::new(vec![]))
}

/// Get datastore status
pub async fn get_datastore_status(name: &str) -> Result<ApiResponse<DatastoreStatus>, ApiError> {
    // TODO: Implement
    Err(ApiError::not_found(&format!("Datastore '{}' not found", name)))
}

/// List backup groups in a datastore
pub async fn list_groups(datastore: &str) -> Result<ApiResponse<Vec<BackupGroupInfo>>, ApiError> {
    // TODO: Implement
    Ok(ApiResponse::new(vec![]))
}

/// List snapshots in a backup group
pub async fn list_snapshots(
    datastore: &str,
    backup_type: &str,
    backup_id: &str,
) -> Result<ApiResponse<Vec<SnapshotInfo>>, ApiError> {
    // TODO: Implement
    Ok(ApiResponse::new(vec![]))
}

/// Get files in a snapshot
pub async fn list_files(
    datastore: &str,
    backup_type: &str,
    backup_id: &str,
    backup_time: &str,
) -> Result<ApiResponse<Vec<FileInfo>>, ApiError> {
    // TODO: Implement
    Ok(ApiResponse::new(vec![]))
}

/// Delete a snapshot
pub async fn delete_snapshot(
    datastore: &str,
    backup_type: &str,
    backup_id: &str,
    backup_time: &str,
) -> Result<ApiResponse<()>, ApiError> {
    // TODO: Implement
    Ok(ApiResponse::new(()))
}

/// Download a file from a snapshot
pub async fn download_file(
    datastore: &str,
    backup_type: &str,
    backup_id: &str,
    backup_time: &str,
    filename: &str,
) -> Result<Vec<u8>, ApiError> {
    // TODO: Implement
    Err(ApiError::not_found("File not found"))
}

/// Upload a chunk (during backup)
pub async fn upload_chunk(
    session_id: &str,
    digest: &str,
    data: &[u8],
) -> Result<ApiResponse<bool>, ApiError> {
    // TODO: Implement
    Ok(ApiResponse::new(true))
}

/// Check if chunks exist (for dedup)
pub async fn check_chunks(
    session_id: &str,
    digests: &[String],
) -> Result<ApiResponse<Vec<bool>>, ApiError> {
    // TODO: Implement
    Ok(ApiResponse::new(digests.iter().map(|_| false).collect()))
}
