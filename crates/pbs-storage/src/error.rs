//! Storage error types

use thiserror::Error;

/// Storage error type
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Chunk not found: {0}")]
    ChunkNotFound(String),

    #[error("Blob not found: {0}")]
    BlobNotFound(String),

    #[error("Index not found: {0}")]
    IndexNotFound(String),

    #[error("Datastore not found: {0}")]
    DatastoreNotFound(String),

    #[error("Snapshot not found: {0}")]
    SnapshotNotFound(String),

    #[error("Snapshot is protected until {0}")]
    SnapshotProtected(String),

    #[error("Storage backend error: {0}")]
    Backend(String),

    #[error("S3 error: {0}")]
    S3(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Core error: {0}")]
    Core(#[from] pbs_core::Error),
}

/// Result type alias
pub type StorageResult<T> = Result<T, StorageError>;
