//! Storage backend trait definitions
//!
//! These traits define the interface for pluggable storage backends.

use async_trait::async_trait;
use bytes::Bytes;
use pbs_core::ChunkDigest;

use crate::error::StorageResult;

/// A storage backend for chunks
#[async_trait]
pub trait ChunkReader: Send + Sync {
    /// Check if a chunk exists
    async fn chunk_exists(&self, digest: &ChunkDigest) -> StorageResult<bool>;

    /// Read a chunk
    async fn read_chunk(&self, digest: &ChunkDigest) -> StorageResult<Bytes>;

    /// List all chunks (for verification/GC)
    async fn list_chunks(&self) -> StorageResult<Vec<ChunkDigest>>;
}

/// A storage backend that can write chunks
#[async_trait]
pub trait ChunkWriter: ChunkReader {
    /// Write a chunk (returns true if newly written, false if already exists)
    async fn write_chunk(&self, digest: &ChunkDigest, data: Bytes) -> StorageResult<bool>;

    /// Delete a chunk
    async fn delete_chunk(&self, digest: &ChunkDigest) -> StorageResult<()>;
}

/// Full storage backend trait
#[async_trait]
pub trait StorageBackend: ChunkWriter {
    /// Get backend name/type
    fn name(&self) -> &str;

    /// Get backend statistics
    async fn stats(&self) -> StorageResult<BackendStats>;

    /// Read a file (blob, index, manifest)
    async fn read_file(&self, path: &str) -> StorageResult<Bytes>;

    /// Write a file
    async fn write_file(&self, path: &str, data: Bytes) -> StorageResult<()>;

    /// Delete a file
    async fn delete_file(&self, path: &str) -> StorageResult<()>;

    /// Check if a file exists
    async fn file_exists(&self, path: &str) -> StorageResult<bool>;

    /// List files under a prefix
    async fn list_files(&self, prefix: &str) -> StorageResult<Vec<String>>;
}

/// Backend statistics
#[derive(Debug, Clone, Default)]
pub struct BackendStats {
    /// Total chunks stored
    pub chunk_count: u64,
    /// Total bytes used by chunks
    pub chunk_bytes: u64,
    /// Number of deduplicated bytes (saved)
    pub dedup_bytes: u64,
    /// Number of files (blobs, indexes, manifests)
    pub file_count: u64,
    /// Total bytes used by files
    pub file_bytes: u64,
}
