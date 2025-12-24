//! Local filesystem storage backend
//!
//! Stores chunks and files on the local filesystem.
//! Structure mirrors PBS:
//! - <root>/.chunks/{prefix}/{digest} - chunk data
//! - <root>/data/{path} - files (manifests, indexes, blobs)

use async_trait::async_trait;
use bytes::Bytes;
use pbs_core::ChunkDigest;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{debug, instrument};

use crate::backend::{BackendStats, ChunkReader, ChunkWriter, StorageBackend};
use crate::error::{StorageError, StorageResult};

/// Local filesystem storage backend
pub struct LocalBackend {
    /// Root directory
    root: PathBuf,
}

impl LocalBackend {
    /// Create a new local backend
    pub async fn new(root: impl AsRef<Path>) -> StorageResult<Self> {
        let root = root.as_ref().to_path_buf();

        // Create directory structure
        fs::create_dir_all(&root).await?;
        fs::create_dir_all(root.join(".chunks")).await?;
        fs::create_dir_all(root.join("data")).await?;

        // Pre-create chunk prefix directories (0000-ffff)
        for i in 0..=0xFFu8 {
            for j in 0..=0xFFu8 {
                let prefix = format!("{:02x}{:02x}", i, j);
                let dir = root.join(".chunks").join(&prefix);
                if !dir.exists() {
                    fs::create_dir_all(&dir).await?;
                }
            }
        }

        Ok(Self { root })
    }

    /// Create without pre-creating all chunk directories (faster for testing)
    pub async fn new_lazy(root: impl AsRef<Path>) -> StorageResult<Self> {
        let root = root.as_ref().to_path_buf();

        // Create only base directories
        fs::create_dir_all(&root).await?;
        fs::create_dir_all(root.join(".chunks")).await?;
        fs::create_dir_all(root.join("data")).await?;

        Ok(Self { root })
    }

    /// Get chunk path
    fn chunk_path(&self, digest: &ChunkDigest) -> PathBuf {
        let prefix = digest.storage_prefix();
        self.root
            .join(".chunks")
            .join(&prefix)
            .join(digest.to_hex())
    }

    /// Get file path
    fn file_path(&self, path: &str) -> PathBuf {
        self.root.join("data").join(path)
    }

    /// Ensure parent directory exists
    async fn ensure_parent(&self, path: &Path) -> StorageResult<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl ChunkReader for LocalBackend {
    #[instrument(skip(self), fields(digest = %digest))]
    async fn chunk_exists(&self, digest: &ChunkDigest) -> StorageResult<bool> {
        let path = self.chunk_path(digest);
        Ok(path.exists())
    }

    #[instrument(skip(self), fields(digest = %digest))]
    async fn read_chunk(&self, digest: &ChunkDigest) -> StorageResult<Bytes> {
        let path = self.chunk_path(digest);

        match fs::read(&path).await {
            Ok(data) => Ok(Bytes::from(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(StorageError::ChunkNotFound(digest.to_hex()))
            }
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    async fn list_chunks(&self) -> StorageResult<Vec<ChunkDigest>> {
        let mut digests = Vec::new();
        let chunks_dir = self.root.join(".chunks");

        let mut prefix_dirs = fs::read_dir(&chunks_dir).await?;

        while let Some(prefix_entry) = prefix_dirs.next_entry().await? {
            if !prefix_entry.file_type().await?.is_dir() {
                continue;
            }

            let mut chunk_files = fs::read_dir(prefix_entry.path()).await?;

            while let Some(chunk_entry) = chunk_files.next_entry().await? {
                if let Some(name) = chunk_entry.file_name().to_str() {
                    if let Ok(digest) = ChunkDigest::from_hex(name) {
                        digests.push(digest);
                    }
                }
            }
        }

        Ok(digests)
    }
}

#[async_trait]
impl ChunkWriter for LocalBackend {
    #[instrument(skip(self, data), fields(digest = %digest, size = data.len()))]
    async fn write_chunk(&self, digest: &ChunkDigest, data: Bytes) -> StorageResult<bool> {
        let path = self.chunk_path(digest);

        // Check if already exists (deduplication)
        if path.exists() {
            debug!("Chunk already exists, skipping write");
            return Ok(false);
        }

        // Ensure parent directory exists
        self.ensure_parent(&path).await?;

        // Write atomically using temp file + rename
        let temp_path = path.with_extension("tmp");

        let mut file = fs::File::create(&temp_path).await?;
        file.write_all(&data).await?;
        file.sync_all().await?;
        drop(file);

        fs::rename(&temp_path, &path).await?;

        Ok(true)
    }

    #[instrument(skip(self), fields(digest = %digest))]
    async fn delete_chunk(&self, digest: &ChunkDigest) -> StorageResult<()> {
        let path = self.chunk_path(digest);

        match fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()), // Already deleted
            Err(e) => Err(StorageError::Io(e)),
        }
    }
}

#[async_trait]
impl StorageBackend for LocalBackend {
    fn name(&self) -> &str {
        "local"
    }

    async fn stats(&self) -> StorageResult<BackendStats> {
        let mut stats = BackendStats::default();

        // Count chunks
        let chunks = self.list_chunks().await?;
        stats.chunk_count = chunks.len() as u64;

        // Calculate chunk sizes
        for digest in &chunks {
            let path = self.chunk_path(digest);
            if let Ok(metadata) = fs::metadata(&path).await {
                stats.chunk_bytes += metadata.len();
            }
        }

        // Count and measure files
        let data_dir = self.root.join("data");
        if data_dir.exists() {
            stats.file_count = count_files_recursive(&data_dir).await?;
            stats.file_bytes = measure_dir_recursive(&data_dir).await?;
        }

        Ok(stats)
    }

    async fn chunk_size(&self, digest: &ChunkDigest) -> StorageResult<u64> {
        let path = self.chunk_path(digest);
        match fs::metadata(&path).await {
            Ok(metadata) => Ok(metadata.len()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(StorageError::ChunkNotFound(digest.to_hex()))
            }
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    #[instrument(skip(self))]
    async fn read_file(&self, path: &str) -> StorageResult<Bytes> {
        let file_path = self.file_path(path);

        match fs::read(&file_path).await {
            Ok(data) => Ok(Bytes::from(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(StorageError::BlobNotFound(path.to_string()))
            }
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    async fn file_size(&self, path: &str) -> StorageResult<u64> {
        let file_path = self.file_path(path);
        match fs::metadata(&file_path).await {
            Ok(metadata) => Ok(metadata.len()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(StorageError::BlobNotFound(path.to_string()))
            }
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    #[instrument(skip(self, data), fields(path = %path, size = data.len()))]
    async fn write_file(&self, path: &str, data: Bytes) -> StorageResult<()> {
        let file_path = self.file_path(path);

        // Ensure parent directory exists
        self.ensure_parent(&file_path).await?;

        // Write atomically
        let temp_path = file_path.with_extension("tmp");

        let mut file = fs::File::create(&temp_path).await?;
        file.write_all(&data).await?;
        file.sync_all().await?;
        drop(file);

        fs::rename(&temp_path, &file_path).await?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_file(&self, path: &str) -> StorageResult<()> {
        let file_path = self.file_path(path);

        match fs::remove_file(&file_path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    async fn file_exists(&self, path: &str) -> StorageResult<bool> {
        let file_path = self.file_path(path);
        Ok(file_path.exists())
    }

    async fn list_files(&self, prefix: &str) -> StorageResult<Vec<String>> {
        let base_path = self.file_path(prefix);
        let data_dir = self.root.join("data");

        if !base_path.exists() {
            return Ok(Vec::new());
        }

        let files = list_files_recursive(&base_path, &data_dir).await?;
        Ok(files)
    }
}

/// Recursively count files in a directory
async fn count_files_recursive(dir: &Path) -> StorageResult<u64> {
    let mut count = 0;
    let mut entries = fs::read_dir(dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        let file_type = entry.file_type().await?;
        if file_type.is_file() {
            count += 1;
        } else if file_type.is_dir() {
            count += Box::pin(count_files_recursive(&entry.path())).await?;
        }
    }

    Ok(count)
}

/// Recursively measure directory size
async fn measure_dir_recursive(dir: &Path) -> StorageResult<u64> {
    let mut size = 0;
    let mut entries = fs::read_dir(dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        let file_type = entry.file_type().await?;
        if file_type.is_file() {
            size += entry.metadata().await?.len();
        } else if file_type.is_dir() {
            size += Box::pin(measure_dir_recursive(&entry.path())).await?;
        }
    }

    Ok(size)
}

/// Recursively list files, returning paths relative to base
async fn list_files_recursive(dir: &Path, base: &Path) -> StorageResult<Vec<String>> {
    let mut files = Vec::new();

    if !dir.exists() {
        return Ok(files);
    }

    let mut entries = fs::read_dir(dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        let file_type = entry.file_type().await?;
        let path = entry.path();

        if file_type.is_file() {
            if let Ok(relative) = path.strip_prefix(base) {
                files.push(relative.to_string_lossy().to_string());
            }
        } else if file_type.is_dir() {
            let mut sub_files = Box::pin(list_files_recursive(&path, base)).await?;
            files.append(&mut sub_files);
        }
    }

    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_chunk_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalBackend::new_lazy(temp_dir.path()).await.unwrap();

        let data = Bytes::from("test chunk data");
        let digest = ChunkDigest::from_data(&data);

        // Write
        let was_new = backend.write_chunk(&digest, data.clone()).await.unwrap();
        assert!(was_new);

        // Exists
        assert!(backend.chunk_exists(&digest).await.unwrap());

        // Read
        let read_data = backend.read_chunk(&digest).await.unwrap();
        assert_eq!(data, read_data);

        // Write again (should be dedup'd)
        let was_new = backend.write_chunk(&digest, data.clone()).await.unwrap();
        assert!(!was_new);

        // Delete
        backend.delete_chunk(&digest).await.unwrap();
        assert!(!backend.chunk_exists(&digest).await.unwrap());
    }

    #[tokio::test]
    async fn test_file_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalBackend::new_lazy(temp_dir.path()).await.unwrap();

        let path = "vm/100/2024-01-01/index.json.blob";
        let data = Bytes::from(r#"{"test": true}"#);

        // Write
        backend.write_file(path, data.clone()).await.unwrap();

        // Exists
        assert!(backend.file_exists(path).await.unwrap());

        // Read
        let read_data = backend.read_file(path).await.unwrap();
        assert_eq!(data, read_data);

        // List
        let files = backend.list_files("vm/100").await.unwrap();
        assert!(files.iter().any(|f| f.contains("index.json.blob")));

        // Delete
        backend.delete_file(path).await.unwrap();
        assert!(!backend.file_exists(path).await.unwrap());
    }

    #[tokio::test]
    async fn test_list_chunks() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalBackend::new_lazy(temp_dir.path()).await.unwrap();

        // Write some chunks
        for i in 0..5 {
            let data = Bytes::from(format!("chunk data {}", i));
            let digest = ChunkDigest::from_data(&data);
            backend.write_chunk(&digest, data).await.unwrap();
        }

        // List
        let chunks = backend.list_chunks().await.unwrap();
        assert_eq!(chunks.len(), 5);
    }
}
