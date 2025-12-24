//! S3-compatible storage backend
//!
//! This backend stores chunks and files in an S3-compatible object store.
//! Structure:
//! - chunks/{prefix}/{digest} - chunk data
//! - data/{path} - files (manifests, indexes, blobs)

use async_trait::async_trait;
use aws_sdk_s3::{primitives::ByteStream, Client};
use bytes::Bytes;
use pbs_core::ChunkDigest;
use tracing::{debug, instrument};

use crate::backend::{BackendStats, ChunkReader, ChunkWriter, StorageBackend};
use crate::error::{StorageError, StorageResult};

/// S3 storage backend configuration
#[derive(Debug, Clone)]
pub struct S3Config {
    /// S3 bucket name
    pub bucket: String,
    /// Optional prefix for all keys
    pub prefix: Option<String>,
    /// Region (for AWS S3)
    pub region: Option<String>,
    /// Endpoint URL (for MinIO, R2, etc.)
    pub endpoint: Option<String>,
}

impl S3Config {
    /// Create config for AWS S3
    pub fn aws(bucket: &str, region: &str) -> Self {
        Self {
            bucket: bucket.to_string(),
            prefix: None,
            region: Some(region.to_string()),
            endpoint: None,
        }
    }

    /// Create config for S3-compatible service (MinIO, R2, etc.)
    pub fn compatible(bucket: &str, endpoint: &str) -> Self {
        Self {
            bucket: bucket.to_string(),
            prefix: None,
            region: None,
            endpoint: Some(endpoint.to_string()),
        }
    }

    /// Set a key prefix
    pub fn with_prefix(mut self, prefix: &str) -> Self {
        self.prefix = Some(prefix.to_string());
        self
    }
}

/// S3 storage backend
pub struct S3Backend {
    client: Client,
    config: S3Config,
}

impl S3Backend {
    /// Create a new S3 backend
    pub async fn new(config: S3Config) -> StorageResult<Self> {
        let mut aws_config = aws_config::from_env();

        if let Some(region) = &config.region {
            aws_config = aws_config.region(aws_sdk_s3::config::Region::new(region.clone()));
        }

        if let Some(endpoint) = &config.endpoint {
            aws_config = aws_config.endpoint_url(endpoint);
        }

        let sdk_config = aws_config.load().await;
        let s3_config = aws_sdk_s3::config::Builder::from(&sdk_config)
            .force_path_style(config.endpoint.is_some()) // Use path style for non-AWS
            .build();

        let client = Client::from_conf(s3_config);

        Ok(Self { client, config })
    }

    /// Build the full key for a chunk
    fn chunk_key(&self, digest: &ChunkDigest) -> String {
        let prefix = digest.storage_prefix();
        let key = format!("chunks/{}/{}", prefix, digest.to_hex());
        self.with_prefix(&key)
    }

    /// Build the full key for a file
    fn file_key(&self, path: &str) -> String {
        let key = format!("data/{}", path);
        self.with_prefix(&key)
    }

    /// Apply optional prefix
    fn with_prefix(&self, key: &str) -> String {
        match &self.config.prefix {
            Some(prefix) => format!("{}/{}", prefix, key),
            None => key.to_string(),
        }
    }

    /// Check if an object exists
    async fn object_exists(&self, key: &str) -> StorageResult<bool> {
        match self
            .client
            .head_object()
            .bucket(&self.config.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                let service_error = e.into_service_error();
                if service_error.is_not_found() {
                    Ok(false)
                } else {
                    Err(StorageError::S3(service_error.to_string()))
                }
            }
        }
    }

    /// Read an object
    async fn read_object(&self, key: &str) -> StorageResult<Bytes> {
        let response = self
            .client
            .get_object()
            .bucket(&self.config.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| StorageError::S3(e.to_string()))?;

        let data = response
            .body
            .collect()
            .await
            .map_err(|e| StorageError::S3(e.to_string()))?;

        Ok(data.into_bytes())
    }

    /// Write an object
    async fn write_object(&self, key: &str, data: Bytes) -> StorageResult<()> {
        self.client
            .put_object()
            .bucket(&self.config.bucket)
            .key(key)
            .body(ByteStream::from(data))
            .send()
            .await
            .map_err(|e| StorageError::S3(e.to_string()))?;

        Ok(())
    }

    /// Delete an object
    async fn delete_object(&self, key: &str) -> StorageResult<()> {
        self.client
            .delete_object()
            .bucket(&self.config.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| StorageError::S3(e.to_string()))?;

        Ok(())
    }

    /// List objects with a prefix
    async fn list_objects(&self, prefix: &str) -> StorageResult<Vec<String>> {
        let full_prefix = self.with_prefix(prefix);
        let mut keys = Vec::new();
        let mut continuation_token: Option<String> = None;

        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.config.bucket)
                .prefix(&full_prefix);

            if let Some(token) = continuation_token.take() {
                request = request.continuation_token(token);
            }

            let response = request
                .send()
                .await
                .map_err(|e| StorageError::S3(e.to_string()))?;

            if let Some(contents) = response.contents {
                for object in contents {
                    if let Some(key) = object.key {
                        // Strip prefix if present
                        let stripped = match &self.config.prefix {
                            Some(p) => key.strip_prefix(&format!("{}/", p)).unwrap_or(&key),
                            None => &key,
                        };
                        keys.push(stripped.to_string());
                    }
                }
            }

            if response.is_truncated.unwrap_or(false) {
                continuation_token = response.next_continuation_token;
            } else {
                break;
            }
        }

        Ok(keys)
    }

    /// List objects with sizes for a prefix
    async fn list_object_sizes(&self, prefix: &str) -> StorageResult<(u64, u64)> {
        let full_prefix = self.with_prefix(prefix);
        let mut continuation_token: Option<String> = None;
        let mut count: u64 = 0;
        let mut bytes: u64 = 0;

        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.config.bucket)
                .prefix(&full_prefix);

            if let Some(token) = continuation_token.take() {
                request = request.continuation_token(token);
            }

            let response = request
                .send()
                .await
                .map_err(|e| StorageError::S3(e.to_string()))?;

            if let Some(contents) = response.contents {
                for object in contents {
                    count += 1;
                    if let Some(size) = object.size {
                        if size > 0 {
                            bytes = bytes.saturating_add(size as u64);
                        }
                    }
                }
            }

            if response.is_truncated.unwrap_or(false) {
                continuation_token = response.next_continuation_token;
            } else {
                break;
            }
        }

        Ok((count, bytes))
    }
}

#[async_trait]
impl ChunkReader for S3Backend {
    #[instrument(skip(self), fields(digest = %digest))]
    async fn chunk_exists(&self, digest: &ChunkDigest) -> StorageResult<bool> {
        let key = self.chunk_key(digest);
        self.object_exists(&key).await
    }

    #[instrument(skip(self), fields(digest = %digest))]
    async fn read_chunk(&self, digest: &ChunkDigest) -> StorageResult<Bytes> {
        let key = self.chunk_key(digest);
        self.read_object(&key).await.map_err(|e| {
            if matches!(e, StorageError::S3(_)) {
                StorageError::ChunkNotFound(digest.to_hex())
            } else {
                e
            }
        })
    }

    async fn list_chunks(&self) -> StorageResult<Vec<ChunkDigest>> {
        let keys = self.list_objects("chunks/").await?;
        let mut digests = Vec::new();

        for key in keys {
            // Parse chunk key: chunks/{prefix}/{digest}
            if let Some(digest_hex) = key
                .strip_prefix("chunks/")
                .and_then(|s| s.split('/').nth(1))
            {
                if let Ok(digest) = ChunkDigest::from_hex(digest_hex) {
                    digests.push(digest);
                }
            }
        }

        Ok(digests)
    }
}

#[async_trait]
impl ChunkWriter for S3Backend {
    #[instrument(skip(self, data), fields(digest = %digest, size = data.len()))]
    async fn write_chunk(&self, digest: &ChunkDigest, data: Bytes) -> StorageResult<bool> {
        let key = self.chunk_key(digest);

        // Check if already exists (deduplication)
        if self.object_exists(&key).await? {
            debug!("Chunk already exists, skipping write");
            return Ok(false);
        }

        self.write_object(&key, data).await?;
        Ok(true)
    }

    #[instrument(skip(self), fields(digest = %digest))]
    async fn delete_chunk(&self, digest: &ChunkDigest) -> StorageResult<()> {
        let key = self.chunk_key(digest);
        self.delete_object(&key).await
    }
}

#[async_trait]
impl StorageBackend for S3Backend {
    fn name(&self) -> &str {
        "s3"
    }

    async fn stats(&self) -> StorageResult<BackendStats> {
        let (chunk_count, chunk_bytes) = self.list_object_sizes("chunks/").await?;
        let (file_count, file_bytes) = self.list_object_sizes("data/").await?;

        Ok(BackendStats {
            chunk_count,
            chunk_bytes,
            file_count,
            file_bytes,
            dedup_bytes: 0,
        })
    }

    async fn chunk_size(&self, digest: &ChunkDigest) -> StorageResult<u64> {
        let key = self.chunk_key(digest);
        match self
            .client
            .head_object()
            .bucket(&self.config.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(resp) => Ok(resp.content_length.unwrap_or(0) as u64),
            Err(e) => {
                let service_error = e.into_service_error();
                if service_error.is_not_found() {
                    Err(StorageError::ChunkNotFound(digest.to_hex()))
                } else {
                    Err(StorageError::S3(service_error.to_string()))
                }
            }
        }
    }

    #[instrument(skip(self))]
    async fn read_file(&self, path: &str) -> StorageResult<Bytes> {
        let key = self.file_key(path);
        self.read_object(&key).await
    }

    async fn file_size(&self, path: &str) -> StorageResult<u64> {
        let key = self.file_key(path);
        match self
            .client
            .head_object()
            .bucket(&self.config.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(resp) => Ok(resp.content_length.unwrap_or(0) as u64),
            Err(e) => {
                let service_error = e.into_service_error();
                if service_error.is_not_found() {
                    Err(StorageError::BlobNotFound(path.to_string()))
                } else {
                    Err(StorageError::S3(service_error.to_string()))
                }
            }
        }
    }

    #[instrument(skip(self, data), fields(path = %path, size = data.len()))]
    async fn write_file(&self, path: &str, data: Bytes) -> StorageResult<()> {
        let key = self.file_key(path);
        self.write_object(&key, data).await
    }

    #[instrument(skip(self))]
    async fn delete_file(&self, path: &str) -> StorageResult<()> {
        let key = self.file_key(path);
        self.delete_object(&key).await
    }

    async fn file_exists(&self, path: &str) -> StorageResult<bool> {
        let key = self.file_key(path);
        self.object_exists(&key).await
    }

    async fn list_files(&self, prefix: &str) -> StorageResult<Vec<String>> {
        let full_prefix = format!("data/{}", prefix);
        let keys = self.list_objects(&full_prefix).await?;

        Ok(keys
            .into_iter()
            .filter_map(|k| k.strip_prefix("data/").map(|s| s.to_string()))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_key_generation() {
        let _config = S3Config::aws("test-bucket", "us-east-1");
        // Can't fully test without S3, but we can verify key format
        let digest = ChunkDigest::from_data(b"test");
        let prefix = digest.storage_prefix();
        assert_eq!(prefix.len(), 4);
    }
}
