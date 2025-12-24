//! Index file formats for chunk references
//!
//! PBS uses two types of indexes:
//! - Fixed Index (.fidx): For VM disk images with fixed-size chunks
//! - Dynamic Index (.didx): For file archives with variable-size chunks

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::chunk::ChunkDigest;
use crate::error::{Error, Result};

/// Magic bytes for fixed index files
const FIXED_INDEX_MAGIC: [u8; 8] = [47, 127, 65, 237, 145, 253, 15, 205];

/// Magic bytes for dynamic index files
const DYNAMIC_INDEX_MAGIC: [u8; 8] = [33, 137, 82, 103, 200, 15, 71, 161];

/// An entry in a dynamic index
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct IndexEntry {
    /// Chunk digest
    pub digest: ChunkDigest,
    /// Offset in the original data
    pub offset: u64,
    /// Size of the chunk
    pub size: u64,
}

/// Fixed Index for VM disk images
///
/// Header format:
/// - MAGIC: [u8; 8]
/// - uuid: [u8; 16]
/// - ctime: i64 (epoch seconds)
/// - index_csum: [u8; 32] (SHA-256 of all digests)
/// - size: u64 (total image size)
/// - chunk_size: u64
/// - Followed by: [ChunkDigest; N]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixedIndex {
    /// Unique identifier
    pub uuid: Uuid,
    /// Creation time
    pub ctime: DateTime<Utc>,
    /// Total size of the indexed data
    pub size: u64,
    /// Size of each chunk (fixed)
    pub chunk_size: u64,
    /// List of chunk digests in order
    pub digests: Vec<ChunkDigest>,
}

impl FixedIndex {
    /// Create a new fixed index
    pub fn new(chunk_size: u64) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            ctime: Utc::now(),
            size: 0,
            chunk_size,
            digests: Vec::new(),
        }
    }

    /// Add a chunk digest
    pub fn push(&mut self, digest: ChunkDigest, chunk_size: u64) {
        self.digests.push(digest);
        self.size += chunk_size;
    }

    /// Get the number of chunks
    pub fn chunk_count(&self) -> usize {
        self.digests.len()
    }

    /// Calculate the index checksum (SHA-256 of all digests)
    fn compute_checksum(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for digest in &self.digests {
            hasher.update(digest.as_bytes());
        }
        let result = hasher.finalize();
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&result);
        checksum
    }

    /// Serialize to wire format
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Magic
        result.extend_from_slice(&FIXED_INDEX_MAGIC);

        // UUID
        result.extend_from_slice(self.uuid.as_bytes());

        // Creation time (epoch seconds)
        let ctime = self.ctime.timestamp();
        result.extend_from_slice(&ctime.to_le_bytes());

        // Index checksum
        let checksum = self.compute_checksum();
        result.extend_from_slice(&checksum);

        // Size
        result.extend_from_slice(&self.size.to_le_bytes());

        // Chunk size
        result.extend_from_slice(&self.chunk_size.to_le_bytes());

        // Digests
        for digest in &self.digests {
            result.extend_from_slice(digest.as_bytes());
        }

        result
    }

    /// Parse from wire format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        const HEADER_SIZE: usize = 8 + 16 + 8 + 32 + 8 + 8; // 80 bytes

        if bytes.len() < HEADER_SIZE {
            return Err(Error::IndexCorrupted("Fixed index too short".into()));
        }

        // Check magic
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[..8]);
        if magic != FIXED_INDEX_MAGIC {
            return Err(Error::InvalidMagic {
                expected: FIXED_INDEX_MAGIC,
                got: magic,
            });
        }

        // Parse UUID
        let uuid =
            Uuid::from_slice(&bytes[8..24]).map_err(|e| Error::IndexCorrupted(e.to_string()))?;

        // Parse ctime (slice is exactly 8 bytes, guaranteed by HEADER_SIZE check)
        let ctime_secs = i64::from_le_bytes(bytes[24..32].try_into().expect("slice is 8 bytes"));
        let ctime = DateTime::from_timestamp(ctime_secs, 0)
            .ok_or_else(|| Error::IndexCorrupted("Invalid timestamp".into()))?;

        // Skip stored checksum (we'll verify after parsing)
        let stored_checksum: [u8; 32] = bytes[32..64].try_into().expect("slice is 32 bytes");

        // Parse size
        let size = u64::from_le_bytes(bytes[64..72].try_into().expect("slice is 8 bytes"));

        // Parse chunk size
        let chunk_size = u64::from_le_bytes(bytes[72..80].try_into().expect("slice is 8 bytes"));

        // Parse digests
        let digest_bytes = &bytes[HEADER_SIZE..];
        if !digest_bytes.len().is_multiple_of(32) {
            return Err(Error::IndexCorrupted("Invalid digest data length".into()));
        }

        let mut digests = Vec::new();
        for chunk in digest_bytes.chunks(32) {
            let mut digest_bytes = [0u8; 32];
            digest_bytes.copy_from_slice(chunk);
            digests.push(ChunkDigest::from_bytes(digest_bytes));
        }

        let index = Self {
            uuid,
            ctime,
            size,
            chunk_size,
            digests,
        };

        // Verify checksum
        let computed_checksum = index.compute_checksum();
        if computed_checksum != stored_checksum {
            return Err(Error::IndexCorrupted("Checksum mismatch".into()));
        }

        Ok(index)
    }

    /// Get unique digests (for deduplication)
    pub fn unique_digests(&self) -> Vec<ChunkDigest> {
        let mut unique: Vec<ChunkDigest> = self.digests.clone();
        unique.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        unique.dedup();
        unique
    }
}

/// Dynamic Index for file archives
///
/// Similar to FixedIndex but with variable-size chunks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicIndex {
    /// Unique identifier
    pub uuid: Uuid,
    /// Creation time
    pub ctime: DateTime<Utc>,
    /// Index entries with offset and size
    pub entries: Vec<IndexEntry>,
}

impl DynamicIndex {
    /// Create a new dynamic index
    pub fn new() -> Self {
        Self {
            uuid: Uuid::new_v4(),
            ctime: Utc::now(),
            entries: Vec::new(),
        }
    }

    /// Add an entry
    pub fn push(&mut self, digest: ChunkDigest, offset: u64, size: u64) {
        self.entries.push(IndexEntry {
            digest,
            offset,
            size,
        });
    }

    /// Get total size
    pub fn total_size(&self) -> u64 {
        self.entries.iter().map(|e| e.size).sum()
    }

    /// Get the number of chunks
    pub fn chunk_count(&self) -> usize {
        self.entries.len()
    }

    /// Calculate the index checksum
    fn compute_checksum(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for entry in &self.entries {
            hasher.update(entry.digest.as_bytes());
            hasher.update(entry.offset.to_le_bytes());
            hasher.update(entry.size.to_le_bytes());
        }
        let result = hasher.finalize();
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&result);
        checksum
    }

    /// Serialize to wire format
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Magic
        result.extend_from_slice(&DYNAMIC_INDEX_MAGIC);

        // UUID
        result.extend_from_slice(self.uuid.as_bytes());

        // Creation time
        let ctime = self.ctime.timestamp();
        result.extend_from_slice(&ctime.to_le_bytes());

        // Checksum
        let checksum = self.compute_checksum();
        result.extend_from_slice(&checksum);

        // Entry count
        let count = self.entries.len() as u64;
        result.extend_from_slice(&count.to_le_bytes());

        // Entries
        for entry in &self.entries {
            result.extend_from_slice(entry.digest.as_bytes());
            result.extend_from_slice(&entry.offset.to_le_bytes());
            result.extend_from_slice(&entry.size.to_le_bytes());
        }

        result
    }

    /// Parse from wire format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        const HEADER_SIZE: usize = 8 + 16 + 8 + 32 + 8; // 72 bytes

        if bytes.len() < HEADER_SIZE {
            return Err(Error::IndexCorrupted("Dynamic index too short".into()));
        }

        // Check magic
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[..8]);
        if magic != DYNAMIC_INDEX_MAGIC {
            return Err(Error::InvalidMagic {
                expected: DYNAMIC_INDEX_MAGIC,
                got: magic,
            });
        }

        // Parse UUID
        let uuid =
            Uuid::from_slice(&bytes[8..24]).map_err(|e| Error::IndexCorrupted(e.to_string()))?;

        // Parse ctime (slice is exactly 8 bytes, guaranteed by HEADER_SIZE check)
        let ctime_secs = i64::from_le_bytes(bytes[24..32].try_into().expect("slice is 8 bytes"));
        let ctime = DateTime::from_timestamp(ctime_secs, 0)
            .ok_or_else(|| Error::IndexCorrupted("Invalid timestamp".into()))?;

        // Store checksum for verification
        let stored_checksum: [u8; 32] = bytes[32..64].try_into().expect("slice is 32 bytes");

        // Parse entry count
        let count =
            u64::from_le_bytes(bytes[64..72].try_into().expect("slice is 8 bytes")) as usize;

        // Parse entries
        let entry_size = 32 + 8 + 8; // digest + offset + size
        let expected_len = HEADER_SIZE + count * entry_size;
        if bytes.len() < expected_len {
            return Err(Error::IndexCorrupted("Not enough entry data".into()));
        }

        let mut entries = Vec::with_capacity(count);
        let mut pos = HEADER_SIZE;
        for _ in 0..count {
            let mut digest_bytes = [0u8; 32];
            digest_bytes.copy_from_slice(&bytes[pos..pos + 32]);
            let digest = ChunkDigest::from_bytes(digest_bytes);
            pos += 32;

            // Safe: length verified by expected_len check above
            let offset =
                u64::from_le_bytes(bytes[pos..pos + 8].try_into().expect("slice is 8 bytes"));
            pos += 8;

            let size =
                u64::from_le_bytes(bytes[pos..pos + 8].try_into().expect("slice is 8 bytes"));
            pos += 8;

            entries.push(IndexEntry {
                digest,
                offset,
                size,
            });
        }

        let index = Self {
            uuid,
            ctime,
            entries,
        };

        // Verify checksum
        let computed_checksum = index.compute_checksum();
        if computed_checksum != stored_checksum {
            return Err(Error::IndexCorrupted("Checksum mismatch".into()));
        }

        Ok(index)
    }

    /// Get unique digests (for deduplication)
    pub fn unique_digests(&self) -> Vec<ChunkDigest> {
        let mut unique: Vec<ChunkDigest> = self.entries.iter().map(|e| e.digest).collect();
        unique.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        unique.dedup();
        unique
    }
}

impl Default for DynamicIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_index_roundtrip() {
        let mut index = FixedIndex::new(4 * 1024 * 1024); // 4 MiB chunks

        // Add some chunks
        for i in 0..10 {
            let data = format!("chunk data {}", i);
            let digest = ChunkDigest::from_data(data.as_bytes());
            index.push(digest, 4 * 1024 * 1024);
        }

        // Serialize and parse
        let bytes = index.to_bytes();
        let parsed = FixedIndex::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.uuid, index.uuid);
        assert_eq!(parsed.chunk_size, index.chunk_size);
        assert_eq!(parsed.digests.len(), index.digests.len());
    }

    #[test]
    fn test_dynamic_index_roundtrip() {
        let mut index = DynamicIndex::new();

        // Add some entries
        let mut offset = 0u64;
        for i in 0..10 {
            let data = format!("dynamic chunk {}", i);
            let digest = ChunkDigest::from_data(data.as_bytes());
            let size = (1000 + i * 100) as u64;
            index.push(digest, offset, size);
            offset += size;
        }

        // Serialize and parse
        let bytes = index.to_bytes();
        let parsed = DynamicIndex::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.uuid, index.uuid);
        assert_eq!(parsed.entries.len(), index.entries.len());
    }
}
