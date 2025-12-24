//! Chunk handling for content-addressable storage
//!
//! Chunks are the fundamental unit of deduplication in PBS.
//! Each chunk is identified by its SHA-256 digest.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

use crate::error::{Error, Result};

/// Minimum chunk size (64 KiB)
pub const CHUNK_SIZE_MIN: usize = 64 * 1024;

/// Maximum chunk size (16 MiB)
pub const CHUNK_SIZE_MAX: usize = 16 * 1024 * 1024;

/// Default chunk size for fixed-size chunking (4 MiB)
pub const CHUNK_SIZE_DEFAULT: usize = 4 * 1024 * 1024;

/// SHA-256 digest identifying a chunk
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChunkDigest([u8; 32]);

impl ChunkDigest {
    /// Compute digest from data
    pub fn from_data(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        Self(digest)
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| Error::InvalidDigest(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(Error::InvalidDigest(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes);
        Ok(Self(digest))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Get the storage prefix (first 4 hex chars, i.e., first 2 bytes)
    /// Used for directory sharding: .chunks/a342/...
    pub fn storage_prefix(&self) -> String {
        hex::encode(&self.0[..2])
    }
}

impl fmt::Display for ChunkDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for ChunkDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChunkDigest({})", &self.to_hex()[..16])
    }
}

/// A chunk of backup data
#[derive(Clone)]
pub struct Chunk {
    /// The chunk's digest (SHA-256 of raw data)
    digest: ChunkDigest,
    /// Raw (unencrypted, uncompressed) data
    data: Vec<u8>,
}

impl Chunk {
    /// Create a new chunk from raw data
    pub fn new(data: Vec<u8>) -> Result<Self> {
        if data.len() > CHUNK_SIZE_MAX {
            return Err(Error::ChunkSizeOutOfRange {
                size: data.len(),
                min: 0,
                max: CHUNK_SIZE_MAX,
            });
        }

        let digest = ChunkDigest::from_data(&data);
        Ok(Self { digest, data })
    }

    /// Get the chunk's digest
    pub fn digest(&self) -> &ChunkDigest {
        &self.digest
    }

    /// Get the raw data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the size of the raw data
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Consume and return the data
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

/// Rolling hash for dynamic chunking (Buzhash variant)
pub struct RollingHash {
    /// Current hash value
    hash: u64,
    /// Window of bytes
    window: Vec<u8>,
    /// Window position
    pos: usize,
    /// Window size
    window_size: usize,
    /// Lookup table for Buzhash
    table: [u64; 256],
}

impl RollingHash {
    /// Create a new rolling hash with the given window size
    pub fn new(window_size: usize) -> Self {
        // Initialize Buzhash table with pseudo-random values
        let mut table = [0u64; 256];
        let mut state = 0x123456789abcdef0u64;
        for item in &mut table {
            // Simple PRNG for table initialization
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            *item = state;
        }

        Self {
            hash: 0,
            window: vec![0; window_size],
            pos: 0,
            window_size,
            table,
        }
    }

    /// Add a byte and return the new hash
    pub fn roll(&mut self, byte: u8) -> u64 {
        let old_byte = self.window[self.pos];

        // Update hash: rotate left, XOR out old byte, XOR in new byte
        self.hash = self.hash.rotate_left(1)
            ^ self.table[old_byte as usize].rotate_left(self.window_size as u32)
            ^ self.table[byte as usize];

        // Update window
        self.window[self.pos] = byte;
        self.pos = (self.pos + 1) % self.window_size;

        self.hash
    }

    /// Check if current position is a chunk boundary
    /// Uses low bits of hash to determine boundary
    pub fn is_boundary(&self, mask: u64) -> bool {
        (self.hash & mask) == 0
    }

    /// Reset the hash state
    pub fn reset(&mut self) {
        self.hash = 0;
        self.window.fill(0);
        self.pos = 0;
    }
}

/// Dynamic chunker for variable-size chunks
pub struct DynamicChunker {
    rolling_hash: RollingHash,
    /// Minimum chunk size
    min_size: usize,
    /// Maximum chunk size
    max_size: usize,
    /// Mask for boundary detection (determines average chunk size)
    mask: u64,
}

impl DynamicChunker {
    /// Create a new dynamic chunker
    ///
    /// `avg_size` determines the average chunk size (must be power of 2)
    pub fn new(min_size: usize, max_size: usize, avg_size: usize) -> Self {
        // Mask is avg_size - 1 (e.g., 64K -> 0xFFFF)
        let mask = (avg_size - 1) as u64;

        Self {
            rolling_hash: RollingHash::new(48), // 48-byte window like PBS
            min_size,
            max_size,
            mask,
        }
    }

    /// Chunk the input data into variable-size chunks
    pub fn chunk(&mut self, data: &[u8]) -> Vec<Chunk> {
        let mut chunks = Vec::new();
        let mut start = 0;

        self.rolling_hash.reset();

        for (i, &byte) in data.iter().enumerate() {
            self.rolling_hash.roll(byte);

            let chunk_len = i - start + 1;

            // Check for chunk boundary
            let is_boundary = chunk_len >= self.min_size
                && (chunk_len >= self.max_size || self.rolling_hash.is_boundary(self.mask));

            if is_boundary {
                if let Ok(chunk) = Chunk::new(data[start..=i].to_vec()) {
                    chunks.push(chunk);
                }
                start = i + 1;
                self.rolling_hash.reset();
            }
        }

        // Handle remaining data
        if start < data.len() {
            if let Ok(chunk) = Chunk::new(data[start..].to_vec()) {
                chunks.push(chunk);
            }
        }

        chunks
    }
}

/// Fixed-size chunker for VM disk images
pub struct FixedChunker {
    chunk_size: usize,
}

impl FixedChunker {
    /// Create a new fixed chunker with the given chunk size
    pub fn new(chunk_size: usize) -> Self {
        Self { chunk_size }
    }

    /// Chunk the input data into fixed-size chunks
    pub fn chunk(&self, data: &[u8]) -> Vec<Chunk> {
        data.chunks(self.chunk_size)
            .filter_map(|chunk_data| Chunk::new(chunk_data.to_vec()).ok())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_digest() {
        let data = b"Hello, world!";
        let digest = ChunkDigest::from_data(data);

        // Verify it's deterministic
        let digest2 = ChunkDigest::from_data(data);
        assert_eq!(digest, digest2);

        // Verify hex roundtrip
        let hex = digest.to_hex();
        let parsed = ChunkDigest::from_hex(&hex).unwrap();
        assert_eq!(digest, parsed);
    }

    #[test]
    fn test_fixed_chunker() {
        let data = vec![0u8; 1024 * 10]; // 10 KiB
        let chunker = FixedChunker::new(1024); // 1 KiB chunks
        let chunks = chunker.chunk(&data);

        assert_eq!(chunks.len(), 10);
        for chunk in &chunks {
            assert_eq!(chunk.size(), 1024);
        }
    }

    #[test]
    fn test_storage_prefix() {
        let digest = ChunkDigest::from_data(b"test");
        let prefix = digest.storage_prefix();
        assert_eq!(prefix.len(), 4);
        assert!(prefix.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
