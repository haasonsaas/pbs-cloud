//! Error types for pbs-core

use thiserror::Error;

/// Core error type
#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid magic bytes: expected {expected:?}, got {got:?}")]
    InvalidMagic { expected: [u8; 8], got: [u8; 8] },

    #[error("CRC32 mismatch: expected {expected:#x}, got {got:#x}")]
    CrcMismatch { expected: u32, got: u32 },

    #[error("Chunk size {size} out of range [{min}, {max}]")]
    ChunkSizeOutOfRange { size: usize, min: usize, max: usize },

    #[error("Data too large: {size} bytes exceeds maximum {max} bytes")]
    DataTooLarge { size: usize, max: usize },

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Compression error: {0}")]
    Compression(String),

    #[error("Decompression error: {0}")]
    Decompression(String),

    #[error("Invalid digest: {0}")]
    InvalidDigest(String),

    #[error("Index corrupted: {0}")]
    IndexCorrupted(String),

    #[error("Manifest error: {0}")]
    Manifest(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Result type alias
pub type Result<T> = std::result::Result<T, Error>;
