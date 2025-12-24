//! PBS-compatible core data structures
//!
//! This crate implements the data formats used by Proxmox Backup Server,
//! enabling wire-compatible backups and restores.

pub mod blob;
pub mod chunk;
pub mod crypto;
pub mod error;
pub mod index;
pub mod manifest;

pub use blob::{DataBlob, BlobType};
pub use chunk::{Chunk, ChunkDigest, CHUNK_SIZE_MIN, CHUNK_SIZE_MAX, CHUNK_SIZE_DEFAULT};
pub use crypto::{CryptoConfig, EncryptionKey};
pub use error::{Error, Result};
pub use index::{DynamicIndex, FixedIndex, IndexEntry};
pub use manifest::{BackupManifest, FileType, ManifestFile};
