//! Data Blob format implementation
//!
//! PBS stores small data as blobs with the following format:
//! - Magic bytes (8 bytes) - identifies blob type
//! - CRC32 checksum (4 bytes)
//! - For encrypted: IV (16 bytes) + TAG (16 bytes)
//! - Data (max 16 MiB)

use crc32fast::Hasher;
use serde::{Deserialize, Serialize};

use crate::crypto::CryptoConfig;
use crate::error::{Error, Result};

/// Maximum blob data size (16 MiB)
pub const BLOB_MAX_SIZE: usize = 16 * 1024 * 1024;

/// Magic bytes for different blob types (from PBS docs)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobType {
    /// Unencrypted, uncompressed
    Uncompressed,
    /// Unencrypted, compressed (zstd)
    Compressed,
    /// Encrypted, uncompressed
    EncryptedUncompressed,
    /// Encrypted, compressed
    EncryptedCompressed,
}

impl BlobType {
    /// Get magic bytes for this blob type
    pub fn magic(&self) -> [u8; 8] {
        match self {
            BlobType::Uncompressed => [66, 171, 56, 7, 190, 131, 112, 161],
            BlobType::Compressed => [49, 185, 88, 66, 111, 182, 163, 127],
            BlobType::EncryptedUncompressed => [123, 103, 133, 190, 34, 45, 76, 240],
            BlobType::EncryptedCompressed => [230, 89, 27, 191, 11, 191, 216, 11],
        }
    }

    /// Parse blob type from magic bytes
    pub fn from_magic(magic: &[u8; 8]) -> Option<Self> {
        if *magic == Self::Uncompressed.magic() {
            Some(BlobType::Uncompressed)
        } else if *magic == Self::Compressed.magic() {
            Some(BlobType::Compressed)
        } else if *magic == Self::EncryptedUncompressed.magic() {
            Some(BlobType::EncryptedUncompressed)
        } else if *magic == Self::EncryptedCompressed.magic() {
            Some(BlobType::EncryptedCompressed)
        } else {
            None
        }
    }

    /// Check if this blob type is encrypted
    pub fn is_encrypted(&self) -> bool {
        matches!(
            self,
            BlobType::EncryptedUncompressed | BlobType::EncryptedCompressed
        )
    }

    /// Check if this blob type is compressed
    pub fn is_compressed(&self) -> bool {
        matches!(self, BlobType::Compressed | BlobType::EncryptedCompressed)
    }
}

/// A data blob containing backup data
#[derive(Clone)]
pub struct DataBlob {
    /// Blob type
    blob_type: BlobType,
    /// Raw encoded data (after magic and CRC)
    raw_data: Vec<u8>,
    /// IV for encrypted blobs (16 bytes)
    iv: Option<[u8; 16]>,
    /// Authentication tag for encrypted blobs (16 bytes)
    tag: Option<[u8; 16]>,
}

impl DataBlob {
    /// Create a new blob from raw (unprocessed) data
    pub fn encode(data: &[u8], config: &CryptoConfig, compress: bool) -> Result<Self> {
        if data.len() > BLOB_MAX_SIZE {
            return Err(Error::DataTooLarge {
                size: data.len(),
                max: BLOB_MAX_SIZE,
            });
        }

        let is_encrypted = config.key.is_some();

        // Optionally compress
        let processed_data = if compress {
            config.compress(data)?
        } else {
            data.to_vec()
        };

        // Optionally encrypt
        let (final_data, iv, tag) = if is_encrypted {
            let (iv_vec, tag_vec, ciphertext) = config.encrypt(&processed_data)?;
            let mut iv = [0u8; 16];
            let mut tag = [0u8; 16];
            iv.copy_from_slice(&iv_vec);
            tag.copy_from_slice(&tag_vec);
            (ciphertext, Some(iv), Some(tag))
        } else {
            (processed_data, None, None)
        };

        let blob_type = match (is_encrypted, compress) {
            (false, false) => BlobType::Uncompressed,
            (false, true) => BlobType::Compressed,
            (true, false) => BlobType::EncryptedUncompressed,
            (true, true) => BlobType::EncryptedCompressed,
        };

        Ok(Self {
            blob_type,
            raw_data: final_data,
            iv,
            tag,
        })
    }

    /// Decode a blob back to raw data
    pub fn decode(&self, config: &CryptoConfig) -> Result<Vec<u8>> {
        // Decrypt if needed
        let decrypted = if self.blob_type.is_encrypted() {
            let iv = self
                .iv
                .as_ref()
                .ok_or_else(|| Error::Decryption("Missing IV for encrypted blob".into()))?;
            let tag = self
                .tag
                .as_ref()
                .ok_or_else(|| Error::Decryption("Missing tag for encrypted blob".into()))?;
            config.decrypt(iv, tag, &self.raw_data)?
        } else {
            self.raw_data.clone()
        };

        // Decompress if needed
        if self.blob_type.is_compressed() {
            config.decompress(&decrypted)
        } else {
            Ok(decrypted)
        }
    }

    /// Serialize to wire format
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Magic
        result.extend_from_slice(&self.blob_type.magic());

        // Prepare data for CRC (everything after CRC field)
        let mut crc_data = Vec::new();
        if let Some(iv) = &self.iv {
            crc_data.extend_from_slice(iv);
        }
        if let Some(tag) = &self.tag {
            crc_data.extend_from_slice(tag);
        }
        crc_data.extend_from_slice(&self.raw_data);

        // CRC32
        let mut hasher = Hasher::new();
        hasher.update(&crc_data);
        let crc = hasher.finalize();
        result.extend_from_slice(&crc.to_le_bytes());

        // IV and tag for encrypted blobs
        if let Some(iv) = &self.iv {
            result.extend_from_slice(iv);
        }
        if let Some(tag) = &self.tag {
            result.extend_from_slice(tag);
        }

        // Data
        result.extend_from_slice(&self.raw_data);

        result
    }

    /// Parse from wire format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 12 {
            return Err(Error::IndexCorrupted("Blob too short".into()));
        }

        // Parse magic
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[..8]);
        let blob_type = BlobType::from_magic(&magic).ok_or_else(|| Error::InvalidMagic {
            expected: BlobType::Uncompressed.magic(),
            got: magic,
        })?;

        // Parse CRC
        let crc_expected = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

        let (iv, tag, data_start) = if blob_type.is_encrypted() {
            if bytes.len() < 12 + 32 {
                return Err(Error::IndexCorrupted("Encrypted blob too short".into()));
            }
            let mut iv = [0u8; 16];
            let mut tag = [0u8; 16];
            iv.copy_from_slice(&bytes[12..28]);
            tag.copy_from_slice(&bytes[28..44]);
            (Some(iv), Some(tag), 44)
        } else {
            (None, None, 12)
        };

        let raw_data = bytes[data_start..].to_vec();

        // Verify CRC
        let mut hasher = Hasher::new();
        hasher.update(&bytes[12..]);
        let crc_actual = hasher.finalize();
        if crc_expected != crc_actual {
            return Err(Error::CrcMismatch {
                expected: crc_expected,
                got: crc_actual,
            });
        }

        Ok(Self {
            blob_type,
            raw_data,
            iv,
            tag,
        })
    }

    /// Get the blob type
    pub fn blob_type(&self) -> BlobType {
        self.blob_type
    }

    /// Get the encoded data size
    pub fn encoded_size(&self) -> usize {
        let base = 8 + 4 + self.raw_data.len(); // magic + crc + data
        if self.blob_type.is_encrypted() {
            base + 32 // +iv +tag
        } else {
            base
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::EncryptionKey;

    #[test]
    fn test_blob_uncompressed() {
        let data = b"Hello, world!";
        let config = CryptoConfig::default();

        let blob = DataBlob::encode(data, &config, false).unwrap();
        assert_eq!(blob.blob_type(), BlobType::Uncompressed);

        let decoded = blob.decode(&config).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_blob_compressed() {
        let data = b"Hello, world! This is some data that should compress well. ".repeat(100);
        let config = CryptoConfig::default();

        let blob = DataBlob::encode(&data, &config, true).unwrap();
        assert_eq!(blob.blob_type(), BlobType::Compressed);

        let decoded = blob.decode(&config).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_blob_encrypted() {
        let data = b"Secret data";
        let key = EncryptionKey::generate();
        let config = CryptoConfig::with_encryption(key);

        let blob = DataBlob::encode(data, &config, true).unwrap();
        assert_eq!(blob.blob_type(), BlobType::EncryptedCompressed);

        let decoded = blob.decode(&config).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_blob_wire_format() {
        let data = b"Test data";
        let config = CryptoConfig::default();

        let blob = DataBlob::encode(data, &config, false).unwrap();
        let bytes = blob.to_bytes();
        let parsed = DataBlob::from_bytes(&bytes).unwrap();

        let decoded = parsed.decode(&config).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }
}
