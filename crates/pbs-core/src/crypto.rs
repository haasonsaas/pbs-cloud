//! Cryptographic primitives for PBS-compatible encryption
//!
//! PBS uses AES-256-GCM for encryption and zstd for compression.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use scrypt::{scrypt, Params as ScryptParams};
use zstd::stream::{decode_all, encode_all};

use crate::error::{Error, Result};

/// 256-bit encryption key
#[derive(Clone)]
pub struct EncryptionKey([u8; 32]);

impl EncryptionKey {
    /// Create a new random encryption key
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self(key)
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Derive a key from a password using scrypt (PBS-compatible KDF)
    pub fn from_password(password: &str, salt: &[u8]) -> Result<Self> {
        let params = ScryptParams::recommended()
            .map_err(|e| Error::Encryption(e.to_string()))?;
        let mut key = [0u8; 32];
        scrypt(password.as_bytes(), salt, &params, &mut key)
            .map_err(|e| Error::Encryption(e.to_string()))?;
        Ok(Self(key))
    }

    /// Get the raw key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Cryptographic configuration
#[derive(Clone)]
pub struct CryptoConfig {
    /// Optional encryption key
    pub key: Option<EncryptionKey>,
    /// Compression level (0-22, default 3)
    pub compression_level: i32,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            key: None,
            compression_level: 3,
        }
    }
}

impl CryptoConfig {
    /// Create config with encryption enabled
    pub fn with_encryption(key: EncryptionKey) -> Self {
        Self {
            key: Some(key),
            compression_level: 3,
        }
    }

    /// Compress data using zstd
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        encode_all(data, self.compression_level)
            .map_err(|e| Error::Compression(e.to_string()))
    }

    /// Decompress data using zstd
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        decode_all(data)
            .map_err(|e| Error::Decompression(e.to_string()))
    }

    /// Encrypt data using AES-256-GCM
    /// Returns (iv, tag, ciphertext)
    pub fn encrypt(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let key = self.key.as_ref()
            .ok_or_else(|| Error::Encryption("No encryption key configured".into()))?;

        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| Error::Encryption(e.to_string()))?;

        // Generate random 96-bit nonce (12 bytes, padded to 16 for PBS compat)
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv[..12]);

        let nonce = Nonce::from_slice(&iv[..12]);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| Error::Encryption(e.to_string()))?;

        // AES-GCM appends the 16-byte tag to ciphertext
        let tag_start = ciphertext.len() - 16;
        let tag = ciphertext[tag_start..].to_vec();
        let encrypted_data = ciphertext[..tag_start].to_vec();

        Ok((iv.to_vec(), tag, encrypted_data))
    }

    /// Decrypt data using AES-256-GCM
    pub fn decrypt(&self, iv: &[u8], tag: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let key = self.key.as_ref()
            .ok_or_else(|| Error::Decryption("No encryption key configured".into()))?;

        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| Error::Decryption(e.to_string()))?;

        let nonce = Nonce::from_slice(&iv[..12]);

        // Reconstruct the ciphertext with tag appended
        let mut full_ciphertext = ciphertext.to_vec();
        full_ciphertext.extend_from_slice(tag);

        cipher
            .decrypt(nonce, full_ciphertext.as_ref())
            .map_err(|e| Error::Decryption(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_roundtrip() {
        let config = CryptoConfig::default();
        let data = b"Hello, world! This is test data for compression.";

        let compressed = config.compress(data).unwrap();
        let decompressed = config.decompress(&compressed).unwrap();

        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_encryption_roundtrip() {
        let key = EncryptionKey::generate();
        let config = CryptoConfig::with_encryption(key);
        let data = b"Secret message for encryption test";

        let (iv, tag, ciphertext) = config.encrypt(data).unwrap();
        let decrypted = config.decrypt(&iv, &tag, &ciphertext).unwrap();

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }
}
