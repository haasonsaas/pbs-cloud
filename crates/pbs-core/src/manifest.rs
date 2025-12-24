//! Backup Manifest
//!
//! The manifest is the top-level description of a backup snapshot.
//! It lists all files (blobs and indexes) that make up the backup.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use chrono::{DateTime, Utc};

use crate::error::Result;

/// Type of file in the backup
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileType {
    /// Fixed-size index (.fidx)
    Fidx,
    /// Dynamic-size index (.didx)
    Didx,
    /// Blob file (.blob)
    Blob,
}

impl FileType {
    /// Get file extension for this type
    pub fn extension(&self) -> &'static str {
        match self {
            FileType::Fidx => "fidx",
            FileType::Didx => "didx",
            FileType::Blob => "blob",
        }
    }

    /// Parse from file extension
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            "fidx" => Some(FileType::Fidx),
            "didx" => Some(FileType::Didx),
            "blob" => Some(FileType::Blob),
            _ => None,
        }
    }
}

/// A file entry in the manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFile {
    /// File name
    pub filename: String,
    /// File type
    #[serde(rename = "type")]
    pub file_type: FileType,
    /// Size in bytes
    pub size: u64,
    /// SHA-256 checksum of the file
    #[serde(with = "hex_serde")]
    pub csum: [u8; 32],
}

/// Hex serialization for checksums
mod hex_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Invalid checksum length"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Backup manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    /// Backup type (e.g., "vm", "ct", "host")
    pub backup_type: String,
    /// Backup ID (e.g., VM ID or hostname)
    pub backup_id: String,
    /// Backup timestamp
    pub backup_time: DateTime<Utc>,
    /// List of files in the backup
    pub files: Vec<ManifestFile>,
    /// Optional unprotected data (JSON value)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unprotected: Option<serde_json::Value>,
    /// Manifest signature (if encrypted)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "option_hex_serde")]
    pub signature: Option<[u8; 32]>,
}

mod option_hex_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => serializer.serialize_str(&hex::encode(b)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom("Invalid signature length"));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

impl BackupManifest {
    /// Create a new manifest
    pub fn new(backup_type: &str, backup_id: &str) -> Self {
        Self {
            backup_type: backup_type.to_string(),
            backup_id: backup_id.to_string(),
            backup_time: Utc::now(),
            files: Vec::new(),
            unprotected: None,
            signature: None,
        }
    }

    /// Add a file to the manifest
    pub fn add_file(&mut self, filename: &str, file_type: FileType, size: u64, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut csum = [0u8; 32];
        csum.copy_from_slice(&result);

        self.files.push(ManifestFile {
            filename: filename.to_string(),
            file_type,
            size,
            csum,
        });
    }

    /// Get snapshot path: <type>/<id>/<timestamp>
    pub fn snapshot_path(&self) -> String {
        format!(
            "{}/{}/{}",
            self.backup_type,
            self.backup_id,
            self.backup_time.format("%Y-%m-%dT%H:%M:%SZ")
        )
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    /// Get all index files
    pub fn index_files(&self) -> Vec<&ManifestFile> {
        self.files
            .iter()
            .filter(|f| matches!(f.file_type, FileType::Fidx | FileType::Didx))
            .collect()
    }

    /// Get all blob files
    pub fn blob_files(&self) -> Vec<&ManifestFile> {
        self.files
            .iter()
            .filter(|f| f.file_type == FileType::Blob)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_json_roundtrip() {
        let mut manifest = BackupManifest::new("vm", "100");

        manifest.add_file("disk-0.fidx", FileType::Fidx, 1024, b"test data");
        manifest.add_file("qemu-server.conf.blob", FileType::Blob, 256, b"config");

        let json = manifest.to_json().unwrap();
        let parsed = BackupManifest::from_json(&json).unwrap();

        assert_eq!(parsed.backup_type, manifest.backup_type);
        assert_eq!(parsed.backup_id, manifest.backup_id);
        assert_eq!(parsed.files.len(), manifest.files.len());
    }

    #[test]
    fn test_snapshot_path() {
        let manifest = BackupManifest::new("vm", "100");
        let path = manifest.snapshot_path();

        assert!(path.starts_with("vm/100/"));
    }
}
