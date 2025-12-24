//! Storage backends for PBS-compatible backup server
//!
//! This crate provides pluggable storage backends for chunk and blob storage.
//! The primary backend is S3-compatible object storage.

pub mod backend;
pub mod datastore;
pub mod error;
pub mod s3;

pub use backend::{StorageBackend, ChunkReader, ChunkWriter};
pub use datastore::Datastore;
pub use error::{StorageError, StorageResult};
