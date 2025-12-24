//! Storage backends for PBS-compatible backup server
//!
//! This crate provides pluggable storage backends for chunk and blob storage.
//! Supports both S3-compatible and local filesystem storage.

pub mod backend;
pub mod datastore;
pub mod error;
pub mod gc;
pub mod local;
pub mod s3;

pub use backend::{BackendStats, ChunkReader, ChunkWriter, StorageBackend};
pub use datastore::{BackupGroup, Datastore};
pub use error::{StorageError, StorageResult};
pub use gc::{GarbageCollector, GcOptions, GcResult, Pruner, PruneOptions, PruneResult};
pub use local::LocalBackend;
pub use s3::{S3Backend, S3Config};
