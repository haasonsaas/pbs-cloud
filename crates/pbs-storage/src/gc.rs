//! Garbage collection for orphaned chunks
//!
//! Identifies and removes chunks that are no longer referenced by any index.

use std::collections::HashSet;
use std::sync::Arc;
use pbs_core::ChunkDigest;
use tracing::{info, warn, instrument};

use crate::backend::StorageBackend;
use crate::datastore::Datastore;
use crate::error::{StorageError, StorageResult};

/// Garbage collection options
#[derive(Debug, Clone)]
pub struct GcOptions {
    /// Only report what would be deleted, don't actually delete
    pub dry_run: bool,
    /// Maximum number of chunks to delete in one run
    pub max_delete: Option<usize>,
}

impl Default for GcOptions {
    fn default() -> Self {
        Self {
            dry_run: false,
            max_delete: None,
        }
    }
}

/// Garbage collection result
#[derive(Debug, Clone, Default)]
pub struct GcResult {
    /// Number of chunks scanned
    pub chunks_scanned: u64,
    /// Number of referenced chunks
    pub chunks_referenced: u64,
    /// Number of orphaned chunks found
    pub chunks_orphaned: u64,
    /// Number of chunks deleted
    pub chunks_deleted: u64,
    /// Bytes freed
    pub bytes_freed: u64,
    /// Errors encountered
    pub errors: Vec<String>,
}

/// Garbage collector
pub struct GarbageCollector {
    datastore: Arc<Datastore>,
    backend: Arc<dyn StorageBackend>,
}

impl GarbageCollector {
    /// Create a new garbage collector
    pub fn new(datastore: Arc<Datastore>, backend: Arc<dyn StorageBackend>) -> Self {
        Self { datastore, backend }
    }

    /// Run garbage collection
    #[instrument(skip(self))]
    pub async fn run(&self, options: GcOptions) -> StorageResult<GcResult> {
        let mut result = GcResult::default();

        info!("Starting garbage collection (dry_run={})", options.dry_run);

        // Phase 1: Collect all referenced chunks from all indexes
        info!("Phase 1: Collecting referenced chunks...");
        let referenced_chunks = self.collect_referenced_chunks(&mut result).await?;
        result.chunks_referenced = referenced_chunks.len() as u64;
        info!("Found {} referenced chunks", referenced_chunks.len());

        // Phase 2: List all chunks in storage
        info!("Phase 2: Listing all chunks...");
        let all_chunks = self.backend.list_chunks().await?;
        result.chunks_scanned = all_chunks.len() as u64;
        info!("Found {} total chunks", all_chunks.len());

        // Phase 3: Find orphaned chunks
        info!("Phase 3: Finding orphaned chunks...");
        let mut orphaned_chunks: Vec<ChunkDigest> = all_chunks
            .into_iter()
            .filter(|digest| !referenced_chunks.contains(digest))
            .collect();
        result.chunks_orphaned = orphaned_chunks.len() as u64;
        info!("Found {} orphaned chunks", orphaned_chunks.len());

        // Apply max_delete limit
        if let Some(max) = options.max_delete {
            if orphaned_chunks.len() > max {
                warn!("Limiting deletion to {} chunks (found {})", max, orphaned_chunks.len());
                orphaned_chunks.truncate(max);
            }
        }

        // Phase 4: Delete orphaned chunks
        if options.dry_run {
            info!("Dry run: would delete {} chunks", orphaned_chunks.len());
        } else {
            info!("Phase 4: Deleting {} orphaned chunks...", orphaned_chunks.len());
            for digest in &orphaned_chunks {
                match self.backend.delete_chunk(digest).await {
                    Ok(()) => {
                        result.chunks_deleted += 1;
                        // We don't know the size without reading, so we estimate
                        result.bytes_freed += 1; // Placeholder
                    }
                    Err(e) => {
                        result.errors.push(format!("Failed to delete {}: {}", digest, e));
                    }
                }
            }
            info!("Deleted {} chunks", result.chunks_deleted);
        }

        Ok(result)
    }

    /// Collect all referenced chunks from all indexes
    async fn collect_referenced_chunks(&self, result: &mut GcResult) -> StorageResult<HashSet<ChunkDigest>> {
        let mut referenced = HashSet::new();

        // List all backup groups
        let groups = self.datastore.list_backup_groups().await?;

        for group in groups {
            // List snapshots in this group
            let snapshots = self.datastore
                .list_snapshots(&group.backup_type, &group.backup_id)
                .await?;

            for timestamp in snapshots {
                // Read the manifest
                let manifest_path = format!("{}/{}/{}/index.json", group.backup_type, group.backup_id, timestamp);

                match self.datastore.read_manifest(&manifest_path).await {
                    Ok(manifest) => {
                        // Process each index file
                        for file in manifest.files {
                            let file_path = format!("{}/{}/{}/{}", group.backup_type, group.backup_id, timestamp, file.filename);

                            match file.file_type {
                                pbs_core::FileType::Fidx => {
                                    match self.datastore.read_fixed_index(&file_path).await {
                                        Ok(index) => {
                                            for digest in index.digests {
                                                referenced.insert(digest);
                                            }
                                        }
                                        Err(e) => {
                                            result.errors.push(format!("Failed to read index {}: {}", file_path, e));
                                        }
                                    }
                                }
                                pbs_core::FileType::Didx => {
                                    match self.datastore.read_dynamic_index(&file_path).await {
                                        Ok(index) => {
                                            for entry in index.entries {
                                                referenced.insert(entry.digest);
                                            }
                                        }
                                        Err(e) => {
                                            result.errors.push(format!("Failed to read index {}: {}", file_path, e));
                                        }
                                    }
                                }
                                pbs_core::FileType::Blob => {
                                    // Blobs don't reference chunks
                                }
                            }
                        }
                    }
                    Err(e) => {
                        result.errors.push(format!("Failed to read manifest {}: {}", manifest_path, e));
                    }
                }
            }
        }

        Ok(referenced)
    }
}

/// Prune options for removing old backups
#[derive(Debug, Clone)]
pub struct PruneOptions {
    /// Keep the last N backups
    pub keep_last: Option<usize>,
    /// Keep hourly backups for the last N hours
    pub keep_hourly: Option<usize>,
    /// Keep daily backups for the last N days
    pub keep_daily: Option<usize>,
    /// Keep weekly backups for the last N weeks
    pub keep_weekly: Option<usize>,
    /// Keep monthly backups for the last N months
    pub keep_monthly: Option<usize>,
    /// Keep yearly backups for the last N years
    pub keep_yearly: Option<usize>,
    /// Only report, don't actually delete
    pub dry_run: bool,
}

impl Default for PruneOptions {
    fn default() -> Self {
        Self {
            keep_last: Some(1),
            keep_hourly: None,
            keep_daily: Some(7),
            keep_weekly: Some(4),
            keep_monthly: Some(6),
            keep_yearly: None,
            dry_run: false,
        }
    }
}

/// Prune result
#[derive(Debug, Clone, Default)]
pub struct PruneResult {
    /// Snapshots that were kept
    pub kept: Vec<String>,
    /// Snapshots that were pruned
    pub pruned: Vec<String>,
    /// Errors encountered
    pub errors: Vec<String>,
}

/// Pruner for removing old backups
pub struct Pruner {
    datastore: Arc<Datastore>,
}

impl Pruner {
    /// Create a new pruner
    pub fn new(datastore: Arc<Datastore>) -> Self {
        Self { datastore }
    }

    /// Prune backups for a backup group
    #[instrument(skip(self))]
    pub async fn prune(
        &self,
        backup_type: &str,
        backup_id: &str,
        options: PruneOptions,
    ) -> StorageResult<PruneResult> {
        let mut result = PruneResult::default();

        // List all snapshots
        let mut snapshots = self.datastore
            .list_snapshots(backup_type, backup_id)
            .await?;

        if snapshots.is_empty() {
            return Ok(result);
        }

        // Sort by timestamp (newest first)
        snapshots.sort();
        snapshots.reverse();

        // Determine which to keep
        let mut keep_set = HashSet::new();

        // Keep last N
        if let Some(n) = options.keep_last {
            for (i, snapshot) in snapshots.iter().enumerate() {
                if i < n {
                    keep_set.insert(snapshot.clone());
                }
            }
        }

        // Keep daily (simplified - just keep first per day)
        if let Some(n) = options.keep_daily {
            let mut days_seen = HashSet::new();
            for snapshot in &snapshots {
                // Extract date part (YYYY-MM-DD)
                if let Some(date) = snapshot.split('T').next() {
                    if days_seen.len() < n && !days_seen.contains(date) {
                        days_seen.insert(date.to_string());
                        keep_set.insert(snapshot.clone());
                    }
                }
            }
        }

        // Keep weekly (simplified)
        if let Some(n) = options.keep_weekly {
            let mut weeks_seen = HashSet::new();
            for snapshot in &snapshots {
                // Use first 7 chars of date as week approximation
                if snapshot.len() >= 10 {
                    let week_key = &snapshot[..7]; // YYYY-WW approximation
                    if weeks_seen.len() < n && !weeks_seen.contains(week_key) {
                        weeks_seen.insert(week_key.to_string());
                        keep_set.insert(snapshot.clone());
                    }
                }
            }
        }

        // Keep monthly
        if let Some(n) = options.keep_monthly {
            let mut months_seen = HashSet::new();
            for snapshot in &snapshots {
                if snapshot.len() >= 7 {
                    let month_key = &snapshot[..7]; // YYYY-MM
                    if months_seen.len() < n && !months_seen.contains(month_key) {
                        months_seen.insert(month_key.to_string());
                        keep_set.insert(snapshot.clone());
                    }
                }
            }
        }

        // Keep yearly
        if let Some(n) = options.keep_yearly {
            let mut years_seen = HashSet::new();
            for snapshot in &snapshots {
                if snapshot.len() >= 4 {
                    let year_key = &snapshot[..4]; // YYYY
                    if years_seen.len() < n && !years_seen.contains(year_key) {
                        years_seen.insert(year_key.to_string());
                        keep_set.insert(snapshot.clone());
                    }
                }
            }
        }

        // Partition into keep and prune
        for snapshot in snapshots {
            if keep_set.contains(&snapshot) {
                result.kept.push(snapshot);
            } else {
                result.pruned.push(snapshot);
            }
        }

        // Delete pruned snapshots
        if !options.dry_run {
            for snapshot in &result.pruned {
                match self.datastore
                    .delete_snapshot(backup_type, backup_id, snapshot)
                    .await
                {
                    Ok(()) => {
                        info!("Pruned snapshot {}/{}/{}", backup_type, backup_id, snapshot);
                    }
                    Err(e) => {
                        result.errors.push(format!(
                            "Failed to delete {}/{}/{}: {}",
                            backup_type, backup_id, snapshot, e
                        ));
                    }
                }
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prune_options_default() {
        let opts = PruneOptions::default();
        assert_eq!(opts.keep_last, Some(1));
        assert_eq!(opts.keep_daily, Some(7));
    }
}
