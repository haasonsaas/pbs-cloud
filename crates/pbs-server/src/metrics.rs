//! Prometheus metrics export
//!
//! Exports server metrics in Prometheus format.

use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramVec,
    Encoder, TextEncoder, Registry, Opts, HistogramOpts,
    register_counter_vec_with_registry, register_gauge_vec_with_registry,
    register_histogram_vec_with_registry, register_counter_with_registry,
    register_gauge_with_registry,
};
use std::sync::Arc;
use tracing::{debug, error};

/// Metrics configuration
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Whether metrics are enabled
    pub enabled: bool,
    /// Namespace prefix for metrics
    pub namespace: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            namespace: "pbs_cloud".to_string(),
        }
    }
}

/// Server metrics
pub struct Metrics {
    registry: Registry,
    config: MetricsConfig,

    // Request metrics
    pub requests_total: CounterVec,
    pub request_duration_seconds: HistogramVec,

    // Session metrics
    pub active_backup_sessions: Gauge,
    pub active_reader_sessions: Gauge,

    // Storage metrics
    pub chunks_total: GaugeVec,
    pub chunks_bytes: GaugeVec,
    pub dedup_ratio: GaugeVec,

    // Backup metrics
    pub backups_total: CounterVec,
    pub backup_bytes: CounterVec,

    // GC metrics
    pub gc_runs_total: Counter,
    pub gc_chunks_deleted: Counter,
    pub gc_bytes_freed: Counter,

    // Auth metrics
    pub auth_attempts_total: CounterVec,

    // Error metrics
    pub errors_total: CounterVec,
}

impl Metrics {
    /// Create a new metrics instance
    pub fn new(config: MetricsConfig) -> anyhow::Result<Self> {
        let registry = Registry::new();
        let ns = &config.namespace;

        // Request metrics
        let requests_total = register_counter_vec_with_registry!(
            Opts::new("requests_total", "Total API requests")
                .namespace(ns),
            &["endpoint", "method", "status"],
            registry
        )?;

        let request_duration_seconds = register_histogram_vec_with_registry!(
            HistogramOpts::new("request_duration_seconds", "Request latency in seconds")
                .namespace(ns)
                .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
            &["endpoint", "method"],
            registry
        )?;

        // Session metrics
        let active_backup_sessions = register_gauge_with_registry!(
            Opts::new("active_backup_sessions", "Current active backup sessions")
                .namespace(ns),
            registry
        )?;

        let active_reader_sessions = register_gauge_with_registry!(
            Opts::new("active_reader_sessions", "Current active reader sessions")
                .namespace(ns),
            registry
        )?;

        // Storage metrics
        let chunks_total = register_gauge_vec_with_registry!(
            Opts::new("chunks_total", "Total chunks stored")
                .namespace(ns),
            &["tenant"],
            registry
        )?;

        let chunks_bytes = register_gauge_vec_with_registry!(
            Opts::new("chunks_bytes", "Total chunk storage bytes")
                .namespace(ns),
            &["tenant"],
            registry
        )?;

        let dedup_ratio = register_gauge_vec_with_registry!(
            Opts::new("dedup_ratio", "Deduplication ratio")
                .namespace(ns),
            &["tenant"],
            registry
        )?;

        // Backup metrics
        let backups_total = register_counter_vec_with_registry!(
            Opts::new("backups_total", "Total backups by tenant")
                .namespace(ns),
            &["tenant", "backup_type"],
            registry
        )?;

        let backup_bytes = register_counter_vec_with_registry!(
            Opts::new("backup_bytes", "Total bytes backed up")
                .namespace(ns),
            &["tenant"],
            registry
        )?;

        // GC metrics
        let gc_runs_total = register_counter_with_registry!(
            Opts::new("gc_runs_total", "Garbage collection runs")
                .namespace(ns),
            registry
        )?;

        let gc_chunks_deleted = register_counter_with_registry!(
            Opts::new("gc_chunks_deleted", "Chunks removed by GC")
                .namespace(ns),
            registry
        )?;

        let gc_bytes_freed = register_counter_with_registry!(
            Opts::new("gc_bytes_freed", "Bytes freed by GC")
                .namespace(ns),
            registry
        )?;

        // Auth metrics
        let auth_attempts_total = register_counter_vec_with_registry!(
            Opts::new("auth_attempts_total", "Authentication attempts")
                .namespace(ns),
            &["result"],  // "success" or "failure"
            registry
        )?;

        // Error metrics
        let errors_total = register_counter_vec_with_registry!(
            Opts::new("errors_total", "Total errors by type")
                .namespace(ns),
            &["type"],
            registry
        )?;

        Ok(Self {
            registry,
            config,
            requests_total,
            request_duration_seconds,
            active_backup_sessions,
            active_reader_sessions,
            chunks_total,
            chunks_bytes,
            dedup_ratio,
            backups_total,
            backup_bytes,
            gc_runs_total,
            gc_chunks_deleted,
            gc_bytes_freed,
            auth_attempts_total,
            errors_total,
        })
    }

    /// Check if metrics are enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Record a request
    pub fn record_request(&self, endpoint: &str, method: &str, status: u16, duration_secs: f64) {
        let status_str = status.to_string();
        self.requests_total
            .with_label_values(&[endpoint, method, &status_str])
            .inc();
        self.request_duration_seconds
            .with_label_values(&[endpoint, method])
            .observe(duration_secs);
    }

    /// Record an authentication attempt
    pub fn record_auth_attempt(&self, success: bool) {
        let result = if success { "success" } else { "failure" };
        self.auth_attempts_total.with_label_values(&[result]).inc();
    }

    /// Record a backup completion
    pub fn record_backup(&self, tenant_id: &str, backup_type: &str, bytes: u64) {
        self.backups_total
            .with_label_values(&[tenant_id, backup_type])
            .inc();
        self.backup_bytes
            .with_label_values(&[tenant_id])
            .inc_by(bytes as f64);
    }

    /// Update session counts
    pub fn update_session_counts(&self, backup_count: usize, reader_count: usize) {
        self.active_backup_sessions.set(backup_count as f64);
        self.active_reader_sessions.set(reader_count as f64);
    }

    /// Update storage metrics
    pub fn update_storage_metrics(&self, tenant_id: &str, chunks: u64, bytes: u64, dedup: f64) {
        self.chunks_total.with_label_values(&[tenant_id]).set(chunks as f64);
        self.chunks_bytes.with_label_values(&[tenant_id]).set(bytes as f64);
        self.dedup_ratio.with_label_values(&[tenant_id]).set(dedup);
    }

    /// Record a GC run
    pub fn record_gc_run(&self, chunks_deleted: u64, bytes_freed: u64) {
        self.gc_runs_total.inc();
        self.gc_chunks_deleted.inc_by(chunks_deleted as f64);
        self.gc_bytes_freed.inc_by(bytes_freed as f64);
    }

    /// Record an error
    pub fn record_error(&self, error_type: &str) {
        self.errors_total.with_label_values(&[error_type]).inc();
    }

    /// Export metrics in Prometheus format
    pub fn export(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();

        let mut buffer = Vec::new();
        if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
            error!("Failed to encode metrics: {}", e);
            return String::new();
        }

        String::from_utf8(buffer).unwrap_or_default()
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new(MetricsConfig::default()).expect("Failed to create default metrics")
    }
}

/// Request timer for measuring request duration
pub struct RequestTimer {
    start: std::time::Instant,
    endpoint: String,
    method: String,
    metrics: Arc<Metrics>,
}

impl RequestTimer {
    /// Start a new request timer
    pub fn new(metrics: Arc<Metrics>, endpoint: &str, method: &str) -> Self {
        Self {
            start: std::time::Instant::now(),
            endpoint: endpoint.to_string(),
            method: method.to_string(),
            metrics,
        }
    }

    /// Stop the timer and record the request
    pub fn finish(self, status: u16) {
        let duration = self.start.elapsed().as_secs_f64();
        self.metrics.record_request(&self.endpoint, &self.method, status, duration);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = Metrics::new(MetricsConfig::default()).unwrap();
        assert!(metrics.is_enabled());
    }

    #[test]
    fn test_request_recording() {
        let metrics = Metrics::new(MetricsConfig::default()).unwrap();

        metrics.record_request("/api/test", "GET", 200, 0.05);
        metrics.record_request("/api/test", "GET", 200, 0.10);
        metrics.record_request("/api/test", "POST", 500, 0.25);

        let output = metrics.export();
        assert!(output.contains("pbs_cloud_requests_total"));
        assert!(output.contains("pbs_cloud_request_duration_seconds"));
    }

    #[test]
    fn test_auth_metrics() {
        let metrics = Metrics::new(MetricsConfig::default()).unwrap();

        metrics.record_auth_attempt(true);
        metrics.record_auth_attempt(true);
        metrics.record_auth_attempt(false);

        let output = metrics.export();
        assert!(output.contains("pbs_cloud_auth_attempts_total"));
    }

    #[test]
    fn test_backup_metrics() {
        let metrics = Metrics::new(MetricsConfig::default()).unwrap();

        metrics.record_backup("tenant1", "vm", 1024 * 1024);
        metrics.record_backup("tenant1", "ct", 512 * 1024);

        let output = metrics.export();
        assert!(output.contains("pbs_cloud_backups_total"));
        assert!(output.contains("pbs_cloud_backup_bytes"));
    }

    #[test]
    fn test_export_format() {
        let metrics = Metrics::new(MetricsConfig::default()).unwrap();
        let output = metrics.export();

        // Should be valid Prometheus format
        assert!(output.contains("# HELP"));
        assert!(output.contains("# TYPE"));
    }
}
