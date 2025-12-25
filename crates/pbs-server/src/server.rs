//! HTTP/2 server implementation
//!
//! Handles both REST API and PBS backup protocol with TLS, rate limiting, and metrics.

use std::collections::HashMap;
use dashmap::DashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use chrono::{Datelike, Duration, TimeZone, Timelike, Weekday};
use chrono_tz::Tz;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::{body::Incoming, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use pbs_core::{
    BackupManifest, Chunk, ChunkDigest, CryptoConfig, DataBlob, DynamicIndex, FileType, FixedIndex,
};
use pbs_storage::error::StorageError;
use pbs_storage::{
    Datastore, GarbageCollector, GcOptions, LocalBackend, PruneOptions, Pruner, S3Backend,
    StorageBackend,
};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, instrument, warn};

use crate::audit;
use crate::auth::{AuthContext, AuthManager, Permission, User};
use crate::billing::{BillingManager, UsageEvent, UsageEventType};
use crate::config::{ServerConfig, StorageConfig};
use crate::metrics::{Metrics, MetricsConfig};
use crate::persistence::{PersistenceConfig, PersistenceManager};
use crate::protocol::{ApiError, BackupParams, BACKUP_PROTOCOL_HEADER, READER_PROTOCOL_HEADER};
use crate::rate_limit::{RateLimitResult, RateLimiter_};
use crate::session::SessionManager;
use crate::streaming::{BackupProtocolHandler, FinishBackupResponse, ReaderProtocolHandler};
use crate::system_info::{collect_system_snapshot, CpuTracker};
use crate::tasks::{TaskListFilter, TaskListRequest, TaskRegistry, TaskSnapshot};
use crate::tenant::TenantManager;
use crate::tls::create_tls_acceptor;
use crate::validation::{
    validate_backup_id, validate_backup_namespace, validate_backup_params,
    validate_backup_params_with_ns, validate_backup_type, validate_datastore_name, validate_digest,
    validate_filename, validate_tenant_name, validate_username,
};
use crate::verify_jobs::{
    DeletableProperty, VerificationJobConfig, VerificationJobConfigUpdater, VerificationJobState,
};

/// Server state
pub struct ServerState {
    /// Configuration
    pub config: ServerConfig,
    /// Storage backend
    pub backend: Arc<dyn StorageBackend>,
    /// Datastores by name
    pub datastores: HashMap<String, Arc<Datastore>>,
    /// Session manager
    pub sessions: Arc<SessionManager>,
    /// Auth manager
    pub auth: Arc<AuthManager>,
    /// Tenant manager
    pub tenants: Arc<TenantManager>,
    /// Billing manager
    pub billing: Arc<BillingManager>,
    /// Rate limiter
    pub rate_limiter: Arc<RateLimiter_>,
    /// Metrics
    pub metrics: Arc<Metrics>,
    /// Persistence manager
    pub persistence: Arc<PersistenceManager>,
    /// TLS acceptor (None if TLS disabled)
    pub tls_acceptor: Option<TlsAcceptor>,
    /// TLS certificate fingerprint (sha256)
    pub tls_fingerprint: Option<String>,
    /// Server start time
    pub start_time: Instant,
    /// CPU usage tracking
    pub cpu_tracker: Mutex<CpuTracker>,
    /// Task registry for PBS task APIs
    pub tasks: Arc<TaskRegistry>,
    /// Last GC status per datastore
    pub gc_status: Arc<RwLock<HashMap<String, serde_json::Value>>>,
    /// Task UPIDs for active backup sessions
    pub backup_tasks: Arc<RwLock<HashMap<String, String>>>,
    /// Task UPIDs for active reader sessions
    pub reader_tasks: Arc<RwLock<HashMap<String, String>>>,
    /// Verification job configurations
    pub verify_jobs: Arc<RwLock<HashMap<String, VerificationJobConfig>>>,
    /// Verification job state (last run, status)
    pub verify_job_state: Arc<RwLock<HashMap<String, VerificationJobState>>>,
    /// Active session tickets (ticket -> username)
    pub tickets: DashMap<String, String>,
    /// Server signing key for tickets (HMAC-SHA256)
    pub ticket_key: [u8; 32],
}

impl ServerState {
    /// Create a new server state from config
    pub async fn from_config(config: ServerConfig) -> anyhow::Result<Self> {
        // Create storage backend
        let backend: Arc<dyn StorageBackend> = match &config.storage {
            StorageConfig::Local { path } => Arc::new(LocalBackend::new(path).await?),
            StorageConfig::S3 {
                bucket,
                region,
                endpoint,
                prefix,
            } => {
                let mut s3_config = match endpoint {
                    Some(ep) => pbs_storage::S3Config::compatible(bucket, ep),
                    None => {
                        pbs_storage::S3Config::aws(bucket, region.as_deref().unwrap_or("us-east-1"))
                    }
                };
                if let Some(p) = prefix {
                    s3_config = s3_config.with_prefix(p);
                }
                Arc::new(S3Backend::new(s3_config).await?)
            }
        };

        // Create default datastore
        let crypto = if let Some(key_hex) = &config.encryption_key {
            let bytes = hex::decode(key_hex)
                .map_err(|e| anyhow::anyhow!("Invalid PBS_ENCRYPTION_KEY: {}", e))?;
            if bytes.len() != 32 {
                return Err(anyhow::anyhow!(
                    "Encryption key must be 32 bytes (64 hex chars)"
                ));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            CryptoConfig::with_encryption(pbs_core::EncryptionKey::from_bytes(key))
        } else {
            CryptoConfig::default()
        };
        let default_ds = Arc::new(Datastore::new("default", backend.clone(), crypto.clone()));

        let mut datastores = HashMap::new();
        datastores.insert("default".to_string(), default_ds);

        for store in &config.datastores {
            if store == "default" || datastores.contains_key(store) {
                continue;
            }
            validate_datastore_name(store)
                .map_err(|e| anyhow::anyhow!("Invalid datastore name {}: {}", store, e))?;

            let store_backend: Arc<dyn StorageBackend> = match &config.storage {
                StorageConfig::Local { path } => {
                    let mut store_path = PathBuf::from(path);
                    store_path.push(store);
                    Arc::new(LocalBackend::new(store_path).await?)
                }
                StorageConfig::S3 {
                    bucket,
                    region,
                    endpoint,
                    prefix,
                } => {
                    let mut s3_config = match endpoint {
                        Some(ep) => pbs_storage::S3Config::compatible(bucket, ep),
                        None => pbs_storage::S3Config::aws(
                            bucket,
                            region.as_deref().unwrap_or("us-east-1"),
                        ),
                    };
                    let base_prefix = prefix
                        .as_deref()
                        .map(|p| p.trim_end_matches('/'))
                        .filter(|p| !p.is_empty());
                    let store_prefix = match base_prefix {
                        Some(p) => format!("{}/{}", p, store),
                        None => store.to_string(),
                    };
                    s3_config = s3_config.with_prefix(&store_prefix);
                    Arc::new(S3Backend::new(s3_config).await?)
                }
            };

            datastores.insert(
                store.clone(),
                Arc::new(Datastore::new(store, store_backend, crypto.clone())),
            );
        }

        let (billing, billing_rx) = BillingManager::new();
        let billing = Arc::new(billing);
        let billing_dispatch = billing.clone();
        tokio::spawn(async move {
            billing_dispatch.run_dispatcher(billing_rx).await;
        });

        // Initialize persistence
        let persistence_config =
            PersistenceConfig::new(config.data_dir.as_deref().unwrap_or("~/.pbs-cloud"));
        let persistence = Arc::new(PersistenceManager::new(persistence_config).await?);

        // Initialize metrics
        let metrics = Arc::new(Metrics::new(MetricsConfig::default())?);

        // Initialize rate limiter
        let rate_limiter = Arc::new(RateLimiter_::new(
            config.rate_limit.clone().unwrap_or_default(),
        ));

        // Initialize TLS
        let (tls_acceptor, tls_fingerprint) =
            create_tls_acceptor(&config.tls.clone().unwrap_or_default())?;

        // Create auth and tenant managers
        let auth = Arc::new(AuthManager::default());
        let tenants = Arc::new(TenantManager::default());

        // Load persisted data
        let users = persistence.load_users().await.unwrap_or_default();
        let tokens = persistence.load_tokens().await.unwrap_or_default();
        let tenant_list = persistence.load_tenants().await.unwrap_or_default();

        // Restore state from persistence
        for user in users {
            auth.restore_user(user).await;
        }
        for token in tokens {
            auth.restore_token(token).await;
        }
        for tenant in tenant_list {
            tenants.restore_tenant(tenant).await;
        }

        info!(
            "Loaded {} users, {} tokens, {} tenants from persistence",
            auth.user_count().await,
            auth.token_count().await,
            tenants.tenant_count().await
        );

        let tasks = Arc::new(TaskRegistry::with_limits(
            "localhost",
            1000,
            config.tasks.log_max_lines,
        ));
        let gc_status = Arc::new(RwLock::new(HashMap::new()));
        let backup_tasks = Arc::new(RwLock::new(HashMap::new()));
        let reader_tasks = Arc::new(RwLock::new(HashMap::new()));
        let verify_jobs = Arc::new(RwLock::new(HashMap::new()));
        let verify_job_state = Arc::new(RwLock::new(HashMap::new()));

        let task_snapshots = persistence.load_tasks().await.unwrap_or_default();
        if !task_snapshots.is_empty() {
            tasks.restore(task_snapshots).await;
            info!("Restored task history from persistence");
        }

        let jobs = persistence.load_verify_jobs().await.unwrap_or_default();
        if !jobs.is_empty() {
            let mut guard = verify_jobs.write().await;
            for job in jobs {
                guard.insert(job.id.clone(), job);
            }
            info!("Loaded verify job configuration from persistence");
        }

        let job_states = persistence
            .load_verify_job_state()
            .await
            .unwrap_or_default();
        if !job_states.is_empty() {
            let job_ids = {
                let guard = verify_jobs.read().await;
                guard
                    .keys()
                    .cloned()
                    .collect::<std::collections::HashSet<_>>()
            };
            let mut guard = verify_job_state.write().await;
            for state in job_states {
                if job_ids.is_empty() || job_ids.contains(&state.id) {
                    guard.insert(state.id.clone(), state);
                }
            }
            info!("Loaded verify job state from persistence");
        }

        Ok(Self {
            config,
            backend,
            datastores,
            sessions: Arc::new(SessionManager::default()),
            auth,
            tenants,
            billing,
            rate_limiter,
            metrics,
            persistence,
            tls_acceptor,
            tls_fingerprint,
            start_time: Instant::now(),
            cpu_tracker: Mutex::new(CpuTracker::default()),
            tasks,
            gc_status,
            backup_tasks,
            reader_tasks,
            verify_jobs,
            verify_job_state,
            tickets: DashMap::new(),
            // Generate random key for signing tickets (in production, this should be persisted)
            ticket_key: {
                use rand::Rng;
                let mut key = [0u8; 32];
                rand::thread_rng().fill(&mut key);
                key
            },
        })
    }

    /// Get a datastore by name
    pub fn get_datastore(&self, name: &str) -> Option<Arc<Datastore>> {
        self.datastores.get(name).cloned()
    }

    /// Get the default datastore
    pub fn default_datastore(&self) -> Arc<Datastore> {
        self.datastores
            .get("default")
            .cloned()
            .expect("default datastore must be configured")
    }

    /// Save current state to persistence
    pub async fn save_state(&self) -> anyhow::Result<()> {
        let users = self.auth.list_users(None).await;
        let tokens = self.auth.list_all_tokens().await;
        let tenants = self.tenants.list_tenants().await;
        let tasks = self.tasks.snapshot().await;
        let verify_jobs = {
            let guard = self.verify_jobs.read().await;
            guard.values().cloned().collect::<Vec<_>>()
        };
        let verify_job_state = {
            let guard = self.verify_job_state.read().await;
            guard.values().cloned().collect::<Vec<_>>()
        };

        self.persistence.save_users(&users).await?;
        self.persistence.save_tokens(&tokens).await?;
        self.persistence.save_tenants(&tenants).await?;
        self.persistence.save_tasks(&tasks).await?;
        self.persistence.save_verify_jobs(&verify_jobs).await?;
        self.persistence
            .save_verify_job_state(&verify_job_state)
            .await?;

        debug!("Saved state to persistence");
        Ok(())
    }
}

/// Start the HTTP/2 server
#[instrument(skip(state))]
pub async fn run_server(state: Arc<ServerState>) -> anyhow::Result<()> {
    let addr: SocketAddr = state.config.listen_addr.parse()?;
    let listener = TcpListener::bind(addr).await?;

    let protocol = if state.tls_acceptor.is_some() {
        "https"
    } else {
        "http"
    };
    info!("PBS Cloud Server listening on {}://{}", protocol, addr);

    // Create root user if no users exist
    if state.auth.user_count().await == 0 {
        let default_tenant = &state.config.tenants.default_tenant;

        // Create default tenant
        let tenant = state.tenants.create_tenant(default_tenant).await;
        info!("Created default tenant: {}", tenant.name);

        // Create root user
        match state.auth.create_root_user(default_tenant).await {
            Ok((user, token)) => {
                info!("Created root user: {}", user.username);
                if let Some(path) = state.config.root_token_file.as_deref() {
                    let write_result = (|| -> std::io::Result<()> {
                        let mut file = std::fs::OpenOptions::new()
                            .create(true)
                            .write(true)
                            .truncate(true)
                            .open(path)?;
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let perms = std::fs::Permissions::from_mode(0o600);
                            std::fs::set_permissions(path, perms)?;
                        }
                        writeln!(file, "{}", token)?;
                        Ok(())
                    })();
                    match write_result {
                        Ok(()) => info!("Root API token written to {}", path),
                        Err(err) => warn!("Failed to write root token to {}: {}", path, err),
                    }
                }

                if state.config.print_root_token {
                    info!("Root API token: {}", token);
                    info!("Save this token - it won't be shown again!");
                } else {
                    info!("Root API token printing disabled");
                }

                // Save immediately
                if let Err(e) = state.save_state().await {
                    warn!("Failed to save initial state: {}", e);
                }
            }
            Err(e) => {
                warn!("Failed to create root user: {}", e);
            }
        }
    }

    // Spawn periodic tasks
    let state_for_cleanup = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            // Clean up expired sessions
            let (expired_backup, expired_reader) =
                state_for_cleanup.sessions.cleanup_expired().await;
            for session_id in expired_backup {
                if let Some(upid) =
                    take_session_task(&state_for_cleanup.backup_tasks, &session_id).await
                {
                    state_for_cleanup
                        .tasks
                        .log(&upid, "Backup session expired")
                        .await;
                    state_for_cleanup.tasks.finish(&upid, "ABORTED").await;
                }
            }
            for session_id in expired_reader {
                if let Some(upid) =
                    take_session_task(&state_for_cleanup.reader_tasks, &session_id).await
                {
                    state_for_cleanup
                        .tasks
                        .log(&upid, "Reader session expired")
                        .await;
                    state_for_cleanup.tasks.finish(&upid, "ABORTED").await;
                }
            }
            // Clean up rate limiter state
            state_for_cleanup.rate_limiter.cleanup();
            // Update session metrics
            let (backup_count, reader_count) = state_for_cleanup.sessions.session_count().await;
            state_for_cleanup
                .metrics
                .update_session_counts(backup_count, reader_count);
        }
    });

    // Spawn periodic persistence save
    let state_for_save = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // Every 5 minutes
        loop {
            interval.tick().await;
            if let Err(e) = state_for_save.save_state().await {
                error!("Failed to save state: {}", e);
            }
        }
    });

    // Spawn scheduled GC if enabled
    if state.config.gc.enabled {
        let state_for_gc = state.clone();
        let gc_interval = tokio::time::Duration::from_secs(state.config.gc.interval_hours * 3600);
        info!(
            "Scheduled GC enabled, running every {} hours",
            state.config.gc.interval_hours
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(gc_interval);
            // Skip the first immediate tick
            interval.tick().await;

            loop {
                interval.tick().await;
                info!("Starting scheduled GC run");

                let datastores: Vec<_> = state_for_gc.datastores.values().cloned().collect();
                for datastore in datastores {
                    let backend = datastore.backend();
                    let gc = GarbageCollector::new(datastore.clone(), backend);

                    let options = GcOptions {
                        dry_run: false,
                        max_delete: None,
                    };

                    match gc.run(options).await {
                        Ok(result) => {
                            info!(
                                "Scheduled GC completed for {}: scanned={}, orphaned={}, deleted={}, freed={}",
                                datastore.name(),
                                result.chunks_scanned,
                                result.chunks_orphaned,
                                result.chunks_deleted,
                                result.bytes_freed
                            );
                            if !result.errors.is_empty() {
                                warn!("GC errors for {}: {:?}", datastore.name(), result.errors);
                            }
                        }
                        Err(e) => {
                            error!("Scheduled GC failed for {}: {}", datastore.name(), e);
                        }
                    }
                }
            }
        });
    }

    // Spawn scheduled verification if enabled
    if state.config.verify.enabled {
        let state_for_verify = state.clone();
        let interval_secs = if state.config.verify.interval_hours > 0 {
            Some(state.config.verify.interval_hours as i64 * 3600)
        } else {
            None
        };
        info!("Scheduled verification enabled");

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            interval.tick().await;

            loop {
                interval.tick().await;
                let now = chrono::Utc::now().timestamp();

                let snapshots = state_for_verify.tasks.snapshot().await;
                let mut running_workers = std::collections::HashSet::new();
                for task in &snapshots {
                    if task.worker_type == "verificationjob" && task.running {
                        if let Some(worker_id) = task.worker_id.clone() {
                            running_workers.insert(worker_id);
                        }
                    }
                }

                let jobs = {
                    let guard = state_for_verify.verify_jobs.read().await;
                    guard.values().cloned().collect::<Vec<_>>()
                };

                if jobs.is_empty() {
                    let Some(interval_secs) = interval_secs else {
                        continue;
                    };
                    let datastores: Vec<_> = state_for_verify
                        .datastores
                        .iter()
                        .map(|(name, ds)| (name.clone(), ds.clone()))
                        .collect();

                    for (store, datastore) in datastores {
                        if running_workers.contains(&store) {
                            continue;
                        }
                        let mut last_task: Option<TaskSnapshot> = None;
                        for task in snapshots.iter().filter(|task| {
                            task.worker_type == "verificationjob"
                                && task.store.as_deref() == Some(store.as_str())
                        }) {
                            if last_task
                                .as_ref()
                                .map(|prev| task.starttime > prev.starttime)
                                .unwrap_or(true)
                            {
                                last_task = Some(task.clone());
                            }
                        }
                        let last_run = last_task
                            .as_ref()
                            .and_then(|task| task.endtime.or(Some(task.starttime)));
                        if let Some(next_run) =
                            compute_next_run(None, last_run, now, Some(interval_secs))
                        {
                            if next_run > now {
                                continue;
                            }
                        } else {
                            continue;
                        }

                        info!("Starting scheduled verification run for {}", store);
                        let auth_id = "root@pam".to_string();
                        let _ = spawn_verify_task(
                            state_for_verify.clone(),
                            datastore,
                            auth_id,
                            store,
                            VerifyTaskOptions {
                                job_id: None,
                                namespace: None,
                                max_depth: None,
                                ignore_verified: false,
                                outdated_after: None,
                                trigger: "scheduled".to_string(),
                            },
                        )
                        .await;
                    }
                } else {
                    for job in jobs {
                        let worker_id = format!("{}:{}", job.store, job.id);
                        if running_workers.contains(&worker_id) {
                            continue;
                        }
                        let datastore = match state_for_verify.get_datastore(&job.store) {
                            Some(ds) => ds,
                            None => {
                                warn!(
                                    "Skipping scheduled verification for {} (datastore missing)",
                                    job.store
                                );
                                continue;
                            }
                        };

                        let next_run = {
                            let mut guard = state_for_verify.verify_job_state.write().await;
                            let entry = guard
                                .entry(job.id.clone())
                                .or_insert_with(|| VerificationJobState::new(&job.id));
                            compute_next_run_cached(&job, entry, now, interval_secs)
                        };
                        let Some(next_run) = next_run else {
                            continue;
                        };
                        if next_run > now {
                            continue;
                        }

                        info!("Starting scheduled verification job {}", job.id);
                        let auth_id = "root@pam".to_string();
                        let _ = spawn_verify_task(
                            state_for_verify.clone(),
                            datastore,
                            auth_id,
                            job.store.clone(),
                            VerifyTaskOptions {
                                job_id: Some(job.id.clone()),
                                namespace: job.ns.clone(),
                                max_depth: job.max_depth,
                                ignore_verified: job.ignore_verified.unwrap_or(true),
                                outdated_after: job.outdated_after,
                                trigger: "scheduled".to_string(),
                            },
                        )
                        .await;
                    }
                }
            }
        });
    }

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let state = state.clone();

        tokio::spawn(async move {
            // Handle TLS if enabled
            let result = if let Some(ref acceptor) = state.tls_acceptor {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        let io = TokioIo::new(tls_stream);
                        http1::Builder::new()
                            .serve_connection(
                                io,
                                service_fn(move |req| {
                                    let state = state.clone();
                                    handle_request(state, peer_addr, req)
                                }),
                            )
                            .with_upgrades()
                            .await
                    }
                    Err(e) => {
                        debug!("TLS handshake failed: {:?}", e);
                        return;
                    }
                }
            } else {
                let io = TokioIo::new(stream);
                http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req| {
                            let state = state.clone();
                            handle_request(state, peer_addr, req)
                        }),
                    )
                    .with_upgrades()
                    .await
            };

            if let Err(err) = result {
                error!("Error serving connection: {:?}", err);
            }
        });
    }
}

/// Handle an HTTP request
async fn handle_request(
    state: Arc<ServerState>,
    peer_addr: SocketAddr,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let start = Instant::now();
    let method = req.method().clone();
    // Normalize path: collapse multiple slashes to single slash
    let path = req.uri().path().to_string();
    let path = path.replace("//", "/");

    debug!("{} {} from {}", method, path, peer_addr);

    // Check rate limit for IP (before auth)
    if let RateLimitResult::Limited {
        retry_after_secs,
        limit,
        remaining,
    } = state.rate_limiter.check_ip(peer_addr.ip())
    {
        state
            .metrics
            .record_request(&path, method.as_str(), 429, start.elapsed().as_secs_f64());
        return Ok(rate_limited_response(retry_after_secs, limit, remaining));
    }

    // Check for protocol upgrade (backup/restore sessions)
    let upgrade_proto = req
        .headers()
        .get("upgrade")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());
    if let Some(proto) = upgrade_proto.as_deref() {
        if proto == BACKUP_PROTOCOL_HEADER || proto == READER_PROTOCOL_HEADER {
            return Ok(handle_protocol_upgrade(state.clone(), peer_addr, req, proto).await);
        }
    }

    // Authenticate request (except for public endpoints)
    let auth_ctx = if is_public_endpoint(&path) {
        None
    } else {
        match authenticate(state.clone(), &req).await {
            Ok(ctx) => {
                state.metrics.record_auth_attempt(true);

                // Check tenant rate limit
                if let RateLimitResult::Limited {
                    retry_after_secs,
                    limit,
                    remaining,
                } = state.rate_limiter.check_tenant(&ctx.user.tenant_id)
                {
                    state.metrics.record_request(
                        &path,
                        method.as_str(),
                        429,
                        start.elapsed().as_secs_f64(),
                    );
                    return Ok(rate_limited_response(retry_after_secs, limit, remaining));
                }

                Some(ctx)
            }
            Err(e) => {
                state.metrics.record_auth_attempt(false);
                state.metrics.record_request(
                    &path,
                    method.as_str(),
                    401,
                    start.elapsed().as_secs_f64(),
                );
                return Ok(error_response(e));
            }
        }
    };

    // Record API request for billing
    if let Some(ctx) = &auth_ctx {
        state
            .billing
            .record_event(UsageEvent::new(
                &ctx.user.tenant_id,
                UsageEventType::ApiRequest,
                0,
            ))
            .await;
    }

    // Route to appropriate handler
    let response = match (method.clone(), path.as_str()) {
        // Health check endpoints (for k8s/load balancers)
        (Method::GET, "/health") | (Method::GET, "/healthz") => handle_health(state.clone()).await,
        (Method::GET, "/ready") | (Method::GET, "/readyz") => handle_ready(state.clone()).await,
        (Method::GET, "/") => {
            if state.config.dashboard_enabled {
                handle_root_ui(state.clone()).await
            } else {
                not_found()
            }
        }

        // Public endpoints
        (Method::GET, "/api2/json/version") => handle_version().await,
        (Method::GET, "/api2/json/ping") => handle_ping().await,
        (Method::GET, "/api2/json/access/ticket") => handle_auth_info().await,

        // Metrics endpoint
        (Method::GET, "/metrics") => {
            if state.config.metrics_public {
                handle_metrics(state.clone()).await
            } else {
                not_found()
            }
        }
        (Method::POST, "/api2/json/billing/webhook") => {
            handle_webhook_receive(state.clone(), req).await
        }

        // Auth endpoints
        (Method::POST, "/api2/json/access/ticket") => handle_login(state.clone(), req).await,

        // API v2 routes (require auth)
        (Method::GET, "/api2/json/metrics") => {
            with_auth(auth_ctx, Permission::Admin, |_| {
                let state = state.clone();
                async move { handle_metrics(state).await }
            })
            .await
        }
        (Method::GET, "/api2/json/nodes") => {
            with_auth(auth_ctx, Permission::Read, |_| {
                let state = state.clone();
                async move { handle_nodes(state).await }
            })
            .await
        }
        (Method::GET, "/api2/json/nodes/localhost/status") => {
            with_auth(auth_ctx, Permission::Read, |_| {
                let state = state.clone();
                async move { handle_node_status(state).await }
            })
            .await
        }
        (_, p) if p.starts_with("/api2/json/nodes/localhost/tasks") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_tasks_api(state, &ctx, req).await }
            })
            .await
        }
        (_, p) if p.starts_with("/api2/json/admin/datastore") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_datastore_api(state, &ctx, req).await }
            })
            .await
        }
        (_, p) if p.starts_with("/api2/json/config/verify") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_verify_config_api(state, &ctx, req).await }
            })
            .await
        }
        (Method::GET, "/api2/json/status/datastore-usage") => {
            with_auth(auth_ctx, Permission::Read, |_| {
                let state = state.clone();
                async move { handle_status_datastore_usage(state).await }
            })
            .await
        }
        (Method::GET, "/api2/json/status") => {
            with_auth(auth_ctx, Permission::Read, |_| {
                let state = state.clone();
                async move { handle_status(state).await }
            })
            .await
        }

        // Backup protocol endpoints
        (Method::POST, p)
            if p.starts_with("/api2/json/admin/datastore/") && p.contains("/backup") =>
        {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_start_backup(state, &ctx, req).await }
            })
            .await
        }

        // Reader/Restore endpoints
        (Method::POST, p)
            if p.starts_with("/api2/json/admin/datastore/") && p.contains("/reader") =>
        {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_start_reader(state, &ctx, req).await }
            })
            .await
        }

        // Session-based backup operations
        (Method::POST, "/api2/json/backup/fixed_chunk") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_upload_chunk(state, &ctx, req, "fixed").await }
            })
            .await
        }
        (Method::POST, "/api2/json/backup/dynamic_chunk") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_upload_chunk(state, &ctx, req, "dynamic").await }
            })
            .await
        }
        (Method::POST, "/api2/json/backup/fixed_index") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_create_index(state, &ctx, req, "fixed").await }
            })
            .await
        }
        (Method::PUT, "/api2/json/backup/fixed_index") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_append_index(state, &ctx, req, "fixed").await }
            })
            .await
        }
        (Method::POST, "/api2/json/backup/fixed_close") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_close_index(state, &ctx, req, "fixed").await }
            })
            .await
        }
        (Method::POST, "/api2/json/backup/dynamic_index") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_create_index(state, &ctx, req, "dynamic").await }
            })
            .await
        }
        (Method::PUT, "/api2/json/backup/dynamic_index") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_append_index(state, &ctx, req, "dynamic").await }
            })
            .await
        }
        (Method::POST, "/api2/json/backup/dynamic_close") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_close_index(state, &ctx, req, "dynamic").await }
            })
            .await
        }
        (Method::POST, "/api2/json/backup/blob") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_upload_blob(state, &ctx, req).await }
            })
            .await
        }
        (Method::POST, "/api2/json/backup/finish") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_finish_backup(state, &ctx, req).await }
            })
            .await
        }
        (Method::POST, "/api2/json/backup/known_chunks") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_known_chunks(state, &ctx, req).await }
            })
            .await
        }

        // Reader/Restore operations
        (Method::GET, "/api2/json/reader/download_chunk") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_download_chunk(state, &ctx, req).await }
            })
            .await
        }
        (Method::GET, "/api2/json/reader/fixed_index") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_read_index(state, &ctx, req, "fixed").await }
            })
            .await
        }
        (Method::GET, "/api2/json/reader/dynamic_index") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_read_index(state, &ctx, req, "dynamic").await }
            })
            .await
        }
        (Method::GET, "/api2/json/reader/blob") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_read_blob(state, &ctx, req).await }
            })
            .await
        }
        (Method::GET, "/api2/json/reader/manifest") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_read_manifest(state, &ctx, req).await }
            })
            .await
        }
        (Method::POST, "/api2/json/reader/close") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_close_reader(state, &ctx, req).await }
            })
            .await
        }

        // Tenant API
        (Method::GET, "/api2/json/tenants") => {
            with_auth(auth_ctx, Permission::Admin, |_| {
                let state = state.clone();
                async move { handle_list_tenants(state).await }
            })
            .await
        }
        (Method::POST, "/api2/json/tenants") => {
            with_auth(auth_ctx, Permission::Admin, |ctx| {
                let state = state.clone();
                async move { handle_create_tenant(state, &ctx, req).await }
            })
            .await
        }
        (Method::DELETE, path) if path.starts_with("/api2/json/tenants/") => {
            let tenant_id = path.strip_prefix("/api2/json/tenants/").unwrap_or("");
            let tenant_id = tenant_id.to_string();
            with_auth(auth_ctx, Permission::Admin, |ctx| {
                let state = state.clone();
                async move { handle_delete_tenant(state, &ctx, &tenant_id).await }
            })
            .await
        }

        // User/Token API
        (Method::GET, "/api2/json/access/users") => {
            with_auth(auth_ctx, Permission::Admin, |ctx| {
                let state = state.clone();
                async move { handle_list_users(state, &ctx).await }
            })
            .await
        }
        (Method::GET, "/api2/json/access/permissions") => {
            with_auth(auth_ctx, Permission::Read, |ctx| async move {
                handle_permissions(&ctx, req).await
            })
            .await
        }
        (Method::POST, "/api2/json/access/users") => {
            with_auth(auth_ctx, Permission::Admin, |ctx| {
                let state = state.clone();
                async move { handle_create_user(state, &ctx, req).await }
            })
            .await
        }
        (Method::DELETE, path) if path.starts_with("/api2/json/access/users/") => {
            let user_id = path.strip_prefix("/api2/json/access/users/").unwrap_or("");
            let user_id = user_id.to_string();
            with_auth(auth_ctx, Permission::Admin, |ctx| {
                let state = state.clone();
                async move { handle_delete_user(state, &ctx, &user_id).await }
            })
            .await
        }
        (Method::GET, "/api2/json/access/tokens") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_list_tokens(state, &ctx).await }
            })
            .await
        }
        (Method::POST, "/api2/json/access/tokens") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_create_token(state, &ctx, req).await }
            })
            .await
        }
        (Method::DELETE, path) if path.starts_with("/api2/json/access/tokens/") => {
            let token_id = path.strip_prefix("/api2/json/access/tokens/").unwrap_or("");
            let token_id = token_id.to_string();
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_delete_token(state, &ctx, &token_id).await }
            })
            .await
        }

        // Billing API
        (Method::GET, "/api2/json/billing/usage") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_get_usage(state, &ctx).await }
            })
            .await
        }
        (Method::GET, "/api2/json/compliance/report") => {
            with_auth(auth_ctx, Permission::Admin, |_| {
                let state = state.clone();
                async move { handle_compliance_report(state, req).await }
            })
            .await
        }

        // Rate limit info
        (Method::GET, "/api2/json/rate_limit") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_rate_limit_info(state, &ctx).await }
            })
            .await
        }

        // GC/Admin API
        (Method::POST, "/api2/json/admin/gc") => {
            with_auth(auth_ctx, Permission::Admin, |ctx| {
                let state = state.clone();
                async move { handle_run_gc(state, &ctx, req).await }
            })
            .await
        }
        (Method::GET, "/api2/json/admin/gc/status") => {
            with_auth(auth_ctx, Permission::Admin, |_| {
                let state = state.clone();
                async move { handle_gc_status(state, req).await }
            })
            .await
        }
        (Method::POST, "/api2/json/admin/prune") => {
            with_auth(auth_ctx, Permission::DatastoreAdmin, |ctx| {
                let state = state.clone();
                async move { handle_prune(state, &ctx, req).await }
            })
            .await
        }
        (_, p) if p.starts_with("/api2/json/admin/verify") => {
            with_auth(auth_ctx, Permission::DatastoreAdmin, |ctx| {
                let state = state.clone();
                async move { handle_verify_api(state, &ctx, req).await }
            })
            .await
        }

        // Default: 404
        _ => not_found(),
    };

    // Record metrics
    let status = response.status().as_u16();
    state.metrics.record_request(
        &path,
        method.as_str(),
        status,
        start.elapsed().as_secs_f64(),
    );

    Ok(response)
}

/// Check if an endpoint is public (no auth required)
fn is_public_endpoint(path: &str) -> bool {
    matches!(
        path,
        "/api2/json/version"
            | "/api2/json/access/ticket"
            | "/metrics"
            | "/api2/json/billing/webhook"
            | "/health"
            | "/healthz"
            | "/ready"
            | "/readyz"
    )
}

/// Authenticate a request
async fn authenticate(
    state: Arc<ServerState>,
    req: &Request<Incoming>,
) -> Result<AuthContext, ApiError> {
    // Log auth attempts for debugging
    tracing::info!("[AUTH] Request path: {} method: {}", req.uri().path(), req.method());
    for (name, value) in req.headers().iter() {
        if name.as_str() == "authorization" || name.as_str() == "cookie" || name.as_str() == "upgrade" {
            tracing::info!("[AUTH] Header: {} = {:?}", name, value.to_str().unwrap_or("<invalid>"));
        }
    }

    // Check Authorization header
    if let Some(auth_header) = req.headers().get("authorization") {
        let auth_str = auth_header
            .to_str()
            .map_err(|_| ApiError::unauthorized("Invalid authorization header"))?;
        tracing::info!("[AUTH] Using Authorization header");
        return state.auth.authenticate_header(auth_str).await;
    }

    // Check for PBS cookie-based auth (ticket or token)
    if let Some(cookie) = req.headers().get("cookie") {
        let cookie_str = cookie.to_str().unwrap_or("");
        tracing::info!("[AUTH] Found cookie header (len={})", cookie_str.len());
        if let Some(ticket) = extract_pbs_token(cookie_str) {
            tracing::info!("[AUTH] Extracted PBS token (first 50 chars): {}", &ticket[..ticket.len().min(50)]);
            // Check if it's a PBS ticket (PBS:username:timestamp::signature)
            if ticket.starts_with("PBS:") && ticket.contains("::") {
                tracing::info!("[AUTH] Token is PBS ticket format, verifying signature");
                // Verify ticket signature cryptographically
                if let Some(username) = verify_pbs_ticket(&state, &ticket) {
                    tracing::info!("[AUTH] Ticket verified for user: {}", username);
                    // Look up user and create auth context
                    // For PBS compatibility, we use the token to authenticate
                    // and the ticket just proves they already authenticated
                    if let Some(user) = state.auth.get_user_by_username(&username).await {
                        tracing::info!("[AUTH] User lookup succeeded");
                        return Ok(AuthContext {
                            user,
                            token_id: None,
                            permission: Permission::Admin,
                        });
                    }
                    // If no user by that exact name, create a synthetic auth context
                    // This handles PBS usernames like "root@pam" which we map to our token user
                    tracing::info!("[AUTH] User '{}' not found directly, using ticket auth", username);
                    // Look up the default tenant by name to get its actual ID
                    let default_tenant_name = &state.config.tenants.default_tenant;
                    let tenant = state.tenants.get_tenant_by_name(default_tenant_name).await
                        .ok_or_else(|| ApiError::internal(&format!("Default tenant '{}' not found", default_tenant_name)))?;
                    tracing::info!("[AUTH] Using tenant '{}' (id: {})", tenant.name, tenant.id);
                    return Ok(AuthContext {
                        user: User::new(&username, &tenant.id, Permission::Admin),
                        token_id: None,
                        permission: Permission::Admin,
                    });
                }
                tracing::warn!("[AUTH] Ticket verification failed");
                return Err(ApiError::unauthorized("Invalid or expired ticket"));
            }
            // Otherwise treat as API token
            tracing::info!("[AUTH] Token is not PBS format, trying as API token");
            return state.auth.authenticate_token(&ticket).await;
        }
        tracing::info!("[AUTH] Could not extract PBSAuthCookie from cookie header");
    } else {
        tracing::info!("[AUTH] No cookie header found");
    }

    tracing::info!("[AUTH] No authentication provided");
    Err(ApiError::unauthorized("No authentication provided"))
}

/// Extract PBS API token from cookie (returns percent-decoded value)
fn extract_pbs_token(cookie: &str) -> Option<String> {
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("PBSAuthCookie=") {
            // PBS client percent-encodes the ticket in cookie
            return Some(
                percent_encoding::percent_decode_str(value)
                    .decode_utf8()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|_| value.to_string()),
            );
        }
    }
    None
}

/// Helper to require authentication with permission check
async fn with_auth<F, Fut>(
    auth_ctx: Option<AuthContext>,
    required: Permission,
    f: F,
) -> Response<Full<Bytes>>
where
    F: FnOnce(AuthContext) -> Fut,
    Fut: std::future::Future<Output = Response<Full<Bytes>>>,
{
    match auth_ctx {
        Some(ctx) => {
            if ctx.allows(required) {
                f(ctx).await
            } else {
                error_response(ApiError::unauthorized("Insufficient permissions"))
            }
        }
        None => error_response(ApiError::unauthorized("Authentication required")),
    }
}

/// Extract query parameter
fn get_query_param(uri: &hyper::Uri, name: &str) -> Option<String> {
    uri.query().and_then(|q| {
        url::form_urlencoded::parse(q.as_bytes())
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.to_string())
    })
}

fn get_query_params(uri: &hyper::Uri, name: &str) -> Vec<String> {
    uri.query()
        .map(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .filter_map(|(k, v)| (k == name).then_some(v.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn epoch_to_rfc3339(epoch: i64) -> Result<String, ApiError> {
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(epoch, 0)
        .ok_or_else(|| ApiError::bad_request("Invalid backup-time"))?;
    Ok(dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

fn snapshot_to_epoch(snapshot: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(snapshot)
        .ok()
        .map(|dt| dt.timestamp())
}

fn build_snapshot_path(
    namespace: Option<&str>,
    backup_type: &str,
    backup_id: &str,
    backup_time: &str,
) -> String {
    let base = format!("{}/{}/{}", backup_type, backup_id, backup_time);
    let prefix = namespace_prefix(namespace);
    if prefix.is_empty() {
        base
    } else {
        format!("{}{}", prefix, base)
    }
}

fn parse_backup_time_param(value: &str) -> Result<String, ApiError> {
    if value.chars().all(|c| c.is_ascii_digit()) {
        let epoch: i64 = value
            .parse()
            .map_err(|_| ApiError::bad_request("Invalid backup-time"))?;
        return epoch_to_rfc3339(epoch);
    }
    if chrono::DateTime::parse_from_rfc3339(value).is_ok() {
        return Ok(value.to_string());
    }
    Err(ApiError::bad_request("Invalid backup-time"))
}

fn parse_bool_param(value: &str) -> Option<bool> {
    match value {
        "1" | "true" | "TRUE" | "True" => Some(true),
        "0" | "false" | "FALSE" | "False" => Some(false),
        _ => None,
    }
}

fn task_auth_id(ctx: &AuthContext) -> String {
    if let Some(token_id) = ctx.token_id.as_deref() {
        format!("{}!{}", ctx.user.username, token_id)
    } else {
        ctx.user.username.clone()
    }
}

fn decode_chunk_blob(blob_bytes: &[u8], crypto: &CryptoConfig) -> Result<Option<Chunk>, String> {
    let blob = DataBlob::from_bytes(blob_bytes).map_err(|e| e.to_string())?;
    if blob.blob_type().is_encrypted() && crypto.key.is_none() {
        return Ok(None);
    }
    let raw_data = blob.decode(crypto).map_err(|e| e.to_string())?;
    let chunk = Chunk::new(raw_data).map_err(|e| e.to_string())?;
    Ok(Some(chunk))
}

async fn store_session_task(
    map: &Arc<RwLock<HashMap<String, String>>>,
    session_id: &str,
    upid: &str,
) {
    let mut guard = map.write().await;
    guard.insert(session_id.to_string(), upid.to_string());
}

async fn take_session_task(
    map: &Arc<RwLock<HashMap<String, String>>>,
    session_id: &str,
) -> Option<String> {
    let mut guard = map.write().await;
    guard.remove(session_id)
}

fn manifest_note_line(manifest: &BackupManifest) -> Option<String> {
    manifest
        .unprotected
        .as_ref()
        .and_then(|v| v.get("notes"))
        .and_then(|v| v.as_str())
        .and_then(|notes| notes.lines().next().map(|s| s.to_string()))
}

fn manifest_notes(manifest: &BackupManifest) -> Option<String> {
    manifest
        .unprotected
        .as_ref()
        .and_then(|v| v.get("notes"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn manifest_verification(manifest: &BackupManifest) -> Option<serde_json::Value> {
    manifest
        .unprotected
        .as_ref()
        .and_then(|v| v.get("verify_state"))
        .cloned()
}

fn manifest_protected(manifest: &BackupManifest) -> bool {
    let protected = manifest
        .unprotected
        .as_ref()
        .and_then(|v| v.get("protected"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if protected {
        return true;
    }
    manifest
        .unprotected
        .as_ref()
        .and_then(|v| v.get("worm_retain_until"))
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt > chrono::Utc::now())
        .unwrap_or(false)
}

fn update_manifest_unprotected(manifest: &mut BackupManifest, key: &str, value: serde_json::Value) {
    let mut unprotected = manifest
        .unprotected
        .take()
        .unwrap_or_else(|| serde_json::json!({}));
    if let Some(obj) = unprotected.as_object_mut() {
        obj.insert(key.to_string(), value);
    } else {
        let mut map = serde_json::Map::new();
        map.insert(key.to_string(), value);
        unprotected = serde_json::Value::Object(map);
    }
    manifest.unprotected = Some(unprotected);
}

fn namespace_depth(ns: &str) -> usize {
    if ns.is_empty() {
        0
    } else {
        ns.split('/').count()
    }
}

fn namespace_matches(filter: &str, ns: Option<&str>) -> bool {
    let value = ns.unwrap_or("");
    if filter.is_empty() {
        value.is_empty()
    } else {
        value == filter
    }
}

fn namespace_is_descendant(root: &str, ns: Option<&str>) -> bool {
    let value = ns.unwrap_or("");
    if root.is_empty() {
        return true;
    }
    value == root || value.starts_with(&format!("{}/", root))
}

fn classify_backup_type(backup_type: &str) -> &'static str {
    match backup_type {
        "ct" => "ct",
        "vm" => "vm",
        "host" => "host",
        _ => "other",
    }
}

async fn collect_datastore_counts(datastore: Arc<Datastore>) -> Option<serde_json::Value> {
    let groups = datastore.list_backup_groups().await.ok()?;
    if groups.is_empty() {
        return None;
    }

    let mut counts: HashMap<&'static str, (u64, u64)> = HashMap::new();
    for group in groups {
        let key = classify_backup_type(&group.backup_type);
        let entry = counts.entry(key).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);

        let snapshots = datastore
            .list_snapshots(
                group.namespace.as_deref(),
                &group.backup_type,
                &group.backup_id,
            )
            .await
            .unwrap_or_default();
        entry.1 = entry.1.saturating_add(snapshots.len() as u64);
    }

    let mut result = serde_json::Map::new();
    for (key, (groups, snapshots)) in counts {
        if groups == 0 && snapshots == 0 {
            continue;
        }
        result.insert(
            key.to_string(),
            serde_json::json!({
                "groups": groups,
                "snapshots": snapshots,
            }),
        );
    }

    if result.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(result))
    }
}

fn gc_status_from_result(
    upid: &str,
    used: u64,
    result: &pbs_storage::GcResult,
) -> serde_json::Value {
    serde_json::json!({
        "upid": upid,
        "index-file-count": 0,
        "index-data-bytes": 0,
        "disk-bytes": used,
        "disk-chunks": result.chunks_scanned as usize,
        "removed-bytes": result.bytes_freed,
        "removed-chunks": result.chunks_deleted as usize,
        "pending-bytes": 0,
        "pending-chunks": 0,
        "removed-bad": 0,
        "still-bad": 0,
    })
}

fn namespace_prefix(namespace: Option<&str>) -> String {
    let ns = match namespace {
        Some(ns) if !ns.is_empty() => ns,
        _ => return String::new(),
    };
    let mut prefix = String::new();
    for part in ns.split('/') {
        if part.is_empty() {
            continue;
        }
        prefix.push_str("ns/");
        prefix.push_str(part);
        prefix.push('/');
    }
    prefix
}

fn namespace_in_scope(
    base: Option<&str>,
    candidate: Option<&str>,
    max_depth: Option<usize>,
) -> bool {
    let base_ns = base.unwrap_or("");
    let cand_ns = candidate.unwrap_or("");

    if base_ns.is_empty() {
        return max_depth
            .map(|depth| namespace_depth(cand_ns) <= depth)
            .unwrap_or(true);
    }

    if cand_ns.is_empty() {
        return false;
    }

    if cand_ns != base_ns && !cand_ns.starts_with(&format!("{}/", base_ns)) {
        return false;
    }

    if let Some(depth) = max_depth {
        let base_depth = namespace_depth(base_ns);
        let cand_depth = namespace_depth(cand_ns);
        return cand_depth.saturating_sub(base_depth) <= depth;
    }

    true
}

const MAX_VERIFY_DEPTH: usize = 7;

fn parse_upid_starttime(upid: &str) -> Option<i64> {
    let mut parts = upid.split(':');
    let _ = parts.next()?; // UPID
    let _ = parts.next()?; // node
    let _ = parts.next()?; // pid
    let _ = parts.next()?; // pstart
    let _ = parts.next()?; // taskid
    let start_hex = parts.next()?;
    u64::from_str_radix(start_hex, 16).ok().map(|v| v as i64)
}

fn should_verify_snapshot(
    ignore_verified: bool,
    outdated_after: Option<i64>,
    manifest: &BackupManifest,
) -> bool {
    if !ignore_verified {
        return true;
    }

    let Some(unprotected) = manifest.unprotected.as_ref() else {
        return true;
    };
    let Some(verify_state) = unprotected.get("verify_state") else {
        return true;
    };
    let Some(upid) = verify_state.get("upid").and_then(|v| v.as_str()) else {
        return true;
    };
    let Some(starttime) = parse_upid_starttime(upid) else {
        return true;
    };

    match outdated_after {
        None => false,
        Some(max_age_days) => {
            let now = chrono::Utc::now().timestamp();
            let days_since = (now - starttime) / 86_400;
            days_since > max_age_days
        }
    }
}

#[derive(Clone, Debug)]
enum CalendarTimezone {
    Local,
    Fixed(chrono::FixedOffset),
    Named(Tz),
}

#[derive(Clone, Debug)]
enum FieldItem {
    Single(u32),
    Range(u32, u32),
    Step { start: u32, step: u32 },
    LastDay,
}

#[derive(Clone, Debug)]
enum FieldMatch {
    Any,
    Items(Vec<FieldItem>),
}

#[derive(Clone, Debug)]
struct CalendarSpec {
    tz: CalendarTimezone,
    years: FieldMatch,
    months: FieldMatch,
    days: FieldMatch,
    weekdays: FieldMatch,
    hours: FieldMatch,
    minutes: FieldMatch,
    seconds: FieldMatch,
}

fn parse_weekday(value: &str) -> Option<Weekday> {
    match value {
        "mon" => Some(Weekday::Mon),
        "tue" | "tues" => Some(Weekday::Tue),
        "wed" => Some(Weekday::Wed),
        "thu" | "thur" | "thurs" => Some(Weekday::Thu),
        "fri" => Some(Weekday::Fri),
        "sat" => Some(Weekday::Sat),
        "sun" => Some(Weekday::Sun),
        _ => None,
    }
}

fn weekday_index(day: Weekday) -> u32 {
    match day {
        Weekday::Mon => 0,
        Weekday::Tue => 1,
        Weekday::Wed => 2,
        Weekday::Thu => 3,
        Weekday::Fri => 4,
        Weekday::Sat => 5,
        Weekday::Sun => 6,
    }
}

fn parse_fixed_offset(value: &str) -> Result<chrono::FixedOffset, ApiError> {
    let trimmed = value.trim();
    let normalized = trimmed
        .strip_prefix("UTC")
        .or_else(|| trimmed.strip_prefix("utc"))
        .unwrap_or(trimmed);
    if normalized.is_empty() || normalized == "Z" || normalized == "z" {
        return Ok(chrono::FixedOffset::east_opt(0).unwrap());
    }

    let (sign, rest) = normalized
        .strip_prefix('+')
        .map(|v| (1, v))
        .or_else(|| normalized.strip_prefix('-').map(|v| (-1, v)))
        .ok_or_else(|| ApiError::bad_request("Invalid schedule timezone"))?;

    let rest = rest.replace(':', "");
    let (hours, minutes) = match rest.len() {
        1 | 2 => (rest.parse::<i32>().ok(), Some(0)),
        3 | 4 => {
            let (h, m) = rest.split_at(rest.len() - 2);
            (h.parse::<i32>().ok(), m.parse::<i32>().ok())
        }
        _ => (None, None),
    };
    let Some(hours) = hours else {
        return Err(ApiError::bad_request("Invalid schedule timezone"));
    };
    let minutes = minutes.unwrap_or(0);
    if hours.abs() > 23 || minutes.abs() > 59 {
        return Err(ApiError::bad_request("Invalid schedule timezone"));
    }
    let total = sign * (hours * 3600 + minutes * 60);
    chrono::FixedOffset::east_opt(total)
        .ok_or_else(|| ApiError::bad_request("Invalid schedule timezone"))
}

fn parse_timezone_token(token: &str) -> Result<Option<CalendarTimezone>, ApiError> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if let Some(value) = trimmed
        .strip_prefix("TZ=")
        .or_else(|| trimmed.strip_prefix("tz="))
    {
        if let Ok(offset) = parse_fixed_offset(value) {
            return Ok(Some(CalendarTimezone::Fixed(offset)));
        }
        let tz = value
            .parse::<Tz>()
            .map_err(|_| ApiError::bad_request("Invalid schedule timezone"))?;
        return Ok(Some(CalendarTimezone::Named(tz)));
    }
    if trimmed.eq_ignore_ascii_case("local") {
        return Ok(Some(CalendarTimezone::Local));
    }
    if trimmed.eq_ignore_ascii_case("utc")
        || trimmed.starts_with("UTC")
        || trimmed.starts_with("utc")
    {
        return parse_fixed_offset(trimmed).map(|offset| Some(CalendarTimezone::Fixed(offset)));
    }
    if trimmed.starts_with('+') || trimmed.starts_with('-') {
        return parse_fixed_offset(trimmed).map(|offset| Some(CalendarTimezone::Fixed(offset)));
    }
    if trimmed.contains('/') && trimmed.chars().any(|c| c.is_ascii_alphabetic()) {
        if let Ok(tz) = trimmed.parse::<Tz>() {
            return Ok(Some(CalendarTimezone::Named(tz)));
        }
        return Ok(None);
    }
    Ok(None)
}

fn parse_numeric_value(value: &str, min: u32, max: u32) -> Result<u32, ApiError> {
    let parsed: u32 = value
        .parse()
        .map_err(|_| ApiError::bad_request("Invalid schedule value"))?;
    if parsed < min || parsed > max {
        return Err(ApiError::bad_request("Schedule value out of range"));
    }
    Ok(parsed)
}

fn parse_month_value(value: &str) -> Result<u32, ApiError> {
    let trimmed = value.trim().to_ascii_lowercase();
    let month = match trimmed.as_str() {
        "jan" | "january" => Some(1),
        "feb" | "february" => Some(2),
        "mar" | "march" => Some(3),
        "apr" | "april" => Some(4),
        "may" => Some(5),
        "jun" | "june" => Some(6),
        "jul" | "july" => Some(7),
        "aug" | "august" => Some(8),
        "sep" | "sept" | "september" => Some(9),
        "oct" | "october" => Some(10),
        "nov" | "november" => Some(11),
        "dec" | "december" => Some(12),
        _ => None,
    };
    if let Some(value) = month {
        return Ok(value);
    }
    parse_numeric_value(value, 1, 12)
}

fn parse_field_items<T>(
    value: &str,
    min: u32,
    max: u32,
    parse_value: T,
) -> Result<FieldMatch, ApiError>
where
    T: Fn(&str) -> Result<u32, ApiError>,
{
    let mut items = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if part == "*" {
            return Ok(FieldMatch::Any);
        }
        if let Some((left, right)) = part.split_once('/') {
            if left.contains("..") {
                return Err(ApiError::bad_request(
                    "Schedule repetition with ranges is not supported",
                ));
            }
            let start = if left == "*" { min } else { parse_value(left)? };
            let step = parse_numeric_value(right, 1, max - min + 1)?;
            items.push(FieldItem::Step { start, step });
            continue;
        }
        if let Some((start, end)) = part.split_once("..") {
            let start = if start == "*" {
                min
            } else {
                parse_value(start)?
            };
            let end = if end == "*" { max } else { parse_value(end)? };
            if start > end {
                return Err(ApiError::bad_request("Invalid schedule range"));
            }
            items.push(FieldItem::Range(start, end));
            continue;
        }
        items.push(FieldItem::Single(parse_value(part)?));
    }
    if items.is_empty() {
        return Err(ApiError::bad_request("Invalid schedule field"));
    }
    Ok(FieldMatch::Items(items))
}

fn parse_weekday_field(value: &str) -> Result<FieldMatch, ApiError> {
    let mut items = Vec::new();
    for part in value.split(',') {
        let part = part.trim().to_ascii_lowercase();
        if part.is_empty() {
            continue;
        }
        if part == "*" {
            return Ok(FieldMatch::Any);
        }
        if let Some((left, right)) = part.split_once('/') {
            if left.contains("..") {
                return Err(ApiError::bad_request(
                    "Schedule repetition with ranges is not supported",
                ));
            }
            let start = if left == "*" {
                0
            } else if let Some(day) = parse_weekday(left) {
                weekday_index(day)
            } else {
                parse_numeric_value(left, 0, 6)?
            };
            let step = parse_numeric_value(right, 1, 7)?;
            items.push(FieldItem::Step { start, step });
            continue;
        }
        if let Some((start, end)) = part.split_once("..") {
            let start = if let Some(day) = parse_weekday(start.trim()) {
                weekday_index(day)
            } else {
                parse_numeric_value(start, 0, 6)?
            };
            let end = if let Some(day) = parse_weekday(end.trim()) {
                weekday_index(day)
            } else {
                parse_numeric_value(end, 0, 6)?
            };
            if start <= end {
                items.push(FieldItem::Range(start, end));
            } else {
                items.push(FieldItem::Range(start, 6));
                items.push(FieldItem::Range(0, end));
            }
            continue;
        }
        if let Some(day) = parse_weekday(&part) {
            items.push(FieldItem::Single(weekday_index(day)));
        } else {
            items.push(FieldItem::Single(parse_numeric_value(&part, 0, 6)?));
        }
    }
    if items.is_empty() {
        return Err(ApiError::bad_request("Invalid schedule weekday"));
    }
    Ok(FieldMatch::Items(items))
}

fn parse_day_field(value: &str) -> Result<FieldMatch, ApiError> {
    let mut items = Vec::new();
    for part in value.split(',') {
        let part = part.trim().to_ascii_lowercase();
        if part.is_empty() {
            continue;
        }
        if part == "*" {
            return Ok(FieldMatch::Any);
        }
        if part == "last" || part == "l" {
            items.push(FieldItem::LastDay);
            continue;
        }
        if let Some((left, right)) = part.split_once('/') {
            if left.contains("..") || left == "last" || left == "l" {
                return Err(ApiError::bad_request("Invalid schedule day"));
            }
            let start = if left == "*" {
                1
            } else {
                parse_numeric_value(left, 1, 31)?
            };
            let step = parse_numeric_value(right, 1, 31)?;
            items.push(FieldItem::Step { start, step });
            continue;
        }
        if let Some((start, end)) = part.split_once("..") {
            let start = if start == "*" {
                1
            } else {
                parse_numeric_value(start, 1, 31)?
            };
            let end = if end == "*" {
                31
            } else {
                parse_numeric_value(end, 1, 31)?
            };
            if start > end {
                return Err(ApiError::bad_request("Invalid schedule day range"));
            }
            items.push(FieldItem::Range(start, end));
            continue;
        }
        items.push(FieldItem::Single(parse_numeric_value(&part, 1, 31)?));
    }
    if items.is_empty() {
        return Err(ApiError::bad_request("Invalid schedule day"));
    }
    Ok(FieldMatch::Items(items))
}

fn parse_date_field(value: &str) -> Result<(FieldMatch, FieldMatch, FieldMatch), ApiError> {
    let parts: Vec<&str> = value.split('-').collect();
    match parts.len() {
        2 => {
            let months = parse_field_items(parts[0], 1, 12, parse_month_value)?;
            let days = parse_day_field(parts[1])?;
            Ok((FieldMatch::Any, months, days))
        }
        3 => {
            let years =
                parse_field_items(parts[0], 1970, 9999, |v| parse_numeric_value(v, 1970, 9999))?;
            let months = parse_field_items(parts[1], 1, 12, parse_month_value)?;
            let days = parse_day_field(parts[2])?;
            Ok((years, months, days))
        }
        _ => Err(ApiError::bad_request("Invalid schedule date")),
    }
}

fn parse_time_field(value: &str) -> Result<(FieldMatch, FieldMatch, FieldMatch), ApiError> {
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() < 2 || parts.len() > 3 {
        return Err(ApiError::bad_request("Invalid schedule time"));
    }
    let hours = parse_field_items(parts[0], 0, 23, |v| parse_numeric_value(v, 0, 23))?;
    let minutes = parse_field_items(parts[1], 0, 59, |v| parse_numeric_value(v, 0, 59))?;
    let seconds = if parts.len() == 3 {
        parse_field_items(parts[2], 0, 59, |v| parse_numeric_value(v, 0, 59))?
    } else {
        FieldMatch::Items(vec![FieldItem::Single(0)])
    };
    Ok((hours, minutes, seconds))
}

fn expand_field(field: &FieldMatch, min: u32, max: u32) -> Vec<u32> {
    match field {
        FieldMatch::Any => (min..=max).collect(),
        FieldMatch::Items(items) => {
            let mut values = Vec::new();
            for item in items {
                match item {
                    FieldItem::Single(value) => {
                        if *value >= min && *value <= max {
                            values.push(*value);
                        }
                    }
                    FieldItem::Range(start, end) => {
                        let start = (*start).max(min);
                        let end = (*end).min(max);
                        if start <= end {
                            values.extend(start..=end);
                        }
                    }
                    FieldItem::Step { start, step } => {
                        let mut value = (*start).max(min);
                        while value <= max {
                            values.push(value);
                            value = value.saturating_add(*step);
                        }
                    }
                    FieldItem::LastDay => {}
                }
            }
            values.sort_unstable();
            values.dedup();
            values
        }
    }
}

fn field_matches(field: &FieldMatch, value: u32) -> bool {
    match field {
        FieldMatch::Any => true,
        FieldMatch::Items(items) => items.iter().any(|item| match item {
            FieldItem::Single(v) => *v == value,
            FieldItem::Range(start, end) => value >= *start && value <= *end,
            FieldItem::Step { start, step } => {
                value >= *start && (value - *start).is_multiple_of(*step)
            }
            FieldItem::LastDay => false,
        }),
    }
}

fn last_day_of_month(year: i32, month: u32) -> Option<u32> {
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    let first_next = chrono::NaiveDate::from_ymd_opt(next_year, next_month, 1)?;
    let last_day = first_next - chrono::Duration::days(1);
    Some(last_day.day())
}

fn day_matches(field: &FieldMatch, day: u32, year: i32, month: u32) -> bool {
    match field {
        FieldMatch::Any => true,
        FieldMatch::Items(items) => items.iter().any(|item| match item {
            FieldItem::Single(value) => *value == day,
            FieldItem::Range(start, end) => day >= *start && day <= *end,
            FieldItem::Step { start, step } => {
                day >= *start && (day - *start).is_multiple_of(*step)
            }
            FieldItem::LastDay => last_day_of_month(year, month) == Some(day),
        }),
    }
}

fn normalize_schedule_alias(value: &str) -> Option<&'static str> {
    match value {
        "minutely" => Some("*-*-* *:*:00"),
        "hourly" => Some("*-*-* *:00:00"),
        "daily" => Some("*-*-* 00:00:00"),
        "weekly" => Some("mon *-*-* 00:00:00"),
        "monthly" => Some("*-*-01 00:00:00"),
        "yearly" | "annually" => Some("*-01-01 00:00:00"),
        "quarterly" => Some("*-1/3-01 00:00:00"),
        "semiannually" | "semi-annually" => Some("*-1/6-01 00:00:00"),
        _ => None,
    }
}

fn parse_calendar_event(value: &str) -> Result<CalendarSpec, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::bad_request("Invalid schedule"));
    }

    let mut tokens = trimmed.split_whitespace().collect::<Vec<_>>();
    if let Some(first) = tokens.first().copied() {
        let first_lower = first.to_ascii_lowercase();
        if let Some(alias) = normalize_schedule_alias(&first_lower) {
            let mut alias_tokens = alias.split_whitespace().collect::<Vec<_>>();
            if tokens.len() == 1 {
                tokens = alias_tokens;
            } else if tokens.len() == 2 && tokens[1].contains(':') {
                if let Some(pos) = alias_tokens.iter().position(|tok| tok.contains(':')) {
                    alias_tokens[pos] = tokens[1];
                    tokens = alias_tokens;
                } else {
                    return Err(ApiError::bad_request("Invalid schedule time"));
                }
            } else if tokens.len() == 2 {
                let mut new_tokens = alias_tokens;
                new_tokens.push(tokens[1]);
                tokens = new_tokens;
            } else if tokens.len() == 3 && tokens[1].contains(':') {
                let mut alias_tokens = alias_tokens.clone();
                if let Some(pos) = alias_tokens.iter().position(|tok| tok.contains(':')) {
                    alias_tokens[pos] = tokens[1];
                }
                alias_tokens.push(tokens[2]);
                tokens = alias_tokens;
            } else {
                return Err(ApiError::bad_request("Invalid schedule"));
            }
        }
    }

    let mut timezone = None;
    if let Some(token) = tokens.last().copied() {
        if let Some(parsed) = parse_timezone_token(token)? {
            timezone = Some(parsed);
            tokens.pop();
        }
    }
    if timezone.is_none() {
        let mut tz_index = None;
        for (idx, token) in tokens.iter().enumerate() {
            if let Some(parsed) = parse_timezone_token(token)? {
                timezone = Some(parsed);
                tz_index = Some(idx);
                break;
            }
        }
        if let Some(idx) = tz_index {
            tokens.remove(idx);
        }
    }

    let mut weekday = None;
    let mut date = None;
    let mut time = None;

    for token in tokens {
        if token.contains(':') {
            if time.is_some() {
                return Err(ApiError::bad_request("Invalid schedule time"));
            }
            time = Some(token);
        } else if token.contains('-') {
            if date.is_some() {
                return Err(ApiError::bad_request("Invalid schedule date"));
            }
            date = Some(token);
        } else if token == "*"
            || token.contains("..")
            || token.contains(',')
            || token.chars().any(|c| c.is_ascii_alphabetic())
        {
            if weekday.is_some() {
                return Err(ApiError::bad_request("Invalid schedule weekday"));
            }
            weekday = Some(token);
        } else if token.contains('*') || token.contains('.') {
            if date.is_some() {
                return Err(ApiError::bad_request("Invalid schedule date"));
            }
            date = Some(token);
        } else {
            return Err(ApiError::bad_request("Invalid schedule"));
        }
    }

    let (years, months, days) = if let Some(date) = date {
        parse_date_field(date)?
    } else {
        (FieldMatch::Any, FieldMatch::Any, FieldMatch::Any)
    };
    let weekdays = if let Some(weekday) = weekday {
        parse_weekday_field(weekday)?
    } else {
        FieldMatch::Any
    };
    let (hours, minutes, seconds) = if let Some(time) = time {
        parse_time_field(time)?
    } else {
        (
            FieldMatch::Items(vec![FieldItem::Single(0)]),
            FieldMatch::Items(vec![FieldItem::Single(0)]),
            FieldMatch::Items(vec![FieldItem::Single(0)]),
        )
    };

    Ok(CalendarSpec {
        tz: timezone.unwrap_or(CalendarTimezone::Local),
        years,
        months,
        days,
        weekdays,
        hours,
        minutes,
        seconds,
    })
}

fn next_calendar_run(
    spec: &CalendarSpec,
    base: chrono::DateTime<chrono::Utc>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let start = base + Duration::seconds(1);
    let max_days = 366 * 200;

    let hours = expand_field(&spec.hours, 0, 23);
    let minutes = expand_field(&spec.minutes, 0, 59);
    let seconds = expand_field(&spec.seconds, 0, 59);

    let (start_naive, to_utc) = match spec.tz {
        CalendarTimezone::Local => {
            let local = chrono::DateTime::<chrono::Local>::from(start);
            (
                local.naive_local(),
                Box::new(|naive: chrono::NaiveDateTime| {
                    match chrono::Local.from_local_datetime(&naive) {
                        chrono::LocalResult::Single(dt) => Some(dt.with_timezone(&chrono::Utc)),
                        chrono::LocalResult::Ambiguous(a, b) => {
                            Some(if a <= b { a } else { b }.with_timezone(&chrono::Utc))
                        }
                        chrono::LocalResult::None => None,
                    }
                })
                    as Box<dyn Fn(chrono::NaiveDateTime) -> Option<chrono::DateTime<chrono::Utc>>>,
            )
        }
        CalendarTimezone::Fixed(offset) => {
            let local = start.with_timezone(&offset);
            (
                local.naive_local(),
                Box::new(move |naive: chrono::NaiveDateTime| {
                    offset
                        .from_local_datetime(&naive)
                        .single()
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                })
                    as Box<dyn Fn(chrono::NaiveDateTime) -> Option<chrono::DateTime<chrono::Utc>>>,
            )
        }
        CalendarTimezone::Named(tz) => {
            let local = start.with_timezone(&tz);
            (
                local.naive_local(),
                Box::new(
                    move |naive: chrono::NaiveDateTime| match tz.from_local_datetime(&naive) {
                        chrono::LocalResult::Single(dt) => Some(dt.with_timezone(&chrono::Utc)),
                        chrono::LocalResult::Ambiguous(a, b) => {
                            Some(if a <= b { a } else { b }.with_timezone(&chrono::Utc))
                        }
                        chrono::LocalResult::None => None,
                    },
                )
                    as Box<dyn Fn(chrono::NaiveDateTime) -> Option<chrono::DateTime<chrono::Utc>>>,
            )
        }
    };

    for day_offset in 0..=max_days {
        let date = start_naive.date() + chrono::Duration::days(day_offset);
        let year = date.year() as u32;
        let month = date.month();
        let day = date.day();
        let weekday = weekday_index(date.weekday());

        if !field_matches(&spec.years, year)
            || !field_matches(&spec.months, month)
            || !day_matches(&spec.days, day, date.year(), month)
            || !field_matches(&spec.weekdays, weekday)
        {
            continue;
        }

        let min_time = if day_offset == 0 {
            Some(start_naive.time())
        } else {
            None
        };

        for hour in &hours {
            for minute in &minutes {
                for second in &seconds {
                    if let Some(min_time) = min_time {
                        if (*hour, *minute, *second)
                            < (min_time.hour(), min_time.minute(), min_time.second())
                        {
                            continue;
                        }
                    }
                    let Some(naive) = date.and_hms_opt(*hour, *minute, *second) else {
                        continue;
                    };
                    if let Some(dt) = to_utc(naive) {
                        if dt > base {
                            return Some(dt);
                        }
                    }
                }
            }
        }
    }
    None
}

fn job_last_run_time(state: Option<&VerificationJobState>) -> Option<i64> {
    state.and_then(|entry| {
        entry.last_run_time.or(entry.last_run_endtime).or_else(|| {
            entry
                .last_run_upid
                .as_deref()
                .and_then(parse_upid_starttime)
        })
    })
}

fn compute_next_run(
    schedule: Option<&str>,
    last_run: Option<i64>,
    now: i64,
    interval: Option<i64>,
) -> Option<i64> {
    if let Some(schedule) = schedule {
        let base = last_run.unwrap_or(now);
        let base_dt = chrono::DateTime::<chrono::Utc>::from_timestamp(base, 0)?;
        let spec = parse_calendar_event(schedule).ok()?;
        return next_calendar_run(&spec, base_dt).map(|dt| dt.timestamp());
    }

    interval.map(|interval| {
        let base = last_run.unwrap_or(now);
        base + interval
    })
}

fn compute_next_run_cached(
    job: &VerificationJobConfig,
    entry: &mut VerificationJobState,
    now: i64,
    interval: Option<i64>,
) -> Option<i64> {
    let schedule = job.schedule.as_deref();
    let last_run_time = job_last_run_time(Some(entry));
    let schedule_changed = entry.last_schedule.as_deref() != schedule;
    let last_run_changed = entry.last_run_time != last_run_time;
    let cached_next = entry.next_run;

    if schedule_changed || last_run_changed || cached_next.is_none() || cached_next <= Some(now) {
        entry.next_run = compute_next_run(schedule, last_run_time, now, interval);
        entry.last_schedule = schedule.map(|value| value.to_string());
        entry.last_run_time = last_run_time;
    }

    entry.next_run
}

fn compute_verify_job_status(
    job: &VerificationJobConfig,
    job_states: &HashMap<String, VerificationJobState>,
    snapshots: &[TaskSnapshot],
    now: i64,
    interval: Option<i64>,
    enabled: bool,
) -> (Option<i64>, Option<String>, Option<String>, Option<i64>) {
    let worker_id = format!("{}:{}", job.store, job.id);
    let mut last_task: Option<TaskSnapshot> = None;
    for task in snapshots.iter().filter(|t| {
        t.worker_type == "verificationjob" && t.worker_id.as_deref() == Some(worker_id.as_str())
    }) {
        if last_task
            .as_ref()
            .map(|prev| task.starttime > prev.starttime)
            .unwrap_or(true)
        {
            last_task = Some(task.clone());
        }
    }

    let state_entry = job_states.get(&job.id);
    let last_run_upid = state_entry
        .and_then(|entry| entry.last_run_upid.clone())
        .or_else(|| last_task.as_ref().map(|task| task.upid.clone()));
    let last_run_state = state_entry
        .and_then(|entry| entry.last_run_state.clone())
        .or_else(|| {
            last_task
                .as_ref()
                .and_then(|task| task.exitstatus.clone().or_else(|| task.status.clone()))
        });
    let last_run_endtime = state_entry
        .and_then(|entry| entry.last_run_endtime)
        .or_else(|| last_task.as_ref().and_then(|task| task.endtime));
    let last_run_time = job_last_run_time(state_entry)
        .or(last_run_endtime)
        .or_else(|| last_run_upid.as_deref().and_then(parse_upid_starttime));

    let next_run = if enabled {
        compute_next_run(job.schedule.as_deref(), last_run_time, now, interval)
    } else {
        None
    };

    (next_run, last_run_state, last_run_upid, last_run_endtime)
}

fn task_snapshot_value(task: &TaskSnapshot) -> serde_json::Value {
    serde_json::json!({
        "upid": task.upid,
        "node": task.node,
        "pid": task.pid,
        "pstart": task.pstart,
        "starttime": task.starttime,
        "worker-type": task.worker_type,
        "worker-id": task.worker_id,
        "worker_type": task.worker_type,
        "worker_id": task.worker_id,
        "user": task.user,
        "endtime": task.endtime,
        "status": task.status,
        "exitstatus": task.exitstatus,
        "running": task.running,
    })
}

enum H2Context {
    Backup(H2BackupContext),
    Reader(H2ReaderContext),
}

struct H2BackupContext {
    state: Arc<ServerState>,
    tenant_id: String,
    session_id: String,
    namespace: Option<String>,
    store: String,
    backup_type: String,
    backup_id: String,
    backup_time_epoch: i64,
}

struct H2ReaderContext {
    state: Arc<ServerState>,
    tenant_id: String,
    session_id: String,
    namespace: Option<String>,
    store: String,
    backup_type: String,
    backup_id: String,
    backup_time: String,
}

async fn handle_h2_request(
    ctx: Arc<H2Context>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let response = match &*ctx {
        H2Context::Backup(backup) => handle_h2_backup(backup, req).await,
        H2Context::Reader(reader) => handle_h2_reader(reader, req).await,
    };
    Ok(response)
}

// === Handler implementations ===

/// Health check endpoint - returns 200 if server is running
async fn handle_health(state: Arc<ServerState>) -> Response<Full<Bytes>> {
    let (backup_sessions, reader_sessions) = state.sessions.session_count().await;
    let health = serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION"),
        "sessions": {
            "backup": backup_sessions,
            "reader": reader_sessions
        }
    });
    json_response(StatusCode::OK, &health)
}

/// Readiness check endpoint - returns 200 if server is ready to accept requests
async fn handle_ready(state: Arc<ServerState>) -> Response<Full<Bytes>> {
    // Check if we have at least one datastore available
    let datastores_count = state.datastores.len();
    if datastores_count == 0 {
        let error = serde_json::json!({
            "status": "not_ready",
            "reason": "no datastores configured"
        });
        return json_response(StatusCode::SERVICE_UNAVAILABLE, &error);
    }

    let ready = serde_json::json!({
        "status": "ready",
        "datastores": datastores_count
    });
    json_response(StatusCode::OK, &ready)
}

fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3600;
    let minutes = (seconds % 3600) / 60;
    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

async fn handle_root_ui(state: Arc<ServerState>) -> Response<Full<Bytes>> {
    let uptime = state.start_time.elapsed().as_secs();
    let uptime_text = format_uptime(uptime);
    let datastores = state.datastores.len();
    let running_tasks = state.tasks.running_count().await;
    let (backup_sessions, reader_sessions) = state.sessions.session_count().await;
    let version = env!("CARGO_PKG_VERSION");

    let html = format!(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>PBS Cloud</title>
    <style>
      :root {{
        --ink: #0b1020;
        --card: rgba(255, 255, 255, 0.08);
        --card-strong: rgba(255, 255, 255, 0.14);
        --accent: #f97316;
        --accent-2: #38bdf8;
        --text: #f8fafc;
        --muted: rgba(248, 250, 252, 0.65);
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        min-height: 100vh;
        font-family: "Space Grotesk", "IBM Plex Sans", "Segoe UI", sans-serif;
        color: var(--text);
        background:
          radial-gradient(circle at 15% 20%, rgba(56, 189, 248, 0.25), transparent 45%),
          radial-gradient(circle at 80% 0%, rgba(249, 115, 22, 0.35), transparent 40%),
          linear-gradient(135deg, #0b1020 0%, #12244d 45%, #0f172a 100%);
      }}
      main {{
        padding: 48px 24px 64px;
        max-width: 1100px;
        margin: 0 auto;
      }}
      header {{
        display: grid;
        gap: 12px;
        margin-bottom: 32px;
      }}
      h1 {{
        font-size: clamp(2rem, 5vw, 3.2rem);
        margin: 0;
        letter-spacing: 0.02em;
      }}
      .subtitle {{
        color: var(--muted);
        font-size: 1rem;
        max-width: 620px;
      }}
      .badge-row {{
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        margin-top: 8px;
      }}
      .badge {{
        padding: 6px 12px;
        border-radius: 999px;
        background: var(--card);
        border: 1px solid rgba(255, 255, 255, 0.18);
        font-size: 0.85rem;
        color: var(--muted);
      }}
      .grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
        gap: 16px;
      }}
      .card {{
        padding: 18px;
        border-radius: 18px;
        background: var(--card);
        border: 1px solid rgba(255, 255, 255, 0.16);
        backdrop-filter: blur(6px);
        box-shadow: 0 18px 50px rgba(2, 6, 23, 0.4);
        transition: transform 0.25s ease, border-color 0.25s ease;
      }}
      .card:hover {{
        transform: translateY(-4px);
        border-color: rgba(249, 115, 22, 0.6);
      }}
      .label {{
        color: var(--muted);
        font-size: 0.85rem;
        letter-spacing: 0.08em;
        text-transform: uppercase;
      }}
      .value {{
        font-size: 1.6rem;
        margin-top: 6px;
      }}
      .links {{
        display: grid;
        gap: 10px;
        margin-top: 12px;
      }}
      a {{
        color: var(--text);
        text-decoration: none;
        background: var(--card-strong);
        padding: 10px 14px;
        border-radius: 12px;
        border: 1px solid rgba(255, 255, 255, 0.2);
        transition: border-color 0.2s ease, transform 0.2s ease;
        font-family: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        font-size: 0.9rem;
      }}
      a:hover {{
        border-color: var(--accent-2);
        transform: translateY(-1px);
      }}
      footer {{
        margin-top: 32px;
        color: var(--muted);
        font-size: 0.9rem;
      }}
      @media (max-width: 640px) {{
        .badge-row {{ gap: 8px; }}
        .card {{ padding: 16px; }}
      }}
    </style>
  </head>
  <body>
    <main>
      <header>
        <h1>PBS Cloud</h1>
        <div class="subtitle">
          A PBS-compatible backup server with S3 and local storage, multi-tenancy, and
          compliance-focused tooling. Use the quick links below to explore the API surface.
        </div>
        <div class="badge-row">
          <div class="badge">Version {version}</div>
          <div class="badge">Uptime {uptime_text}</div>
        </div>
      </header>

      <section class="grid">
        <div class="card">
          <div class="label">Datastores</div>
          <div class="value">{datastores}</div>
        </div>
        <div class="card">
          <div class="label">Tasks Running</div>
          <div class="value">{running_tasks}</div>
        </div>
        <div class="card">
          <div class="label">Sessions</div>
          <div class="value">{backup_sessions} backup / {reader_sessions} reader</div>
        </div>
      </section>

      <section class="card" style="margin-top: 18px;">
        <div class="label">Quick API Links</div>
        <div class="links">
          <a href="/api2/json/version">/api2/json/version</a>
          <a href="/api2/json/ping">/api2/json/ping</a>
          <a href="/api2/json/status">/api2/json/status</a>
          <a href="/api2/json/status/datastore-usage">/api2/json/status/datastore-usage</a>
          <a href="/api2/json/nodes">/api2/json/nodes</a>
          <a href="/metrics">/metrics</a>
        </div>
      </section>

      <footer>Auth-protected endpoints require a PBS API token.</footer>
    </main>
  </body>
</html>"#
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(html)))
        .expect("valid response")
}

async fn handle_version() -> Response<Full<Bytes>> {
    let version = serde_json::json!({
        "data": {
            "version": env!("CARGO_PKG_VERSION"),
            "release": "1.0",
            "repoid": "pbs-cloud"
        }
    });
    json_response(StatusCode::OK, &version)
}

async fn handle_ping() -> Response<Full<Bytes>> {
    let response = serde_json::json!({
        "data": {
            "pong": true
        }
    });
    json_response(StatusCode::OK, &response)
}

async fn handle_auth_info() -> Response<Full<Bytes>> {
    let info = serde_json::json!({
        "data": {
            "realm": "pbs",
            "methods": ["token"]
        }
    });
    json_response(StatusCode::OK, &info)
}

async fn handle_metrics(state: Arc<ServerState>) -> Response<Full<Bytes>> {
    let output = state.metrics.export();
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain; version=0.0.4")
        .body(Full::new(Bytes::from(output)))
        .expect("valid response")
}

async fn handle_webhook_receive(
    state: Arc<ServerState>,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let secret = match &state.config.webhook_receiver_secret {
        Some(secret) => secret.clone(),
        None => return bad_request("Webhook receiver not configured"),
    };

    let signature = match req.headers().get("X-Signature-256") {
        Some(sig) => match sig.to_str() {
            Ok(v) => v.to_string(),
            Err(_) => return bad_request("Invalid signature header"),
        },
        None => return error_response(ApiError::unauthorized("Missing signature")),
    };

    let body = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return bad_request("Failed to read request body"),
    };

    if !verify_webhook_signature(&secret, &body, &signature) {
        return error_response(ApiError::unauthorized("Invalid signature"));
    }

    json_response(
        StatusCode::OK,
        &serde_json::json!({"data": {"verified": true}}),
    )
}

fn verify_webhook_signature(secret: &str, body: &[u8], header: &str) -> bool {
    let signature = header.strip_prefix("sha256=").unwrap_or(header);
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(body);
    let sig_bytes = match hex::decode(signature) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    mac.verify_slice(&sig_bytes).is_ok()
}

async fn handle_compliance_report(
    state: Arc<ServerState>,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let store = get_query_param(req.uri(), "store").unwrap_or_else(|| "default".to_string());
    if let Err(e) = validate_datastore_name(&store) {
        return error_response(e);
    }
    let datastore = match state.get_datastore(&store) {
        Some(ds) => ds,
        None => return not_found(),
    };
    let groups = datastore.list_backup_groups().await.unwrap_or_default();
    let mut snapshots = Vec::new();
    let mut total_bytes: u64 = 0;

    for group in groups {
        let times = datastore
            .list_snapshots(
                group.namespace.as_deref(),
                &group.backup_type,
                &group.backup_id,
            )
            .await
            .unwrap_or_default();

        for time in times {
            let snapshot_path = format!("{}/{}", group.path(), time);
            if let Ok(manifest) = datastore.read_manifest_any(&snapshot_path).await {
                let size: u64 = manifest.files.iter().map(|f| f.size).sum();
                total_bytes = total_bytes.saturating_add(size);
                let retain_until = manifest
                    .unprotected
                    .as_ref()
                    .and_then(|v| v.get("worm_retain_until"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let protected = retain_until
                    .as_ref()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt > chrono::Utc::now())
                    .unwrap_or(false);

                snapshots.push(serde_json::json!({
                    "ns": group.namespace,
                    "backup-type": group.backup_type,
                    "backup-id": group.backup_id,
                    "backup-time": time,
                    "size": size,
                    "retain-until": retain_until,
                    "protected": protected
                }));
            }
        }
    }

    let report = serde_json::json!({
        "data": {
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "snapshot_count": snapshots.len(),
            "total_bytes": total_bytes,
            "snapshots": snapshots
        }
    });

    json_response(StatusCode::OK, &report)
}

async fn handle_login(state: Arc<ServerState>, req: Request<Incoming>) -> Response<Full<Bytes>> {
    // Check Content-Type header to determine parsing method
    let is_json = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("application/json"))
        .unwrap_or(false);

    let body = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return bad_request("Failed to read request body"),
    };

    #[derive(serde::Deserialize)]
    struct LoginRequest {
        username: String,
        password: String,
    }

    // Try JSON first, then form-urlencoded (for PBS client compatibility)
    let params: LoginRequest = if is_json {
        match serde_json::from_slice(&body) {
            Ok(p) => p,
            Err(_) => return bad_request("Invalid JSON"),
        }
    } else {
        // Try form-urlencoded (application/x-www-form-urlencoded)
        match serde_urlencoded::from_bytes(&body) {
            Ok(p) => p,
            // Fallback to JSON parsing for backwards compatibility
            Err(_) => match serde_json::from_slice(&body) {
                Ok(p) => p,
                Err(_) => return bad_request("Invalid request body (expected JSON or form-urlencoded)"),
            },
        }
    };

    // Token-based auth: password field contains the API token
    match state.auth.authenticate_token(&params.password).await {
        Ok(ctx) => {
            audit::log_auth_success(&params.username, &ctx.user.tenant_id, None);
            // Generate PBS-compatible ticket
            let ticket = generate_pbs_ticket(&state, &params.username);
            tracing::info!("[AUTH] Generated ticket for user {}: {}", params.username, &ticket[..ticket.len().min(50)]);

            // Generate CSRF token using same HMAC key
            let csrf_token = generate_csrf_token(&state, &params.username);

            let response = serde_json::json!({
                "data": {
                    "username": params.username,
                    "ticket": ticket,
                    "CSRFPreventionToken": csrf_token
                }
            });
            json_response(StatusCode::OK, &response)
        }
        Err(e) => {
            audit::log_auth_failure(Some(&params.username), None, &e.message);
            error_response(e)
        }
    }
}

/// Generate a PBS-compatible ticket in format: PBS:<userid>:<timestamp_hex>::<base64_signature>
fn generate_pbs_ticket(state: &ServerState, username: &str) -> String {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Ticket data to sign: PBS:<userid>:<timestamp_hex>
    let ticket_data = format!("PBS:{}:{:08X}", username, timestamp);

    // Sign with server's ticket key
    let mut mac = HmacSha256::new_from_slice(&state.ticket_key)
        .expect("HMAC can take key of any size");
    mac.update(ticket_data.as_bytes());
    let signature = mac.finalize().into_bytes();

    // Encode signature as base64 without padding (like proxmox_base64::encode_no_pad)
    let sig_b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&signature);

    // Full ticket: PBS:<userid>:<timestamp>::<base64_signature> (note double colon)
    format!("{}::{}", ticket_data, sig_b64)
}

/// Verify a PBS ticket and return the username if valid
fn verify_pbs_ticket(state: &ServerState, ticket: &str) -> Option<String> {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;

    // Parse ticket: PBS:<userid>:<timestamp>::<signature>
    // Split on "::" first to get data and signature
    let (data_part, sig_part) = ticket.split_once("::")?;

    // data_part should be: PBS:<userid>:<timestamp>
    let parts: Vec<&str> = data_part.splitn(3, ':').collect();
    if parts.len() != 3 || parts[0] != "PBS" {
        tracing::warn!("[AUTH] Ticket parse failed: wrong format");
        return None;
    }

    let username = parts[1];
    let timestamp_hex = parts[2];

    // Parse timestamp and check age (allow -5 min to +2 hours)
    let timestamp = i64::from_str_radix(timestamp_hex, 16).ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let age = now - timestamp;

    if age < -300 {
        tracing::warn!("[AUTH] Ticket rejected: timestamp too far in future");
        return None;
    }
    if age > 7200 { // 2 hour lifetime
        tracing::warn!("[AUTH] Ticket rejected: expired (age={}s)", age);
        return None;
    }

    // Verify signature
    let expected_sig = base64::engine::general_purpose::STANDARD_NO_PAD.decode(sig_part).ok()?;

    let mut mac = HmacSha256::new_from_slice(&state.ticket_key)
        .expect("HMAC can take key of any size");
    mac.update(data_part.as_bytes());

    if mac.verify_slice(&expected_sig).is_err() {
        tracing::warn!("[AUTH] Ticket rejected: invalid signature");
        return None;
    }

    tracing::info!("[AUTH] Ticket verified for user: {}", username);
    Some(username.to_string())
}

/// Generate CSRF prevention token
fn generate_csrf_token(state: &ServerState, username: &str) -> String {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let data = format!("{:08X}:{}:", timestamp, username);

    let mut mac = HmacSha256::new_from_slice(&state.ticket_key)
        .expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    let signature = mac.finalize().into_bytes();

    let sig_b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&signature);
    format!("{:08X}:{}", timestamp, sig_b64)
}

async fn handle_nodes(state: Arc<ServerState>) -> Response<Full<Bytes>> {
    let data_dir = state
        .config
        .data_dir
        .as_deref()
        .map(Path::new)
        .unwrap_or_else(|| Path::new("/"));
    let snapshot = {
        let mut tracker = state.cpu_tracker.lock();
        collect_system_snapshot(Some(data_dir), state.tls_fingerprint.as_deref(), &mut tracker)
    };
    let nodes = serde_json::json!({
        "data": [{
            "node": "localhost",
            "status": "online",
            "cpu": snapshot.cpu_usage,
            "maxcpu": snapshot.cpuinfo.cpus,
            "mem": snapshot.memory.used,
            "maxmem": snapshot.memory.total,
            "uptime": snapshot.uptime,
        }]
    });
    json_response(StatusCode::OK, &nodes)
}

async fn handle_node_status(state: Arc<ServerState>) -> Response<Full<Bytes>> {
    let data_dir = state
        .config
        .data_dir
        .as_deref()
        .map(Path::new)
        .unwrap_or_else(|| Path::new("/"));
    let snapshot = {
        let mut tracker = state.cpu_tracker.lock();
        collect_system_snapshot(Some(data_dir), state.tls_fingerprint.as_deref(), &mut tracker)
    };
    let data = serde_json::json!({
        "data": {
            "memory": {
                "total": snapshot.memory.total,
                "used": snapshot.memory.used,
                "free": snapshot.memory.free
            },
            "swap": {
                "total": snapshot.swap.total,
                "used": snapshot.swap.used,
                "free": snapshot.swap.free
            },
            "root": {
                "total": snapshot.root.total,
                "used": snapshot.root.used,
                "avail": snapshot.root.avail
            },
            "uptime": snapshot.uptime,
            "loadavg": snapshot.loadavg,
            "current-kernel": {
                "sysname": snapshot.kernel.sysname,
                "release": snapshot.kernel.release,
                "version": snapshot.kernel.version,
                "machine": snapshot.kernel.machine
            },
            "kversion": format!(
                "{} {} {}",
                snapshot.kernel.sysname,
                snapshot.kernel.release,
                snapshot.kernel.version
            ).trim().to_string(),
            "cpu": snapshot.cpu_usage,
            "wait": snapshot.cpu_wait,
            "cpuinfo": {
                "model": snapshot.cpuinfo.model,
                "sockets": snapshot.cpuinfo.sockets,
                "cpus": snapshot.cpuinfo.cpus
            },
            "info": { "fingerprint": snapshot.fingerprint },
            "boot-info": {
                "mode": snapshot.boot.mode,
                "secureboot": snapshot.boot.secure_boot
            }
        }
    });
    json_response(StatusCode::OK, &data)
}

async fn collect_namespaces(datastore: Arc<Datastore>) -> Vec<String> {
    use std::collections::HashSet;
    let mut namespaces = HashSet::new();
    namespaces.insert(String::new()); // root

    if let Ok(groups) = datastore.list_backup_groups().await {
        for group in groups {
            if let Some(ns) = group.namespace {
                namespaces.insert(ns);
            }
        }
    }

    if let Ok(files) = datastore.backend().list_files("").await {
        for file in files {
            let Some(prefix) = file.strip_suffix("/.namespace") else {
                continue;
            };
            if prefix.is_empty() {
                namespaces.insert(String::new());
                continue;
            }
            let parts: Vec<&str> = prefix.split('/').collect();
            let mut idx = 0;
            let mut ns_parts = Vec::new();
            while idx + 1 < parts.len() && parts[idx] == "ns" {
                let part = parts[idx + 1];
                if part.is_empty() {
                    ns_parts.clear();
                    break;
                }
                ns_parts.push(part.to_string());
                idx += 2;
            }
            if idx == parts.len() && !ns_parts.is_empty() {
                namespaces.insert(ns_parts.join("/"));
            }
        }
    }

    let mut list: Vec<String> = namespaces.into_iter().collect();
    list.sort();
    list
}

async fn handle_datastore_api(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let uri = req.uri().clone();
    let path = uri.path();
    let parts: Vec<&str> = path
        .trim_start_matches("/api2/json/admin/datastore/")
        .split('/')
        .collect();

    if parts.is_empty() || parts[0].is_empty() {
        // List datastores
        let ds_list: Vec<_> = state
            .datastores
            .keys()
            .map(|name| serde_json::json!({"store": name}))
            .collect();
        return json_response(StatusCode::OK, &serde_json::json!({"data": ds_list}));
    }

    let ds_name = parts[0];
    if let Err(e) = validate_datastore_name(ds_name) {
        return error_response(e);
    }
    let datastore = match state.get_datastore(ds_name) {
        Some(ds) => ds,
        None => return not_found(),
    };

    let subpath = parts.get(1).copied().unwrap_or("");
    let method = req.method().clone();

    match (method, subpath) {
        (Method::GET, "") => {
            let stats = datastore.backend().stats().await.unwrap_or_default();
            let used = stats.chunk_bytes + stats.file_bytes;
            let total = used.max(1);
            let mut info = serde_json::json!({
                "data": {
                    "store": ds_name,
                    "total": total,
                    "used": used,
                    "avail": total.saturating_sub(used),
                }
            });
            let counts = collect_datastore_counts(datastore.clone()).await;
            let gc_status = {
                let map = state.gc_status.read().await;
                map.get(ds_name).cloned()
            };
            if let Some(obj) = info.get_mut("data").and_then(|value| value.as_object_mut()) {
                if let Some(counts) = counts {
                    obj.insert("counts".to_string(), counts);
                }
                if let Some(gc_status) = gc_status {
                    obj.insert("gc-status".to_string(), gc_status);
                }
            }
            json_response(StatusCode::OK, &info)
        }
        (Method::GET, "status") => {
            let stats = datastore.backend().stats().await.unwrap_or_default();
            let used = stats.chunk_bytes + stats.file_bytes;
            let total = used.max(1);
            let mut info = serde_json::json!({
                "data": {
                    "total": total,
                    "used": used,
                    "avail": total.saturating_sub(used),
                }
            });
            let counts = collect_datastore_counts(datastore.clone()).await;
            let gc_status = {
                let map = state.gc_status.read().await;
                map.get(ds_name).cloned()
            };
            if let Some(obj) = info.get_mut("data").and_then(|value| value.as_object_mut()) {
                if let Some(counts) = counts {
                    obj.insert("counts".to_string(), counts);
                }
                if let Some(gc_status) = gc_status {
                    obj.insert("gc-status".to_string(), gc_status);
                }
            }
            json_response(StatusCode::OK, &info)
        }
        (Method::GET, "groups") => {
            let namespace = get_query_param(&uri, "ns").unwrap_or_default();
            if !namespace.is_empty() {
                if let Err(e) = validate_backup_namespace(&namespace) {
                    return error_response(e);
                }
            }

            let groups = datastore.list_backup_groups().await.unwrap_or_default();
            let mut group_info = Vec::new();

            for group in groups {
                if !namespace_matches(&namespace, group.namespace.as_deref()) {
                    continue;
                }
                let snapshots = datastore
                    .list_snapshots(
                        group.namespace.as_deref(),
                        &group.backup_type,
                        &group.backup_id,
                    )
                    .await
                    .unwrap_or_default();
                if snapshots.is_empty() {
                    continue;
                }
                let mut last_epoch: i64 = 0;
                let mut latest_snapshot: Option<String> = None;
                for snapshot in &snapshots {
                    if let Some(epoch) = snapshot_to_epoch(snapshot) {
                        if epoch >= last_epoch {
                            last_epoch = epoch;
                            latest_snapshot = Some(snapshot.clone());
                        }
                    }
                }

                let mut files = Vec::new();
                let mut comment = None;
                if let Some(snapshot) = latest_snapshot {
                    let snapshot_path = format!("{}/{}", group.path(), snapshot);
                    if let Ok(manifest) = datastore.read_manifest_any(&snapshot_path).await {
                        files = manifest.files.iter().map(|f| f.filename.clone()).collect();
                        comment = manifest_note_line(&manifest);
                    }
                }

                let owner = datastore.read_group_owner(&group).await.ok().flatten();

                group_info.push(serde_json::json!({
                    "backup-type": group.backup_type,
                    "backup-id": group.backup_id,
                    "last-backup": last_epoch,
                    "backup-count": snapshots.len() as u64,
                    "files": files,
                    "owner": owner,
                    "comment": comment,
                }));
            }

            json_response(StatusCode::OK, &serde_json::json!({"data": group_info}))
        }
        (Method::GET, "snapshots") => {
            let namespace = get_query_param(&uri, "ns").unwrap_or_default();
            if !namespace.is_empty() {
                if let Err(e) = validate_backup_namespace(&namespace) {
                    return error_response(e);
                }
            }
            let backup_type = get_query_param(&uri, "backup-type");
            let backup_id = get_query_param(&uri, "backup-id");
            if let Some(bt) = backup_type.as_deref() {
                if let Err(e) = validate_backup_type(bt) {
                    return error_response(e);
                }
            }
            if let Some(bi) = backup_id.as_deref() {
                if let Err(e) = validate_backup_id(bi) {
                    return error_response(e);
                }
            }

            let groups = datastore.list_backup_groups().await.unwrap_or_default();
            let mut snapshots = Vec::new();

            for group in groups {
                if !namespace_matches(&namespace, group.namespace.as_deref()) {
                    continue;
                }
                if let Some(bt) = backup_type.as_deref() {
                    if group.backup_type != bt {
                        continue;
                    }
                }
                if let Some(bi) = backup_id.as_deref() {
                    if group.backup_id != bi {
                        continue;
                    }
                }
                let owner = datastore.read_group_owner(&group).await.ok().flatten();
                let times = datastore
                    .list_snapshots(
                        group.namespace.as_deref(),
                        &group.backup_type,
                        &group.backup_id,
                    )
                    .await
                    .unwrap_or_default();

                for time in times {
                    let backup_time = match snapshot_to_epoch(&time) {
                        Some(epoch) => epoch,
                        None => continue,
                    };
                    let snapshot_path = format!("{}/{}", group.path(), time);
                    let mut files = Vec::new();
                    let mut size: Option<u64> = None;
                    let mut comment = None;
                    let mut protected = false;
                    let mut verification = None;
                    if let Ok(manifest) = datastore.read_manifest_any(&snapshot_path).await {
                        files = manifest
                            .files
                            .iter()
                            .map(|f| {
                                serde_json::json!({
                                    "filename": f.filename,
                                    "size": f.size,
                                })
                            })
                            .collect();
                        size = Some(manifest.files.iter().map(|f| f.size).sum());
                        comment = manifest_note_line(&manifest);
                        protected = manifest_protected(&manifest);
                        verification = manifest_verification(&manifest);
                    }

                    let mut snapshot = serde_json::json!({
                        "backup-type": group.backup_type,
                        "backup-id": group.backup_id,
                        "backup-time": backup_time,
                        "files": files,
                        "size": size,
                        "comment": comment,
                        "protected": protected,
                        "owner": owner,
                    });
                    if let Some(value) = verification {
                        if let Some(obj) = snapshot.as_object_mut() {
                            obj.insert("verification".to_string(), value);
                        }
                    }
                    snapshots.push(snapshot);
                }
            }

            json_response(StatusCode::OK, &serde_json::json!({"data": snapshots}))
        }
        (Method::DELETE, "snapshots") => {
            if !ctx.allows(Permission::DatastoreAdmin) {
                return error_response(ApiError::unauthorized("Insufficient permissions"));
            }
            let backup_type = match get_query_param(&uri, "backup-type") {
                Some(v) => v,
                None => return bad_request("Missing backup-type"),
            };
            let backup_id = match get_query_param(&uri, "backup-id") {
                Some(v) => v,
                None => return bad_request("Missing backup-id"),
            };
            let backup_time = match get_query_param(&uri, "backup-time") {
                Some(v) => v,
                None => return bad_request("Missing backup-time"),
            };
            let namespace = get_query_param(&uri, "ns");
            if let Err(e) = validate_backup_params_with_ns(
                &backup_type,
                &backup_id,
                &backup_time,
                namespace.as_deref(),
                None,
            ) {
                return error_response(e);
            }
            let backup_time = match parse_backup_time_param(&backup_time) {
                Ok(t) => t,
                Err(e) => return error_response(e),
            };

            match datastore
                .delete_snapshot(namespace.as_deref(), &backup_type, &backup_id, &backup_time)
                .await
            {
                Ok(()) => json_response(StatusCode::OK, &serde_json::json!({"data": null})),
                Err(StorageError::SnapshotProtected(reason)) => {
                    bad_request(&format!("Snapshot is protected until {}", reason))
                }
                Err(StorageError::SnapshotNotFound(_)) => not_found(),
                Err(e) => error_response(ApiError::internal(&e.to_string())),
            }
        }
        (Method::GET, "files") => {
            let backup_type = match get_query_param(&uri, "backup-type") {
                Some(v) => v,
                None => return bad_request("Missing backup-type"),
            };
            let backup_id = match get_query_param(&uri, "backup-id") {
                Some(v) => v,
                None => return bad_request("Missing backup-id"),
            };
            let backup_time = match get_query_param(&uri, "backup-time") {
                Some(v) => v,
                None => return bad_request("Missing backup-time"),
            };
            let namespace = get_query_param(&uri, "ns");
            if let Err(e) = validate_backup_params_with_ns(
                &backup_type,
                &backup_id,
                &backup_time,
                namespace.as_deref(),
                None,
            ) {
                return error_response(e);
            }
            let backup_time = match parse_backup_time_param(&backup_time) {
                Ok(t) => t,
                Err(e) => return error_response(e),
            };
            let snapshot_path =
                build_snapshot_path(namespace.as_deref(), &backup_type, &backup_id, &backup_time);
            let mut files = Vec::new();

            if let Ok(manifest) = datastore.read_manifest_any(&snapshot_path).await {
                files.extend(manifest.files.iter().map(|f| {
                    serde_json::json!({
                        "filename": f.filename,
                        "size": f.size,
                    })
                }));
            }

            let log_path = format!("{}/client.log.blob", snapshot_path);
            if let Ok(data) = datastore.backend().read_file(&log_path).await {
                files.push(serde_json::json!({
                    "filename": "client.log.blob",
                    "size": data.len() as u64,
                }));
            }

            json_response(StatusCode::OK, &serde_json::json!({"data": files}))
        }
        (Method::POST, "upload-backup-log") => {
            if !ctx.allows(Permission::Backup) {
                return error_response(ApiError::unauthorized("Insufficient permissions"));
            }
            let backup_type = match get_query_param(&uri, "backup-type") {
                Some(v) => v,
                None => return bad_request("Missing backup-type"),
            };
            let backup_id = match get_query_param(&uri, "backup-id") {
                Some(v) => v,
                None => return bad_request("Missing backup-id"),
            };
            let backup_time = match get_query_param(&uri, "backup-time") {
                Some(v) => v,
                None => return bad_request("Missing backup-time"),
            };
            let namespace = get_query_param(&uri, "ns");
            if let Err(e) = validate_backup_params_with_ns(
                &backup_type,
                &backup_id,
                &backup_time,
                namespace.as_deref(),
                None,
            ) {
                return error_response(e);
            }
            let backup_time = match parse_backup_time_param(&backup_time) {
                Ok(t) => t,
                Err(e) => return error_response(e),
            };
            let snapshot_path =
                build_snapshot_path(namespace.as_deref(), &backup_type, &backup_id, &backup_time);
            let log_path = format!("{}/client.log.blob", snapshot_path);
            if datastore.backend().read_file(&log_path).await.is_ok() {
                return bad_request("Backup log already exists");
            }

            let body = match req.collect().await {
                Ok(collected) => collected.to_bytes().to_vec(),
                Err(_) => return bad_request("Failed to read log data"),
            };
            if let Err(e) = pbs_core::DataBlob::from_bytes(&body) {
                return bad_request(&format!("Invalid data blob: {}", e));
            }

            match datastore.store_blob(&log_path, &body).await {
                Ok(()) => json_response(StatusCode::OK, &serde_json::json!({"data": null})),
                Err(e) => error_response(ApiError::internal(&e.to_string())),
            }
        }
        (Method::GET, "notes") => {
            let backup_type = match get_query_param(&uri, "backup-type") {
                Some(v) => v,
                None => return bad_request("Missing backup-type"),
            };
            let backup_id = match get_query_param(&uri, "backup-id") {
                Some(v) => v,
                None => return bad_request("Missing backup-id"),
            };
            let backup_time = match get_query_param(&uri, "backup-time") {
                Some(v) => v,
                None => return bad_request("Missing backup-time"),
            };
            let namespace = get_query_param(&uri, "ns");
            if let Err(e) = validate_backup_params_with_ns(
                &backup_type,
                &backup_id,
                &backup_time,
                namespace.as_deref(),
                None,
            ) {
                return error_response(e);
            }
            let backup_time = match parse_backup_time_param(&backup_time) {
                Ok(t) => t,
                Err(e) => return error_response(e),
            };
            let snapshot_path =
                build_snapshot_path(namespace.as_deref(), &backup_type, &backup_id, &backup_time);
            match datastore.read_manifest_any(&snapshot_path).await {
                Ok(manifest) => {
                    let notes = manifest_notes(&manifest).unwrap_or_default();
                    json_response(StatusCode::OK, &serde_json::json!({"data": notes}))
                }
                Err(e) => error_response(ApiError::not_found(&e.to_string())),
            }
        }
        (Method::PUT, "notes") => {
            if !ctx.allows(Permission::DatastoreAdmin) {
                return error_response(ApiError::unauthorized("Insufficient permissions"));
            }
            let backup_type = match get_query_param(&uri, "backup-type") {
                Some(v) => v,
                None => return bad_request("Missing backup-type"),
            };
            let backup_id = match get_query_param(&uri, "backup-id") {
                Some(v) => v,
                None => return bad_request("Missing backup-id"),
            };
            let backup_time = match get_query_param(&uri, "backup-time") {
                Some(v) => v,
                None => return bad_request("Missing backup-time"),
            };
            let notes = match get_query_param(&uri, "notes") {
                Some(v) => v,
                None => return bad_request("Missing notes"),
            };
            let namespace = get_query_param(&uri, "ns");
            if let Err(e) = validate_backup_params_with_ns(
                &backup_type,
                &backup_id,
                &backup_time,
                namespace.as_deref(),
                None,
            ) {
                return error_response(e);
            }
            let backup_time = match parse_backup_time_param(&backup_time) {
                Ok(t) => t,
                Err(e) => return error_response(e),
            };
            let snapshot_path =
                build_snapshot_path(namespace.as_deref(), &backup_type, &backup_id, &backup_time);
            match datastore.read_manifest_any(&snapshot_path).await {
                Ok(mut manifest) => {
                    update_manifest_unprotected(&mut manifest, "notes", notes.into());
                    if let Err(e) = datastore.store_manifest_at(&snapshot_path, &manifest).await {
                        return error_response(ApiError::internal(&e.to_string()));
                    }
                    json_response(StatusCode::OK, &serde_json::json!({"data": null}))
                }
                Err(e) => error_response(ApiError::not_found(&e.to_string())),
            }
        }
        (Method::GET, "protected") => {
            let backup_type = match get_query_param(&uri, "backup-type") {
                Some(v) => v,
                None => return bad_request("Missing backup-type"),
            };
            let backup_id = match get_query_param(&uri, "backup-id") {
                Some(v) => v,
                None => return bad_request("Missing backup-id"),
            };
            let backup_time = match get_query_param(&uri, "backup-time") {
                Some(v) => v,
                None => return bad_request("Missing backup-time"),
            };
            let namespace = get_query_param(&uri, "ns");
            if let Err(e) = validate_backup_params_with_ns(
                &backup_type,
                &backup_id,
                &backup_time,
                namespace.as_deref(),
                None,
            ) {
                return error_response(e);
            }
            let backup_time = match parse_backup_time_param(&backup_time) {
                Ok(t) => t,
                Err(e) => return error_response(e),
            };
            let snapshot_path =
                build_snapshot_path(namespace.as_deref(), &backup_type, &backup_id, &backup_time);
            match datastore.read_manifest_any(&snapshot_path).await {
                Ok(manifest) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({"data": manifest_protected(&manifest)}),
                ),
                Err(e) => error_response(ApiError::not_found(&e.to_string())),
            }
        }
        (Method::PUT, "protected") => {
            if !ctx.allows(Permission::DatastoreAdmin) {
                return error_response(ApiError::unauthorized("Insufficient permissions"));
            }
            let backup_type = match get_query_param(&uri, "backup-type") {
                Some(v) => v,
                None => return bad_request("Missing backup-type"),
            };
            let backup_id = match get_query_param(&uri, "backup-id") {
                Some(v) => v,
                None => return bad_request("Missing backup-id"),
            };
            let backup_time = match get_query_param(&uri, "backup-time") {
                Some(v) => v,
                None => return bad_request("Missing backup-time"),
            };
            let protected = match get_query_param(&uri, "protected")
                .as_deref()
                .and_then(parse_bool_param)
            {
                Some(value) => value,
                None => return bad_request("Missing protected"),
            };
            let namespace = get_query_param(&uri, "ns");
            if let Err(e) = validate_backup_params_with_ns(
                &backup_type,
                &backup_id,
                &backup_time,
                namespace.as_deref(),
                None,
            ) {
                return error_response(e);
            }
            let backup_time = match parse_backup_time_param(&backup_time) {
                Ok(t) => t,
                Err(e) => return error_response(e),
            };
            let snapshot_path =
                build_snapshot_path(namespace.as_deref(), &backup_type, &backup_id, &backup_time);
            match datastore.read_manifest_any(&snapshot_path).await {
                Ok(mut manifest) => {
                    update_manifest_unprotected(
                        &mut manifest,
                        "protected",
                        serde_json::Value::Bool(protected),
                    );
                    if let Err(e) = datastore.store_manifest_at(&snapshot_path, &manifest).await {
                        return error_response(ApiError::internal(&e.to_string()));
                    }
                    json_response(StatusCode::OK, &serde_json::json!({"data": null}))
                }
                Err(e) => error_response(ApiError::not_found(&e.to_string())),
            }
        }
        (Method::GET, "namespace") => {
            let parent = get_query_param(&uri, "parent").unwrap_or_default();
            if !parent.is_empty() {
                if let Err(e) = validate_backup_namespace(&parent) {
                    return error_response(e);
                }
            }
            let max_depth =
                get_query_param(&uri, "max-depth").and_then(|v| v.parse::<usize>().ok());
            let parent_depth = namespace_depth(&parent);

            let namespaces = collect_namespaces(datastore.clone()).await;
            let mut list = Vec::new();
            for ns in namespaces {
                if !parent.is_empty() {
                    if ns != parent && !ns.starts_with(&format!("{}/", parent)) {
                        continue;
                    }
                    let depth = namespace_depth(&ns);
                    if let Some(max) = max_depth {
                        if depth.saturating_sub(parent_depth) > max {
                            continue;
                        }
                    }
                } else if let Some(max) = max_depth {
                    if namespace_depth(&ns) > max {
                        continue;
                    }
                }
                list.push(serde_json::json!({
                    "ns": ns,
                    "comment": null,
                }));
            }
            json_response(StatusCode::OK, &serde_json::json!({"data": list}))
        }
        (Method::POST, "namespace") => {
            if !ctx.allows(Permission::DatastoreAdmin) {
                return error_response(ApiError::unauthorized("Insufficient permissions"));
            }
            let body = match req.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => return bad_request("Failed to read request body"),
            };
            #[derive(serde::Deserialize)]
            struct NamespaceCreate {
                #[serde(default)]
                parent: Option<String>,
                name: String,
            }
            let params: NamespaceCreate = match serde_json::from_slice(&body) {
                Ok(p) => p,
                Err(_) => return bad_request("Invalid JSON"),
            };
            let parent = params.parent.unwrap_or_default();
            if !parent.is_empty() {
                if let Err(e) = validate_backup_namespace(&parent) {
                    return error_response(e);
                }
            }
            if let Err(e) = validate_backup_namespace(&params.name) {
                return error_response(e);
            }
            let namespace = if parent.is_empty() {
                params.name
            } else {
                format!("{}/{}", parent, params.name)
            };
            if let Err(e) = validate_backup_namespace(&namespace) {
                return error_response(e);
            }
            let marker_path = format!("{}{}.namespace", namespace_prefix(Some(&namespace)), "");
            if let Err(e) = datastore
                .backend()
                .write_file(&marker_path, Bytes::from_static(b"{}"))
                .await
            {
                return error_response(ApiError::internal(&e.to_string()));
            }
            json_response(StatusCode::OK, &serde_json::json!({"data": null}))
        }
        (Method::DELETE, "namespace") => {
            if !ctx.allows(Permission::DatastoreAdmin) {
                return error_response(ApiError::unauthorized("Insufficient permissions"));
            }
            let namespace = match get_query_param(&uri, "ns") {
                Some(ns) => ns,
                None => return bad_request("Missing ns"),
            };
            if namespace.is_empty() {
                return bad_request("Root namespace cannot be deleted");
            }
            if let Err(e) = validate_backup_namespace(&namespace) {
                return error_response(e);
            }
            let delete_groups = get_query_param(&uri, "delete-groups")
                .as_deref()
                .and_then(parse_bool_param)
                .unwrap_or(false);

            let groups = datastore.list_backup_groups().await.unwrap_or_default();
            let mut target_groups = Vec::new();
            for group in groups {
                if namespace_is_descendant(&namespace, group.namespace.as_deref()) {
                    target_groups.push(group);
                }
            }

            if !delete_groups && !target_groups.is_empty() {
                return bad_request("Namespace contains backup groups");
            }

            let marker_prefix = namespace_prefix(Some(&namespace));

            if delete_groups {
                for group in target_groups {
                    let snapshots = datastore
                        .list_snapshots(
                            group.namespace.as_deref(),
                            &group.backup_type,
                            &group.backup_id,
                        )
                        .await
                        .unwrap_or_default();
                    for snapshot in snapshots {
                        if let Err(e) = datastore
                            .delete_snapshot(
                                group.namespace.as_deref(),
                                &group.backup_type,
                                &group.backup_id,
                                &snapshot,
                            )
                            .await
                        {
                            return error_response(ApiError::internal(&e.to_string()));
                        }
                    }
                }
                if let Ok(files) = datastore.backend().list_files(&marker_prefix).await {
                    for file in files {
                        if file.ends_with("/.namespace") {
                            let _ = datastore.backend().delete_file(&file).await;
                        }
                    }
                }
            }

            let marker_path = format!("{}{}.namespace", marker_prefix, "");
            let _ = datastore.backend().delete_file(&marker_path).await;

            json_response(StatusCode::OK, &serde_json::json!({"data": null}))
        }
        (Method::POST, "change-owner") => {
            if !ctx.allows(Permission::DatastoreAdmin) {
                return error_response(ApiError::unauthorized("Insufficient permissions"));
            }
            let body = match req.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => return bad_request("Failed to read request body"),
            };
            #[derive(serde::Deserialize)]
            struct ChangeOwnerRequest {
                #[serde(rename = "backup-type")]
                backup_type: String,
                #[serde(rename = "backup-id")]
                backup_id: String,
                #[serde(rename = "new-owner")]
                new_owner: String,
                #[serde(default)]
                ns: Option<String>,
            }
            let params: ChangeOwnerRequest = match serde_json::from_slice(&body) {
                Ok(p) => p,
                Err(_) => return bad_request("Invalid JSON"),
            };
            if let Err(e) = validate_backup_type(&params.backup_type) {
                return error_response(e);
            }
            if let Err(e) = validate_backup_id(&params.backup_id) {
                return error_response(e);
            }
            if let Some(ns) = params.ns.as_deref() {
                if let Err(e) = validate_backup_namespace(ns) {
                    return error_response(e);
                }
            }
            let group = pbs_storage::datastore::BackupGroup {
                namespace: params.ns.clone(),
                backup_type: params.backup_type.clone(),
                backup_id: params.backup_id.clone(),
            };
            let snapshots = datastore
                .list_snapshots(
                    group.namespace.as_deref(),
                    &group.backup_type,
                    &group.backup_id,
                )
                .await
                .unwrap_or_default();
            if snapshots.is_empty() {
                return not_found();
            }
            if let Err(e) = datastore.store_group_owner(&group, &params.new_owner).await {
                return error_response(ApiError::internal(&e.to_string()));
            }
            json_response(StatusCode::OK, &serde_json::json!({"data": null}))
        }
        (Method::POST, "gc") => {
            if !ctx.allows(Permission::DatastoreAdmin) {
                return error_response(ApiError::unauthorized("Insufficient permissions"));
            }
            let body = match req.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => return bad_request("Failed to read request body"),
            };
            #[derive(serde::Deserialize, Default)]
            struct GcRequest {
                #[serde(default)]
                dry_run: bool,
                max_delete: Option<usize>,
            }
            let params: GcRequest = if body.is_empty() {
                GcRequest::default()
            } else {
                match serde_json::from_slice(&body) {
                    Ok(p) => p,
                    Err(_) => return bad_request("Invalid JSON"),
                }
            };
            let options = GcOptions {
                dry_run: params.dry_run,
                max_delete: params.max_delete,
            };
            let auth_id = task_auth_id(ctx);
            let store_name = ds_name.to_string();
            let upid = state
                .tasks
                .create(&auth_id, "gc", Some(ds_name), Some(ds_name))
                .await;
            let state = state.clone();
            let datastore = datastore.clone();
            let upid_clone = upid.clone();
            tokio::spawn(async move {
                state
                    .tasks
                    .log(&upid_clone, "Starting garbage collection")
                    .await;
                state
                    .tasks
                    .log(
                        &upid_clone,
                        &format!(
                            "GC options: dry_run={}, max_delete={:?}",
                            options.dry_run, options.max_delete
                        ),
                    )
                    .await;
                let backend = datastore.backend();
                let gc = GarbageCollector::new(datastore.clone(), backend);
                match gc.run(options).await {
                    Ok(result) => {
                        state
                            .tasks
                            .log(
                                &upid_clone,
                                &format!(
                                    "GC completed: deleted {} chunks ({} bytes)",
                                    result.chunks_deleted, result.bytes_freed
                                ),
                            )
                            .await;
                        state
                            .tasks
                            .log(
                                &upid_clone,
                                &format!(
                                    "GC stats: scanned={}, referenced={}, orphaned={}, deleted={}, errors={}",
                                    result.chunks_scanned,
                                    result.chunks_referenced,
                                    result.chunks_orphaned,
                                    result.chunks_deleted,
                                    result.errors.len()
                                ),
                            )
                            .await;
                        if !result.errors.is_empty() {
                            state
                                .tasks
                                .log(
                                    &upid_clone,
                                    "GC errors present; see server logs for details",
                                )
                                .await;
                        }
                        state.tasks.finish(&upid_clone, "OK").await;
                        let stats = datastore.backend().stats().await.unwrap_or_default();
                        let used = stats.chunk_bytes + stats.file_bytes;
                        let gc_status = gc_status_from_result(&upid_clone, used, &result);
                        let mut map = state.gc_status.write().await;
                        map.insert(store_name, gc_status);
                    }
                    Err(e) => {
                        state
                            .tasks
                            .log(&upid_clone, &format!("GC failed: {}", e))
                            .await;
                        state.tasks.finish(&upid_clone, "ERROR").await;
                    }
                }
            });
            json_response(StatusCode::OK, &serde_json::json!({ "data": upid }))
        }
        (Method::POST, "prune") => {
            if !ctx.allows(Permission::DatastoreAdmin) {
                return error_response(ApiError::unauthorized("Insufficient permissions"));
            }
            let body = match req.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => return bad_request("Failed to read request body"),
            };
            return handle_prune_body(state, ctx, ds_name, body).await;
        }
        _ => not_found(),
    }
}

async fn handle_tasks_api(
    state: Arc<ServerState>,
    _ctx: &AuthContext,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let uri = req.uri().clone();
    let path = uri.path();
    let prefix = "/api2/json/nodes/localhost/tasks";
    let rest = path
        .strip_prefix(prefix)
        .unwrap_or("")
        .trim_start_matches('/');

    if rest.is_empty() {
        if req.method() != Method::GET {
            return not_found();
        }
        let running = get_query_param(&uri, "running").and_then(|v| parse_bool_param(&v));
        let errors = get_query_param(&uri, "errors")
            .and_then(|v| parse_bool_param(&v))
            .unwrap_or(false);
        let start = get_query_param(&uri, "start")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        let limit = get_query_param(&uri, "limit")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(50);
        let userfilter = get_query_param(&uri, "userfilter");
        let store = get_query_param(&uri, "store");
        let since = get_query_param(&uri, "since").and_then(|v| v.parse::<i64>().ok());
        let until = get_query_param(&uri, "until").and_then(|v| v.parse::<i64>().ok());
        let typefilter = get_query_param(&uri, "typefilter");
        let mut status_entries = Vec::new();
        for value in get_query_params(&uri, "statusfilter") {
            for entry in value.split(',') {
                let entry = entry.trim().to_ascii_lowercase();
                if !entry.is_empty() {
                    status_entries.push(entry);
                }
            }
        }
        let statusfilter = if status_entries.is_empty() {
            None
        } else {
            Some(status_entries)
        };

        let (list, total) = state
            .tasks
            .list(TaskListRequest {
                start,
                limit,
                filter: TaskListFilter {
                    running,
                    userfilter: userfilter.as_deref(),
                    store: store.as_deref(),
                    errors,
                    since,
                    until,
                    typefilter: typefilter.as_deref(),
                    statusfilter: statusfilter.as_deref(),
                },
            })
            .await;
        return json_response(
            StatusCode::OK,
            &serde_json::json!({ "data": list, "total": total }),
        );
    }

    let mut parts = rest.split('/');
    let upid_encoded = parts.next().unwrap_or("");
    let upid = percent_encoding::percent_decode_str(upid_encoded)
        .decode_utf8()
        .map(|v| v.to_string())
        .unwrap_or_else(|_| upid_encoded.to_string());
    let action = parts.next();

    match (req.method().clone(), action) {
        (Method::GET, Some("log")) => {
            let download = get_query_param(&uri, "download")
                .and_then(|v| parse_bool_param(&v))
                .unwrap_or(false);
            let test_status = get_query_param(&uri, "test-status")
                .and_then(|v| parse_bool_param(&v))
                .unwrap_or(false);

            if download {
                let has_start = get_query_param(&uri, "start").is_some();
                let has_limit = get_query_param(&uri, "limit").is_some();
                let has_test = get_query_param(&uri, "test-status").is_some();
                if has_start || has_limit || has_test {
                    return bad_request("Parameter 'download' cannot be used with other params");
                }
                let task = match state.tasks.get(&upid).await {
                    Some(task) => task,
                    None => return not_found(),
                };
                let mut body = task.log.join("\n");
                if !body.is_empty() {
                    body.push('\n');
                }
                let filename = match epoch_to_rfc3339(task.starttime) {
                    Ok(ts) => format!("task-{}-{}-{}.log", task.node, task.worker_type, ts),
                    Err(_) => format!("task-{}-{}.log", task.node, task.worker_type),
                };
                return Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/plain")
                    .header(
                        "content-disposition",
                        format!("attachment; filename={}", filename),
                    )
                    .body(Full::new(Bytes::from(body)))
                    .expect("valid response");
            }

            let start = get_query_param(&uri, "start")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            let limit = get_query_param(&uri, "limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(50);
            match state.tasks.log_entries(&upid, start, limit).await {
                Some((data, total, active)) => {
                    let mut body = serde_json::json!({
                        "data": data,
                        "total": total,
                    });
                    if test_status {
                        if let Some(obj) = body.as_object_mut() {
                            obj.insert("active".to_string(), serde_json::Value::Bool(active));
                        }
                    }
                    json_response(StatusCode::OK, &body)
                }
                None => not_found(),
            }
        }
        (Method::GET, Some("status")) => match state.tasks.get(&upid).await {
            Some(task) => {
                let status = if task.running { "running" } else { "stopped" };
                let (user, tokenid) = match task.user.split_once('!') {
                    Some((base, token)) => (base.to_string(), Some(token.to_string())),
                    None => (task.user.clone(), None),
                };
                json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "data": {
                            "upid": task.upid,
                            "node": task.node,
                            "pid": task.pid,
                            "pstart": task.pstart,
                            "starttime": task.starttime,
                            "type": task.worker_type,
                            "id": task.worker_id,
                            "worker_type": task.worker_type,
                            "worker_id": task.worker_id,
                            "user": user,
                            "tokenid": tokenid,
                            "status": status,
                            "exitstatus": task.exitstatus,
                        }
                    }),
                )
            }
            None => not_found(),
        },
        (Method::DELETE, None) => {
            state.tasks.abort(&upid).await;
            json_response(StatusCode::OK, &serde_json::json!({"data": null}))
        }
        _ => not_found(),
    }
}

async fn handle_status(state: Arc<ServerState>) -> Response<Full<Bytes>> {
    let (backup_sessions, reader_sessions) = state.sessions.session_count().await;
    let running_tasks = state.tasks.running_count().await;
    let summary = serde_json::json!({
        "uptime": state.start_time.elapsed().as_secs(),
        "tasks": {
            "running": running_tasks,
            "scheduled": 0
        },
        "sessions": {
            "backup": backup_sessions,
            "reader": reader_sessions
        }
    });
    let status = serde_json::json!({
        "data": [
            { "subdir": "datastore-usage" }
        ],
        "summary": summary
    });
    json_response(StatusCode::OK, &status)
}

async fn handle_status_datastore_usage(state: Arc<ServerState>) -> Response<Full<Bytes>> {
    let mut stores: Vec<_> = state.datastores.keys().cloned().collect();
    stores.sort();
    let mut data = Vec::new();

    for store in stores {
        let datastore = match state.datastores.get(&store) {
            Some(ds) => ds.clone(),
            None => continue,
        };
        let mut entry = serde_json::Map::new();
        entry.insert(
            "store".to_string(),
            serde_json::Value::String(store.clone()),
        );

        match datastore.backend().stats().await {
            Ok(stats) => {
                let used = stats.chunk_bytes.saturating_add(stats.file_bytes);
                entry.insert("used".to_string(), serde_json::Value::from(used));
            }
            Err(err) => {
                entry.insert(
                    "error".to_string(),
                    serde_json::Value::String(err.to_string()),
                );
            }
        }

        let gc_status = {
            let map = state.gc_status.read().await;
            map.get(&store).cloned()
        };
        if let Some(gc_status) = gc_status {
            entry.insert("gc-status".to_string(), gc_status);
        }

        data.push(serde_json::Value::Object(entry));
    }

    json_response(StatusCode::OK, &serde_json::json!({ "data": data }))
}

async fn handle_protocol_upgrade(
    state: Arc<ServerState>,
    _peer_addr: SocketAddr,
    req: Request<Incoming>,
    protocol: &str,
) -> Response<Full<Bytes>> {
    let auth_ctx = match authenticate(state.clone(), &req).await {
        Ok(ctx) => ctx,
        Err(e) => return error_response(e),
    };

    let (mode, required) = if protocol == BACKUP_PROTOCOL_HEADER {
        ("backup", Permission::Backup)
    } else {
        ("reader", Permission::Read)
    };

    if !auth_ctx.allows(required) {
        return error_response(ApiError::unauthorized("Insufficient permissions"));
    }

    let state_for_upgrade = state.clone();
    let tenant_id = auth_ctx.user.tenant_id.clone();
    let uri = req.uri().clone();
    let path = uri.path();
    if mode == "backup" && path != "/api2/json/backup" {
        return bad_request("Invalid backup upgrade path");
    }
    if mode == "reader" && path != "/api2/json/reader" {
        return bad_request("Invalid reader upgrade path");
    }

    // Parse common query parameters
    let backup_type = match get_query_param(&uri, "backup-type") {
        Some(v) => v,
        None => return bad_request("Missing backup-type"),
    };
    let backup_id = match get_query_param(&uri, "backup-id") {
        Some(v) => v,
        None => return bad_request("Missing backup-id"),
    };
    let backup_time_epoch: i64 =
        match get_query_param(&uri, "backup-time").and_then(|v| v.parse::<i64>().ok()) {
            Some(v) => v,
            None => return bad_request("Invalid backup-time"),
        };

    let backup_time = match epoch_to_rfc3339(backup_time_epoch) {
        Ok(v) => v,
        Err(e) => return error_response(e),
    };

    if let Err(e) = validate_backup_type(&backup_type) {
        return error_response(e);
    }
    if let Err(e) = validate_backup_id(&backup_id) {
        return error_response(e);
    }
    let namespace = get_query_param(&uri, "ns");
    if let Some(ns) = namespace.as_deref() {
        if let Err(e) = validate_backup_namespace(ns) {
            return error_response(e);
        }
    }

    let store = get_query_param(&uri, "store").unwrap_or_else(|| "default".to_string());
    if let Err(e) = validate_datastore_name(&store) {
        return error_response(e);
    }
    if state.get_datastore(&store).is_none() {
        return not_found();
    }

    if mode == "backup" {
        let encrypt = get_query_param(&uri, "encrypt")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let retain_until = get_query_param(&uri, "retain-until");
        let retention_days =
            get_query_param(&uri, "retention-days").and_then(|v| v.parse::<u64>().ok());
        let params = BackupParams {
            backup_type: backup_type.clone(),
            backup_id: backup_id.clone(),
            backup_time: backup_time.clone(),
            namespace: namespace.clone(),
            store: Some(store.clone()),
            encrypt,
            retain_until,
            retention_days,
        };

        let handler = BackupProtocolHandler::new(state.clone());
        let session_id = match handler.start_backup(&auth_ctx, params).await {
            Ok(id) => id,
            Err(e) => return error_response(e),
        };
        let auth_id = task_auth_id(&auth_ctx);
        let upid = state
            .tasks
            .create(&auth_id, "backup", Some(&session_id), Some(&store))
            .await;
        state
            .tasks
            .log(
                &upid,
                &format!(
                    "Backup started: {}/{} {}",
                    backup_type, backup_id, backup_time_epoch
                ),
            )
            .await;
        store_session_task(&state.backup_tasks, &session_id, &upid).await;

        let ctx = Arc::new(H2Context::Backup(H2BackupContext {
            state: state_for_upgrade,
            tenant_id,
            session_id,
            namespace,
            store,
            backup_type,
            backup_id,
            backup_time_epoch,
        }));

        let upgrade_fut = hyper::upgrade::on(req);
        tokio::spawn(async move {
            if let Ok(upgraded) = upgrade_fut.await {
                let _ = http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(
                        upgraded,
                        service_fn(move |req| handle_h2_request(ctx.clone(), req)),
                    )
                    .await;
            }
        });
    } else {
        let handler = ReaderProtocolHandler::new(state.clone());
        let session_id = match handler
            .start_reader(
                &auth_ctx,
                &backup_type,
                &backup_id,
                &backup_time,
                namespace.clone(),
                Some(store.clone()),
            )
            .await
        {
            Ok(id) => id,
            Err(e) => return error_response(e),
        };
        let auth_id = task_auth_id(&auth_ctx);
        let upid = state
            .tasks
            .create(&auth_id, "reader", Some(&session_id), Some(&store))
            .await;
        state
            .tasks
            .log(
                &upid,
                &format!(
                    "Reader started: {}/{} {}",
                    backup_type, backup_id, backup_time
                ),
            )
            .await;
        store_session_task(&state.reader_tasks, &session_id, &upid).await;

        let ctx = Arc::new(H2Context::Reader(H2ReaderContext {
            state: state_for_upgrade,
            tenant_id,
            session_id,
            namespace,
            store,
            backup_type,
            backup_id,
            backup_time,
        }));

        let upgrade_fut = hyper::upgrade::on(req);
        tokio::spawn(async move {
            if let Ok(upgraded) = upgrade_fut.await {
                let _ = http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(
                        upgraded,
                        service_fn(move |req| handle_h2_request(ctx.clone(), req)),
                    )
                    .await;
            }
        });
    }

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("connection", "upgrade")
        .header("upgrade", protocol)
        .body(Full::new(Bytes::new()))
        .expect("valid response")
}

async fn handle_h2_backup(ctx: &H2BackupContext, req: Request<Incoming>) -> Response<Full<Bytes>> {
    let method = req.method().clone();
    let path = req.uri().path().trim_start_matches('/').to_string();

    match (method, path.as_str()) {
        (Method::POST, "blob") => {
            let name = match get_query_param(req.uri(), "file-name") {
                Some(n) => n,
                None => return bad_request("Missing file-name"),
            };
            if let Err(e) = validate_filename(&name) {
                return error_response(e);
            }
            if !name.ends_with(".blob") {
                return bad_request("Blob filename must end with .blob");
            }
            let encoded_size: usize =
                match get_query_param(req.uri(), "encoded-size").and_then(|v| v.parse().ok()) {
                    Some(v) => v,
                    None => return bad_request("Missing encoded-size"),
                };

            let body = match req.collect().await {
                Ok(collected) => collected.to_bytes().to_vec(),
                Err(_) => return bad_request("Failed to read blob data"),
            };
            if body.len() != encoded_size {
                return bad_request("encoded-size mismatch");
            }
            if let Err(e) = pbs_core::DataBlob::from_bytes(&body) {
                return bad_request(&format!("Invalid data blob: {}", e));
            }

            let handler = BackupProtocolHandler::new(ctx.state.clone());
            match handler
                .upload_blob(&ctx.session_id, &ctx.tenant_id, &name, body)
                .await
            {
                Ok(_) => json_response(StatusCode::OK, &serde_json::json!({"data": {}})),
                Err(e) => error_response(e),
            }
        }
        (Method::POST, "fixed_index") => {
            let name = match get_query_param(req.uri(), "archive-name") {
                Some(n) => n,
                None => return bad_request("Missing archive-name"),
            };
            if let Err(e) = validate_filename(&name) {
                return error_response(e);
            }
            if !name.ends_with(".fidx") {
                return bad_request("Fixed index filename must end with .fidx");
            }
            let chunk_size = get_query_param(req.uri(), "size")
                .and_then(|s| s.parse().ok())
                .unwrap_or(pbs_core::CHUNK_SIZE_DEFAULT as u64);

            let result = ctx
                .state
                .sessions
                .with_backup_session_verified(&ctx.session_id, &ctx.tenant_id, |session| {
                    Ok(session.create_fixed_index_with_id(&name, chunk_size))
                })
                .await;

            match result {
                Ok(wid) => json_response(StatusCode::OK, &serde_json::json!({"data": wid})),
                Err(e) => error_response(e),
            }
        }
        (Method::POST, "dynamic_index") => {
            let name = match get_query_param(req.uri(), "archive-name") {
                Some(n) => n,
                None => return bad_request("Missing archive-name"),
            };
            if let Err(e) = validate_filename(&name) {
                return error_response(e);
            }
            if !name.ends_with(".didx") {
                return bad_request("Dynamic index filename must end with .didx");
            }

            let result = ctx
                .state
                .sessions
                .with_backup_session_verified(&ctx.session_id, &ctx.tenant_id, |session| {
                    Ok(session.create_dynamic_index_with_id(&name))
                })
                .await;

            match result {
                Ok(wid) => json_response(StatusCode::OK, &serde_json::json!({"data": wid})),
                Err(e) => error_response(e),
            }
        }
        (Method::PUT, "fixed_index") | (Method::PUT, "dynamic_index") => {
            let is_fixed = path == "fixed_index";
            let body = match req.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => return bad_request("Failed to read request body"),
            };

            #[derive(serde::Deserialize)]
            struct AppendIndexRequest {
                wid: u64,
                #[serde(rename = "digest-list")]
                digest_list: Vec<String>,
                #[serde(rename = "offset-list")]
                offset_list: Vec<u64>,
            }

            let params: AppendIndexRequest = match serde_json::from_slice(&body) {
                Ok(p) => p,
                Err(_) => return bad_request("Invalid JSON"),
            };

            if params.digest_list.len() != params.offset_list.len() {
                return bad_request("digest-list and offset-list length mismatch");
            }

            let result = ctx
                .state
                .sessions
                .with_backup_session_verified(&ctx.session_id, &ctx.tenant_id, |session| {
                    for (digest_str, offset) in
                        params.digest_list.iter().zip(params.offset_list.iter())
                    {
                        let digest = ChunkDigest::from_hex(digest_str)
                            .map_err(|_| ApiError::bad_request("Invalid digest format"))?;
                        if is_fixed {
                            session.append_fixed_index_by_id(params.wid, digest, None)?;
                        } else {
                            session
                                .append_dynamic_index_by_id(params.wid, digest, *offset, None)?;
                        }
                    }
                    Ok(())
                })
                .await;

            match result {
                Ok(_) => json_response(StatusCode::OK, &serde_json::json!({"data": {}})),
                Err(e) => error_response(e),
            }
        }
        (Method::POST, "fixed_chunk") | (Method::POST, "dynamic_chunk") => {
            let wid: u64 = match get_query_param(req.uri(), "wid").and_then(|v| v.parse().ok()) {
                Some(v) => v,
                None => return bad_request("Missing wid"),
            };
            let digest_str = match get_query_param(req.uri(), "digest") {
                Some(d) => d,
                None => return bad_request("Missing digest"),
            };
            if let Err(e) = validate_digest(&digest_str) {
                return error_response(e);
            }
            let digest = match ChunkDigest::from_hex(&digest_str) {
                Ok(d) => d,
                Err(_) => return bad_request("Invalid digest format"),
            };
            let raw_size: u64 =
                match get_query_param(req.uri(), "size").and_then(|v| v.parse().ok()) {
                    Some(v) => v,
                    None => return bad_request("Missing size"),
                };
            let encoded_size: usize =
                match get_query_param(req.uri(), "encoded-size").and_then(|v| v.parse().ok()) {
                    Some(v) => v,
                    None => return bad_request("Missing encoded-size"),
                };

            let body = match req.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => return bad_request("Failed to read chunk data"),
            };
            if body.len() != encoded_size {
                return bad_request("encoded-size mismatch");
            }

            let blob = match pbs_core::DataBlob::from_bytes(&body) {
                Ok(b) => b,
                Err(e) => return bad_request(&format!("Invalid data blob: {}", e)),
            };
            let datastore = match ctx.state.get_datastore(&ctx.store) {
                Some(ds) => ds,
                None => return not_found(),
            };
            let crypto = datastore.crypto_config();
            match blob.decode(&crypto) {
                Ok(raw) => {
                    if raw.len() as u64 != raw_size {
                        return bad_request("Chunk size mismatch");
                    }
                    let computed = ChunkDigest::from_data(&raw);
                    if computed != digest {
                        return bad_request("Chunk digest mismatch");
                    }
                }
                Err(pbs_core::Error::Decryption(_)) if crypto.key.is_none() => {
                    // Encrypted payload with unknown key; accept but cannot verify digest/size.
                }
                Err(e) => {
                    return bad_request(&format!("Invalid data blob: {}", e));
                }
            }

            let writer_check = ctx
                .state
                .sessions
                .with_backup_session_verified(&ctx.session_id, &ctx.tenant_id, |session| {
                    if !session.writers.contains_key(&wid) {
                        return Err(ApiError::not_found("Writer not found"));
                    }
                    Ok(())
                })
                .await;
            if let Err(e) = writer_check {
                return error_response(e);
            }

            let handler = BackupProtocolHandler::new(ctx.state.clone());
            match handler
                .upload_chunk_blob(&ctx.session_id, &ctx.tenant_id, digest, body)
                .await
            {
                Ok(stored) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({"data": {"stored": stored}}),
                ),
                Err(e) => error_response(e),
            }
        }
        (Method::POST, "fixed_close") | (Method::POST, "dynamic_close") => {
            let wid: u64 = match get_query_param(req.uri(), "wid").and_then(|v| v.parse().ok()) {
                Some(v) => v,
                None => return bad_request("Missing wid"),
            };
            let size: u64 = match get_query_param(req.uri(), "size").and_then(|v| v.parse().ok()) {
                Some(v) => v,
                None => return bad_request("Missing size"),
            };
            let chunk_count: usize =
                match get_query_param(req.uri(), "chunk-count").and_then(|v| v.parse().ok()) {
                    Some(v) => v,
                    None => return bad_request("Missing chunk-count"),
                };
            let csum = match get_query_param(req.uri(), "csum") {
                Some(v) => v,
                None => return bad_request("Missing csum"),
            };
            if csum.len() != 64 || !csum.chars().all(|c| c.is_ascii_hexdigit()) {
                return bad_request("Invalid csum");
            }
            let expected_csum = match hex::decode(&csum) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    arr
                }
                _ => return bad_request("Invalid csum"),
            };

            let result = ctx
                .state
                .sessions
                .with_backup_session_async(&ctx.session_id, |session| {
                    Box::pin(session.finalize_index_by_id(wid, size, chunk_count, expected_csum))
                })
                .await;

            match result {
                Ok(_) => json_response(StatusCode::OK, &serde_json::json!({"data": {}})),
                Err(e) => error_response(e),
            }
        }
        (Method::POST, "finish") => {
            let handler = BackupProtocolHandler::new(ctx.state.clone());
            match handler.finish_backup(&ctx.session_id, &ctx.tenant_id).await {
                Ok(result) => {
                    let response: FinishBackupResponse = result.into();
                    json_response(StatusCode::OK, &serde_json::json!({"data": response}))
                }
                Err(e) => error_response(e),
            }
        }
        (Method::GET, "previous_backup_time") => {
            let datastore = match ctx.state.get_datastore(&ctx.store) {
                Some(ds) => ds,
                None => return not_found(),
            };
            let snapshots = datastore
                .list_snapshots(ctx.namespace.as_deref(), &ctx.backup_type, &ctx.backup_id)
                .await
                .unwrap_or_default();
            let mut times: Vec<i64> = snapshots
                .iter()
                .filter_map(|s| snapshot_to_epoch(s))
                .filter(|t| *t < ctx.backup_time_epoch)
                .collect();
            times.sort();
            let previous = times.pop();

            json_response(StatusCode::OK, &serde_json::json!({"data": previous}))
        }
        (Method::GET, "previous") => {
            let archive = match get_query_param(req.uri(), "archive-name") {
                Some(n) => n,
                None => return bad_request("Missing archive-name"),
            };
            if let Err(e) = validate_filename(&archive) {
                return error_response(e);
            }

            let datastore = match ctx.state.get_datastore(&ctx.store) {
                Some(ds) => ds,
                None => return not_found(),
            };
            let snapshots = datastore
                .list_snapshots(ctx.namespace.as_deref(), &ctx.backup_type, &ctx.backup_id)
                .await
                .unwrap_or_default();
            let mut times: Vec<i64> = snapshots
                .iter()
                .filter_map(|s| snapshot_to_epoch(s))
                .filter(|t| *t < ctx.backup_time_epoch)
                .collect();
            times.sort();
            let previous = match times.pop() {
                Some(t) => t,
                None => return not_found(),
            };
            let snapshot = match epoch_to_rfc3339(previous) {
                Ok(s) => s,
                Err(e) => return error_response(e),
            };
            let path = format!(
                "{}{}/{}/{}/{}",
                namespace_prefix(ctx.namespace.as_deref()),
                ctx.backup_type,
                ctx.backup_id,
                snapshot,
                archive
            );
            let data = match datastore.backend().read_file(&path).await {
                Ok(d) => d,
                Err(_) => return not_found(),
            };
            Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(data))
                .expect("valid response")
        }
        _ => not_found(),
    }
}

async fn handle_h2_reader(ctx: &H2ReaderContext, req: Request<Incoming>) -> Response<Full<Bytes>> {
    if let Err(err) = ctx
        .state
        .sessions
        .verify_reader_session_ownership(&ctx.session_id, &ctx.tenant_id)
        .await
    {
        return error_response(err);
    }

    let method = req.method().clone();
    let path = req.uri().path().trim_start_matches('/').to_string();

    match (method, path.as_str()) {
        (Method::GET, "download") => {
            let name = match get_query_param(req.uri(), "file-name") {
                Some(n) => n,
                None => return bad_request("Missing file-name"),
            };
            if let Err(e) = validate_filename(&name) {
                return error_response(e);
            }
            let file_path = format!(
                "{}{}/{}/{}/{}",
                namespace_prefix(ctx.namespace.as_deref()),
                ctx.backup_type,
                ctx.backup_id,
                ctx.backup_time,
                name
            );
            let datastore = match ctx.state.get_datastore(&ctx.store) {
                Some(ds) => ds,
                None => return not_found(),
            };
            let data = match datastore.backend().read_file(&file_path).await {
                Ok(d) => d,
                Err(_) => return not_found(),
            };
            Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(data))
                .expect("valid response")
        }
        (Method::GET, "chunk") => {
            let digest_str = match get_query_param(req.uri(), "digest") {
                Some(d) => d,
                None => return bad_request("Missing digest"),
            };
            if let Err(e) = validate_digest(&digest_str) {
                return error_response(e);
            }
            let digest = match ChunkDigest::from_hex(&digest_str) {
                Ok(d) => d,
                Err(_) => return bad_request("Invalid digest format"),
            };
            let datastore = match ctx.state.get_datastore(&ctx.store) {
                Some(ds) => ds,
                None => return not_found(),
            };
            let data = match datastore.read_chunk_blob(&digest).await {
                Ok(d) => d,
                Err(_) => return not_found(),
            };
            Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(data))
                .expect("valid response")
        }
        (Method::GET, "speedtest") => {
            let data = vec![0u8; 10 * 1024 * 1024];
            Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from(data)))
                .expect("valid response")
        }
        _ => not_found(),
    }
}

async fn handle_start_backup(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let body = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return bad_request("Failed to read request body"),
    };

    let params: BackupParams = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return bad_request("Invalid backup parameters"),
    };

    // Validate backup parameters
    if let Err(e) = validate_backup_params_with_ns(
        &params.backup_type,
        &params.backup_id,
        &params.backup_time,
        params.namespace.as_deref(),
        params.store.as_deref(),
    ) {
        return error_response(e);
    }

    let store = params
        .store
        .clone()
        .unwrap_or_else(|| "default".to_string());
    let backup_type = params.backup_type.clone();
    let backup_id = params.backup_id.clone();
    let backup_time = params.backup_time.clone();
    let handler = BackupProtocolHandler::new(state.clone());
    match handler.start_backup(ctx, params).await {
        Ok(session_id) => {
            let auth_id = task_auth_id(ctx);
            let upid = state
                .tasks
                .create(&auth_id, "backup", Some(&session_id), Some(&store))
                .await;
            state
                .tasks
                .log(
                    &upid,
                    &format!(
                        "Backup started: {}/{} {}",
                        backup_type, backup_id, backup_time
                    ),
                )
                .await;
            store_session_task(&state.backup_tasks, &session_id, &upid).await;

            json_response(
                StatusCode::OK,
                &serde_json::json!({"data": {"session_id": session_id}}),
            )
        }
        Err(e) => error_response(e),
    }
}

async fn handle_start_reader(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let body = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return bad_request("Failed to read request body"),
    };

    #[derive(serde::Deserialize)]
    struct ReaderParams {
        backup_type: String,
        backup_id: String,
        backup_time: String,
        #[serde(default)]
        ns: Option<String>,
        #[serde(default)]
        store: Option<String>,
    }

    let params: ReaderParams = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return bad_request("Invalid reader parameters"),
    };

    // Validate backup parameters
    if let Err(e) = validate_backup_params_with_ns(
        &params.backup_type,
        &params.backup_id,
        &params.backup_time,
        params.ns.as_deref(),
        params.store.as_deref(),
    ) {
        return error_response(e);
    }

    let store = params
        .store
        .clone()
        .unwrap_or_else(|| "default".to_string());
    let backup_type = params.backup_type.clone();
    let backup_id = params.backup_id.clone();
    let backup_time = params.backup_time.clone();
    let handler = ReaderProtocolHandler::new(state.clone());
    match handler
        .start_reader(
            ctx,
            &params.backup_type,
            &params.backup_id,
            &params.backup_time,
            params.ns,
            params.store,
        )
        .await
    {
        Ok(session_id) => {
            let auth_id = task_auth_id(ctx);
            let upid = state
                .tasks
                .create(&auth_id, "reader", Some(&session_id), Some(&store))
                .await;
            state
                .tasks
                .log(
                    &upid,
                    &format!(
                        "Reader started: {}/{} {}",
                        backup_type, backup_id, backup_time
                    ),
                )
                .await;
            store_session_task(&state.reader_tasks, &session_id, &upid).await;

            json_response(
                StatusCode::OK,
                &serde_json::json!({"data": {"session_id": session_id}}),
            )
        }
        Err(e) => error_response(e),
    }
}

async fn handle_upload_chunk(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
    chunk_type: &str,
) -> Response<Full<Bytes>> {
    let session_id = match get_query_param(req.uri(), "session_id") {
        Some(id) => id,
        None => return bad_request("Missing session_id"),
    };
    let digest_str = match get_query_param(req.uri(), "digest") {
        Some(d) => d,
        None => return bad_request("Missing digest"),
    };

    // Validate digest format
    if let Err(e) = validate_digest(&digest_str) {
        return error_response(e);
    }

    let digest = match ChunkDigest::from_hex(&digest_str) {
        Ok(d) => d,
        Err(_) => return bad_request("Invalid digest format"),
    };

    let body = match req.collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(_) => return bad_request("Failed to read chunk data"),
    };

    // Check upload rate limit
    if let RateLimitResult::Limited {
        retry_after_secs,
        limit,
        remaining,
    } = state
        .rate_limiter
        .check_upload(&ctx.user.tenant_id, body.len() as u64)
    {
        return rate_limited_response(retry_after_secs, limit, remaining);
    }

    let handler = BackupProtocolHandler::new(state.clone());
    let result = if chunk_type == "fixed" {
        handler
            .upload_fixed_chunk(&session_id, &ctx.user.tenant_id, digest, body)
            .await
    } else {
        handler
            .upload_dynamic_chunk(&session_id, &ctx.user.tenant_id, digest, body)
            .await
    };

    match result {
        Ok(stored) => json_response(
            StatusCode::OK,
            &serde_json::json!({"data": {"stored": stored}}),
        ),
        Err(e) => error_response(e),
    }
}

async fn handle_create_index(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
    index_type: &str,
) -> Response<Full<Bytes>> {
    let session_id = match get_query_param(req.uri(), "session_id") {
        Some(id) => id,
        None => return bad_request("Missing session_id"),
    };
    let name = match get_query_param(req.uri(), "name") {
        Some(n) => n,
        None => return bad_request("Missing name"),
    };

    // Validate index name (no path traversal)
    if let Err(e) = validate_filename(&name) {
        return error_response(e);
    }

    let handler = BackupProtocolHandler::new(state.clone());

    let result = if index_type == "fixed" {
        let chunk_size = get_query_param(req.uri(), "chunk_size")
            .and_then(|s| s.parse().ok())
            .unwrap_or(4 * 1024 * 1024); // 4MB default
        handler
            .create_fixed_index(&session_id, &ctx.user.tenant_id, &name, chunk_size)
            .await
    } else {
        handler
            .create_dynamic_index(&session_id, &ctx.user.tenant_id, &name)
            .await
    };

    match result {
        Ok(_) => json_response(StatusCode::OK, &serde_json::json!({"data": {}})),
        Err(e) => error_response(e),
    }
}

async fn handle_append_index(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
    index_type: &str,
) -> Response<Full<Bytes>> {
    let session_id = match get_query_param(req.uri(), "session_id") {
        Some(id) => id,
        None => return bad_request("Missing session_id"),
    };
    let name = match get_query_param(req.uri(), "name") {
        Some(n) => n,
        None => return bad_request("Missing name"),
    };
    let digest_str = match get_query_param(req.uri(), "digest") {
        Some(d) => d,
        None => return bad_request("Missing digest"),
    };
    let size: u64 = get_query_param(req.uri(), "size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Validate name and digest
    if let Err(e) = validate_filename(&name) {
        return error_response(e);
    }
    if let Err(e) = validate_digest(&digest_str) {
        return error_response(e);
    }

    let digest = match ChunkDigest::from_hex(&digest_str) {
        Ok(d) => d,
        Err(_) => return bad_request("Invalid digest format"),
    };

    let handler = BackupProtocolHandler::new(state.clone());

    let result = if index_type == "fixed" {
        handler
            .append_fixed_index(&session_id, &ctx.user.tenant_id, &name, digest, size)
            .await
    } else {
        let offset: u64 = get_query_param(req.uri(), "offset")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        handler
            .append_dynamic_index(
                &session_id,
                &ctx.user.tenant_id,
                &name,
                digest,
                offset,
                size,
            )
            .await
    };

    match result {
        Ok(_) => json_response(StatusCode::OK, &serde_json::json!({"data": {}})),
        Err(e) => error_response(e),
    }
}

async fn handle_close_index(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
    index_type: &str,
) -> Response<Full<Bytes>> {
    let session_id = match get_query_param(req.uri(), "session_id") {
        Some(id) => id,
        None => return bad_request("Missing session_id"),
    };
    let name = match get_query_param(req.uri(), "name") {
        Some(n) => n,
        None => return bad_request("Missing name"),
    };

    // Validate index name
    if let Err(e) = validate_filename(&name) {
        return error_response(e);
    }

    let handler = BackupProtocolHandler::new(state.clone());

    let result = if index_type == "fixed" {
        handler
            .close_fixed_index(&session_id, &ctx.user.tenant_id, &name)
            .await
    } else {
        handler
            .close_dynamic_index(&session_id, &ctx.user.tenant_id, &name)
            .await
    };

    match result {
        Ok((size, digest)) => json_response(
            StatusCode::OK,
            &serde_json::json!({
                "data": {
                    "size": size,
                    "digest": digest.to_hex()
                }
            }),
        ),
        Err(e) => error_response(e),
    }
}

async fn handle_upload_blob(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let session_id = match get_query_param(req.uri(), "session_id") {
        Some(id) => id,
        None => return bad_request("Missing session_id"),
    };
    let name = match get_query_param(req.uri(), "name") {
        Some(n) => n,
        None => return bad_request("Missing name"),
    };

    // Validate blob name
    if let Err(e) = validate_filename(&name) {
        return error_response(e);
    }

    let body = match req.collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(_) => return bad_request("Failed to read blob data"),
    };

    let handler = BackupProtocolHandler::new(state.clone());
    match handler
        .upload_blob(&session_id, &ctx.user.tenant_id, &name, body)
        .await
    {
        Ok(_) => json_response(StatusCode::OK, &serde_json::json!({"data": {}})),
        Err(e) => error_response(e),
    }
}

async fn handle_finish_backup(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let session_id = match get_query_param(req.uri(), "session_id") {
        Some(id) => id,
        None => return bad_request("Missing session_id"),
    };

    let handler = BackupProtocolHandler::new(state.clone());
    match handler
        .finish_backup(&session_id, &ctx.user.tenant_id)
        .await
    {
        Ok(result) => {
            state
                .metrics
                .record_backup(&ctx.user.tenant_id, "backup", result.total_bytes);
            if let Some(upid) = take_session_task(&state.backup_tasks, &session_id).await {
                state
                    .tasks
                    .log(
                        &upid,
                        &format!(
                            "Backup finished: {} bytes, {} chunks",
                            result.total_bytes, result.chunk_count
                        ),
                    )
                    .await;
                state.tasks.finish(&upid, "OK").await;
            }
            let response: FinishBackupResponse = result.into();
            json_response(StatusCode::OK, &serde_json::json!({"data": response}))
        }
        Err(e) => {
            if let Some(upid) = take_session_task(&state.backup_tasks, &session_id).await {
                state
                    .tasks
                    .log(&upid, &format!("Backup failed: {}", e))
                    .await;
                state.tasks.finish(&upid, "ERROR").await;
            }
            error_response(e)
        }
    }
}

async fn handle_known_chunks(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let session_id = match get_query_param(req.uri(), "session_id") {
        Some(id) => id,
        None => return bad_request("Missing session_id"),
    };

    // Verify session ownership - prevent cross-tenant chunk enumeration
    if let Err(e) = state
        .sessions
        .verify_session_ownership(&session_id, &ctx.user.tenant_id)
        .await
    {
        return error_response(e);
    }

    let body = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return bad_request("Failed to read request body"),
    };

    #[derive(serde::Deserialize)]
    struct KnownChunksRequest {
        digests: Vec<String>,
    }

    let params: KnownChunksRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return bad_request("Invalid JSON"),
    };

    let digests: Result<Vec<_>, _> = params
        .digests
        .iter()
        .map(|s| ChunkDigest::from_hex(s))
        .collect();

    let digests = match digests {
        Ok(d) => d,
        Err(_) => return bad_request("Invalid digest format"),
    };

    let handler = BackupProtocolHandler::new(state.clone());
    match handler
        .check_known_chunks(&session_id, &ctx.user.tenant_id, &digests)
        .await
    {
        Ok(known) => json_response(
            StatusCode::OK,
            &serde_json::json!({"data": {"known": known}}),
        ),
        Err(e) => error_response(e),
    }
}

async fn handle_download_chunk(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let session_id = match get_query_param(req.uri(), "session_id") {
        Some(id) => id,
        None => return bad_request("Missing session_id"),
    };
    let digest_str = match get_query_param(req.uri(), "digest") {
        Some(d) => d,
        None => return bad_request("Missing digest"),
    };

    // Validate digest format
    if let Err(e) = validate_digest(&digest_str) {
        return error_response(e);
    }

    let digest = match ChunkDigest::from_hex(&digest_str) {
        Ok(d) => d,
        Err(_) => return bad_request("Invalid digest format"),
    };

    let handler = ReaderProtocolHandler::new(state.clone());
    match handler
        .download_chunk(&session_id, &digest, &ctx.user.tenant_id)
        .await
    {
        Ok(data) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/octet-stream")
            .body(Full::new(Bytes::from(data)))
            .expect("valid response"),
        Err(e) => error_response(e),
    }
}

async fn handle_read_index(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
    index_type: &str,
) -> Response<Full<Bytes>> {
    let session_id = match get_query_param(req.uri(), "session_id") {
        Some(id) => id,
        None => return bad_request("Missing session_id"),
    };
    let name = match get_query_param(req.uri(), "name") {
        Some(n) => n,
        None => return bad_request("Missing name"),
    };

    // Validate index name
    if let Err(e) = validate_filename(&name) {
        return error_response(e);
    }

    let handler = ReaderProtocolHandler::new(state.clone());
    let result = if index_type == "fixed" {
        handler
            .read_fixed_index(&session_id, &ctx.user.tenant_id, &name)
            .await
    } else {
        handler
            .read_dynamic_index(&session_id, &ctx.user.tenant_id, &name)
            .await
    };

    match result {
        Ok(data) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/octet-stream")
            .body(Full::new(Bytes::from(data)))
            .expect("valid response"),
        Err(e) => error_response(e),
    }
}

async fn handle_read_blob(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let session_id = match get_query_param(req.uri(), "session_id") {
        Some(id) => id,
        None => return bad_request("Missing session_id"),
    };
    let name = match get_query_param(req.uri(), "name") {
        Some(n) => n,
        None => return bad_request("Missing name"),
    };

    // Validate blob name
    if let Err(e) = validate_filename(&name) {
        return error_response(e);
    }

    let handler = ReaderProtocolHandler::new(state.clone());
    match handler
        .read_blob(&session_id, &ctx.user.tenant_id, &name)
        .await
    {
        Ok(data) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/octet-stream")
            .body(Full::new(Bytes::from(data)))
            .expect("valid response"),
        Err(e) => error_response(e),
    }
}

async fn handle_read_manifest(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let session_id = match get_query_param(req.uri(), "session_id") {
        Some(id) => id,
        None => return bad_request("Missing session_id"),
    };

    let handler = ReaderProtocolHandler::new(state.clone());
    match handler
        .read_manifest(&session_id, &ctx.user.tenant_id)
        .await
    {
        Ok(json) => json_response(StatusCode::OK, &serde_json::json!({"data": json})),
        Err(e) => error_response(e),
    }
}

async fn handle_close_reader(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let session_id = match get_query_param(req.uri(), "session_id") {
        Some(id) => id,
        None => return bad_request("Missing session_id"),
    };

    // Verify session ownership
    if let Err(e) = state
        .sessions
        .verify_reader_session_ownership(&session_id, &ctx.user.tenant_id)
        .await
    {
        return error_response(e);
    }

    let handler = ReaderProtocolHandler::new(state.clone());
    match handler.close_reader(&session_id).await {
        Ok(_) => {
            if let Some(upid) = take_session_task(&state.reader_tasks, &session_id).await {
                state.tasks.log(&upid, "Reader session closed").await;
                state.tasks.finish(&upid, "OK").await;
            }
            json_response(StatusCode::OK, &serde_json::json!({"data": {}}))
        }
        Err(e) => error_response(e),
    }
}

async fn handle_list_tenants(state: Arc<ServerState>) -> Response<Full<Bytes>> {
    let tenants = state.tenants.list_tenants().await;
    json_response(StatusCode::OK, &serde_json::json!({"data": tenants}))
}

async fn handle_create_tenant(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let body = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return bad_request("Failed to read request body"),
    };

    #[derive(serde::Deserialize)]
    struct CreateTenantRequest {
        name: String,
    }

    let params: CreateTenantRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return bad_request("Invalid JSON"),
    };

    // Validate tenant name
    if let Err(e) = validate_tenant_name(&params.name) {
        return error_response(e);
    }

    let tenant = state.tenants.create_tenant(&params.name).await;

    // Audit log
    audit::log_tenant_created(
        &ctx.user.username,
        &ctx.user.tenant_id,
        &tenant.id,
        &tenant.name,
    );

    // Save state
    if let Err(e) = state.save_state().await {
        warn!("Failed to save state after tenant creation: {}", e);
    }

    json_response(StatusCode::CREATED, &serde_json::json!({"data": tenant}))
}

async fn handle_delete_tenant(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    tenant_id: &str,
) -> Response<Full<Bytes>> {
    // Prevent deleting the default tenant
    if tenant_id == "default" {
        return error_response(ApiError::bad_request("Cannot delete the default tenant"));
    }

    match state.tenants.delete_tenant(tenant_id).await {
        Some(tenant) => {
            // Audit log
            audit::log_tenant_deleted(
                &ctx.user.username,
                &ctx.user.tenant_id,
                &tenant.id,
                &tenant.name,
            );

            // Save state
            if let Err(e) = state.save_state().await {
                warn!("Failed to save state after tenant deletion: {}", e);
            }

            json_response(
                StatusCode::OK,
                &serde_json::json!({"data": {"deleted": true, "tenant": tenant}}),
            )
        }
        None => error_response(ApiError::not_found("Tenant not found")),
    }
}

async fn handle_list_users(state: Arc<ServerState>, ctx: &AuthContext) -> Response<Full<Bytes>> {
    // Admins see all users, others only see their tenant's users
    let tenant_filter = if ctx.permission == Permission::Admin {
        None
    } else {
        Some(ctx.user.tenant_id.as_str())
    };

    let users = state.auth.list_users(tenant_filter).await;
    json_response(StatusCode::OK, &serde_json::json!({"data": users}))
}

fn permission_privileges(permission: Permission) -> Vec<&'static str> {
    match permission {
        Permission::Read => vec!["Datastore.Audit", "Datastore.Read"],
        Permission::Backup => vec!["Datastore.Audit", "Datastore.Read", "Datastore.Backup"],
        Permission::DatastoreAdmin => vec![
            "Datastore.Audit",
            "Datastore.Read",
            "Datastore.Backup",
            "Datastore.Verify",
            "Datastore.Prune",
            "Datastore.Modify",
        ],
        Permission::Admin => vec![
            "Datastore.Audit",
            "Datastore.Read",
            "Datastore.Backup",
            "Datastore.Verify",
            "Datastore.Prune",
            "Datastore.Modify",
            "Sys.Audit",
            "Sys.Modify",
            "Sys.PowerMgmt",
            "Permissions.Modify",
        ],
    }
}

async fn handle_permissions(ctx: &AuthContext, req: Request<Incoming>) -> Response<Full<Bytes>> {
    let uri = req.uri().clone();
    let auth_id = get_query_param(&uri, "auth-id");
    if let Some(requested) = auth_id.as_deref() {
        let is_self = requested == ctx.user.username;
        if !is_self && !ctx.allows(Permission::Admin) {
            return error_response(ApiError::unauthorized("Insufficient permissions"));
        }
    }

    let path = get_query_param(&uri, "path").unwrap_or_else(|| "/".to_string());
    let mut privs = serde_json::Map::new();
    for privilege in permission_privileges(ctx.permission) {
        privs.insert(privilege.to_string(), serde_json::Value::Bool(true));
    }

    let mut data = serde_json::Map::new();
    data.insert(path, serde_json::Value::Object(privs));

    json_response(StatusCode::OK, &serde_json::json!({ "data": data }))
}

async fn handle_create_user(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let body = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return bad_request("Failed to read request body"),
    };

    #[derive(serde::Deserialize)]
    struct CreateUserRequest {
        username: String,
        tenant_id: String,
        permission: String,
    }

    let params: CreateUserRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return bad_request("Invalid JSON"),
    };

    // Validate username
    if let Err(e) = validate_username(&params.username) {
        return error_response(e);
    }

    let permission = match params.permission.as_str() {
        "admin" => Permission::Admin,
        "datastore_admin" => Permission::DatastoreAdmin,
        "backup" => Permission::Backup,
        "read" => Permission::Read,
        _ => return bad_request("Invalid permission level"),
    };

    match state
        .auth
        .create_user(&params.username, &params.tenant_id, permission)
        .await
    {
        Ok(user) => {
            // Audit log
            audit::log_user_created(
                &ctx.user.username,
                &ctx.user.tenant_id,
                &user.id,
                &user.username,
            );

            // Save state
            if let Err(e) = state.save_state().await {
                warn!("Failed to save state after user creation: {}", e);
            }
            json_response(StatusCode::CREATED, &serde_json::json!({"data": user}))
        }
        Err(e) => error_response(e),
    }
}

async fn handle_delete_user(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    user_id: &str,
) -> Response<Full<Bytes>> {
    // Prevent deleting the root user
    if let Some(user) = state.auth.get_user(user_id).await {
        if user.username == "root@pam" {
            return error_response(ApiError::bad_request("Cannot delete the root user"));
        }
    }

    match state.auth.delete_user(user_id).await {
        Ok(user) => {
            // Audit log
            audit::log_user_deleted(
                &ctx.user.username,
                &ctx.user.tenant_id,
                &user.id,
                &user.username,
            );

            // Save state
            if let Err(e) = state.save_state().await {
                warn!("Failed to save state after user deletion: {}", e);
            }

            json_response(
                StatusCode::OK,
                &serde_json::json!({"data": {"deleted": true, "user": user}}),
            )
        }
        Err(e) => error_response(e),
    }
}

async fn handle_list_tokens(state: Arc<ServerState>, ctx: &AuthContext) -> Response<Full<Bytes>> {
    let tokens = state.auth.list_tokens(&ctx.user.id).await;
    json_response(StatusCode::OK, &serde_json::json!({"data": tokens}))
}

async fn handle_create_token(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let body = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return bad_request("Failed to read request body"),
    };

    #[derive(serde::Deserialize)]
    struct CreateTokenRequest {
        name: String,
        permission: Option<String>,
    }

    let params: CreateTokenRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return bad_request("Invalid JSON"),
    };

    let permission = match params.permission.as_deref() {
        Some("admin") => Permission::Admin,
        Some("datastore_admin") => Permission::DatastoreAdmin,
        Some("backup") => Permission::Backup,
        Some("read") | None => Permission::Read,
        _ => return bad_request("Invalid permission level"),
    };

    match state
        .auth
        .create_token(&ctx.user.id, &params.name, permission, None)
        .await
    {
        Ok((token, token_string)) => {
            // Audit log
            audit::log_token_created(
                &ctx.user.username,
                &ctx.user.tenant_id,
                &token.id,
                &token.name,
            );

            // Save state
            if let Err(e) = state.save_state().await {
                warn!("Failed to save state after token creation: {}", e);
            }

            let response = serde_json::json!({
                "data": {
                    "token": token,
                    "value": token_string  // Only shown once!
                }
            });
            json_response(StatusCode::CREATED, &response)
        }
        Err(e) => error_response(e),
    }
}

async fn handle_delete_token(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    token_id: &str,
) -> Response<Full<Bytes>> {
    // Check that the token belongs to the current user (or user is admin)
    if ctx.permission != Permission::Admin {
        if let Some(token) = state.auth.get_token(token_id).await {
            if token.user_id != ctx.user.id {
                return error_response(ApiError::forbidden("Cannot delete another user's token"));
            }
        }
    }

    match state.auth.delete_token(token_id).await {
        Ok(()) => {
            // Audit log
            audit::log_token_deleted(&ctx.user.username, &ctx.user.tenant_id, token_id);

            // Save state
            if let Err(e) = state.save_state().await {
                warn!("Failed to save state after token deletion: {}", e);
            }

            json_response(
                StatusCode::OK,
                &serde_json::json!({"data": {"deleted": true}}),
            )
        }
        Err(e) => error_response(e),
    }
}

async fn handle_get_usage(state: Arc<ServerState>, ctx: &AuthContext) -> Response<Full<Bytes>> {
    let usage = state.billing.get_usage(&ctx.user.tenant_id).await;
    json_response(StatusCode::OK, &serde_json::json!({"data": usage}))
}

async fn handle_rate_limit_info(
    state: Arc<ServerState>,
    ctx: &AuthContext,
) -> Response<Full<Bytes>> {
    let stats = state.rate_limiter.get_tenant_stats(&ctx.user.tenant_id);
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "data": {
                "upload_bytes_used": stats.upload_bytes_used,
                "upload_bytes_limit": stats.upload_bytes_limit,
                "requests_per_minute_limit": stats.requests_per_minute_limit
            }
        }),
    )
}

// === GC/Admin handlers ===

async fn handle_run_gc(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let body = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return bad_request("Failed to read request body"),
    };

    #[derive(serde::Deserialize, Default)]
    struct GcRequest {
        #[serde(default)]
        dry_run: bool,
        max_delete: Option<usize>,
        #[serde(default)]
        store: Option<String>,
    }

    let params: GcRequest = if body.is_empty() {
        GcRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(p) => p,
            Err(_) => return bad_request("Invalid JSON"),
        }
    };

    let store = params
        .store
        .clone()
        .unwrap_or_else(|| "default".to_string());
    if let Err(e) = validate_datastore_name(&store) {
        return error_response(e);
    }
    let datastore = match state.get_datastore(&store) {
        Some(ds) => ds,
        None => return not_found(),
    };
    let backend = datastore.backend();
    let gc = GarbageCollector::new(datastore.clone(), backend);

    let options = GcOptions {
        dry_run: params.dry_run,
        max_delete: params.max_delete,
    };

    // Audit log: GC started
    audit::log_gc_started(&ctx.user.username, &ctx.user.tenant_id, params.dry_run);

    match gc.run(options).await {
        Ok(result) => {
            // Audit log: GC completed
            audit::log_gc_completed(
                &ctx.user.username,
                &ctx.user.tenant_id,
                result.chunks_deleted,
                result.bytes_freed,
            );

            let stats = datastore.backend().stats().await.unwrap_or_default();
            let used = stats.chunk_bytes + stats.file_bytes;
            let gc_status = gc_status_from_result("manual", used, &result);
            let mut map = state.gc_status.write().await;
            map.insert(store.clone(), gc_status);

            let response = serde_json::json!({
                "data": {
                    "chunks_scanned": result.chunks_scanned,
                    "chunks_referenced": result.chunks_referenced,
                    "chunks_orphaned": result.chunks_orphaned,
                    "chunks_deleted": result.chunks_deleted,
                    "bytes_freed": result.bytes_freed,
                    "errors": result.errors
                }
            });
            json_response(StatusCode::OK, &response)
        }
        Err(e) => error_response(ApiError::internal(&e.to_string())),
    }
}

async fn handle_gc_status(
    state: Arc<ServerState>,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let store = get_query_param(req.uri(), "store").unwrap_or_else(|| "default".to_string());
    if let Err(e) = validate_datastore_name(&store) {
        return error_response(e);
    }
    let datastore = match state.get_datastore(&store) {
        Some(ds) => ds,
        None => return not_found(),
    };
    let backend = datastore.backend();

    match backend.list_chunks().await {
        Ok(chunks) => json_response(
            StatusCode::OK,
            &serde_json::json!({
                "data": {
                    "total_chunks": chunks.len(),
                    "gc_running": false
                }
            }),
        ),
        Err(e) => error_response(ApiError::internal(&e.to_string())),
    }
}

#[derive(serde::Deserialize)]
struct PruneRequest {
    backup_type: String,
    backup_id: String,
    #[serde(default)]
    ns: Option<String>,
    #[serde(default)]
    store: Option<String>,
    #[serde(default)]
    dry_run: bool,
    keep_last: Option<usize>,
    keep_daily: Option<usize>,
    keep_weekly: Option<usize>,
    keep_monthly: Option<usize>,
    keep_yearly: Option<usize>,
}

async fn handle_prune_body(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    store: &str,
    body: Bytes,
) -> Response<Full<Bytes>> {
    let params: PruneRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return bad_request("Invalid JSON"),
    };

    // Validate backup parameters
    if let Err(e) = validate_backup_params(
        &params.backup_type,
        &params.backup_id,
        "2000-01-01T00:00:00Z",
    ) {
        return error_response(e);
    }
    if let Some(ns) = params.ns.as_deref() {
        if let Err(e) = validate_backup_namespace(ns) {
            return error_response(e);
        }
    }

    if let Err(e) = validate_datastore_name(store) {
        return error_response(e);
    }
    let datastore = match state.get_datastore(store) {
        Some(ds) => ds,
        None => return not_found(),
    };
    let pruner = Pruner::new(datastore.clone());

    let options = PruneOptions {
        keep_last: params.keep_last.or(Some(1)),
        keep_hourly: None,
        keep_daily: params.keep_daily.or(Some(7)),
        keep_weekly: params.keep_weekly.or(Some(4)),
        keep_monthly: params.keep_monthly.or(Some(6)),
        keep_yearly: params.keep_yearly,
        dry_run: params.dry_run,
    };

    let auth_id = task_auth_id(ctx);
    let worker_id = format!("{}/{}", params.backup_type, params.backup_id);
    let upid = state
        .tasks
        .create(&auth_id, "prune", Some(&worker_id), Some(store))
        .await;
    state
        .tasks
        .log(
            &upid,
            &format!(
                "Prune started (dry_run={}): {}/{}",
                params.dry_run, params.backup_type, params.backup_id
            ),
        )
        .await;

    info!(
        "Pruning {}/{} (dry_run={})",
        params.backup_type, params.backup_id, params.dry_run
    );

    let result = match pruner
        .prune(
            &params.backup_type,
            &params.backup_id,
            params.ns.as_deref(),
            options,
        )
        .await
    {
        Ok(result) => result,
        Err(e) => {
            state
                .tasks
                .log(&upid, &format!("Prune failed: {}", e))
                .await;
            state.tasks.finish(&upid, "ERROR").await;
            return error_response(ApiError::internal(&e.to_string()));
        }
    };

    if !params.dry_run {
        audit::log_prune_executed(&ctx.user.username, &ctx.user.tenant_id, result.pruned.len());
    }
    state
        .tasks
        .log(
            &upid,
            &format!(
                "Prune complete: kept={}, pruned={}",
                result.kept.len(),
                result.pruned.len()
            ),
        )
        .await;
    state.tasks.finish(&upid, "OK").await;

    let mut items = Vec::new();
    let ns = params.ns.clone().unwrap_or_default();
    let backup_type = params.backup_type.clone();
    let backup_id = params.backup_id.clone();

    for snapshot in result.kept.iter().chain(result.pruned.iter()) {
        let keep = result.kept.contains(snapshot);
        let backup_time = match snapshot_to_epoch(snapshot) {
            Some(epoch) => epoch,
            None => continue,
        };
        let snapshot_path = build_snapshot_path(
            if ns.is_empty() {
                None
            } else {
                Some(ns.as_str())
            },
            &backup_type,
            &backup_id,
            snapshot,
        );
        let protected = datastore
            .read_manifest_any(&snapshot_path)
            .await
            .map(|m| manifest_protected(&m))
            .unwrap_or(false);
        let mut item = serde_json::json!({
            "backup-type": backup_type.clone(),
            "backup-id": backup_id.clone(),
            "backup-time": backup_time,
            "keep": keep,
            "protected": protected,
        });
        if !ns.is_empty() {
            if let Some(obj) = item.as_object_mut() {
                obj.insert("ns".to_string(), serde_json::Value::String(ns.clone()));
            }
        }
        items.push(item);
    }

    json_response(StatusCode::OK, &serde_json::json!({"data": items}))
}

async fn handle_prune(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let body = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return bad_request("Failed to read request body"),
    };

    let params: PruneRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return bad_request("Invalid JSON"),
    };
    let store = params
        .store
        .clone()
        .unwrap_or_else(|| "default".to_string());

    handle_prune_body(state, ctx, &store, body).await
}

struct VerifyTaskOptions {
    job_id: Option<String>,
    namespace: Option<String>,
    max_depth: Option<usize>,
    ignore_verified: bool,
    outdated_after: Option<i64>,
    trigger: String,
}

async fn spawn_verify_task(
    state: Arc<ServerState>,
    datastore: Arc<Datastore>,
    auth_id: String,
    store_name: String,
    options: VerifyTaskOptions,
) -> String {
    let VerifyTaskOptions {
        job_id,
        namespace,
        max_depth,
        ignore_verified,
        outdated_after,
        trigger,
    } = options;

    let worker_id = job_id
        .as_deref()
        .map(|id| format!("{}:{}", store_name, id))
        .unwrap_or_else(|| store_name.clone());
    let upid = state
        .tasks
        .create(
            &auth_id,
            "verificationjob",
            Some(&worker_id),
            Some(&store_name),
        )
        .await;
    let state_clone = state.clone();
    let datastore_clone = datastore.clone();
    let upid_clone = upid.clone();
    let store_name_clone = store_name.clone();
    let namespace_clone = namespace.clone();
    let max_depth_clone = max_depth;
    let ignore_verified_clone = ignore_verified;
    let outdated_after_clone = outdated_after;
    let trigger_label = trigger;
    let job_id_clone = job_id.clone();

    tokio::spawn(async move {
        if let Some(job_id) = job_id_clone.as_deref() {
            let mut guard = state_clone.verify_job_state.write().await;
            let entry = guard
                .entry(job_id.to_string())
                .or_insert_with(|| VerificationJobState::new(job_id));
            entry.last_run_upid = Some(upid_clone.clone());
            entry.last_run_state = Some("running".to_string());
            entry.last_run_endtime = None;
            entry.last_run_time = None;
            entry.next_run = None;
        }

        let mut start_message = format!("Verification started for {}", store_name_clone);
        if !trigger_label.is_empty() {
            start_message.push_str(&format!(" ({})", trigger_label));
        }
        state_clone.tasks.log(&upid_clone, &start_message).await;

        let groups = match datastore_clone.list_backup_groups().await {
            Ok(groups) => groups,
            Err(e) => {
                state_clone
                    .tasks
                    .log(&upid_clone, &format!("Failed to list groups: {}", e))
                    .await;
                state_clone.tasks.finish(&upid_clone, "ERROR").await;
                return;
            }
        };
        let mut total = 0u64;
        let mut ok = 0u64;
        let mut failed = 0u64;

        for group in groups {
            if !namespace_in_scope(
                namespace_clone.as_deref(),
                group.namespace.as_deref(),
                max_depth_clone,
            ) {
                continue;
            }
            let snapshots = datastore_clone
                .list_snapshots(
                    group.namespace.as_deref(),
                    &group.backup_type,
                    &group.backup_id,
                )
                .await
                .unwrap_or_default();
            for snapshot in snapshots {
                total = total.saturating_add(1);
                let snapshot_path = format!("{}/{}", group.path(), snapshot);
                match datastore_clone.read_manifest_any(&snapshot_path).await {
                    Ok(mut manifest) => {
                        if !should_verify_snapshot(
                            ignore_verified_clone,
                            outdated_after_clone,
                            &manifest,
                        ) {
                            ok = ok.saturating_add(1);
                            state_clone
                                .tasks
                                .log(
                                    &upid_clone,
                                    &format!(
                                        "Skipping snapshot {} (recently verified)",
                                        snapshot_path
                                    ),
                                )
                                .await;
                            continue;
                        }
                        let prefix = format!("{}/", snapshot_path);
                        let mut missing = Vec::new();
                        let mut size_mismatch = Vec::new();
                        let mut index_errors = Vec::new();
                        let mut missing_chunks = Vec::new();
                        let mut digest_mismatch = Vec::new();
                        let mut chunk_checked = 0usize;
                        let mut chunk_missing = 0usize;
                        let mut chunk_skipped = 0usize;
                        let mut skipped_chunks = Vec::new();
                        let crypto = datastore_clone.crypto_config();
                        let existing = match datastore_clone.backend().list_files(&prefix).await {
                            Ok(files) => {
                                let mut set = std::collections::HashSet::new();
                                for file in files {
                                    if let Some(rel) = file.strip_prefix(&prefix) {
                                        if !rel.is_empty() {
                                            set.insert(rel.to_string());
                                        }
                                    }
                                }
                                Some(set)
                            }
                            Err(e) => {
                                state_clone
                                    .tasks
                                    .log(
                                        &upid_clone,
                                        &format!("Failed to list files {}: {}", snapshot_path, e),
                                    )
                                    .await;
                                None
                            }
                        };
                        if let Some(existing) = existing {
                            for file in &manifest.files {
                                if !existing.contains(&file.filename) {
                                    missing.push(file.filename.clone());
                                    continue;
                                }
                                let path = format!("{}{}", prefix, file.filename);
                                match datastore_clone.backend().file_size(&path).await {
                                    Ok(size) => {
                                        if size != file.size {
                                            size_mismatch.push(format!(
                                                "{} (expected {}, got {})",
                                                file.filename, file.size, size
                                            ));
                                        }
                                    }
                                    Err(e) => {
                                        size_mismatch
                                            .push(format!("{} (size error: {})", file.filename, e));
                                    }
                                }
                            }
                        }

                        let mut chunk_expectations = std::collections::HashMap::new();

                        for file in &manifest.files {
                            if matches!(file.file_type, FileType::Fidx | FileType::Didx)
                                && !missing.contains(&file.filename)
                            {
                                let path = format!("{}{}", prefix, file.filename);
                                let data = match datastore_clone.backend().read_file(&path).await {
                                    Ok(bytes) => bytes,
                                    Err(e) => {
                                        index_errors.push(format!(
                                            "{}: read failed ({})",
                                            file.filename, e
                                        ));
                                        continue;
                                    }
                                };
                                match file.file_type {
                                    FileType::Fidx => match FixedIndex::from_bytes(&data) {
                                        Ok(index) => {
                                            for digest in index.unique_digests() {
                                                chunk_expectations.entry(digest).or_insert(None);
                                            }
                                        }
                                        Err(e) => {
                                            index_errors.push(format!(
                                                "{}: parse failed ({})",
                                                file.filename, e
                                            ));
                                        }
                                    },
                                    FileType::Didx => match DynamicIndex::from_bytes(&data) {
                                        Ok(index) => {
                                            for entry in index.entries {
                                                chunk_expectations
                                                    .entry(entry.digest)
                                                    .or_insert(Some(entry.size));
                                            }
                                        }
                                        Err(e) => {
                                            index_errors.push(format!(
                                                "{}: parse failed ({})",
                                                file.filename, e
                                            ));
                                        }
                                    },
                                    FileType::Blob => {}
                                }
                            }
                        }

                        for (digest, expected_size) in chunk_expectations {
                            chunk_checked = chunk_checked.saturating_add(1);
                            let blob_bytes = match datastore_clone.read_chunk_blob(&digest).await {
                                Ok(bytes) => bytes,
                                Err(e) => {
                                    chunk_missing = chunk_missing.saturating_add(1);
                                    if missing_chunks.len() < 10 {
                                        missing_chunks.push(format!(
                                            "{} (error: {})",
                                            digest.to_hex(),
                                            e
                                        ));
                                    }
                                    continue;
                                }
                            };

                            let chunk = match decode_chunk_blob(&blob_bytes, &crypto) {
                                Ok(Some(chunk)) => chunk,
                                Ok(None) => {
                                    chunk_skipped = chunk_skipped.saturating_add(1);
                                    if skipped_chunks.len() < 10 {
                                        skipped_chunks.push(digest.to_hex());
                                    }
                                    continue;
                                }
                                Err(e) => {
                                    chunk_missing = chunk_missing.saturating_add(1);
                                    if missing_chunks.len() < 10 {
                                        missing_chunks.push(format!(
                                            "{} (decode error: {})",
                                            digest.to_hex(),
                                            e
                                        ));
                                    }
                                    continue;
                                }
                            };

                            if chunk.digest() != &digest && digest_mismatch.len() < 10 {
                                digest_mismatch.push(digest.to_hex());
                            }
                            if let Some(size) = expected_size {
                                if chunk.size() as u64 != size && digest_mismatch.len() < 10 {
                                    digest_mismatch.push(format!(
                                        "{} (size {} != {})",
                                        digest.to_hex(),
                                        chunk.size(),
                                        size
                                    ));
                                }
                            }
                        }

                        let verify_state = if missing.is_empty()
                            && size_mismatch.is_empty()
                            && chunk_missing == 0
                            && index_errors.is_empty()
                            && digest_mismatch.is_empty()
                        {
                            serde_json::json!({
                                "upid": upid_clone.clone(),
                                "state": "ok",
                            })
                        } else {
                            serde_json::json!({
                                "upid": upid_clone.clone(),
                                "state": "failed",
                            })
                        };
                        update_manifest_unprotected(&mut manifest, "verify_state", verify_state);
                        if let Err(e) = datastore_clone
                            .store_manifest_at(&snapshot_path, &manifest)
                            .await
                        {
                            failed = failed.saturating_add(1);
                            state_clone
                                .tasks
                                .log(
                                    &upid_clone,
                                    &format!("Failed to store manifest {}: {}", snapshot_path, e),
                                )
                                .await;
                        } else if missing.is_empty()
                            && size_mismatch.is_empty()
                            && chunk_missing == 0
                            && index_errors.is_empty()
                            && digest_mismatch.is_empty()
                        {
                            ok = ok.saturating_add(1);
                        } else {
                            failed = failed.saturating_add(1);
                            state_clone
                                .tasks
                                .log(
                                    &upid_clone,
                                    &format!(
                                        "Missing files in {}: {}",
                                        snapshot_path,
                                        missing.join(", ")
                                    ),
                                )
                                .await;
                            if !size_mismatch.is_empty() {
                                state_clone
                                    .tasks
                                    .log(
                                        &upid_clone,
                                        &format!(
                                            "Size mismatches in {}: {}",
                                            snapshot_path,
                                            size_mismatch.join(", ")
                                        ),
                                    )
                                    .await;
                            }
                            if !index_errors.is_empty() {
                                state_clone
                                    .tasks
                                    .log(
                                        &upid_clone,
                                        &format!(
                                            "Index errors in {}: {}",
                                            snapshot_path,
                                            index_errors.join(", ")
                                        ),
                                    )
                                    .await;
                            }
                            if chunk_checked > 0 {
                                state_clone
                                    .tasks
                                    .log(
                                        &upid_clone,
                                        &format!(
                                            "Chunk check in {}: checked={}, missing={}, skipped={}, samples={}",
                                            snapshot_path,
                                            chunk_checked,
                                            chunk_missing,
                                            chunk_skipped,
                                            missing_chunks.join(", ")
                                        ),
                                    )
                                    .await;
                                if chunk_skipped > 0 && !skipped_chunks.is_empty() {
                                    state_clone
                                        .tasks
                                        .log(
                                            &upid_clone,
                                            &format!(
                                                "Chunk check skipped (encrypted, no key) in {}: {}",
                                                snapshot_path,
                                                skipped_chunks.join(", ")
                                            ),
                                        )
                                        .await;
                                }
                            }
                            if !digest_mismatch.is_empty() {
                                state_clone
                                    .tasks
                                    .log(
                                        &upid_clone,
                                        &format!(
                                            "Chunk digest/size mismatches in {}: {}",
                                            snapshot_path,
                                            digest_mismatch.join(", ")
                                        ),
                                    )
                                    .await;
                            }
                        }
                    }
                    Err(e) => {
                        failed = failed.saturating_add(1);
                        state_clone
                            .tasks
                            .log(
                                &upid_clone,
                                &format!("Missing manifest {}: {}", snapshot_path, e),
                            )
                            .await;
                    }
                }
            }
        }

        state_clone
            .tasks
            .log(
                &upid_clone,
                &format!(
                    "Verification finished: total={}, ok={}, failed={}",
                    total, ok, failed
                ),
            )
            .await;
        let exit_status = if failed > 0 {
            format!("WARNINGS: {}", failed)
        } else {
            "OK".to_string()
        };
        state_clone.tasks.finish(&upid_clone, &exit_status).await;

        if let Some(job_id) = job_id_clone.as_deref() {
            let mut guard = state_clone.verify_job_state.write().await;
            if let Some(entry) = guard.get_mut(job_id) {
                entry.last_run_state = Some(exit_status.clone());
                let endtime = chrono::Utc::now().timestamp();
                entry.last_run_endtime = Some(endtime);
                entry.last_run_time = Some(endtime);
                entry.last_run_upid = Some(upid_clone.clone());
                entry.next_run = None;
            }
        }

        if let Err(e) = state_clone.save_state().await {
            warn!("Failed to save state after verification job: {}", e);
        }
    });

    upid
}

fn normalize_verify_job_config(config: &mut VerificationJobConfig) {
    if let Some(comment) = config.comment.as_ref() {
        let trimmed = comment.trim();
        if trimmed.is_empty() {
            config.comment = None;
        } else if trimmed.len() != comment.len() {
            config.comment = Some(trimmed.to_string());
        }
    }

    if let Some(schedule) = config.schedule.as_ref() {
        let trimmed = schedule.trim();
        if trimmed.is_empty() {
            config.schedule = None;
        } else if trimmed.len() != schedule.len() {
            config.schedule = Some(trimmed.to_string());
        }
    }

    if let Some(ns) = config.ns.as_ref() {
        let trimmed = ns.trim();
        if trimmed.is_empty() {
            config.ns = None;
        } else if trimmed.len() != ns.len() {
            config.ns = Some(trimmed.to_string());
        }
    }
}

fn validate_verify_job_config(
    state: &ServerState,
    config: &VerificationJobConfig,
) -> Result<(), ApiError> {
    validate_filename(&config.id)?;
    validate_datastore_name(&config.store)?;
    if state.get_datastore(&config.store).is_none() {
        return Err(ApiError::not_found("Datastore not found"));
    }
    if let Some(ns) = config.ns.as_ref() {
        validate_backup_namespace(ns)?;
    }
    if let Some(max_depth) = config.max_depth {
        if max_depth > MAX_VERIFY_DEPTH {
            return Err(ApiError::bad_request(
                "max-depth exceeds namespace depth limit",
            ));
        }
    }
    if let Some(outdated_after) = config.outdated_after {
        if outdated_after < 0 {
            return Err(ApiError::bad_request(
                "outdated-after must be a non-negative integer",
            ));
        }
    }
    if let Some(schedule) = config.schedule.as_ref() {
        let _ = parse_calendar_event(schedule)?;
    }
    Ok(())
}

fn collect_verify_jobs_sorted(
    guard: &HashMap<String, VerificationJobConfig>,
) -> Vec<VerificationJobConfig> {
    let mut jobs = guard.values().cloned().collect::<Vec<_>>();
    jobs.sort_by(|a, b| a.id.cmp(&b.id));
    jobs
}

fn compute_verify_jobs_digest(jobs: &[VerificationJobConfig]) -> String {
    let json = serde_json::to_vec(jobs).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&json);
    hex::encode(hasher.finalize())
}

async fn handle_verify_config_api(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let uri = req.uri().clone();
    let path = uri.path();
    let rest = path
        .trim_start_matches("/api2/json/config/verify")
        .trim_start_matches('/');

    if rest.is_empty() {
        match *req.method() {
            Method::GET => {
                let store_filter = get_query_param(&uri, "store");
                let (mut items, digest) = {
                    let guard = state.verify_jobs.read().await;
                    let items = collect_verify_jobs_sorted(&guard);
                    let digest = compute_verify_jobs_digest(&items);
                    (items, digest)
                };
                if let Some(filter) = store_filter {
                    items.retain(|job| job.store == filter);
                }
                return json_response(
                    StatusCode::OK,
                    &serde_json::json!({ "data": items, "digest": digest }),
                );
            }
            Method::POST => {
                if let Err(e) = ctx.require(Permission::DatastoreAdmin) {
                    return error_response(e);
                }

                let body = match req.collect().await {
                    Ok(collected) => collected.to_bytes(),
                    Err(_) => return bad_request("Failed to read request body"),
                };

                let mut config: VerificationJobConfig = match serde_json::from_slice(&body) {
                    Ok(p) => p,
                    Err(_) => return bad_request("Invalid JSON"),
                };
                normalize_verify_job_config(&mut config);

                if let Err(e) = validate_verify_job_config(&state, &config) {
                    return error_response(e);
                }

                let mut guard = state.verify_jobs.write().await;
                if guard.contains_key(&config.id) {
                    return bad_request("Verification job already exists");
                }
                guard.insert(config.id.clone(), config.clone());
                let digest = compute_verify_jobs_digest(&collect_verify_jobs_sorted(&guard));
                drop(guard);

                let mut state_guard = state.verify_job_state.write().await;
                let entry = state_guard
                    .entry(config.id.clone())
                    .or_insert_with(|| VerificationJobState::new(&config.id));
                entry.last_schedule = config.schedule.clone();
                entry.next_run = None;
                drop(state_guard);

                if let Err(e) = state.save_state().await {
                    warn!("Failed to save state after verify job creation: {}", e);
                }

                return json_response(
                    StatusCode::CREATED,
                    &serde_json::json!({ "data": config, "digest": digest }),
                );
            }
            _ => return not_found(),
        }
    }

    if rest.contains('/') {
        return not_found();
    }
    let id = rest;

    if let Err(e) = validate_filename(id) {
        return error_response(e);
    }

    match *req.method() {
        Method::GET => {
            let guard = state.verify_jobs.read().await;
            let digest = compute_verify_jobs_digest(&collect_verify_jobs_sorted(&guard));
            match guard.get(id) {
                Some(job) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({ "data": job, "digest": digest }),
                ),
                None => not_found(),
            }
        }
        Method::PUT => {
            if let Err(e) = ctx.require(Permission::DatastoreAdmin) {
                return error_response(e);
            }

            let body = match req.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => return bad_request("Failed to read request body"),
            };

            #[derive(serde::Deserialize)]
            struct UpdateRequest {
                #[serde(flatten)]
                update: VerificationJobConfigUpdater,
                delete: Option<Vec<DeletableProperty>>,
                digest: Option<String>,
            }

            let params: UpdateRequest = match serde_json::from_slice(&body) {
                Ok(p) => p,
                Err(_) => return bad_request("Invalid JSON"),
            };
            let mut guard = state.verify_jobs.write().await;
            if let Some(ref digest) = params.digest {
                let current = compute_verify_jobs_digest(&collect_verify_jobs_sorted(&guard));
                if digest != &current {
                    return bad_request("Configuration digest mismatch");
                }
            }
            let Some(existing) = guard.get_mut(id) else {
                return not_found();
            };
            let mut updated = existing.clone();
            updated.apply_update(params.update, params.delete);
            normalize_verify_job_config(&mut updated);
            if let Err(e) = validate_verify_job_config(&state, &updated) {
                return error_response(e);
            }
            *existing = updated.clone();
            let digest = compute_verify_jobs_digest(&collect_verify_jobs_sorted(&guard));
            drop(guard);

            let mut state_guard = state.verify_job_state.write().await;
            let entry = state_guard
                .entry(updated.id.clone())
                .or_insert_with(|| VerificationJobState::new(&updated.id));
            entry.last_schedule = updated.schedule.clone();
            entry.next_run = None;
            drop(state_guard);

            if let Err(e) = state.save_state().await {
                warn!("Failed to save state after verify job update: {}", e);
            }

            json_response(
                StatusCode::OK,
                &serde_json::json!({ "data": updated, "digest": digest }),
            )
        }
        Method::DELETE => {
            if let Err(e) = ctx.require(Permission::DatastoreAdmin) {
                return error_response(e);
            }

            let mut guard = state.verify_jobs.write().await;
            let digest_param = get_query_param(&uri, "digest");
            if let Some(ref digest) = digest_param {
                let current = compute_verify_jobs_digest(&collect_verify_jobs_sorted(&guard));
                if digest != &current {
                    return bad_request("Configuration digest mismatch");
                }
            }
            let removed = guard.remove(id);
            let digest = compute_verify_jobs_digest(&collect_verify_jobs_sorted(&guard));
            drop(guard);
            if removed.is_none() {
                return not_found();
            }

            let mut state_guard = state.verify_job_state.write().await;
            state_guard.remove(id);
            drop(state_guard);

            if let Err(e) = state.save_state().await {
                warn!("Failed to save state after verify job deletion: {}", e);
            }

            json_response(
                StatusCode::OK,
                &serde_json::json!({ "data": { "deleted": true, "id": id }, "digest": digest }),
            )
        }
        _ => not_found(),
    }
}

async fn handle_verify_api(
    state: Arc<ServerState>,
    ctx: &AuthContext,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let uri = req.uri().clone();
    let path = uri.path();
    let rest = path
        .trim_start_matches("/api2/json/admin/verify")
        .trim_start_matches('/');
    if rest.is_empty() {
        if req.method() != Method::GET {
            return not_found();
        }
        let store_filter = get_query_param(req.uri(), "store");
        let snapshots = state.tasks.snapshot().await;
        let now = chrono::Utc::now().timestamp();
        let interval = state.config.verify.interval_hours as i64 * 3600;

        let mut items = Vec::new();
        let jobs = {
            let guard = state.verify_jobs.read().await;
            guard.values().cloned().collect::<Vec<_>>()
        };
        let job_states = {
            let guard = state.verify_job_state.read().await;
            guard.clone()
        };

        if jobs.is_empty() {
            for store in state.datastores.keys() {
                if let Some(ref filter) = store_filter {
                    if store != filter {
                        continue;
                    }
                }
                let mut last_task: Option<TaskSnapshot> = None;
                for task in snapshots.iter().filter(|t| {
                    t.worker_type == "verificationjob" && t.store.as_deref() == Some(store.as_str())
                }) {
                    if last_task
                        .as_ref()
                        .map(|prev| task.starttime > prev.starttime)
                        .unwrap_or(true)
                    {
                        last_task = Some(task.clone());
                    }
                }

                let (last_run_upid, last_run_state, last_run_endtime) = match last_task.as_ref() {
                    Some(task) => (
                        Some(task.upid.clone()),
                        task.exitstatus.clone().or_else(|| task.status.clone()),
                        task.endtime,
                    ),
                    None => (None, None, None),
                };

                let next_run = if state.config.verify.enabled && interval > 0 {
                    let base = last_run_endtime.unwrap_or(now);
                    Some(base + interval)
                } else {
                    None
                };

                items.push(serde_json::json!({
                    "id": store,
                    "store": store,
                    "schedule": None::<String>,
                    "comment": None::<String>,
                    "ignore-verified": None::<bool>,
                    "outdated-after": None::<i64>,
                    "ns": None::<String>,
                    "max-depth": None::<usize>,
                    "next-run": next_run,
                    "last-run-state": last_run_state,
                    "last-run-upid": last_run_upid,
                    "last-run-endtime": last_run_endtime,
                }));
            }
        } else {
            for job in jobs {
                if let Some(ref filter) = store_filter {
                    if job.store != *filter {
                        continue;
                    }
                }
                let (next_run, last_run_state, last_run_upid, last_run_endtime) =
                    compute_verify_job_status(
                        &job,
                        &job_states,
                        &snapshots,
                        now,
                        if interval > 0 { Some(interval) } else { None },
                        state.config.verify.enabled,
                    );

                items.push(serde_json::json!({
                    "id": job.id,
                    "store": job.store,
                    "schedule": job.schedule,
                    "comment": job.comment,
                    "ignore-verified": job.ignore_verified,
                    "outdated-after": job.outdated_after,
                    "ns": job.ns,
                    "max-depth": job.max_depth,
                    "next-run": next_run,
                    "last-run-state": last_run_state,
                    "last-run-upid": last_run_upid,
                    "last-run-endtime": last_run_endtime,
                }));
            }
        }

        return json_response(StatusCode::OK, &serde_json::json!({ "data": items }));
    }

    let parts: Vec<&str> = rest.split('/').collect();
    match (req.method(), parts.as_slice()) {
        (&Method::GET, [job_id, "status"]) => {
            let job = {
                let guard = state.verify_jobs.read().await;
                guard.get(*job_id).cloned()
            };
            let Some(job) = job else {
                return not_found();
            };

            let snapshots = state.tasks.snapshot().await;
            let job_states = {
                let guard = state.verify_job_state.read().await;
                guard.clone()
            };
            let now = chrono::Utc::now().timestamp();
            let interval = state.config.verify.interval_hours as i64 * 3600;
            let (next_run, last_run_state, last_run_upid, last_run_endtime) =
                compute_verify_job_status(
                    &job,
                    &job_states,
                    &snapshots,
                    now,
                    if interval > 0 { Some(interval) } else { None },
                    state.config.verify.enabled,
                );

            json_response(
                StatusCode::OK,
                &serde_json::json!({
                    "data": {
                        "next-run": next_run,
                        "last-run-state": last_run_state,
                        "last-run-upid": last_run_upid,
                        "last-run-endtime": last_run_endtime,
                    }
                }),
            )
        }
        (&Method::GET, [job_id, "history"]) => {
            let job = {
                let guard = state.verify_jobs.read().await;
                guard.get(*job_id).cloned()
            };
            let Some(job) = job else {
                return not_found();
            };
            let start = get_query_param(&uri, "start")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            let limit = get_query_param(&uri, "limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(50);
            let worker_id = format!("{}:{}", job.store, job.id);
            let (items, total) = state
                .tasks
                .list_by_worker("verificationjob", &worker_id, start, limit, true)
                .await;
            let data = items.iter().map(task_snapshot_value).collect::<Vec<_>>();

            json_response(
                StatusCode::OK,
                &serde_json::json!({ "data": data, "total": total }),
            )
        }
        (&Method::POST, [target, "run"]) => {
            let job = {
                let guard = state.verify_jobs.read().await;
                guard.get(*target).cloned()
            };

            let auth_id = task_auth_id(ctx);
            let upid = if let Some(job) = job {
                let datastore = match state.get_datastore(&job.store) {
                    Some(ds) => ds,
                    None => return not_found(),
                };
                spawn_verify_task(
                    state.clone(),
                    datastore,
                    auth_id,
                    job.store.clone(),
                    VerifyTaskOptions {
                        job_id: Some(job.id.clone()),
                        namespace: job.ns.clone(),
                        max_depth: job.max_depth,
                        ignore_verified: job.ignore_verified.unwrap_or(true),
                        outdated_after: job.outdated_after,
                        trigger: "manual".to_string(),
                    },
                )
                .await
            } else {
                if let Err(e) = validate_datastore_name(target) {
                    return error_response(e);
                }
                let datastore = match state.get_datastore(target) {
                    Some(ds) => ds,
                    None => return not_found(),
                };
                spawn_verify_task(
                    state.clone(),
                    datastore,
                    auth_id,
                    target.to_string(),
                    VerifyTaskOptions {
                        job_id: None,
                        namespace: None,
                        max_depth: None,
                        ignore_verified: false,
                        outdated_after: None,
                        trigger: "manual".to_string(),
                    },
                )
                .await
            };

            json_response(StatusCode::OK, &serde_json::json!({ "data": upid }))
        }
        _ => not_found(),
    }
}

// === Response helpers ===

fn json_response<T: serde::Serialize>(status: StatusCode, data: &T) -> Response<Full<Bytes>> {
    let json = serde_json::to_string(data).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(json)))
        .expect("valid response")
}

fn error_response(error: ApiError) -> Response<Full<Bytes>> {
    let status = match error.status {
        400 => StatusCode::BAD_REQUEST,
        401 => StatusCode::UNAUTHORIZED,
        403 => StatusCode::FORBIDDEN,
        404 => StatusCode::NOT_FOUND,
        429 => StatusCode::TOO_MANY_REQUESTS,
        507 => StatusCode::INSUFFICIENT_STORAGE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let body = serde_json::json!({"error": error.message});
    json_response(status, &body)
}

fn rate_limited_response(retry_after: u32, limit: u32, remaining: u32) -> Response<Full<Bytes>> {
    let body = serde_json::json!({
        "error": "Rate limit exceeded",
        "retry_after": retry_after
    });
    // serde_json::Value always serializes successfully
    let json = serde_json::to_string(&body).expect("JSON value serializes");
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "application/json")
        .header("Retry-After", retry_after.to_string())
        .header("X-RateLimit-Limit", limit.to_string())
        .header("X-RateLimit-Remaining", remaining.to_string())
        .body(Full::new(Bytes::from(json)))
        .expect("valid response")
}

fn not_found() -> Response<Full<Bytes>> {
    error_response(ApiError::not_found("Not found"))
}

fn bad_request(message: &str) -> Response<Full<Bytes>> {
    error_response(ApiError::bad_request(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use pbs_core::EncryptionKey;

    #[test]
    fn test_decode_chunk_blob_skips_without_key() {
        let data = vec![7u8; 128];
        let chunk = Chunk::new(data).expect("chunk");
        let crypto = CryptoConfig::with_encryption(EncryptionKey::generate());
        let blob = DataBlob::encode(chunk.data(), &crypto, true).expect("blob");
        let bytes = blob.to_bytes();

        let no_key = CryptoConfig::default();
        let decoded = decode_chunk_blob(&bytes, &no_key).expect("decode");
        assert!(decoded.is_none());

        let decoded = decode_chunk_blob(&bytes, &crypto)
            .expect("decode")
            .expect("chunk");
        assert_eq!(decoded.digest(), chunk.digest());
    }

    #[test]
    fn test_calendar_next_run_daily_utc() {
        let spec = parse_calendar_event("daily 12:05 UTC").expect("schedule");
        let base = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let next = next_calendar_run(&spec, base).expect("next");
        assert_eq!(next, Utc.with_ymd_and_hms(2024, 1, 1, 12, 5, 0).unwrap());
    }

    #[test]
    fn test_calendar_next_run_weekday_range() {
        let spec = parse_calendar_event("mon..fri 8..17,22:0/15 UTC").expect("schedule");
        let base = Utc.with_ymd_and_hms(2024, 1, 1, 8, 7, 0).unwrap();
        let next = next_calendar_run(&spec, base).expect("next");
        assert_eq!(next, Utc.with_ymd_and_hms(2024, 1, 1, 8, 15, 0).unwrap());
    }

    #[test]
    fn test_calendar_timezone_offset() {
        let spec = parse_calendar_event("daily 12:00 +02:00").expect("schedule");
        let base = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let next = next_calendar_run(&spec, base).expect("next");
        assert_eq!(next, Utc.with_ymd_and_hms(2024, 1, 1, 10, 0, 0).unwrap());
    }

    #[test]
    fn test_calendar_named_timezone() {
        let spec = parse_calendar_event("daily 00:00 America/New_York").expect("schedule");
        let base = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let next = next_calendar_run(&spec, base).expect("next");
        assert_eq!(next, Utc.with_ymd_and_hms(2024, 1, 1, 5, 0, 0).unwrap());
    }

    #[test]
    fn test_calendar_month_name_last_day() {
        let spec = parse_calendar_event("feb-last 00:00 UTC").expect("schedule");
        let base = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let next = next_calendar_run(&spec, base).expect("next");
        assert_eq!(next, Utc.with_ymd_and_hms(2024, 2, 29, 0, 0, 0).unwrap());
    }

    #[test]
    fn test_calendar_month_name_with_year() {
        let spec = parse_calendar_event("2024-jan-02 03:00 UTC").expect("schedule");
        let base = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let next = next_calendar_run(&spec, base).expect("next");
        assert_eq!(next, Utc.with_ymd_and_hms(2024, 1, 2, 3, 0, 0).unwrap());
    }

    #[test]
    fn test_calendar_weekday_step_token() {
        let spec = parse_calendar_event("mon/2 03:00 UTC").expect("schedule");
        let base = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let next = next_calendar_run(&spec, base).expect("next");
        assert_eq!(next, Utc.with_ymd_and_hms(2024, 1, 1, 3, 0, 0).unwrap());
    }
}
