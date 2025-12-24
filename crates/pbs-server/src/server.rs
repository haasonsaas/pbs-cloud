//! HTTP/2 server implementation
//!
//! Handles both REST API and PBS backup protocol with TLS, rate limiting, and metrics.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{body::Incoming, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use pbs_core::{ChunkDigest, CryptoConfig};
use pbs_storage::{
    Datastore, LocalBackend, S3Backend, StorageBackend,
    GarbageCollector, GcOptions, Pruner, PruneOptions,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, instrument, warn, debug};

use crate::auth::{AuthContext, AuthManager, Permission};
use crate::billing::{BillingManager, UsageEvent, UsageEventType};
use crate::config::{ServerConfig, StorageConfig};
use crate::metrics::{Metrics, MetricsConfig};
use crate::persistence::{PersistenceConfig, PersistenceManager};
use crate::protocol::{ApiError, BackupParams, PROTOCOL_HEADER};
use crate::rate_limit::{RateLimiter_, RateLimitResult};
use crate::session::SessionManager;
use crate::streaming::{BackupProtocolHandler, ReaderProtocolHandler, FinishBackupResponse};
use crate::tenant::TenantManager;
use crate::tls::create_tls_acceptor;
use crate::validation::{
    validate_backup_params, validate_filename, validate_digest,
    validate_username, validate_tenant_name,
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
}

impl ServerState {
    /// Create a new server state from config
    pub async fn from_config(config: ServerConfig) -> anyhow::Result<Self> {
        // Create storage backend
        let backend: Arc<dyn StorageBackend> = match &config.storage {
            StorageConfig::Local { path } => {
                Arc::new(LocalBackend::new(path).await?)
            }
            StorageConfig::S3 { bucket, region, endpoint, prefix } => {
                let mut s3_config = match endpoint {
                    Some(ep) => pbs_storage::S3Config::compatible(bucket, ep),
                    None => pbs_storage::S3Config::aws(bucket, region.as_deref().unwrap_or("us-east-1")),
                };
                if let Some(p) = prefix {
                    s3_config = s3_config.with_prefix(p);
                }
                Arc::new(S3Backend::new(s3_config).await?)
            }
        };

        // Create default datastore
        let crypto = CryptoConfig::default();
        let default_ds = Arc::new(Datastore::new("default", backend.clone(), crypto));

        let mut datastores = HashMap::new();
        datastores.insert("default".to_string(), default_ds);

        let (billing, _rx) = BillingManager::new();

        // Initialize persistence
        let persistence_config = PersistenceConfig::new(
            config.data_dir.as_deref().unwrap_or("~/.pbs-cloud")
        );
        let persistence = Arc::new(PersistenceManager::new(persistence_config).await?);

        // Initialize metrics
        let metrics = Arc::new(Metrics::new(MetricsConfig::default())?);

        // Initialize rate limiter
        let rate_limiter = Arc::new(RateLimiter_::new(
            config.rate_limit.clone().unwrap_or_default()
        ));

        // Initialize TLS
        let tls_acceptor = create_tls_acceptor(&config.tls.clone().unwrap_or_default())?;

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

        info!("Loaded {} users, {} tokens, {} tenants from persistence",
            auth.user_count().await,
            auth.token_count().await,
            tenants.tenant_count().await
        );

        Ok(Self {
            config,
            backend,
            datastores,
            sessions: Arc::new(SessionManager::default()),
            auth,
            tenants,
            billing: Arc::new(billing),
            rate_limiter,
            metrics,
            persistence,
            tls_acceptor,
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

        self.persistence.save_users(&users).await?;
        self.persistence.save_tokens(&tokens).await?;
        self.persistence.save_tenants(&tenants).await?;

        debug!("Saved state to persistence");
        Ok(())
    }
}

/// Start the HTTP/2 server
#[instrument(skip(state))]
pub async fn run_server(state: Arc<ServerState>) -> anyhow::Result<()> {
    let addr: SocketAddr = state.config.listen_addr.parse()?;
    let listener = TcpListener::bind(addr).await?;

    let protocol = if state.tls_acceptor.is_some() { "https" } else { "http" };
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
                info!("Root API token: {}", token);
                info!("Save this token - it won't be shown again!");

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
            state_for_cleanup.sessions.cleanup_expired().await;
            // Clean up rate limiter state
            state_for_cleanup.rate_limiter.cleanup();
            // Update session metrics
            let (backup_count, reader_count) = state_for_cleanup.sessions.session_count().await;
            state_for_cleanup.metrics.update_session_counts(backup_count, reader_count);
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
        info!("Scheduled GC enabled, running every {} hours", state.config.gc.interval_hours);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(gc_interval);
            // Skip the first immediate tick
            interval.tick().await;

            loop {
                interval.tick().await;
                info!("Starting scheduled GC run");

                let datastore = state_for_gc.default_datastore();
                let backend = datastore.backend();
                let gc = GarbageCollector::new(datastore, backend);

                let options = GcOptions {
                    dry_run: false,
                    max_delete: None,
                };

                match gc.run(options).await {
                    Ok(result) => {
                        info!(
                            "Scheduled GC completed: scanned={}, orphaned={}, deleted={}, freed={}",
                            result.chunks_scanned,
                            result.chunks_orphaned,
                            result.chunks_deleted,
                            result.bytes_freed
                        );
                        if !result.errors.is_empty() {
                            warn!("GC errors: {:?}", result.errors);
                        }
                    }
                    Err(e) => {
                        error!("Scheduled GC failed: {}", e);
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
                        http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                            .serve_connection(
                                io,
                                service_fn(move |req| {
                                    let state = state.clone();
                                    handle_request(state, peer_addr, req)
                                }),
                            )
                            .await
                    }
                    Err(e) => {
                        debug!("TLS handshake failed: {:?}", e);
                        return;
                    }
                }
            } else {
                let io = TokioIo::new(stream);
                http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(
                        io,
                        service_fn(move |req| {
                            let state = state.clone();
                            handle_request(state, peer_addr, req)
                        }),
                    )
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
    let path = req.uri().path().to_string();

    debug!("{} {} from {}", method, path, peer_addr);

    // Check rate limit for IP (before auth)
    if let RateLimitResult::Limited { retry_after_secs, limit, remaining } =
        state.rate_limiter.check_ip(peer_addr.ip())
    {
        state.metrics.record_request(&path, method.as_str(), 429, start.elapsed().as_secs_f64());
        return Ok(rate_limited_response(retry_after_secs, limit, remaining));
    }

    // Check for protocol upgrade (backup/restore sessions)
    if let Some(upgrade) = req.headers().get("upgrade") {
        if upgrade.to_str().unwrap_or("") == PROTOCOL_HEADER {
            return Ok(handle_protocol_upgrade(state.clone(), &req).await);
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
                if let RateLimitResult::Limited { retry_after_secs, limit, remaining } =
                    state.rate_limiter.check_tenant(&ctx.user.tenant_id)
                {
                    state.metrics.record_request(&path, method.as_str(), 429, start.elapsed().as_secs_f64());
                    return Ok(rate_limited_response(retry_after_secs, limit, remaining));
                }

                Some(ctx)
            }
            Err(e) => {
                state.metrics.record_auth_attempt(false);
                state.metrics.record_request(&path, method.as_str(), 401, start.elapsed().as_secs_f64());
                return Ok(error_response(e));
            }
        }
    };

    // Record API request for billing
    if let Some(ctx) = &auth_ctx {
        state.billing.record_event(
            UsageEvent::new(&ctx.user.tenant_id, UsageEventType::ApiRequest, 0)
        ).await;
    }

    // Route to appropriate handler
    let response = match (method.clone(), path.as_str()) {
        // Public endpoints
        (Method::GET, "/api2/json/version") => handle_version().await,
        (Method::GET, "/api2/json/access/ticket") => handle_auth_info().await,

        // Metrics endpoint
        (Method::GET, "/metrics") => handle_metrics(state.clone()).await,

        // Auth endpoints
        (Method::POST, "/api2/json/access/ticket") => {
            handle_login(state.clone(), req).await
        }

        // API v2 routes (require auth)
        (Method::GET, "/api2/json/nodes") => {
            with_auth(auth_ctx, Permission::Read, |_| async { handle_nodes().await }).await
        }
        (Method::GET, p) if p.starts_with("/api2/json/admin/datastore") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                let path = p.to_string();
                async move { handle_datastore_api(state, &ctx, &path).await }
            }).await
        }
        (Method::GET, "/api2/json/status") => {
            with_auth(auth_ctx, Permission::Read, |_| {
                let state = state.clone();
                async move { handle_status(state).await }
            }).await
        }

        // Backup protocol endpoints
        (Method::POST, p) if p.starts_with("/api2/json/admin/datastore/") && p.contains("/backup") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_start_backup(state, &ctx, req).await }
            }).await
        }

        // Reader/Restore endpoints
        (Method::POST, p) if p.starts_with("/api2/json/admin/datastore/") && p.contains("/reader") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_start_reader(state, &ctx, req).await }
            }).await
        }

        // Session-based backup operations
        (Method::POST, "/api2/json/backup/fixed_chunk") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_upload_chunk(state, &ctx, req, "fixed").await }
            }).await
        }
        (Method::POST, "/api2/json/backup/dynamic_chunk") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_upload_chunk(state, &ctx, req, "dynamic").await }
            }).await
        }
        (Method::POST, "/api2/json/backup/fixed_index") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_create_index(state, &ctx, req, "fixed").await }
            }).await
        }
        (Method::PUT, "/api2/json/backup/fixed_index") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_append_index(state, &ctx, req, "fixed").await }
            }).await
        }
        (Method::POST, "/api2/json/backup/fixed_close") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_close_index(state, &ctx, req, "fixed").await }
            }).await
        }
        (Method::POST, "/api2/json/backup/dynamic_index") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_create_index(state, &ctx, req, "dynamic").await }
            }).await
        }
        (Method::PUT, "/api2/json/backup/dynamic_index") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_append_index(state, &ctx, req, "dynamic").await }
            }).await
        }
        (Method::POST, "/api2/json/backup/dynamic_close") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_close_index(state, &ctx, req, "dynamic").await }
            }).await
        }
        (Method::POST, "/api2/json/backup/blob") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_upload_blob(state, &ctx, req).await }
            }).await
        }
        (Method::POST, "/api2/json/backup/finish") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_finish_backup(state, &ctx, req).await }
            }).await
        }
        (Method::POST, "/api2/json/backup/known_chunks") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_known_chunks(state, &ctx, req).await }
            }).await
        }

        // Reader/Restore operations
        (Method::GET, "/api2/json/reader/download_chunk") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_download_chunk(state, &ctx, req).await }
            }).await
        }
        (Method::GET, "/api2/json/reader/fixed_index") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_read_index(state, &ctx, req, "fixed").await }
            }).await
        }
        (Method::GET, "/api2/json/reader/dynamic_index") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_read_index(state, &ctx, req, "dynamic").await }
            }).await
        }
        (Method::GET, "/api2/json/reader/blob") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_read_blob(state, &ctx, req).await }
            }).await
        }
        (Method::GET, "/api2/json/reader/manifest") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_read_manifest(state, &ctx, req).await }
            }).await
        }
        (Method::POST, "/api2/json/reader/close") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_close_reader(state, &ctx, req).await }
            }).await
        }

        // Tenant API
        (Method::GET, "/api2/json/tenants") => {
            with_auth(auth_ctx, Permission::Admin, |_| {
                let state = state.clone();
                async move { handle_list_tenants(state).await }
            }).await
        }
        (Method::POST, "/api2/json/tenants") => {
            with_auth(auth_ctx, Permission::Admin, |_| {
                let state = state.clone();
                async move { handle_create_tenant(state, req).await }
            }).await
        }

        // User/Token API
        (Method::GET, "/api2/json/access/users") => {
            with_auth(auth_ctx, Permission::Admin, |ctx| {
                let state = state.clone();
                async move { handle_list_users(state, &ctx).await }
            }).await
        }
        (Method::POST, "/api2/json/access/users") => {
            with_auth(auth_ctx, Permission::Admin, |_| {
                let state = state.clone();
                async move { handle_create_user(state, req).await }
            }).await
        }
        (Method::GET, "/api2/json/access/tokens") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_list_tokens(state, &ctx).await }
            }).await
        }
        (Method::POST, "/api2/json/access/tokens") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_create_token(state, &ctx, req).await }
            }).await
        }

        // Billing API
        (Method::GET, "/api2/json/billing/usage") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_get_usage(state, &ctx).await }
            }).await
        }

        // Rate limit info
        (Method::GET, "/api2/json/rate_limit") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_rate_limit_info(state, &ctx).await }
            }).await
        }

        // GC/Admin API
        (Method::POST, "/api2/json/admin/gc") => {
            with_auth(auth_ctx, Permission::Admin, |_| {
                let state = state.clone();
                async move { handle_run_gc(state, req).await }
            }).await
        }
        (Method::GET, "/api2/json/admin/gc/status") => {
            with_auth(auth_ctx, Permission::Admin, |_| {
                let state = state.clone();
                async move { handle_gc_status(state).await }
            }).await
        }
        (Method::POST, "/api2/json/admin/prune") => {
            with_auth(auth_ctx, Permission::DatastoreAdmin, |_| {
                let state = state.clone();
                async move { handle_prune(state, req).await }
            }).await
        }

        // Default: 404
        _ => not_found(),
    };

    // Record metrics
    let status = response.status().as_u16();
    state.metrics.record_request(&path, method.as_str(), status, start.elapsed().as_secs_f64());

    Ok(response)
}

/// Check if an endpoint is public (no auth required)
fn is_public_endpoint(path: &str) -> bool {
    matches!(
        path,
        "/api2/json/version" | "/api2/json/access/ticket" | "/metrics"
    )
}

/// Authenticate a request
async fn authenticate(
    state: Arc<ServerState>,
    req: &Request<Incoming>,
) -> Result<AuthContext, ApiError> {
    // Check Authorization header
    if let Some(auth_header) = req.headers().get("authorization") {
        let auth_str = auth_header
            .to_str()
            .map_err(|_| ApiError::unauthorized("Invalid authorization header"))?;
        return state.auth.authenticate_header(auth_str).await;
    }

    // Check for PBS cookie-based auth
    if let Some(cookie) = req.headers().get("cookie") {
        let cookie_str = cookie.to_str().unwrap_or("");
        if let Some(token) = extract_pbs_token(cookie_str) {
            return state.auth.authenticate_token(token).await;
        }
    }

    Err(ApiError::unauthorized("No authentication provided"))
}

/// Extract PBS API token from cookie
fn extract_pbs_token(cookie: &str) -> Option<&str> {
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("PBSAuthCookie=") {
            return Some(value);
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
    uri.query()
        .and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.to_string())
        })
}

// === Handler implementations ===

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

async fn handle_login(state: Arc<ServerState>, req: Request<Incoming>) -> Response<Full<Bytes>> {
    let body = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return bad_request("Failed to read request body"),
    };

    #[derive(serde::Deserialize)]
    struct LoginRequest {
        username: String,
        password: String,
    }

    let params: LoginRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return bad_request("Invalid JSON"),
    };

    // For now, we only support token-based auth
    // Password field would contain the API token
    match state.auth.authenticate_token(&params.password).await {
        Ok(ctx) => {
            let response = serde_json::json!({
                "data": {
                    "username": ctx.user.username,
                    "ticket": params.password,  // Echo back the token
                    "CSRFPreventionToken": "not-used"
                }
            });
            json_response(StatusCode::OK, &response)
        }
        Err(e) => error_response(e),
    }
}

async fn handle_nodes() -> Response<Full<Bytes>> {
    let nodes = serde_json::json!({
        "data": [{
            "node": "pbs-cloud",
            "status": "online",
            "cpu": 0.0,
            "maxcpu": 1,
            "mem": 0,
            "maxmem": 0
        }]
    });
    json_response(StatusCode::OK, &nodes)
}

async fn handle_datastore_api(
    state: Arc<ServerState>,
    _ctx: &AuthContext,
    path: &str,
) -> Response<Full<Bytes>> {
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
    let datastore = match state.get_datastore(ds_name) {
        Some(ds) => ds,
        None => return not_found(),
    };

    // Route based on sub-path
    if parts.len() == 1 {
        // Datastore info
        let stats = state.backend.stats().await.unwrap_or_default();
        let info = serde_json::json!({
            "data": {
                "store": ds_name,
                "total": stats.chunk_bytes + stats.file_bytes,
                "used": stats.chunk_bytes + stats.file_bytes,
                "avail": 0
            }
        });
        return json_response(StatusCode::OK, &info);
    }

    match parts[1] {
        "groups" => {
            let groups = datastore.list_backup_groups().await.unwrap_or_default();
            let group_info: Vec<_> = groups
                .iter()
                .map(|g| {
                    serde_json::json!({
                        "backup-type": g.backup_type,
                        "backup-id": g.backup_id
                    })
                })
                .collect();
            json_response(StatusCode::OK, &serde_json::json!({"data": group_info}))
        }
        "snapshots" => {
            json_response(StatusCode::OK, &serde_json::json!({"data": []}))
        }
        _ => not_found(),
    }
}

async fn handle_status(state: Arc<ServerState>) -> Response<Full<Bytes>> {
    let (backup_sessions, reader_sessions) = state.sessions.session_count().await;
    let status = serde_json::json!({
        "data": {
            "uptime": 0,
            "tasks": {
                "running": backup_sessions + reader_sessions,
                "scheduled": 0
            },
            "sessions": {
                "backup": backup_sessions,
                "reader": reader_sessions
            }
        }
    });
    json_response(StatusCode::OK, &status)
}

async fn handle_protocol_upgrade(
    _state: Arc<ServerState>,
    _req: &Request<Incoming>,
) -> Response<Full<Bytes>> {
    // Protocol upgrade for streaming - this is handled via HTTP/2 streams
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("upgrade", PROTOCOL_HEADER)
        .body(Full::new(Bytes::new()))
        .expect("valid response")
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
    if let Err(e) = validate_backup_params(&params.backup_type, &params.backup_id, &params.backup_time) {
        return error_response(e);
    }

    let handler = BackupProtocolHandler::new(state);
    match handler.start_backup(ctx, params).await {
        Ok(session_id) => {
            json_response(StatusCode::OK, &serde_json::json!({"data": {"session_id": session_id}}))
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
    }

    let params: ReaderParams = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return bad_request("Invalid reader parameters"),
    };

    // Validate backup parameters
    if let Err(e) = validate_backup_params(&params.backup_type, &params.backup_id, &params.backup_time) {
        return error_response(e);
    }

    let handler = ReaderProtocolHandler::new(state.clone());
    match handler.start_reader(ctx, &params.backup_type, &params.backup_id, &params.backup_time).await {
        Ok(session_id) => {
            json_response(StatusCode::OK, &serde_json::json!({"data": {"session_id": session_id}}))
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
    if let RateLimitResult::Limited { retry_after_secs, limit, remaining } =
        state.rate_limiter.check_upload(&ctx.user.tenant_id, body.len() as u64)
    {
        return rate_limited_response(retry_after_secs, limit, remaining);
    }

    let handler = BackupProtocolHandler::new(state.clone());
    let result = if chunk_type == "fixed" {
        handler.upload_fixed_chunk(&session_id, &ctx.user.tenant_id, digest, body).await
    } else {
        handler.upload_dynamic_chunk(&session_id, &ctx.user.tenant_id, digest, body).await
    };

    match result {
        Ok(stored) => json_response(StatusCode::OK, &serde_json::json!({"data": {"stored": stored}})),
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
        handler.create_fixed_index(&session_id, &ctx.user.tenant_id, &name, chunk_size).await
    } else {
        handler.create_dynamic_index(&session_id, &ctx.user.tenant_id, &name).await
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
        handler.append_fixed_index(&session_id, &ctx.user.tenant_id, &name, digest, size).await
    } else {
        let offset: u64 = get_query_param(req.uri(), "offset")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        handler.append_dynamic_index(&session_id, &ctx.user.tenant_id, &name, digest, offset, size).await
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
        handler.close_fixed_index(&session_id, &ctx.user.tenant_id, &name).await
    } else {
        handler.close_dynamic_index(&session_id, &ctx.user.tenant_id, &name).await
    };

    match result {
        Ok((size, digest)) => json_response(StatusCode::OK, &serde_json::json!({
            "data": {
                "size": size,
                "digest": digest.to_hex()
            }
        })),
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
    match handler.upload_blob(&session_id, &ctx.user.tenant_id, &name, body).await {
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
    match handler.finish_backup(&session_id, &ctx.user.tenant_id).await {
        Ok(result) => {
            state.metrics.record_backup(&ctx.user.tenant_id, "backup", result.total_bytes);
            let response: FinishBackupResponse = result.into();
            json_response(StatusCode::OK, &serde_json::json!({"data": response}))
        }
        Err(e) => error_response(e),
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
    if let Err(e) = state.sessions.verify_session_ownership(&session_id, &ctx.user.tenant_id).await {
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

    let digests: Result<Vec<_>, _> = params.digests.iter()
        .map(|s| ChunkDigest::from_hex(s))
        .collect();

    let digests = match digests {
        Ok(d) => d,
        Err(_) => return bad_request("Invalid digest format"),
    };

    let handler = BackupProtocolHandler::new(state.clone());
    match handler.check_known_chunks(&session_id, &digests).await {
        Ok(known) => json_response(StatusCode::OK, &serde_json::json!({"data": {"known": known}})),
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
    match handler.download_chunk(&session_id, &digest, &ctx.user.tenant_id).await {
        Ok(data) => {
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/octet-stream")
                .body(Full::new(Bytes::from(data)))
                .expect("valid response")
        }
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
        handler.read_fixed_index(&session_id, &ctx.user.tenant_id, &name).await
    } else {
        handler.read_dynamic_index(&session_id, &ctx.user.tenant_id, &name).await
    };

    match result {
        Ok(data) => {
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/octet-stream")
                .body(Full::new(Bytes::from(data)))
                .expect("valid response")
        }
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
    match handler.read_blob(&session_id, &ctx.user.tenant_id, &name).await {
        Ok(data) => {
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/octet-stream")
                .body(Full::new(Bytes::from(data)))
                .expect("valid response")
        }
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
    match handler.read_manifest(&session_id, &ctx.user.tenant_id).await {
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
    if let Err(e) = state.sessions.verify_reader_session_ownership(&session_id, &ctx.user.tenant_id).await {
        return error_response(e);
    }

    let handler = ReaderProtocolHandler::new(state.clone());
    match handler.close_reader(&session_id).await {
        Ok(_) => json_response(StatusCode::OK, &serde_json::json!({"data": {}})),
        Err(e) => error_response(e),
    }
}

async fn handle_list_tenants(state: Arc<ServerState>) -> Response<Full<Bytes>> {
    let tenants = state.tenants.list_tenants().await;
    json_response(StatusCode::OK, &serde_json::json!({"data": tenants}))
}

async fn handle_create_tenant(
    state: Arc<ServerState>,
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

    // Save state
    if let Err(e) = state.save_state().await {
        warn!("Failed to save state after tenant creation: {}", e);
    }

    json_response(StatusCode::CREATED, &serde_json::json!({"data": tenant}))
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

async fn handle_create_user(
    state: Arc<ServerState>,
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

    match state.auth.create_user(&params.username, &params.tenant_id, permission).await {
        Ok(user) => {
            // Save state
            if let Err(e) = state.save_state().await {
                warn!("Failed to save state after user creation: {}", e);
            }
            json_response(StatusCode::CREATED, &serde_json::json!({"data": user}))
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

    match state.auth.create_token(&ctx.user.id, &params.name, permission, None).await {
        Ok((token, token_string)) => {
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

async fn handle_get_usage(state: Arc<ServerState>, ctx: &AuthContext) -> Response<Full<Bytes>> {
    let usage = state.billing.get_usage(&ctx.user.tenant_id).await;
    json_response(StatusCode::OK, &serde_json::json!({"data": usage}))
}

async fn handle_rate_limit_info(state: Arc<ServerState>, ctx: &AuthContext) -> Response<Full<Bytes>> {
    let stats = state.rate_limiter.get_tenant_stats(&ctx.user.tenant_id);
    json_response(StatusCode::OK, &serde_json::json!({
        "data": {
            "upload_bytes_used": stats.upload_bytes_used,
            "upload_bytes_limit": stats.upload_bytes_limit,
            "requests_per_minute_limit": stats.requests_per_minute_limit
        }
    }))
}

// === GC/Admin handlers ===

async fn handle_run_gc(
    state: Arc<ServerState>,
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
    }

    let params: GcRequest = if body.is_empty() {
        GcRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(p) => p,
            Err(_) => return bad_request("Invalid JSON"),
        }
    };

    let datastore = state.default_datastore();
    let backend = datastore.backend();
    let gc = GarbageCollector::new(datastore, backend);

    let options = GcOptions {
        dry_run: params.dry_run,
        max_delete: params.max_delete,
    };

    info!("Starting GC run (dry_run={})", params.dry_run);

    match gc.run(options).await {
        Ok(result) => {
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

async fn handle_gc_status(state: Arc<ServerState>) -> Response<Full<Bytes>> {
    // For now, just return datastore stats - could be extended to track ongoing GC
    let datastore = state.default_datastore();
    let backend = datastore.backend();

    match backend.list_chunks().await {
        Ok(chunks) => {
            json_response(StatusCode::OK, &serde_json::json!({
                "data": {
                    "total_chunks": chunks.len(),
                    "gc_running": false
                }
            }))
        }
        Err(e) => error_response(ApiError::internal(&e.to_string())),
    }
}

async fn handle_prune(
    state: Arc<ServerState>,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let body = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return bad_request("Failed to read request body"),
    };

    #[derive(serde::Deserialize)]
    struct PruneRequest {
        backup_type: String,
        backup_id: String,
        #[serde(default)]
        dry_run: bool,
        keep_last: Option<usize>,
        keep_daily: Option<usize>,
        keep_weekly: Option<usize>,
        keep_monthly: Option<usize>,
        keep_yearly: Option<usize>,
    }

    let params: PruneRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return bad_request("Invalid JSON"),
    };

    // Validate backup parameters
    if let Err(e) = validate_backup_params(&params.backup_type, &params.backup_id, "2000-01-01T00:00:00Z") {
        return error_response(e);
    }

    let datastore = state.default_datastore();
    let pruner = Pruner::new(datastore);

    let options = PruneOptions {
        keep_last: params.keep_last.or(Some(1)),
        keep_hourly: None,
        keep_daily: params.keep_daily.or(Some(7)),
        keep_weekly: params.keep_weekly.or(Some(4)),
        keep_monthly: params.keep_monthly.or(Some(6)),
        keep_yearly: params.keep_yearly,
        dry_run: params.dry_run,
    };

    info!(
        "Pruning {}/{} (dry_run={})",
        params.backup_type, params.backup_id, params.dry_run
    );

    match pruner.prune(&params.backup_type, &params.backup_id, options).await {
        Ok(result) => {
            json_response(StatusCode::OK, &serde_json::json!({
                "data": {
                    "kept": result.kept,
                    "pruned": result.pruned,
                    "errors": result.errors
                }
            }))
        }
        Err(e) => error_response(ApiError::internal(&e.to_string())),
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
