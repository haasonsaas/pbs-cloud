//! HTTP/2 server implementation
//!
//! Handles both REST API and PBS backup protocol.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{body::Incoming, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use pbs_core::{ChunkDigest, CryptoConfig, Chunk};
use pbs_storage::{Datastore, LocalBackend, S3Backend, StorageBackend};
use tokio::net::TcpListener;
use tracing::{error, info, instrument, warn};

use crate::auth::{AuthContext, AuthManager, Permission};
use crate::billing::{BillingManager, UsageEvent, UsageEventType};
use crate::config::{ServerConfig, StorageConfig};
use crate::protocol::{ApiError, BackupParams, PROTOCOL_HEADER};
use crate::session::SessionManager;
use crate::tenant::TenantManager;

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

        Ok(Self {
            config,
            backend,
            datastores,
            sessions: Arc::new(SessionManager::default()),
            auth: Arc::new(AuthManager::default()),
            tenants: Arc::new(TenantManager::default()),
            billing: Arc::new(billing),
        })
    }

    /// Get a datastore by name
    pub fn get_datastore(&self, name: &str) -> Option<Arc<Datastore>> {
        self.datastores.get(name).cloned()
    }

    /// Get the default datastore
    pub fn default_datastore(&self) -> Arc<Datastore> {
        self.datastores.get("default").cloned().unwrap()
    }
}

/// Start the HTTP/2 server
#[instrument(skip(state))]
pub async fn run_server(state: Arc<ServerState>) -> anyhow::Result<()> {
    let addr: SocketAddr = state.config.listen_addr.parse()?;
    let listener = TcpListener::bind(addr).await?;

    info!("PBS Cloud Server listening on {}", addr);

    // Create root user if no users exist
    if state.auth.list_users(None).await.is_empty() {
        let default_tenant = &state.config.tenants.default_tenant;

        // Create default tenant
        state.tenants.create_tenant(default_tenant).await;

        // Create root user
        match state.auth.create_root_user(default_tenant).await {
            Ok((user, token)) => {
                info!("Created root user: {}", user.username);
                info!("Root API token: {}", token);
                info!("Save this token - it won't be shown again!");
            }
            Err(e) => {
                warn!("Failed to create root user: {}", e);
            }
        }
    }

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let state = state.clone();

        tokio::spawn(async move {
            let io = TokioIo::new(stream);

            if let Err(err) = http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        let state = state.clone();
                        handle_request(state, peer_addr, req)
                    }),
                )
                .await
            {
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
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    info!("{} {} from {}", method, path, peer_addr);

    // Check for protocol upgrade (backup/restore sessions)
    if let Some(upgrade) = req.headers().get("upgrade") {
        if upgrade.to_str().unwrap_or("") == PROTOCOL_HEADER {
            return Ok(handle_protocol_upgrade(&state, &req).await);
        }
    }

    // Authenticate request (except for public endpoints)
    let auth_ctx = if is_public_endpoint(&path) {
        None
    } else {
        match authenticate(&state, &req).await {
            Ok(ctx) => Some(ctx),
            Err(e) => return Ok(error_response(e)),
        }
    };

    // Record API request for billing
    if let Some(ctx) = &auth_ctx {
        state.billing.record_event(
            UsageEvent::new(&ctx.user.tenant_id, UsageEventType::ApiRequest, 0)
        ).await;
    }

    // Route to appropriate handler
    let response = match (method, path.as_str()) {
        // Public endpoints
        (Method::GET, "/api2/json/version") => handle_version().await,
        (Method::GET, "/api2/json/access/ticket") => handle_auth_info().await,

        // Auth endpoints
        (Method::POST, "/api2/json/access/ticket") => {
            handle_login(&state, req).await
        }

        // API v2 routes (require auth)
        (Method::GET, "/api2/json/nodes") => {
            with_auth(auth_ctx, Permission::Read, |_| async { handle_nodes().await }).await
        }
        (Method::GET, p) if p.starts_with("/api2/json/admin/datastore") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                let path = p.to_string();
                async move { handle_datastore_api(&state, &ctx, &path).await }
            }).await
        }
        (Method::GET, "/api2/json/status") => {
            with_auth(auth_ctx, Permission::Read, |_| async { handle_status().await }).await
        }

        // Backup protocol endpoints
        (Method::POST, p) if p.starts_with("/api2/json/admin/datastore/") && p.contains("/backup") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_start_backup(&state, &ctx, req).await }
            }).await
        }

        // Tenant API
        (Method::GET, "/api2/json/tenants") => {
            with_auth(auth_ctx, Permission::Admin, |_| {
                let state = state.clone();
                async move { handle_list_tenants(&state).await }
            }).await
        }
        (Method::POST, "/api2/json/tenants") => {
            with_auth(auth_ctx, Permission::Admin, |_| {
                let state = state.clone();
                async move { handle_create_tenant(&state, req).await }
            }).await
        }

        // User/Token API
        (Method::GET, "/api2/json/access/users") => {
            with_auth(auth_ctx, Permission::Admin, |ctx| {
                let state = state.clone();
                async move { handle_list_users(&state, &ctx).await }
            }).await
        }
        (Method::POST, "/api2/json/access/users") => {
            with_auth(auth_ctx, Permission::Admin, |_| {
                let state = state.clone();
                async move { handle_create_user(&state, req).await }
            }).await
        }
        (Method::GET, "/api2/json/access/tokens") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_list_tokens(&state, &ctx).await }
            }).await
        }
        (Method::POST, "/api2/json/access/tokens") => {
            with_auth(auth_ctx, Permission::Backup, |ctx| {
                let state = state.clone();
                async move { handle_create_token(&state, &ctx, req).await }
            }).await
        }

        // Billing API
        (Method::GET, "/api2/json/billing/usage") => {
            with_auth(auth_ctx, Permission::Read, |ctx| {
                let state = state.clone();
                async move { handle_get_usage(&state, &ctx).await }
            }).await
        }

        // Default: 404
        _ => not_found(),
    };

    Ok(response)
}

/// Check if an endpoint is public (no auth required)
fn is_public_endpoint(path: &str) -> bool {
    matches!(
        path,
        "/api2/json/version" | "/api2/json/access/ticket"
    )
}

/// Authenticate a request
async fn authenticate(
    state: &ServerState,
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

async fn handle_login(state: &ServerState, req: Request<Incoming>) -> Response<Full<Bytes>> {
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
    state: &ServerState,
    ctx: &AuthContext,
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
            // TODO: Parse query params for backup-type and backup-id
            json_response(StatusCode::OK, &serde_json::json!({"data": []}))
        }
        _ => not_found(),
    }
}

async fn handle_status() -> Response<Full<Bytes>> {
    let status = serde_json::json!({
        "data": {
            "uptime": 0,
            "tasks": {
                "running": 0,
                "scheduled": 0
            }
        }
    });
    json_response(StatusCode::OK, &status)
}

async fn handle_protocol_upgrade(
    state: &ServerState,
    req: &Request<Incoming>,
) -> Response<Full<Bytes>> {
    // This would initiate the HTTP/2 upgrade for backup/restore
    // Full implementation would handle the streaming protocol
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("upgrade", PROTOCOL_HEADER)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

async fn handle_start_backup(
    state: &ServerState,
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

    let datastore = state.default_datastore();
    let session_id = state.sessions.create_backup_session(
        &ctx.user.tenant_id,
        params,
        datastore,
    ).await;

    let response = serde_json::json!({
        "data": {
            "session_id": session_id
        }
    });
    json_response(StatusCode::OK, &response)
}

async fn handle_list_tenants(state: &ServerState) -> Response<Full<Bytes>> {
    let tenants = state.tenants.list_tenants().await;
    json_response(StatusCode::OK, &serde_json::json!({"data": tenants}))
}

async fn handle_create_tenant(
    state: &ServerState,
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

    let tenant = state.tenants.create_tenant(&params.name).await;
    json_response(StatusCode::CREATED, &serde_json::json!({"data": tenant}))
}

async fn handle_list_users(state: &ServerState, ctx: &AuthContext) -> Response<Full<Bytes>> {
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
    state: &ServerState,
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

    let permission = match params.permission.as_str() {
        "admin" => Permission::Admin,
        "datastore_admin" => Permission::DatastoreAdmin,
        "backup" => Permission::Backup,
        "read" => Permission::Read,
        _ => return bad_request("Invalid permission level"),
    };

    match state.auth.create_user(&params.username, &params.tenant_id, permission).await {
        Ok(user) => json_response(StatusCode::CREATED, &serde_json::json!({"data": user})),
        Err(e) => error_response(e),
    }
}

async fn handle_list_tokens(state: &ServerState, ctx: &AuthContext) -> Response<Full<Bytes>> {
    let tokens = state.auth.list_tokens(&ctx.user.id).await;
    json_response(StatusCode::OK, &serde_json::json!({"data": tokens}))
}

async fn handle_create_token(
    state: &ServerState,
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

async fn handle_get_usage(state: &ServerState, ctx: &AuthContext) -> Response<Full<Bytes>> {
    let usage = state.billing.get_usage(&ctx.user.tenant_id).await;
    json_response(StatusCode::OK, &serde_json::json!({"data": usage}))
}

// === Response helpers ===

fn json_response<T: serde::Serialize>(status: StatusCode, data: &T) -> Response<Full<Bytes>> {
    let json = serde_json::to_string(data).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(json)))
        .unwrap()
}

fn error_response(error: ApiError) -> Response<Full<Bytes>> {
    let status = match error.status {
        400 => StatusCode::BAD_REQUEST,
        401 => StatusCode::UNAUTHORIZED,
        403 => StatusCode::FORBIDDEN,
        404 => StatusCode::NOT_FOUND,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let body = serde_json::json!({"error": error.message});
    json_response(status, &body)
}

fn not_found() -> Response<Full<Bytes>> {
    error_response(ApiError::not_found("Not found"))
}

fn bad_request(message: &str) -> Response<Full<Bytes>> {
    error_response(ApiError::bad_request(message))
}
