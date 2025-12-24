//! HTTP/2 server implementation
//!
//! Handles both REST API and backup protocol upgrade.

use std::net::SocketAddr;
use std::sync::Arc;

use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{body::Incoming, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use http_body_util::{BodyExt, Full};
use bytes::Bytes;
use tokio::net::TcpListener;
use tracing::{info, error, instrument};

use crate::config::ServerConfig;
use crate::protocol::PROTOCOL_HEADER;
use crate::tenant::TenantManager;

/// Server state
pub struct ServerState {
    /// Configuration
    pub config: ServerConfig,
    /// Tenant manager
    pub tenants: Arc<TenantManager>,
}

impl ServerState {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            tenants: Arc::new(TenantManager::new()),
        }
    }
}

/// Start the HTTP/2 server
#[instrument(skip(state))]
pub async fn run_server(state: Arc<ServerState>) -> anyhow::Result<()> {
    let addr: SocketAddr = state.config.listen_addr.parse()?;
    let listener = TcpListener::bind(addr).await?;

    info!("PBS Cloud Server listening on {}", addr);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let state = state.clone();

        tokio::spawn(async move {
            let io = TokioIo::new(stream);

            if let Err(err) = http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(io, service_fn(move |req| {
                    let state = state.clone();
                    handle_request(state, peer_addr, req)
                }))
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
            return Ok(handle_protocol_upgrade(&path).await);
        }
    }

    // Route to appropriate handler
    let response = match (method, path.as_str()) {
        // API v2 routes
        (Method::GET, "/api2/json/version") => handle_version().await,
        (Method::GET, "/api2/json/nodes") => handle_nodes().await,
        (Method::GET, p) if p.starts_with("/api2/json/admin/datastore") => {
            handle_datastore_api(&p).await
        }
        (Method::GET, p) if p.starts_with("/api2/json/status") => {
            handle_status().await
        }

        // Tenant API (our extension)
        (Method::GET, "/api2/json/tenants") => handle_list_tenants(&state).await,
        (Method::POST, "/api2/json/tenants") => handle_create_tenant(&state, req).await,

        // Default: 404
        _ => not_found(),
    };

    Ok(response)
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

async fn handle_datastore_api(path: &str) -> Response<Full<Bytes>> {
    // Parse datastore name and route
    let parts: Vec<&str> = path.trim_start_matches("/api2/json/admin/datastore/").split('/').collect();

    if parts.is_empty() || parts[0].is_empty() {
        // List datastores
        let datastores = serde_json::json!({
            "data": []
        });
        return json_response(StatusCode::OK, &datastores);
    }

    // Specific datastore operations
    let _datastore = parts[0];
    // TODO: Route to specific handlers based on remaining path

    let data = serde_json::json!({"data": {}});
    json_response(StatusCode::OK, &data)
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

async fn handle_protocol_upgrade(path: &str) -> Response<Full<Bytes>> {
    // TODO: Implement actual protocol upgrade
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("upgrade", PROTOCOL_HEADER)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

async fn handle_list_tenants(state: &ServerState) -> Response<Full<Bytes>> {
    let tenants = state.tenants.list_tenants().await;
    let data = serde_json::json!({ "data": tenants });
    json_response(StatusCode::OK, &data)
}

async fn handle_create_tenant(
    state: &ServerState,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    // Parse request body
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
    let data = serde_json::json!({ "data": tenant });
    json_response(StatusCode::CREATED, &data)
}

fn json_response<T: serde::Serialize>(status: StatusCode, data: &T) -> Response<Full<Bytes>> {
    let json = serde_json::to_string(data).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(json)))
        .unwrap()
}

fn not_found() -> Response<Full<Bytes>> {
    let error = serde_json::json!({
        "error": "Not found"
    });
    json_response(StatusCode::NOT_FOUND, &error)
}

fn bad_request(message: &str) -> Response<Full<Bytes>> {
    let error = serde_json::json!({
        "error": message
    });
    json_response(StatusCode::BAD_REQUEST, &error)
}
