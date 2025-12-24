# AGENTS.md

## Project overview
- PBS Cloud is a PBS-compatible backup server (Proxmox Backup Server protocol) with local/S3 backends, multi-tenancy, billing hooks, WORM retention, and compliance reporting.
- Primary compatibility target: `proxmox-backup-client` over the HTTP/2 upgrade protocol.

## Repo layout
- `crates/pbs-core`: PBS formats (chunks, blobs, indexes, manifests, crypto).
- `crates/pbs-storage`: datastore + backends (local, S3), GC + prune.
- `crates/pbs-server`: HTTP server, auth, sessions, streaming protocol, billing, metrics.

## Build & test
- Build: `cargo build --release`
- Test: `cargo test`

## Run
- Local storage:
  - `export PBS_DATA_DIR=/var/lib/pbs-cloud`
  - `cargo run -p pbs-server --bin pbs-cloud-server`
- S3 storage:
  - `export PBS_S3_BUCKET=...`
  - `export PBS_S3_REGION=us-east-1`
  - Optional: `export PBS_S3_ENDPOINT=https://...`
  - Optional: `export PBS_S3_PREFIX=...`

## Configuration (env vars)
- Server: `PBS_LISTEN_ADDR`, `PBS_PERSISTENCE_DIR`
- Storage: `PBS_DATA_DIR`, `PBS_S3_BUCKET`, `PBS_S3_REGION`, `PBS_S3_ENDPOINT`, `PBS_S3_PREFIX`
- Tenancy: `PBS_DEFAULT_TENANT`
- TLS: `PBS_TLS_DISABLED`, `PBS_TLS_CERT`, `PBS_TLS_KEY`
- GC: `PBS_GC_DISABLED`, `PBS_GC_INTERVAL_HOURS`
- WORM: `PBS_WORM_ENABLED`, `PBS_WORM_RETENTION_DAYS`, `PBS_WORM_ALLOW_OVERRIDE`
- Webhook verification: `PBS_WEBHOOK_RECEIVER_SECRET`
- Server-managed encryption: `PBS_ENCRYPTION_KEY` (hex, 32 bytes), `PBS_ENCRYPTION_KEY_FILE`

## Protocol compatibility
- Upgrade headers: `proxmox-backup-protocol-v1` and `proxmox-backup-reader-protocol-v1`.
- Upgrade endpoints (HTTP/1.1): `GET /api2/json/backup` and `GET /api2/json/reader`.
- H2 paths used by PBS clients:
  - Backup: `/blob`, `/fixed_index`, `/dynamic_index`, `/fixed_chunk`, `/dynamic_chunk`, `/fixed_close`, `/dynamic_close`, `/finish`, `/previous_backup_time`, `/previous`.
  - Reader: `/download`, `/chunk`, `/speedtest`.
- `backup-time` on upgrade is a Unix epoch; stored internally as RFC3339.

## Storage layout
- Manifests: `index.json.blob` (DataBlob-encoded JSON).
- Indexes: raw `.fidx`/`.didx` bytes (no DataBlob wrapper).
- Chunks: DataBlob bytes (client-encoded for H2 uploads).

## Shortcuts / compatibility gaps
- Namespaces (`ns`) are ignored; only the default datastore (`store=default`) is supported.
- H2 `fixed_close`/`dynamic_close` ignore `chunk-count` and `csum` (no server-side verification).
- H2 chunk uploads trust client digests/encoded sizes (no recompute/validation on upload).
- Indexes are persisted at session finish (not at `*_close`), so partial sessions do not leave index files.
- Server-managed encryption is global (env-only, no rotation); H2 encrypted chunks are stored as-is.
- No migration path for legacy manifests stored as `index.json` (non-blob).

## Operational endpoints
- Health: `/health`, `/healthz`, `/ready`, `/readyz`.
- Metrics: `/metrics` (public).
- Compliance report: `GET /api2/json/compliance/report` (Admin).
- Webhook verification: `POST /api2/json/billing/webhook` with `X-Signature-256`.

## Where to look
- Routing: `crates/pbs-server/src/server.rs`
- Streaming protocol: `crates/pbs-server/src/streaming.rs`
- Session state: `crates/pbs-server/src/session.rs`
- Datastore/backends: `crates/pbs-storage/src/datastore.rs`, `crates/pbs-storage/src/local.rs`, `crates/pbs-storage/src/s3.rs`
