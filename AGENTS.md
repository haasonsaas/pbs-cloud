# AGENTS.md

## Project overview
- PBS Cloud is a PBS-compatible backup server (Proxmox Backup Server protocol) with local/S3 backends, multi-tenancy, billing hooks, WORM retention, and compliance reporting.
- Primary compatibility target: `proxmox-backup-client` over the HTTP/2 upgrade protocol.

## Repo layout
- `crates/pbs-core`: PBS formats (chunks, blobs, indexes, manifests, crypto).
- `crates/pbs-storage`: datastore + backends (local, S3), GC + prune.
- `crates/pbs-server`: HTTP server, auth, sessions, streaming protocol, billing, metrics.
- `charts/pbs-cloud`: Helm chart for Kubernetes deployment.

## Build & test
- Build: `cargo build --release`
- Test: `cargo test`
- Format (CI): `cargo fmt --all -- --check`
- Lint (CI): `cargo clippy --all-targets --all-features -- -D warnings`
- Helm chart lint (CI): `helm lint ./charts/pbs-cloud`

## Run
- Local storage:
  - `export PBS_DATA_DIR=/var/lib/pbs-cloud`
  - `cargo run -p pbs-server --bin pbs-cloud-server`
- S3 storage:
  - `export PBS_S3_BUCKET=...`
  - `export PBS_S3_REGION=us-east-1`
  - Optional: `export PBS_S3_ENDPOINT=https://...`
  - Optional: `export PBS_S3_PREFIX=...`
- Multiple datastores:
  - `export PBS_DATASTORES=fast,archive`
  - Default store uses `PBS_DATA_DIR` or `PBS_S3_PREFIX`; additional stores are created under per-store paths/prefixes.

## Configuration (env vars)
- Server: `PBS_LISTEN_ADDR`, `PBS_PERSISTENCE_DIR`
- Storage: `PBS_DATA_DIR`, `PBS_S3_BUCKET`, `PBS_S3_REGION`, `PBS_S3_ENDPOINT`, `PBS_S3_PREFIX`, `PBS_DATASTORES`
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
- Query params supported on upgrade: `backup-type`, `backup-id`, `backup-time`, `ns` (namespace), `store` (datastore).
- `backup-time` on upgrade is a Unix epoch; stored internally as RFC3339.

## Storage layout
- Manifests: `index.json.blob` (DataBlob-encoded JSON), with legacy fallback to `index.json`.
- Indexes: raw `.fidx`/`.didx` bytes (no DataBlob wrapper).
- Chunks: DataBlob bytes (client-encoded for H2 uploads).
- Namespace prefixes: `ns/<segment>/` repeated per namespace level.

## Shortcuts / compatibility gaps
- Server-managed encryption is global (env-only) with no key rotation or per-datastore keys.
- If clients upload encrypted DataBlob payloads and the server has no key, size/digest verification is skipped.
- Admin/REST surface is a focused subset of PBS APIs (no task scheduler or UI-specific endpoints).

## Operational endpoints
- Health: `/health`, `/healthz`, `/ready`, `/readyz`.
- Metrics: `/metrics` (public).
- Compliance report: `GET /api2/json/compliance/report` (Admin, optional `store`).
- Webhook verification: `POST /api2/json/billing/webhook` with `X-Signature-256`.

## Where to look
- Routing: `crates/pbs-server/src/server.rs`
- Streaming protocol: `crates/pbs-server/src/streaming.rs`
- Session state: `crates/pbs-server/src/session.rs`
- Datastore/backends: `crates/pbs-storage/src/datastore.rs`, `crates/pbs-storage/src/local.rs`, `crates/pbs-storage/src/s3.rs`
