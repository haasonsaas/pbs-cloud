# AGENTS.md

## Project overview
- PBS Cloud is a PBS-compatible backup server (Proxmox Backup Server protocol) with local/S3 backends, multi-tenancy, billing hooks, WORM retention, and compliance reporting.
- Primary compatibility target: `proxmox-backup-client` over the HTTP/2 upgrade protocol.

## Agent do / don't
### Do
- Keep changes small and focused; prefer minimal diffs over repo-wide rewrites.
- Validate compatibility against upstream `proxmox/proxmox-backup` using `gh api` when touching protocol or admin endpoints.
- Align response payloads with upstream `pbs-api-types` (field names and optional fields matter).
- Update AGENTS.md when you change APIs, compatibility, or operational behavior.
- Run `cargo test` and `helm lint ./charts/pbs-cloud` before pushing.
- Add nested `AGENTS.md` or `AGENTS.override.md` only when a subdirectory needs stricter or different rules.

### Don't
- Do not change manifest format or storage layout without a migration plan.
- Do not add heavy dependencies or new services without explicit approval.
- Do not change auth semantics or API paths unless it is required for compatibility.

## Compatibility checklist
- Cross-check HTTP paths used by `proxmox-backup-client` (main.rs, snapshot.rs, namespace.rs).
- Keep query params consistent: `backup-type`, `backup-id`, `backup-time`, `ns`, `store`.
- Preserve DataBlob validation semantics for uploaded blobs and logs.
- Prefer epoch timestamps in API responses (PBS expects Unix epoch for `backup-time`).

## Repo layout
- `crates/pbs-core`: PBS formats (chunks, blobs, indexes, manifests, crypto).
- `crates/pbs-storage`: datastore + backends (local, S3), GC + prune.
- `crates/pbs-server`: HTTP server, auth, sessions, streaming protocol, billing, metrics.
- `charts/pbs-cloud`: Helm chart for Kubernetes deployment.

## Build & test
- Build: `cargo build --release`
- Test: `./scripts/test.sh` (sets TMPDIR/CARGO_HOME to `target/` for low-space environments)
- CI/local full check: `./scripts/ci.sh` (also uses repo-scoped TMPDIR/CARGO_HOME)
- Format (CI): `cargo fmt --all -- --check`
- Lint (CI): `cargo clippy --all-targets --all-features -- -D warnings`
- Helm chart lint (CI): `helm lint ./charts/pbs-cloud`

## Pre-commit (optional)
- Install hooks: `pre-commit install`
- Run manual hooks: `pre-commit run --all-files --hook-stage manual`

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
- Verify: `PBS_VERIFY_DISABLED`, `PBS_VERIFY_INTERVAL_HOURS`
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

## Admin/REST compatibility (proxmox-backup-client)
- `/api2/json/admin/datastore` (GET) list datastores.
- `/api2/json/admin/datastore/<store>` (GET) datastore stats.
- `/api2/json/admin/datastore/<store>/status` (GET) datastore stats.
- `/api2/json/admin/datastore/<store>/groups` (GET) group listing.
- `/api2/json/admin/datastore/<store>/snapshots` (GET, DELETE) snapshot listing and deletion.
- `/api2/json/admin/datastore/<store>/files` (GET) snapshot file list.
- `/api2/json/admin/datastore/<store>/upload-backup-log` (POST) upload `client.log.blob`.
- `/api2/json/admin/datastore/<store>/notes` (GET, PUT) snapshot notes.
- `/api2/json/admin/datastore/<store>/protected` (GET, PUT) snapshot protection.
- `/api2/json/admin/datastore/<store>/namespace` (GET, POST, DELETE) namespace operations.
- `/api2/json/admin/datastore/<store>/change-owner` (POST) group ownership.
- `/api2/json/admin/datastore/<store>/gc` (POST) GC.
- `/api2/json/admin/datastore/<store>/prune` (POST) prune.
- `/api2/json/admin/verify` (GET) verification job list (synthetic per datastore).
- `/api2/json/admin/verify/<store>/run` (POST) run verification task.

## Storage layout
- Manifests: `index.json.blob` (DataBlob-encoded JSON), with legacy fallback to `index.json`.
- Indexes: raw `.fidx`/`.didx` bytes (no DataBlob wrapper).
- Chunks: DataBlob bytes (client-encoded for H2 uploads).
- Namespace prefixes: `ns/<segment>/` repeated per namespace level.
- Group owner file: `owner` (first line is `Authid`).

## Shortcuts / compatibility gaps
- Server-managed encryption is global (env-only) with no key rotation or per-datastore keys.
- If clients upload encrypted DataBlob payloads and the server has no key, size/digest verification is skipped.
- Admin/REST surface is a focused subset of PBS APIs (no full job config endpoints or UI-specific endpoints).
- Verification jobs are interval-based and not configurable via PBS job config APIs (no per-namespace/outdated filters).
- Namespace comments are not stored (API always returns `comment: null`).
- Datastore `total`/`avail` in status are synthetic for backends without capacity reporting.
- Task APIs track GC, prune, backup, and reader sessions; other operations may not emit task logs yet.
- Verification tasks check manifest presence, archive file existence, size consistency, and chunk existence/digest integrity via index parsing.

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
