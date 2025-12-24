# AGENTS.md

## Project overview
- PBS Cloud is a PBS-compatible backup server with S3/local storage, multi-tenancy, and billing hooks.
- Workspace crates:
  - `crates/pbs-core`: PBS data formats (chunks, blobs, indexes, manifests, crypto).
  - `crates/pbs-storage`: storage backends (local + S3), datastore logic, GC + prune.
  - `crates/pbs-server`: HTTP/2 API server, auth, sessions, metrics, billing.

## Build and run
- Build: `cargo build --release`
- Test: `cargo test`
- Run (local storage):
  - `export PBS_DATA_DIR=/var/lib/pbs-cloud`
  - `cargo run -p pbs-server --bin pbs-cloud-server`
- Run (S3 storage):
  - `export AWS_ACCESS_KEY_ID=...`
  - `export AWS_SECRET_ACCESS_KEY=...`
  - `export PBS_S3_BUCKET=...`
  - `export PBS_S3_REGION=us-east-1`
  - Optional: `export PBS_S3_ENDPOINT=https://...` (MinIO/R2)
  - `cargo run -p pbs-server --bin pbs-cloud-server`

## Configuration (env vars)
- `PBS_LISTEN_ADDR` (default `0.0.0.0:8007`)
- `PBS_DATA_DIR` (local storage path)
- `PBS_S3_BUCKET`, `PBS_S3_REGION`, `PBS_S3_ENDPOINT`, `PBS_S3_PREFIX`
- `PBS_DEFAULT_TENANT`

## Persistence and auth
- Users/tokens/tenants persist to `ServerConfig.data_dir` (default is the literal `~/.pbs-cloud` path).
- First boot creates `root@pam` + prints a one-time API token to stdout.
- Auth is token-based; the login endpoint expects the token in the password field.

## Operational notes
- Sessions time out after 1 hour (`SessionManager::default`).
- Metrics are exposed at `/metrics` (public endpoint).
- Rate limiting is enabled by default (see `RateLimitConfig`).
- S3 stats are computed by listing objects (can be slow on large buckets).

## Where to look
- API routing: `crates/pbs-server/src/server.rs`
- Backup/restore protocol handlers: `crates/pbs-server/src/streaming.rs`
- Session state: `crates/pbs-server/src/session.rs`
- Storage backends: `crates/pbs-storage/src/local.rs`, `crates/pbs-storage/src/s3.rs`

## Known limitations
- Encryption key management is not wired into config; `CryptoConfig::default()` disables encryption.
- Password-derived encryption keys require a caller-provided salt (no env wiring yet).
- Multi-tenancy uses a single datastore; tenant isolation is enforced via session/auth checks.
- Roadmap items in README (HTTP/2 streaming upgrade, WORM, compliance) are not implemented.
