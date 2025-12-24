# PBS Cloud

A PBS-compatible backup server with S3 storage, multi-tenancy, and compliance features.

## Overview

PBS Cloud is a clean-room implementation of a backup server compatible with [Proxmox Backup Server](https://www.proxmox.com/en/proxmox-backup-server) clients. It implements the documented PBS protocols and file formats, enabling:

- **S3-Compatible Storage**: Store backups in any S3-compatible object storage (AWS S3, MinIO, Cloudflare R2, etc.)
- **Local Storage**: Traditional filesystem-based storage with the same PBS layout
- **Multi-Tenancy**: Isolated datastores per tenant with usage tracking and billing hooks
- **Drop-in Compatibility**: Works with the stock `proxmox-backup-client`

## Features

### Core (Implemented)

- [x] PBS-compatible data formats (blobs, chunks, indexes)
- [x] Content-addressable chunk storage with SHA-256
- [x] Fixed and dynamic chunking (for VMs and file archives)
- [x] AES-256-GCM encryption + zstd compression
- [x] S3 storage backend
- [x] Local filesystem storage backend
- [x] Multi-tenant management with usage tracking
- [x] API token authentication (PBS-compatible)
- [x] Role-based permissions (Admin, DatastoreAdmin, Backup, Read)
- [x] Garbage collection for orphaned chunks
- [x] Prune policies (keep-last, daily, weekly, monthly, yearly)
- [x] Billing webhooks for usage events

### Roadmap

- [ ] Full streaming backup protocol (HTTP/2 upgrade)
- [ ] Encryption key management
- [ ] WORM/immutable backups
- [ ] Compliance reporting
- [ ] Webhook signature verification

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    pbs-server                           │
│  HTTP/2 API Server + PBS Protocol Implementation        │
│  - Authentication (API tokens)                          │
│  - Session management (backup/restore)                  │
│  - Multi-tenancy & billing                              │
├─────────────────────────────────────────────────────────┤
│                    pbs-storage                          │
│  Storage Backends: S3, Local FS                         │
│  - Chunk deduplication                                  │
│  - Garbage collection                                   │
│  - Prune policies                                       │
├─────────────────────────────────────────────────────────┤
│                     pbs-core                            │
│  Data Formats: Blobs, Chunks, Indexes, Manifests        │
│  - Wire-compatible with PBS                             │
│  - AES-256-GCM encryption                               │
│  - zstd compression                                     │
└─────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Rust 1.75+
- S3-compatible storage (or use local filesystem)

### Build

```bash
cargo build --release
```

### Run with Local Storage

```bash
export PBS_DATA_DIR=/var/lib/pbs-cloud
./target/release/pbs-cloud-server
```

### Run with S3 Storage

```bash
export AWS_ACCESS_KEY_ID=your-key
export AWS_SECRET_ACCESS_KEY=your-secret
export PBS_S3_BUCKET=your-bucket
export PBS_S3_REGION=us-east-1
# Optional: PBS_S3_ENDPOINT=https://minio.example.com for non-AWS S3

./target/release/pbs-cloud-server
```

On first run, the server will create a root user and display the API token:

```
INFO Created root user: root@pam
INFO Root API token: pbs_abc123...
INFO Save this token - it won't be shown again!
```

### Use with proxmox-backup-client

```bash
# Set the repository (adjust hostname as needed)
export PBS_REPOSITORY="root@pam!root-token@localhost:8007:default"

# Create a backup
proxmox-backup-client backup root.pxar:/

# List backups
proxmox-backup-client list

# Restore
proxmox-backup-client restore host/hostname/2024-01-01T00:00:00Z root.pxar /restore/path
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PBS_LISTEN_ADDR` | Server listen address | `0.0.0.0:8007` |
| `PBS_DATA_DIR` | Local storage path | `/var/lib/pbs-cloud` |
| `PBS_S3_BUCKET` | S3 bucket name | - |
| `PBS_S3_REGION` | AWS region | `us-east-1` |
| `PBS_S3_ENDPOINT` | S3 endpoint URL (for MinIO, R2, etc.) | - |
| `PBS_S3_PREFIX` | Key prefix in bucket | - |
| `PBS_DEFAULT_TENANT` | Default tenant ID | `default` |

## API Extensions

PBS Cloud adds APIs beyond standard PBS for multi-tenancy and billing:

### Authentication

```bash
# Get a token (use your root token in the password field)
curl -X POST http://localhost:8007/api2/json/access/ticket \
  -d '{"username":"root@pam","password":"pbs_abc123..."}'
```

### Tenant Management (Admin only)

```bash
# List tenants
curl -H "Authorization: Bearer pbs_..." \
  http://localhost:8007/api2/json/tenants

# Create tenant
curl -X POST -H "Authorization: Bearer pbs_..." \
  -H "Content-Type: application/json" \
  http://localhost:8007/api2/json/tenants \
  -d '{"name": "Acme Corp"}'
```

### User & Token Management

```bash
# Create a new user
curl -X POST -H "Authorization: Bearer pbs_..." \
  -H "Content-Type: application/json" \
  http://localhost:8007/api2/json/access/users \
  -d '{"username":"backup@pam","tenant_id":"default","permission":"backup"}'

# Create an API token
curl -X POST -H "Authorization: Bearer pbs_..." \
  -H "Content-Type: application/json" \
  http://localhost:8007/api2/json/access/tokens \
  -d '{"name":"my-backup-token","permission":"backup"}'
```

### Billing & Usage

```bash
# Get usage for current tenant
curl -H "Authorization: Bearer pbs_..." \
  http://localhost:8007/api2/json/billing/usage
```

### Webhook Integration

Configure webhooks to receive usage events for billing integration:

```json
{
  "url": "https://billing.example.com/webhook",
  "secret": "your-hmac-secret",
  "event_filter": ["backup_created", "storage_updated"]
}
```

Events include:
- `backup_created` - New backup completed
- `backup_deleted` - Backup removed
- `data_restored` - Data downloaded
- `storage_updated` - Storage usage changed
- `api_request` - API call made

## Permissions

| Level | Capabilities |
|-------|-------------|
| `read` | View backups, download data |
| `backup` | Create backups + read |
| `datastore_admin` | Manage datastores (prune, GC) + backup |
| `admin` | Full access including user/tenant management |

## Testing

```bash
cargo test
```

## License

MIT OR Apache-2.0

## Disclaimer

This is a clean-room implementation based on publicly documented protocols. It is not affiliated with or endorsed by Proxmox Server Solutions GmbH.
