# PBS Cloud

A PBS-compatible backup server with S3 storage, multi-tenancy, and compliance features.

## Overview

PBS Cloud is a clean-room implementation of a backup server compatible with [Proxmox Backup Server](https://www.proxmox.com/en/proxmox-backup-server) clients. It implements the documented PBS protocols and file formats, enabling:

- **S3-Compatible Storage**: Store backups in any S3-compatible object storage (AWS S3, MinIO, Cloudflare R2, etc.)
- **Multi-Tenancy**: Isolated datastores per tenant with usage tracking and billing hooks
- **Drop-in Compatibility**: Works with the stock `proxmox-backup-client`

## Features

### Core (Implemented)

- [x] PBS-compatible data formats (blobs, chunks, indexes)
- [x] Content-addressable chunk storage with SHA-256
- [x] Fixed and dynamic chunking (for VMs and file archives)
- [x] AES-256-GCM encryption + zstd compression
- [x] S3 storage backend
- [x] Multi-tenant management

### Roadmap

- [ ] Full HTTP/2 backup protocol
- [ ] Garbage collection
- [ ] Prune policies
- [ ] WORM/immutable backups
- [ ] Compliance reporting
- [ ] Billing API integration

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    pbs-server                           │
│  HTTP/2 API Server + PBS Protocol Implementation        │
├─────────────────────────────────────────────────────────┤
│                    pbs-storage                          │
│  Storage Backends: S3, Local FS                         │
├─────────────────────────────────────────────────────────┤
│                     pbs-core                            │
│  Data Formats: Blobs, Chunks, Indexes, Manifests        │
└─────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Rust 1.75+
- S3-compatible storage (or MinIO for local testing)

### Build

```bash
cargo build --release
```

### Run

```bash
# With environment variables for S3
export AWS_ACCESS_KEY_ID=your-key
export AWS_SECRET_ACCESS_KEY=your-secret
export PBS_CLOUD_BUCKET=your-bucket
export PBS_CLOUD_ENDPOINT=https://s3.amazonaws.com  # or MinIO URL

./target/release/pbs-cloud-server
```

### Use with proxmox-backup-client

```bash
# Point your PBS client at the server
export PBS_REPOSITORY="admin@pbs-cloud.example.com:datastore"

# Create a backup
proxmox-backup-client backup root.pxar:/

# List backups
proxmox-backup-client list

# Restore
proxmox-backup-client restore host/hostname/2024-01-01T00:00:00Z root.pxar /restore/path
```

## Configuration

Configuration is via environment variables or a config file:

```toml
# /etc/pbs-cloud/config.toml

listen_addr = "0.0.0.0:8007"

[storage]
type = "s3"
bucket = "my-backup-bucket"
region = "us-east-1"
# endpoint = "http://localhost:9000"  # For MinIO

[tenants]
enabled = true
```

## API Extensions

PBS Cloud adds APIs beyond standard PBS:

### Tenant Management

```bash
# List tenants
curl -X GET http://localhost:8007/api2/json/tenants

# Create tenant
curl -X POST http://localhost:8007/api2/json/tenants \
  -H "Content-Type: application/json" \
  -d '{"name": "Acme Corp"}'

# Get tenant usage (for billing)
curl -X GET http://localhost:8007/api2/json/tenants/{id}/usage
```

## License

MIT OR Apache-2.0

## Contributing

Contributions welcome! Please read our contributing guidelines first.

## Disclaimer

This is a clean-room implementation based on publicly documented protocols. It is not affiliated with or endorsed by Proxmox Server Solutions GmbH.
