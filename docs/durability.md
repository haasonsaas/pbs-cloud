# Durability and Failure Modes

This document describes the durability assumptions and failure modes for PBS Cloud.

## Integrity invariants

- Backups are defined by manifests (`index.json.blob`) which reference chunk and archive data.
- Chunks are content-addressed by SHA-256 and stored immutably once written.
- A snapshot is considered valid once its manifest is fully written and readable.

## Upload lifecycle and crash behavior

- Clients upload blobs, indexes, and manifests as discrete objects.
- If the server crashes mid-upload, partially written objects may exist but are not referenced
  by a completed manifest.
- A restart does not automatically resume in-flight uploads; the client should retry.

## GC / prune safety

- GC enumerates all manifests, builds a reachable chunk set, then deletes orphaned chunks.
- There is no explicit lease/epoch protocol yet, so GC can race with in-flight uploads.
- Recommendation: run GC during low-traffic windows and avoid concurrent GC with large ingests.

## Object count and chunk sizing

- Chunk sizing is controlled by the **client** (`proxmox-backup-client`), not the server.
- Upstream clients enforce `--chunk-size` between 64 KiB and 4 MiB (default 4 MiB).
- Changing server-side constants does **not** reduce object counts; lowering object counts
  requires either:
  - Prune + GC to delete old/unreferenced chunks, and/or
  - A forked client that allows larger chunk sizes (compatibility risk).

## Suggested lifecycle hygiene (B2/S3)

- Prefer prune + GC to remove objects; do **not** blindly expire `chunks/` objects.
- If versioning is enabled, expire noncurrent versions after a short window.
- Abort incomplete multipart uploads after a few days to reduce clutter.

## Object storage semantics (S3)

- GC and verification rely on list/read operations being consistent enough to observe newly
  uploaded objects.
- If your object store has eventual consistency for list operations, prefer:
  - Strongly consistent storage classes, or
  - Disabling GC during heavy ingest, or
  - Enabling versioning/object-lock to reduce the risk of premature deletion.

## Verification behavior

- Verification checks manifest presence, archive file existence, size consistency, and chunk
  existence/digest integrity based on index files.
- For client-side encrypted blobs, verification cannot inspect payload contents without the key.

## WORM / immutability scope

- WORM enforcement blocks deletion within the configured retention window.
- It is **not** a legal-hold mechanism unless backed by immutable storage (object lock/versioning).

## Recommendations

- Enable verification jobs for critical workloads.
- Enable object versioning or object lock if you require immutable retention.
- Schedule GC and prune during quiet hours.
