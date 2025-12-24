#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP_BASE=${TMPDIR:-"$ROOT_DIR/target/tmp"}
mkdir -p "$TMP_BASE"

if ! command -v proxmox-backup-client >/dev/null 2>&1; then
  echo "SKIP: proxmox-backup-client not installed."
  exit 0
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "SKIP: openssl not installed."
  exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "SKIP: python3 not installed."
  exit 0
fi

WORKDIR=$(mktemp -d "$TMP_BASE/pbs-client-smoke.XXXXXX")
SERVER_LOG="$WORKDIR/server.log"
DATA_DIR="$WORKDIR/data"
TOKEN_FILE="$WORKDIR/root.token"
CERT_FILE="$WORKDIR/server.crt"
KEY_FILE="$WORKDIR/server.key"
SRC_DIR="$WORKDIR/src"
RESTORE_DIR="$WORKDIR/restore"
PORT=18007

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

mkdir -p "$DATA_DIR" "$SRC_DIR" "$RESTORE_DIR"

if ! openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY_FILE" -out "$CERT_FILE" \
  -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1; then
  OPENSSL_CONF="$WORKDIR/openssl.cnf"
  cat <<'CONF' > "$OPENSSL_CONF"
[req]
req_extensions = req_ext
distinguished_name = dn
prompt = no

[dn]
CN = localhost

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
CONF
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY_FILE" -out "$CERT_FILE" \
    -days 1 -config "$OPENSSL_CONF" -extensions req_ext >/dev/null
fi

FINGERPRINT=$(openssl x509 -in "$CERT_FILE" -noout -fingerprint -sha256 | cut -d= -f2 | tr 'A-F' 'a-f' | tr -d '\r')
if [[ -z "$FINGERPRINT" ]]; then
  echo "Failed to compute TLS fingerprint"
  exit 1
fi

RUST_LOG=info \
PBS_LISTEN_ADDR="127.0.0.1:$PORT" \
PBS_DATA_DIR="$DATA_DIR" \
PBS_TLS_CERT="$CERT_FILE" \
PBS_TLS_KEY="$KEY_FILE" \
PBS_ROOT_TOKEN_FILE="$TOKEN_FILE" \
PBS_PRINT_ROOT_TOKEN=0 \
PBS_DASHBOARD_ENABLED=0 \
PBS_METRICS_PUBLIC=0 \
cargo run -p pbs-server --bin pbs-cloud-server >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 60); do
  if [[ -f "$TOKEN_FILE" ]]; then
    break
  fi
  if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    echo "Server exited early. Log output:"
    cat "$SERVER_LOG"
    exit 1
  fi
  sleep 0.5
done

if [[ ! -f "$TOKEN_FILE" ]]; then
  echo "Root token was not created. Log output:"
  cat "$SERVER_LOG"
  exit 1
fi

for _ in $(seq 1 40); do
  if curl -sk "https://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

if ! curl -sk "https://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
  echo "Server did not become healthy. Log output:"
  cat "$SERVER_LOG"
  exit 1
fi

TOKEN=$(cat "$TOKEN_FILE")

export PBS_REPOSITORY="root@pam!root-token@127.0.0.1:$PORT:default"
export PBS_PASSWORD="$TOKEN"
export PBS_FINGERPRINT="$FINGERPRINT"

proxmox-backup-client --version

echo "hello" > "$SRC_DIR/hello.txt"

proxmox-backup-client backup test.pxar:"$SRC_DIR"

LIST_JSON=$(proxmox-backup-client list --output-format json)
SNAPSHOT=$(printf '%s' "$LIST_JSON" | python3 - <<'PY'
import json
import sys
from datetime import datetime, timezone

payload = json.load(sys.stdin)
data = payload.get("data") if isinstance(payload, dict) else payload
if not isinstance(data, list) or not data:
    sys.exit(2)
item = data[-1]
backup_type = item.get("backup-type")
backup_id = item.get("backup-id")
backup_time = item.get("backup-time")
if backup_type is None or backup_id is None or backup_time is None:
    sys.exit(3)
stamp = datetime.fromtimestamp(int(backup_time), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
print(f"{backup_type}/{backup_id}/{stamp}")
PY
)

if [[ -z "$SNAPSHOT" ]]; then
  echo "Failed to parse snapshot list."
  exit 1
fi

proxmox-backup-client restore "$SNAPSHOT" test.pxar "$RESTORE_DIR"

if ! find "$RESTORE_DIR" -type f -name hello.txt | grep -q .; then
  echo "Restore verification failed: hello.txt not found"
  exit 1
fi
