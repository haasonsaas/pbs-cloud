# Build stage
FROM rust:1.85-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build release binary
RUN cargo build --release --package pbs-server

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 1000 -g nogroup pbs

# Create data directories
RUN mkdir -p /data/state /data/storage /tmp && \
    chown -R pbs:nogroup /data /tmp

# Copy binary from builder
COPY --from=builder /build/target/release/pbs-server /usr/local/bin/pbs-server

# Use non-root user
USER pbs

# Default environment
ENV RUST_LOG=info \
    PBS_LISTEN_ADDR=0.0.0.0:8007 \
    PBS_PERSISTENCE_DIR=/data/state \
    PBS_DATA_DIR=/data/storage

# Expose HTTPS port
EXPOSE 8007

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -kfs https://localhost:8007/health || exit 1

ENTRYPOINT ["/usr/local/bin/pbs-server"]
