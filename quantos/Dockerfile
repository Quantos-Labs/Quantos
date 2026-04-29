# ============================================================================
# Quantos Node — Production Multi-Stage Dockerfile
# ============================================================================
# Build:  docker build -t quantos:latest .
# Run:    docker run -p 8545:8545 -p 30303:30303 quantos:latest
# ============================================================================

# --------------------------------------------------------------------------
# Stage 1: Build
# --------------------------------------------------------------------------
FROM rust:1.77-bookworm AS builder

# Install system dependencies for RocksDB, libp2p, etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    cmake \
    libclang-dev \
    libssl-dev \
    pkg-config \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependencies: copy manifests first
COPY Cargo.toml Cargo.lock* ./

# Create a dummy main to build deps only (layer caching)
RUN mkdir -p src && \
    echo 'fn main() { println!("placeholder"); }' > src/main.rs && \
    echo 'fn main() { println!("placeholder"); }' > src/cli.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src

# Copy full source
COPY . .

# Touch main files to force rebuild with real sources
RUN touch src/main.rs src/cli.rs

# Build both binaries in release mode
RUN cargo build --release --bin quantos --bin quantos-cli

# --------------------------------------------------------------------------
# Stage 2: Runtime
# --------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r quantos && useradd -r -g quantos -m -d /home/quantos quantos

# Copy binaries from builder
COPY --from=builder /build/target/release/quantos /usr/local/bin/quantos
COPY --from=builder /build/target/release/quantos-cli /usr/local/bin/quantos-cli

# Create data & config directories
RUN mkdir -p /data/quantos /config && chown -R quantos:quantos /data /config

# Switch to non-root
USER quantos
WORKDIR /home/quantos

# --------------------------------------------------------------------------
# Environment defaults (overridable at runtime)
# --------------------------------------------------------------------------
ENV QUANTOS_DB_PATH=/data/quantos
ENV QUANTOS_P2P_PORT=30303
ENV QUANTOS_RPC_PORT=8545
ENV QUANTOS_METRICS_PORT=9615
ENV QUANTOS_SHARDS=1000
ENV QUANTOS_COMMITTEES=1000
ENV RUST_LOG=info

# --------------------------------------------------------------------------
# Ports
# --------------------------------------------------------------------------
# RPC (JSON-RPC API)
EXPOSE 8545
# P2P (libp2p)
EXPOSE 30303
# Prometheus metrics
EXPOSE 9615

# --------------------------------------------------------------------------
# Volumes
# --------------------------------------------------------------------------
VOLUME ["/data/quantos", "/config"]

# --------------------------------------------------------------------------
# Health check
# --------------------------------------------------------------------------
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD quantos-cli --rpc http://127.0.0.1:${QUANTOS_RPC_PORT} node health || exit 1

# --------------------------------------------------------------------------
# Entrypoint
# --------------------------------------------------------------------------
ENTRYPOINT ["quantos"]
CMD ["run", "--network", "testnet", "--datadir", "/data/quantos", "--rpc-port", "8545", "--p2p-port", "30303", "--metrics-port", "9615"]
