# ============================================================================
# Quantos Node — Production Multi-Stage Dockerfile
# ============================================================================
# Build:  docker build -t quantos:latest -f L1/Dockerfile .
# Run:    docker run -p 8545:8545 -p 30303:30303 quantos:latest
# ============================================================================

# --------------------------------------------------------------------------
# Stage 1: Build
# --------------------------------------------------------------------------
FROM rust:1.95-bookworm AS builder

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

# --------------------------------------------------------------------------
# Step 1: Copy all Cargo.toml files for dependency caching
# --------------------------------------------------------------------------
COPY Cargo.toml Cargo.lock ./
COPY L1/Cargo.toml L1/Cargo.toml
COPY quantos-wallet-core/Cargo.toml quantos-wallet-core/Cargo.toml
COPY quantos-wallet-server/Cargo.toml quantos-wallet-server/Cargo.toml
COPY quantos-l0-sdk/Cargo.toml quantos-l0-sdk/Cargo.toml

# --------------------------------------------------------------------------
# Step 2: Create dummy sources for all workspace members
# --------------------------------------------------------------------------
RUN mkdir -p L1/src/bin L1/benches && \
    echo 'fn main() { println!("placeholder"); }' > L1/src/main.rs && \
    echo 'fn main() { println!("placeholder"); }' > L1/src/cli.rs && \
    echo 'fn main() { println!("placeholder"); }' > L1/src/solang_cli.rs && \
    echo 'fn main() { println!("placeholder"); }' > L1/src/bin/stress_test.rs && \
    echo 'fn main() { println!("placeholder"); }' > L1/benches/raw_tps.rs && \
    echo 'fn main() { println!("placeholder"); }' > L1/benches/testnet_tps.rs && \
    echo 'fn main() { println!("placeholder"); }' > L1/benches/pqc_bloat.rs && \
    echo 'fn main() { println!("placeholder"); }' > L1/benches/tps_throughput.rs && \
    mkdir -p quantos-wallet-core/src && \
    echo 'pub fn placeholder() {}' > quantos-wallet-core/src/lib.rs && \
    mkdir -p quantos-wallet-server/src && \
    echo 'fn main() { println!("placeholder"); }' > quantos-wallet-server/src/main.rs && \
    mkdir -p quantos-l0-sdk/src && \
    echo 'pub fn placeholder() {}' > quantos-l0-sdk/src/lib.rs

# --------------------------------------------------------------------------
# Step 3: Build dependencies only (layer caching — this is the slow step)
# --------------------------------------------------------------------------
RUN cargo build --release 2>/dev/null || true

# --------------------------------------------------------------------------
# Step 4: Copy real sources for all workspace members
# --------------------------------------------------------------------------
COPY L1/ L1/
COPY quantos-wallet-core/src/ quantos-wallet-core/src/
COPY quantos-wallet-server/src/ quantos-wallet-server/src/
COPY quantos-l0-sdk/src/ quantos-l0-sdk/src/

# --------------------------------------------------------------------------
# Step 5: Touch main files to force rebuild with real sources
# --------------------------------------------------------------------------
RUN touch L1/src/main.rs L1/src/cli.rs L1/src/solang_cli.rs && \
    touch quantos-wallet-core/src/lib.rs && \
    touch quantos-wallet-server/src/main.rs && \
    touch quantos-l0-sdk/src/lib.rs

# --------------------------------------------------------------------------
# Step 6: Build all binaries in release mode
# --------------------------------------------------------------------------
# wasmer 4.2 references __rust_probestack which was removed in Rust 1.82+.
# Provide a no-op shim so linking succeeds.
RUN echo '.globl __rust_probestack\n__rust_probestack:\n\tret' > /tmp/probestack.S && \
    cc -c /tmp/probestack.S -o /tmp/probestack.o && \
    ar rcs /usr/lib/libprobestack.a /tmp/probestack.o && \
    RUSTFLAGS="-C link-arg=-lprobestack" cargo build --release --bin quantos --bin quantos-cli

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
CMD ["--network", "testnet", "--datadir", "/data/quantos", "--rpc-port", "8545", "--p2p-port", "30303", "--metrics-port", "9615", "run"]
