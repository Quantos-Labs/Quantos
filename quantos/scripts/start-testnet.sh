#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Quantos local testnet — starts 3 validator nodes on loopback.
#
# Usage:
#   ./scripts/start-testnet.sh [build]
#
# The optional "build" argument runs `cargo build --release` first.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BIN_DIR="$ROOT_DIR/target/release"
BUILD=0

if [ "${1:-}" = "build" ]; then
    BUILD=1
fi

cd "$ROOT_DIR"

# ─────────────────────────────────────────────────────────────────────────────
# 1. Build if requested
# ─────────────────────────────────────────────────────────────────────────────
if [ "$BUILD" -eq 1 ]; then
    echo "🔨 Building release binary..."
    cargo build --release --bin quantos
fi

if [ ! -f "$BIN_DIR/quantos" ]; then
    echo "❌ Binary not found: $BIN_DIR/quantos"
    echo "   Run: ./scripts/start-testnet.sh build"
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# 2. Prepare data dirs
# ─────────────────────────────────────────────────────────────────────────────
mkdir -p data/testnet-node1
mkdir -p data/testnet-node2
mkdir -p data/testnet-node3

# ─────────────────────────────────────────────────────────────────────────────
# 3. Stop any previous testnet
# ─────────────────────────────────────────────────────────────────────────────
if [ -f data/testnet.pid ]; then
    while read -r pid; do
        kill "$pid" 2>/dev/null || true
    done < data/testnet.pid
    rm -f data/testnet.pid
    sleep 2
fi

# ─────────────────────────────────────────────────────────────────────────────
# 4. Generate unique validator keys if missing
# ─────────────────────────────────────────────────────────────────────────────
echo "🔑 Ensuring unique validator key sets..."
for i in 1 2 3; do
    key_file="data/testnet-node$i/validator_keys.json"
    if [ ! -f "$key_file" ]; then
        "$BIN_DIR/quantos" generate-validator-keys \
            --output "$key_file" \
            --name "Testnet Validator $i"
        echo "  ✅ Generated validator key for node $i"
    else
        echo "  ✅ Reusing validator key for node $i"
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
# 5. Create shared genesis from validator keys
# ─────────────────────────────────────────────────────────────────────────────
GENESIS_FILE="data/testnet-genesis.json"
if [ ! -f "$GENESIS_FILE" ]; then
    echo "📦 Creating shared genesis with 3 validators..."
    "$BIN_DIR/quantos" create-genesis \
        --network testnet \
        --output "$GENESIS_FILE" \
        --validators "data/testnet-node1/validator_keys.json,data/testnet-node2/validator_keys.json,data/testnet-node3/validator_keys.json" \
        --stake 1000000 \
        --commission-bps 0
else
    echo "📦 Reusing shared genesis"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6. Start nodes
# ─────────────────────────────────────────────────────────────────────────────
echo "🚀 Starting 3-node Quantos testnet..."

start_node() {
    local id=$1
    local p2p_port=$2
    local rpc_port=$3
    local metrics_port=$4
    local data_dir="data/testnet-node$id"
    local log_file="data/testnet-node$id.log"
    local key_file="$data_dir/validator_keys.json"

    echo "  Node $id — p2p:$p2p_port rpc:$rpc_port metrics:$metrics_port"

    QUANTOS_NETWORK=testnet \
    QUANTOS_NUM_SHARDS=4 \
    QUANTOS_MIN_SHARDS=4 \
    QUANTOS_MAX_SHARDS=4 \
    QUANTOS_NUM_COMMITTEES=3 \
    QUANTOS_VALIDATORS_PER_COMMITTEE=3 \
    QUANTOS_COMMITTEE_ROTATION_MS=1000 \
    QUANTOS_CHECKPOINT_INTERVAL=32 \
    QUANTOS_DYNAMIC_SHARDING=false \
    QUANTOS_SIDECHAINS_ENABLED=false \
    QUANTOS_L0_ENABLED=false \
    QUANTOS_STACC_REQUIRE_ACTIVATION=false \
    QUANTOS_P2P_PEERS_PATH="$data_dir/p2p/peers.json" \
    "$BIN_DIR/quantos" run \
        --network testnet \
        --genesis "$GENESIS_FILE" \
        --datadir "$data_dir" \
        --p2p-port "$p2p_port" \
        --rpc-port "$rpc_port" \
        --metrics-port "$metrics_port" \
        --validator-key "$key_file" \
        > "$log_file" 2>&1 &

    echo $! >> data/testnet.pid
}

start_node 1 30303 8545 9615
start_node 2 30304 8546 9616
start_node 3 30305 8547 9617

# ─────────────────────────────────────────────────────────────────────────────
# 5. Health check
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "⏳ Waiting for nodes to boot..."
sleep 8

for port in 8545 8546 8547; do
    if curl -s -X POST http://127.0.0.1:$port \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"qnt_health","params":[],"id":1}' \
        >/dev/null 2>&1; then
        echo "  ✅ RPC port $port is healthy"
    else
        echo "  ⚠️  RPC port $port not responding yet (check logs)"
    fi
done

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Testnet running!"
echo ""
echo "  RPC endpoints:"
echo "    Node 1: http://127.0.0.1:8545"
echo "    Node 2: http://127.0.0.1:8546"
echo "    Node 3: http://127.0.0.1:8547"
echo ""
echo "  Logs:"
echo "    data/testnet-node1.log"
echo "    data/testnet-node2.log"
echo "    data/testnet-node3.log"
echo ""
echo "  Stop: ./scripts/stop-testnet.sh"
echo "═══════════════════════════════════════════════════════════════"
