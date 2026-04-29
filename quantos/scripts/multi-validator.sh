#!/usr/bin/env bash
# ============================================================================
# Quantos Multi-Validator Local Orchestration Script
# ============================================================================
#
# Launches N validator nodes locally for development, testing, and staging.
# Each validator gets its own data directory, ports, and Dilithium-3 keypair.
#
# Usage:
#   ./scripts/multi-validator.sh                # 4 validators (default)
#   ./scripts/multi-validator.sh --validators 7 # 7 validators
#   ./scripts/multi-validator.sh --clean        # Wipe data & restart
#   ./scripts/multi-validator.sh --stop         # Stop all validators
#   ./scripts/multi-validator.sh --status       # Show running validators
#   ./scripts/multi-validator.sh --logs 1       # Tail logs for validator 1
#
# Each validator is assigned:
#   P2P:     30303 + (i-1)     → 30303, 30304, 30305, ...
#   RPC:     8545  + (i-1)     → 8545,  8546,  8547,  ...
#   Metrics: 9615  + (i-1)     → 9615,  9616,  9617,  ...
#
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="$PROJECT_DIR/config"
MULTI_DIR="$PROJECT_DIR/data/multi-validator"
KEYS_DIR="$MULTI_DIR/keys"
LOGS_DIR="$MULTI_DIR/logs"
PIDS_DIR="$MULTI_DIR/pids"
GENESIS_FILE="$MULTI_DIR/genesis.json"
BINARY="$PROJECT_DIR/target/release/quantos"

# Defaults
NUM_VALIDATORS=${QUANTOS_VALIDATORS:-4}
NETWORK="devnet"
BASE_P2P_PORT=30303
BASE_RPC_PORT=8545
BASE_METRICS_PORT=9615
MIN_STAKE="1000000000000000000000"  # 1000 QTS in smallest units
BUILD_RELEASE=true

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step()  { echo -e "${CYAN}[STEP]${NC}  $*"; }

banner() {
    echo -e "${BLUE}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "  Quantos Multi-Validator Orchestrator"
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"
}

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --validators N    Number of validator nodes to launch (default: 4)
  --network NAME    Network type: devnet (default), testnet
  --clean           Remove all data and start fresh
  --stop            Stop all running validator nodes
  --status          Show status of running validators
  --logs N          Tail logs for validator N (1-indexed)
  --no-build        Skip cargo build step
  --help            Show this help message

Environment variables:
  QUANTOS_VALIDATORS   Number of validators (default: 4)
  RUST_LOG             Log level (default: info)

Examples:
  $(basename "$0")                        # Launch 4 validators
  $(basename "$0") --validators 7         # Launch 7 validators
  $(basename "$0") --clean --validators 3 # Fresh start with 3 validators
  $(basename "$0") --stop                 # Stop everything
  $(basename "$0") --logs 2              # Follow validator 2 logs
EOF
}

# ---------------------------------------------------------------------------
# Parse Arguments
# ---------------------------------------------------------------------------

ACTION="start"
TAIL_VALIDATOR=""
CLEAN=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --validators|-n)
            NUM_VALIDATORS="$2"
            shift 2
            ;;
        --network)
            NETWORK="$2"
            shift 2
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        --stop)
            ACTION="stop"
            shift
            ;;
        --status)
            ACTION="status"
            shift
            ;;
        --logs)
            ACTION="logs"
            TAIL_VALIDATOR="$2"
            shift 2
            ;;
        --no-build)
            BUILD_RELEASE=false
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Stop all validators
# ---------------------------------------------------------------------------

stop_validators() {
    log_step "Stopping all validator processes..."
    local stopped=0

    if [[ -d "$PIDS_DIR" ]]; then
        for pidfile in "$PIDS_DIR"/validator-*.pid; do
            [[ -f "$pidfile" ]] || continue
            local pid
            pid=$(cat "$pidfile")
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
                stopped=$((stopped + 1))
            fi
            rm -f "$pidfile"
        done
    fi

    if [[ $stopped -gt 0 ]]; then
        log_info "Stopped $stopped validator(s)"
        # Give processes time to exit
        sleep 2
    else
        log_info "No running validators found"
    fi
}

# ---------------------------------------------------------------------------
# Show status
# ---------------------------------------------------------------------------

show_status() {
    echo -e "${BOLD}Quantos Multi-Validator Status${NC}"
    echo "────────────────────────────────────────────────────────────"
    printf "%-6s %-8s %-8s %-8s %-10s %-12s\n" \
        "ID" "PID" "P2P" "RPC" "Metrics" "Status"
    echo "────────────────────────────────────────────────────────────"

    if [[ ! -d "$PIDS_DIR" ]]; then
        echo "  No validator data found."
        return
    fi

    for pidfile in "$PIDS_DIR"/validator-*.pid; do
        [[ -f "$pidfile" ]] || continue
        local id pid p2p rpc metrics status
        id=$(basename "$pidfile" | sed 's/validator-//;s/\.pid//')
        pid=$(cat "$pidfile")
        p2p=$((BASE_P2P_PORT + id - 1))
        rpc=$((BASE_RPC_PORT + id - 1))
        metrics=$((BASE_METRICS_PORT + id - 1))

        if kill -0 "$pid" 2>/dev/null; then
            status="${GREEN}running${NC}"
        else
            status="${RED}stopped${NC}"
        fi
        printf "%-6s %-8s %-8s %-8s %-10s " "$id" "$pid" "$p2p" "$rpc" "$metrics"
        echo -e "$status"
    done
    echo "────────────────────────────────────────────────────────────"

    # Also show key addresses
    if [[ -d "$KEYS_DIR" ]]; then
        echo ""
        echo -e "${BOLD}Validator Keys${NC}"
        echo "────────────────────────────────────────────────────────────"
        for keyfile in "$KEYS_DIR"/validator-*.json; do
            [[ -f "$keyfile" ]] || continue
            local id addr
            id=$(basename "$keyfile" | sed 's/validator-//;s/\.json//')
            addr=$(python3 -c "import json; d=json.load(open('$keyfile')); print(d.get('address','?'))" 2>/dev/null || echo "?")
            printf "  Validator %s: %s\n" "$id" "$addr"
        done
    fi
}

# ---------------------------------------------------------------------------
# Tail logs
# ---------------------------------------------------------------------------

tail_logs() {
    local v="$1"
    local logfile="$LOGS_DIR/validator-${v}.log"
    if [[ ! -f "$logfile" ]]; then
        log_error "Log file not found: $logfile"
        exit 1
    fi
    log_info "Following logs for validator $v (Ctrl+C to stop)"
    tail -f "$logfile"
}

# ---------------------------------------------------------------------------
# Dispatch action
# ---------------------------------------------------------------------------

case "$ACTION" in
    stop)
        stop_validators
        exit 0
        ;;
    status)
        show_status
        exit 0
        ;;
    logs)
        if [[ -z "$TAIL_VALIDATOR" ]]; then
            log_error "Specify validator number: --logs N"
            exit 1
        fi
        tail_logs "$TAIL_VALIDATOR"
        exit 0
        ;;
esac

# ====================================================================
# Main: start N validators
# ====================================================================

banner

log_info "Validators:  $NUM_VALIDATORS"
log_info "Network:     $NETWORK"
log_info "Data dir:    $MULTI_DIR"
log_info ""

# ---------------------------------------------------------------------------
# Step 0: Clean if requested
# ---------------------------------------------------------------------------

if [[ "$CLEAN" == true ]]; then
    log_step "Cleaning previous data..."
    stop_validators
    rm -rf "$MULTI_DIR"
    log_info "Cleaned $MULTI_DIR"
fi

# ---------------------------------------------------------------------------
# Step 1: Build the binary
# ---------------------------------------------------------------------------

if [[ "$BUILD_RELEASE" == true ]]; then
    log_step "Building quantos (release mode)..."
    cd "$PROJECT_DIR"
    cargo build --release --bin quantos 2>&1 | tail -5
    log_info "Binary: $BINARY"
else
    if [[ ! -f "$BINARY" ]]; then
        log_error "Binary not found at $BINARY — run without --no-build first"
        exit 1
    fi
    log_info "Skipping build, using existing binary"
fi

# ---------------------------------------------------------------------------
# Step 2: Create directories
# ---------------------------------------------------------------------------

mkdir -p "$KEYS_DIR" "$LOGS_DIR" "$PIDS_DIR"

# ---------------------------------------------------------------------------
# Step 3: Generate validator keys (Dilithium-3)
# ---------------------------------------------------------------------------

log_step "Generating Dilithium-3 validator keys..."

for i in $(seq 1 "$NUM_VALIDATORS"); do
    keyfile="$KEYS_DIR/validator-${i}.json"
    if [[ -f "$keyfile" ]]; then
        log_info "  Key $i already exists, skipping"
    else
        "$BINARY" generate-key -o "$keyfile"
        log_info "  Generated key $i → $keyfile"
    fi
done

# ---------------------------------------------------------------------------
# Step 4: Build multi-validator genesis
# ---------------------------------------------------------------------------

log_step "Building genesis with $NUM_VALIDATORS validators..."

# Collect validator info for genesis
VALIDATORS_JSON="["
for i in $(seq 1 "$NUM_VALIDATORS"); do
    keyfile="$KEYS_DIR/validator-${i}.json"
    # Extract address_hex and public_key from key file
    addr_hex=$(python3 -c "import json; d=json.load(open('$keyfile')); print(d['address_hex'])")
    pub_key=$(python3 -c "import json; d=json.load(open('$keyfile')); print(d['public_key'])")

    if [[ $i -gt 1 ]]; then
        VALIDATORS_JSON+=","
    fi

    VALIDATORS_JSON+=$(cat <<VJSON
    {
      "address": "$addr_hex",
      "public_key": "$pub_key",
      "stake": $MIN_STAKE,
      "name": "Validator $i",
      "commission_bps": 500
    }
VJSON
    )
done
VALIDATORS_JSON+="]"

# Determine chain config based on network
if [[ "$NETWORK" == "testnet" ]]; then
    CHAIN_ID=2
    EPOCH_LENGTH=32
    MIN_SHARDS=1
    MAX_SHARDS=10000
    INITIAL_SHARDS=4
    UNBONDING=604800
else
    # devnet defaults — fast iteration
    CHAIN_ID=3
    EPOCH_LENGTH=16
    MIN_SHARDS=1
    MAX_SHARDS=1000
    INITIAL_SHARDS=2
    UNBONDING=300
fi

# Allocations: fund all validators + a faucet address
ALLOCATIONS_JSON="["
for i in $(seq 1 "$NUM_VALIDATORS"); do
    keyfile="$KEYS_DIR/validator-${i}.json"
    addr_hex=$(python3 -c "import json; d=json.load(open('$keyfile')); print(d['address_hex'])")
    if [[ $i -gt 1 ]]; then
        ALLOCATIONS_JSON+=","
    fi
    ALLOCATIONS_JSON+=$(cat <<AJSON
    {
      "address": "$addr_hex",
      "balance": 10000000000000000000000000,
      "vesting": null,
      "label": "Validator $i Funding"
    }
AJSON
    )
done
ALLOCATIONS_JSON+="]"

# Assemble full genesis JSON
GENESIS_TIME=$(date +%s)

cat > "$GENESIS_FILE" <<GENESIS
{
  "network": "$NETWORK",
  "genesis_time": $GENESIS_TIME,
  "chain": {
    "chain_id": $CHAIN_ID,
    "block_time_ms": 200,
    "max_tx_per_block": 10000,
    "max_block_size": 10485760,
    "min_gas_price": 0,
    "max_gas_per_tx": 0,
    "max_gas_per_block": 0,
    "min_validator_stake": $MIN_STAKE,
    "max_validators_per_committee": 21,
    "initial_shards": $INITIAL_SHARDS,
    "epoch_length": $EPOCH_LENGTH,
    "double_sign_slash_bps": 500,
    "downtime_slash_bps": 100,
    "unbonding_period_seconds": $UNBONDING,
    "dynamic_sharding": true,
    "min_shards": $MIN_SHARDS,
    "max_shards": $MAX_SHARDS
  },
  "validators": $VALIDATORS_JSON,
  "allocations": $ALLOCATIONS_JSON,
  "system_contracts": [],
  "extra_data": "Quantos Multi-Validator Genesis ($NUM_VALIDATORS validators)"
}
GENESIS

log_info "Genesis written to $GENESIS_FILE"
log_info "  Chain ID:    $CHAIN_ID"
log_info "  Validators:  $NUM_VALIDATORS"
log_info "  Shards:      $INITIAL_SHARDS (dynamic: $MIN_SHARDS–$MAX_SHARDS)"

# ---------------------------------------------------------------------------
# Step 5: Stop any existing validators
# ---------------------------------------------------------------------------

stop_validators

# ---------------------------------------------------------------------------
# Step 6: Build bootnode list from validator 1
# ---------------------------------------------------------------------------

# Validator 1 is the bootnode; others connect to it
BOOTNODE_P2P_PORT=$BASE_P2P_PORT
# We'll set bootnodes after validator 1 starts (if peer_id is needed)
# For local, we can use localhost multiaddr format
# libp2p bootnodes require peer_id, but for local testing the DHT discovers peers on the same machine

# ---------------------------------------------------------------------------
# Step 7: Launch all validators
# ---------------------------------------------------------------------------

log_step "Launching $NUM_VALIDATORS validator nodes..."
echo ""

printf "${BOLD}%-5s %-8s %-8s %-10s %-40s${NC}\n" "ID" "P2P" "RPC" "Metrics" "Address"
echo "──────────────────────────────────────────────────────────────────────────────"

for i in $(seq 1 "$NUM_VALIDATORS"); do
    p2p_port=$((BASE_P2P_PORT + i - 1))
    rpc_port=$((BASE_RPC_PORT + i - 1))
    metrics_port=$((BASE_METRICS_PORT + i - 1))
    datadir="$MULTI_DIR/node-${i}"
    keyfile="$KEYS_DIR/validator-${i}.json"
    logfile="$LOGS_DIR/validator-${i}.log"
    pidfile="$PIDS_DIR/validator-${i}.pid"

    mkdir -p "$datadir"

    addr=$(python3 -c "import json; d=json.load(open('$keyfile')); print(d.get('address','?')[:16] + '...')" 2>/dev/null || echo "?")
    printf "%-5s %-8s %-8s %-10s %-40s" "$i" "$p2p_port" "$rpc_port" "$metrics_port" "$addr"

    # Build command
    CMD="$BINARY"
    CMD+=" --network $NETWORK"
    CMD+=" --genesis $GENESIS_FILE"
    CMD+=" --datadir $datadir"
    CMD+=" --p2p-port $p2p_port"
    CMD+=" --rpc-port $rpc_port"
    CMD+=" --metrics-port $metrics_port"
    CMD+=" --validator"
    CMD+=" --validator-key $keyfile"

    # All nodes except validator 1 get bootnodes pointing to validator 1
    # (Local discovery will handle same-machine peers, but explicit is safer)
    if [[ $i -gt 1 ]]; then
        CMD+=" --bootnodes /ip4/127.0.0.1/tcp/$BOOTNODE_P2P_PORT"
    fi

    # Launch in background
    RUST_LOG="${RUST_LOG:-info}" \
    QUANTOS_DB_PATH="$datadir" \
        nohup $CMD > "$logfile" 2>&1 &
    local_pid=$!
    echo "$local_pid" > "$pidfile"

    echo -e "  ${GREEN}PID $local_pid${NC}"

    # Small delay between launches to let the first node bind its port
    if [[ $i -eq 1 ]]; then
        sleep 2
    else
        sleep 0.5
    fi
done

echo ""
echo "──────────────────────────────────────────────────────────────────────────────"
echo ""

# ---------------------------------------------------------------------------
# Step 8: Wait for nodes to be ready
# ---------------------------------------------------------------------------

log_step "Waiting for nodes to initialize..."
sleep 3

RUNNING=0
for i in $(seq 1 "$NUM_VALIDATORS"); do
    pidfile="$PIDS_DIR/validator-${i}.pid"
    if [[ -f "$pidfile" ]]; then
        pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            RUNNING=$((RUNNING + 1))
        else
            log_warn "Validator $i (PID $pid) exited early — check $LOGS_DIR/validator-${i}.log"
        fi
    fi
done

echo ""
if [[ $RUNNING -eq $NUM_VALIDATORS ]]; then
    log_info "${GREEN}All $NUM_VALIDATORS validators are running!${NC}"
else
    log_warn "$RUNNING / $NUM_VALIDATORS validators running"
fi

# ---------------------------------------------------------------------------
# Step 9: Health checks via RPC
# ---------------------------------------------------------------------------

log_step "RPC health checks..."

for i in $(seq 1 "$NUM_VALIDATORS"); do
    rpc_port=$((BASE_RPC_PORT + i - 1))
    response=$(curl -s -m 2 -X POST "http://127.0.0.1:$rpc_port" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"qnt_health","params":[],"id":1}' 2>/dev/null || echo "")
    
    if [[ -n "$response" && "$response" != *"error"* ]]; then
        echo -e "  Validator $i (port $rpc_port): ${GREEN}healthy${NC}"
    else
        echo -e "  Validator $i (port $rpc_port): ${YELLOW}starting...${NC}"
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Multi-Validator Cluster Ready${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Validators:    $RUNNING / $NUM_VALIDATORS"
echo "  Network:       $NETWORK (chain_id: $CHAIN_ID)"
echo "  Genesis:       $GENESIS_FILE"
echo ""
echo "  RPC endpoints:"
for i in $(seq 1 "$NUM_VALIDATORS"); do
    rpc_port=$((BASE_RPC_PORT + i - 1))
    echo "    Validator $i:  http://127.0.0.1:$rpc_port"
done
echo ""
echo "  Useful commands:"
echo "    $(basename "$0") --status           Show running validators"
echo "    $(basename "$0") --logs N           Tail validator N logs"
echo "    $(basename "$0") --stop             Stop all validators"
echo ""
echo "  Query a validator:"
echo "    curl -s http://127.0.0.1:$BASE_RPC_PORT -X POST \\"
echo "      -H 'Content-Type: application/json' \\"
echo "      -d '{\"jsonrpc\":\"2.0\",\"method\":\"qnt_getValidators\",\"params\":[],\"id\":1}'"
echo ""
