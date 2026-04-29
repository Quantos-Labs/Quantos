#!/bin/bash
# Quantos Testnet Launch Script
# 
# Usage:
#   ./scripts/run-testnet.sh [--validator]
#
# Options:
#   --validator    Run as validator node (requires key)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="$PROJECT_DIR/config"
DATA_DIR="$PROJECT_DIR/data"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "═══════════════════════════════════════════════════════════════"
echo "  Quantos Testnet Launcher"
echo "═══════════════════════════════════════════════════════════════"
echo -e "${NC}"

# Parse arguments
VALIDATOR_MODE=false
VALIDATOR_KEY=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --validator)
            VALIDATOR_MODE=true
            shift
            ;;
        --key)
            VALIDATOR_KEY="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Check if genesis exists, if not initialize
GENESIS_FILE="$CONFIG_DIR/testnet-genesis.json"
if [ ! -f "$GENESIS_FILE" ]; then
    echo -e "${YELLOW}Genesis file not found. Initializing...${NC}"
    cd "$PROJECT_DIR"
    cargo run --release -- init --network testnet --output "$GENESIS_FILE"
fi

# Create data directory
mkdir -p "$DATA_DIR"

# Build arguments
ARGS="--network testnet --genesis $GENESIS_FILE --datadir $DATA_DIR"

# P2P, RPC, and metrics ports (can be overridden via env vars)
P2P_PORT=${QUANTOS_P2P_PORT:-30303}
RPC_PORT=${QUANTOS_RPC_PORT:-8545}
METRICS_PORT=${QUANTOS_METRICS_PORT:-9615}
ARGS="$ARGS --p2p-port $P2P_PORT --rpc-port $RPC_PORT --metrics-port $METRICS_PORT"

# Add validator mode if specified
if [ "$VALIDATOR_MODE" = true ]; then
    ARGS="$ARGS --validator"
    if [ -n "$VALIDATOR_KEY" ]; then
        ARGS="$ARGS --validator-key $VALIDATOR_KEY"
    elif [ -f "$CONFIG_DIR/validator-key.json" ]; then
        ARGS="$ARGS --validator-key $CONFIG_DIR/validator-key.json"
    else
        echo -e "${YELLOW}Warning: Validator mode enabled but no key specified${NC}"
        echo -e "${YELLOW}Generate a key with: cargo run --release -- generate-key -o $CONFIG_DIR/validator-key.json${NC}"
    fi
fi

# Add bootnodes if available
BOOTNODES_FILE="$CONFIG_DIR/bootnodes.txt"
if [ -f "$BOOTNODES_FILE" ]; then
    BOOTNODES=$(grep -v '^\s*#' "$BOOTNODES_FILE" | grep -v '^\s*$' | tr '\n' ',' | sed 's/,$//')
    if [ -n "$BOOTNODES" ]; then
        ARGS="$ARGS --bootnodes $BOOTNODES"
    fi
fi

echo -e "${GREEN}Starting Quantos Testnet Node...${NC}"
echo ""
echo "  Network:    testnet"
echo "  Chain ID:   2"
echo "  P2P Port:     $P2P_PORT"
echo "  RPC Port:     $RPC_PORT"
echo "  Metrics Port: $METRICS_PORT"
echo "  Data Dir:   $DATA_DIR"
echo "  Genesis:    $GENESIS_FILE"
echo "  Validator:  $VALIDATOR_MODE"
echo ""

# Run the node
cd "$PROJECT_DIR"
exec cargo run --release --bin quantos -- $ARGS
