#!/bin/bash
# Quantos Devnet Launch Script
# 
# Single-node local development network
# Fast block times, pre-funded accounts

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="$PROJECT_DIR/config"
DATA_DIR="$PROJECT_DIR/data/devnet"

echo "═══════════════════════════════════════════════════════════════"
echo "  Quantos Devnet (Local Development)"
echo "═══════════════════════════════════════════════════════════════"

# Initialize genesis if needed
GENESIS_FILE="$CONFIG_DIR/devnet-genesis.json"
if [ ! -f "$GENESIS_FILE" ]; then
    echo "Initializing devnet genesis..."
    cd "$PROJECT_DIR"
    cargo run --release -- init --network devnet --output "$GENESIS_FILE"
fi

# Create data directory
mkdir -p "$DATA_DIR"

# Default ports for devnet
P2P_PORT=${QUANTOS_P2P_PORT:-30304}
RPC_PORT=${QUANTOS_RPC_PORT:-8546}
METRICS_PORT=${QUANTOS_METRICS_PORT:-9616}

echo ""
echo "  Network:      devnet"
echo "  Chain ID:     3"
echo "  P2P Port:     $P2P_PORT"
echo "  RPC Port:     $RPC_PORT"
echo "  Metrics Port: $METRICS_PORT"
echo "  Data Dir:     $DATA_DIR"
echo ""
echo "Pre-funded accounts available for testing"
echo ""

cd "$PROJECT_DIR"
exec cargo run --release -- \
    --network devnet \
    --genesis "$GENESIS_FILE" \
    --datadir "$DATA_DIR" \
    --p2p-port $P2P_PORT \
    --rpc-port $RPC_PORT \
    --metrics-port $METRICS_PORT
