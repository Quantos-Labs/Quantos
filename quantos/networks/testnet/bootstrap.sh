#!/bin/bash
# ============================================================================
# Quantos Testnet Bootstrap
# ============================================================================
#
# Generates genesis config and 4 validator keys for the testnet.
# Run this ONCE before starting the network.
#
# Usage:
#   cd networks/testnet
#   ./bootstrap.sh
#   docker compose up -d
#
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "═══════════════════════════════════════════════════════════════"
echo "  Quantos Testnet Bootstrap"
echo "  Chain ID: 2 | Validators: 4 | Shards: 4"
echo "═══════════════════════════════════════════════════════════════"
echo -e "${NC}"

# Check if already bootstrapped
if [ -f "$SCRIPT_DIR/genesis/testnet-genesis.json" ]; then
    echo -e "${YELLOW}Testnet already bootstrapped.${NC}"
    echo "  Genesis: $SCRIPT_DIR/genesis/testnet-genesis.json"
    echo ""
    read -p "Re-bootstrap? This will RESET all keys and genesis. (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
    echo -e "${YELLOW}Resetting testnet state...${NC}"
fi

# Build if needed
echo -e "${BLUE}[1/3] Building Quantos...${NC}"
cd "$PROJECT_DIR"
cargo build --release --bin quantos 2>&1 | tail -1
QUANTOS_BIN="$PROJECT_DIR/target/release/quantos"

if [ ! -f "$QUANTOS_BIN" ]; then
    echo -e "${RED}Build failed. Cannot find $QUANTOS_BIN${NC}"
    exit 1
fi

# Generate validator keys
echo -e "${BLUE}[2/3] Generating validator keys...${NC}"
for i in 1 2 3 4; do
    KEY_DIR="$SCRIPT_DIR/keys/validator-$i"
    mkdir -p "$KEY_DIR"
    $QUANTOS_BIN generate-key -o "$KEY_DIR/validator-key.json"
    echo -e "  ${GREEN}✓ Validator $i key generated${NC}"
done

# Generate genesis
echo -e "${BLUE}[3/3] Generating testnet genesis...${NC}"
mkdir -p "$SCRIPT_DIR/genesis"
$QUANTOS_BIN init --network testnet --output "$SCRIPT_DIR/genesis/testnet-genesis.json"

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Testnet bootstrapped successfully!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Genesis:     $SCRIPT_DIR/genesis/testnet-genesis.json"
echo "  Validator 1: $SCRIPT_DIR/keys/validator-1/validator-key.json"
echo "  Validator 2: $SCRIPT_DIR/keys/validator-2/validator-key.json"
echo "  Validator 3: $SCRIPT_DIR/keys/validator-3/validator-key.json"
echo "  Validator 4: $SCRIPT_DIR/keys/validator-4/validator-key.json"
echo ""
echo "  Start the network:"
echo "    docker compose up -d"
echo ""
echo "  Start with monitoring:"
echo "    docker compose --profile monitoring up -d"
echo ""
echo "  Check status:"
echo "    quantos-cli --rpc http://localhost:8545 node health"
echo ""
