#!/bin/bash
# ============================================================================
# Quantos Devnet Bootstrap
# ============================================================================
#
# Generates genesis config and a single validator key for local development.
# Run this ONCE before starting the devnet.
#
# Usage:
#   cd networks/devnet
#   ./bootstrap.sh
#   docker compose up -d
#
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}"
echo "═══════════════════════════════════════════════════════════════"
echo "  Quantos Devnet Bootstrap"
echo "  Chain ID: 3 | Block time: 100ms | Shards: 1"
echo "═══════════════════════════════════════════════════════════════"
echo -e "${NC}"

# Check if already bootstrapped
if [ -f "$SCRIPT_DIR/genesis/devnet-genesis.json" ]; then
    echo -e "${YELLOW}Devnet already bootstrapped.${NC}"
    read -p "Re-bootstrap? This will RESET the genesis and key. (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

# Build
echo -e "${BLUE}[1/3] Building Quantos...${NC}"
cd "$PROJECT_DIR"
cargo build --release --bin quantos 2>&1 | tail -1
QUANTOS_BIN="$PROJECT_DIR/target/release/quantos"

if [ ! -f "$QUANTOS_BIN" ]; then
    echo -e "${RED}Build failed.${NC}"
    exit 1
fi

# Generate validator key
echo -e "${BLUE}[2/3] Generating validator key...${NC}"
mkdir -p "$SCRIPT_DIR/keys"
$QUANTOS_BIN generate-key -o "$SCRIPT_DIR/keys/validator-key.json"
echo -e "  ${GREEN}✓ Validator key generated${NC}"

# Generate genesis
echo -e "${BLUE}[3/3] Generating devnet genesis...${NC}"
mkdir -p "$SCRIPT_DIR/genesis"
$QUANTOS_BIN init --network devnet --output "$SCRIPT_DIR/genesis/devnet-genesis.json"

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Devnet bootstrapped!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Genesis:   $SCRIPT_DIR/genesis/devnet-genesis.json"
echo "  Validator: $SCRIPT_DIR/keys/validator-key.json"
echo ""
echo "  No pre-funded accounts (only validator stake)"
echo "  Block time: 200ms | Epoch: 16 slots | Dynamic sharding enabled"
echo ""
echo "  Start:"
echo "    docker compose up -d"
echo ""
echo "  Check:"
echo "    quantos-cli --rpc http://localhost:8545 node health"
echo ""
echo "  Reset:"
echo "    docker compose down -v && ./bootstrap.sh"
echo ""
