#!/usr/bin/env bash
# Stops the local Quantos testnet started by start-testnet.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
PID_FILE="$ROOT_DIR/data/testnet.pid"

if [ ! -f "$PID_FILE" ]; then
    echo "⚠️  No testnet PID file found at $PID_FILE"
    echo "   Testnet may not be running."
    exit 0
fi

echo "🛑 Stopping Quantos testnet..."
while read -r pid; do
    if kill "$pid" 2>/dev/null; then
        echo "  Stopped PID $pid"
    else
        echo "  PID $pid not running"
    fi
done < "$PID_FILE"

rm -f "$PID_FILE"
echo "✅ Testnet stopped."
