#!/bin/bash
# Build Quantos wallet WASM package
# Requires: wasm-pack (cargo install wasm-pack)

set -e

echo "Building quantos-wallet-core WASM..."
wasm-pack build --target web --out-dir pkg --release

echo "Done! Output in ./pkg/"
echo "Import in TypeScript: import init, { generateKeypair, sign, verify } from 'quantos-wallet-core'"
