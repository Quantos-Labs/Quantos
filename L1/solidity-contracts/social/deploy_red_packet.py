#!/usr/bin/env python3
"""
Deploy VybssRedPacket contract via wallet server.

Usage:
  1. Compile VybssRedPacket.sol with Solang:
       solang compile VybssRedPacket.sol --target substrate -o build/
  2. Run this script:
       python3 deploy_red_packet.py

  3. Copy the printed contract address into your .env:
       VITE_RED_PACKET_CONTRACT_ADDRESS=QTS:<address>
"""

import json
import os
import subprocess
import sys
from pathlib import Path

WALLET_SERVER = os.getenv("WALLET_SERVER", "http://127.0.0.1:3001")
PIN           = os.getenv("DEPLOY_PIN", "999999")
SCRIPT_DIR    = Path(__file__).parent
WASM_PATH     = SCRIPT_DIR / "VybssRedPacket.wasm"
META_PATH     = SCRIPT_DIR / "VybssRedPacket.contract"


def curl_post(url, data):
    payload = json.dumps(data)
    r = subprocess.run(
        ["curl", "-s", "-w", "\nHTTP_CODE:%{http_code}", url,
         "-X", "POST", "-H", "Content-Type: application/json",
         "--max-time", "60", "-d", payload],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(f"curl error (rc={r.returncode}): {r.stderr}", file=sys.stderr)
        sys.exit(1)
    parts = r.stdout.rsplit("\nHTTP_CODE:", 1)
    body     = parts[0] if parts else r.stdout
    http_code = parts[1] if len(parts) > 1 else "?"
    print(f"   [HTTP {http_code}] body len={len(body)}")
    if not body.strip():
        print(f"   Empty response! stderr: {r.stderr[:300]}", file=sys.stderr)
        sys.exit(1)
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        print(f"Bad JSON: {body[:500]}", file=sys.stderr)
        sys.exit(1)


def read_constructor_selector():
    if not META_PATH.exists():
        print(f"  Warning: {META_PATH} not found, using empty constructor selector")
        return ""
    spec = json.loads(META_PATH.read_text()).get("spec", {})
    constructors = spec.get("constructors", [])
    if not constructors:
        return ""
    return constructors[0]["selector"].removeprefix("0x")


def main():
    # Verify WASM exists
    if not WASM_PATH.exists():
        print(f"Error: {WASM_PATH} not found.", file=sys.stderr)
        print("Compile first:  solang compile VybssRedPacket.sol --target substrate -o build/", file=sys.stderr)
        sys.exit(1)

    print("1. Creating deployer wallet...")
    wallet_resp    = curl_post(f"{WALLET_SERVER}/wallet/create", {"pin": PIN})
    address        = wallet_resp["wallet"]["address"]
    encrypted_key  = wallet_resp["encrypted_key"]
    print(f"   Address: {address}")

    print("2. Unlocking wallet...")
    session_resp  = curl_post(f"{WALLET_SERVER}/wallet/unlock", {
        "address": address, "encrypted_key": encrypted_key, "pin": PIN,
    })
    token = session_resp["session_token"]
    print(f"   Session: {token[:16]}...")

    print("3. Reading VybssRedPacket.wasm...")
    with open(WASM_PATH, "rb") as f:
        bytecode_hex = f.read().hex()
    print(f"   Bytecode: {len(bytecode_hex) // 2} bytes")
    constructor_data_hex = read_constructor_selector()

    print("4. Deploying VybssRedPacket contract...")
    deploy_resp = curl_post(f"{WALLET_SERVER}/wallet/deploy", {
        "session_token":         token,
        "bytecode_hex":          bytecode_hex,
        "constructor_data_hex":  constructor_data_hex,
    })
    print(f"   Deploy response: {json.dumps(deploy_resp, indent=2)}")

    tx_hash = deploy_resp.get("tx_hash", "unknown")
    print(f"\n✓ VybssRedPacket deployed!")
    print(f"  tx_hash:  {tx_hash}")
    print(f"  Deployer: {address}")
    print(f"\n  Add to your .env:")
    print(f"  VITE_RED_PACKET_CONTRACT_ADDRESS={address}")


if __name__ == "__main__":
    main()
