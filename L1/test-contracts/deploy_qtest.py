#!/usr/bin/env python3
"""Deploy QTEST contract via wallet server (signed transaction)."""

import json
import subprocess
import sys
from pathlib import Path

WALLET_SERVER = "http://127.0.0.1:3001"
PIN = "999999"
WASM_PATH = "/Users/wayle/Quantos_labs/quantos/test-contracts/build/QTEST.wasm"
CONTRACT_METADATA_PATH = "/Users/wayle/Quantos_labs/quantos/test-contracts/build/QTEST.contract"


def curl_post(url, data):
    payload = json.dumps(data)
    r = subprocess.run(
        ["curl", "-s", "-w", "\nHTTP_CODE:%{http_code}", url, "-X", "POST",
         "-H", "Content-Type: application/json",
         "--max-time", "30",
         "-d", payload],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        print(f"curl error (rc={r.returncode}): {r.stderr}", file=sys.stderr)
        sys.exit(1)
    parts = r.stdout.rsplit("\nHTTP_CODE:", 1)
    body = parts[0] if parts else r.stdout
    http_code = parts[1] if len(parts) > 1 else "?"
    print(f"   [HTTP {http_code}] body len={len(body)}")
    if not body.strip():
        print(f"   Empty response body! stderr: {r.stderr[:300]}", file=sys.stderr)
        sys.exit(1)
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        print(f"Bad JSON: {body[:500]}", file=sys.stderr)
        sys.exit(1)


def read_constructor_selector():
    spec = json.loads(Path(CONTRACT_METADATA_PATH).read_text()).get("spec", {})
    constructors = spec.get("constructors", [])
    if not constructors:
        return ""
    return constructors[0]["selector"].removeprefix("0x")


def main():
    # 1. Create deployer wallet
    print("1. Creating deployer wallet...")
    wallet_resp = curl_post(f"{WALLET_SERVER}/wallet/create", {"pin": PIN})
    address = wallet_resp["wallet"]["address"]
    encrypted_key = wallet_resp["encrypted_key"]
    print(f"   Address: {address}")

    # 2. Unlock wallet → session token
    print("2. Unlocking wallet...")
    session_resp = curl_post(f"{WALLET_SERVER}/wallet/unlock", {
        "address": address,
        "encrypted_key": encrypted_key,
        "pin": PIN,
    })
    token = session_resp["session_token"]
    print(f"   Session: {token[:16]}...")

    # 3. Read QTEST.wasm bytecode
    print("3. Reading QTEST.wasm...")
    with open(WASM_PATH, "rb") as f:
        bytecode_hex = f.read().hex()
    print(f"   Bytecode: {len(bytecode_hex) // 2} bytes")
    constructor_data_hex = read_constructor_selector()

    # 4. Deploy via signed transaction
    print("4. Deploying QTEST contract...")
    deploy_resp = curl_post(f"{WALLET_SERVER}/wallet/deploy", {
        "session_token": token,
        "bytecode_hex": bytecode_hex,
        "constructor_data_hex": constructor_data_hex,
    })
    print(f"   Deploy response: {json.dumps(deploy_resp, indent=2)}")

    tx_hash = deploy_resp.get("tx_hash", "unknown")
    print(f"\n✓ QTEST deployed! tx_hash: {tx_hash}")
    print(f"  Deployer: {address}")


if __name__ == "__main__":
    main()
