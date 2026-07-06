#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from pathlib import Path

WALLET_SERVER = os.environ.get("WALLET_SERVER", "http://127.0.0.1:3001")
PIN = os.environ.get("PIN", "999999")
WASM_PATH = Path(os.environ.get("VAULT_WASM_PATH", "/Users/wayle/Quantos_labs/quantos/test-contracts/build/QuantosBridgeVault.wasm"))
QTEST_ADDRESS = os.environ.get("QTEST_ADDRESS", "").strip()
OWNER_ADDRESS = os.environ.get("OWNER_ADDRESS", "").strip()
BASE_CHAIN_ID = int(os.environ.get("BASE_CHAIN_ID", "84532"))


def fail(message: str):
    print(message, file=sys.stderr)
    sys.exit(1)


def curl_post(url, data):
    payload = json.dumps(data)
    r = subprocess.run(
        [
            "curl", "-s", "-w", "\nHTTP_CODE:%{http_code}", url,
            "-X", "POST",
            "-H", "Content-Type: application/json",
            "--max-time", "30",
            "-d", payload,
        ],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        fail(f"curl error (rc={r.returncode}): {r.stderr}")
    parts = r.stdout.rsplit("\nHTTP_CODE:", 1)
    body = parts[0] if parts else r.stdout
    http_code = parts[1] if len(parts) > 1 else "?"
    print(f"   [HTTP {http_code}] body len={len(body)}")
    if not body.strip():
        fail(f"Empty response body! stderr: {r.stderr[:300]}")
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        fail(f"Bad JSON: {body[:500]}")



def parse_qts_address(value: str) -> bytes:
    cleaned = value.strip()
    if cleaned.startswith("QTS:") or cleaned.startswith("qts:"):
        cleaned = cleaned[4:]
    elif cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    raw = bytes.fromhex(cleaned)
    if len(raw) != 32:
        fail(f"Invalid address length for {value!r}: expected 32 bytes, got {len(raw)}")
    return raw



def encode_uint256_le(value: int) -> bytes:
    if value < 0:
        fail("uint256 cannot be negative")
    return value.to_bytes(32, byteorder="little", signed=False)



def build_constructor_data(token_address: str, owner_address: str, base_chain_id: int) -> str:
    # Constructor selector from QuantosBridgeVault.contract metadata
    selector = bytes.fromhex("fe39a961")
    encoded = b"".join([
        selector,
        parse_qts_address(token_address),
        parse_qts_address(owner_address),
        encode_uint256_le(base_chain_id),
    ])
    return encoded.hex()



def main():
    if not QTEST_ADDRESS:
        fail("QTEST_ADDRESS is required")
    if not WASM_PATH.exists():
        fail(f"Vault WASM not found at {WASM_PATH}")

    print("1. Creating deployer wallet...")
    wallet_resp = curl_post(f"{WALLET_SERVER}/wallet/create", {"pin": PIN})
    deployer_address = wallet_resp["wallet"]["address"]
    encrypted_key = wallet_resp["encrypted_key"]
    print(f"   Address: {deployer_address}")

    print("2. Unlocking wallet...")
    session_resp = curl_post(f"{WALLET_SERVER}/wallet/unlock", {
        "address": deployer_address,
        "encrypted_key": encrypted_key,
        "pin": PIN,
    })
    session_token = session_resp["session_token"]
    print(f"   Session: {session_token[:16]}...")

    owner_address = OWNER_ADDRESS or deployer_address
    print(f"3. Owner: {owner_address}")
    print(f"4. Base chain id: {BASE_CHAIN_ID}")
    print(f"5. QTEST address: {QTEST_ADDRESS}")

    with WASM_PATH.open("rb") as f:
        bytecode_hex = f.read().hex()
    constructor_data_hex = build_constructor_data(QTEST_ADDRESS, owner_address, BASE_CHAIN_ID)

    print("6. Deploying QuantosBridgeVault...")
    deploy_resp = curl_post(f"{WALLET_SERVER}/wallet/deploy", {
        "session_token": session_token,
        "bytecode_hex": bytecode_hex,
        "constructor_data_hex": constructor_data_hex,
    })
    print(json.dumps(deploy_resp, indent=2))

    tx_hash = deploy_resp.get("tx_hash", "unknown")
    print(f"\nVault deploy submitted. tx_hash: {tx_hash}")
    print(f"Deployer: {deployer_address}")
    print(f"Owner: {owner_address}")


if __name__ == "__main__":
    main()
