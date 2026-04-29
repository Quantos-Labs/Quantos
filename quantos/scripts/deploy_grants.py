#!/usr/bin/env python3
"""Deploy VybssGrants to Quantos testnet.

Usage:
    QTEST_ADDRESS=QTS:... python3 scripts/deploy_grants.py

Environment:
    WALLET_SERVER  - wallet server URL (default: http://127.0.0.1:3001)
    PIN            - wallet pin (default: 999999)
    QTEST_ADDRESS  - QTEST token contract address (donation token)
"""
import json
import os
import subprocess
import sys
from pathlib import Path

WALLET_SERVER = os.environ.get("WALLET_SERVER", "http://127.0.0.1:3001")
PIN = os.environ.get("PIN", "999999")


def fail(msg):
    print(msg, file=sys.stderr)
    sys.exit(1)


def curl_post(url, data):
    payload = json.dumps(data)
    r = subprocess.run(
        ["curl", "-s", "-w", "\nHTTP_CODE:%{http_code}", url,
         "-X", "POST", "-H", "Content-Type: application/json",
         "--max-time", "30", "-d", payload],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        fail(f"curl error (rc={r.returncode}): {r.stderr}")
    parts = r.stdout.rsplit("\nHTTP_CODE:", 1)
    body = parts[0] if parts else r.stdout
    http_code = parts[1] if len(parts) > 1 else "?"
    if not body.strip():
        fail(f"Empty response! stderr: {r.stderr[:300]}")
    if http_code.startswith("4") or http_code.startswith("5"):
        fail(f"HTTP {http_code}: {body[:500]}")
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        fail(f"Bad JSON: {body[:500]}")


def parse_qts_address(value):
    cleaned = value.strip()
    if cleaned.startswith("QTS:") or cleaned.startswith("qts:"):
        cleaned = cleaned[4:]
    elif cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    raw = bytes.fromhex(cleaned)
    if len(raw) != 32:
        fail(f"Invalid address length for {value!r}: expected 32 bytes, got {len(raw)}")
    return raw


def deploy_contract(session_token, wasm_path, constructor_data=b""):
    with wasm_path.open("rb") as f:
        bytecode_hex = f.read().hex()
    return curl_post(f"{WALLET_SERVER}/wallet/deploy", {
        "session_token": session_token,
        "bytecode_hex": bytecode_hex,
        "constructor_data_hex": constructor_data.hex() if constructor_data else None,
    })


def call_contract(session_token, contract_address, calldata):
    return curl_post(f"{WALLET_SERVER}/wallet/call", {
        "session_token": session_token,
        "contract_address": contract_address,
        "calldata_hex": calldata.hex(),
        "amount": "0",
    })


def get_selector(contract_json, label):
    for msg in contract_json["spec"]["messages"]:
        if msg["label"] == label:
            return bytes.fromhex(msg["selector"][2:])
    for ctor in contract_json["spec"]["constructors"]:
        if ctor["label"] == "new":
            return bytes.fromhex(ctor["selector"][2:])
    fail(f"Selector not found: {label}")


def main():
    grants_dir = Path(__file__).parent.parent / "solidity-contracts" / "grants"

    # Check compiled artifacts
    wasm = grants_dir / "VybssGrants.wasm"
    contract = grants_dir / "VybssGrants.contract"
    if not wasm.exists() or not contract.exists():
        fail(f"Missing {wasm} or {contract}. Compile first:\n"
             f"  quantos-sol compile {grants_dir / 'VybssGrants.sol'}")

    # Load metadata for selectors
    meta = json.loads(contract.read_text())

    # QTEST address
    qtest_addr = os.environ.get("QTEST_ADDRESS", "").strip()
    if not qtest_addr:
        fail("QTEST_ADDRESS env var required")

    print("=== Vybss Grants Deployment ===")
    print(f"  QTEST: {qtest_addr}")

    # Create deployer wallet
    wallet_resp = curl_post(f"{WALLET_SERVER}/wallet/create", {"pin": PIN})
    deployer = wallet_resp["wallet"]["address"]
    encrypted_key = wallet_resp["encrypted_key"]
    session = curl_post(f"{WALLET_SERVER}/wallet/unlock", {
        "address": deployer,
        "encrypted_key": encrypted_key,
        "pin": PIN,
    })
    token = session["session_token"]
    print(f"  Deployer: {deployer}")

    # Fund deployer
    for _ in range(3):
        try:
            curl_post(f"{WALLET_SERVER}/faucet/claim", {"session_token": token})
        except SystemExit:
            pass
    print("  Faucet claimed")

    # ── Deploy VybssGrants ─────────────────────────────────────
    print("\n1. Deploying VybssGrants...")

    # Constructor: constructor(address _donationToken)
    ctor_sel = get_selector(meta, "new")
    qtest_bytes = parse_qts_address(qtest_addr)
    ctor_data = ctor_sel + qtest_bytes

    resp = deploy_contract(token, wasm, ctor_data)
    grants_addr = resp.get("contract_address") or resp.get("address")
    if not grants_addr:
        fail(f"Deploy failed: {resp}")

    print(f"   VybssGrants: {grants_addr}")

    # ── Summary ────────────────────────────────────────────────
    summary = {
        "grants_address": grants_addr,
        "donation_token": qtest_addr,
        "deployer": deployer,
    }

    print("\n=== Deployment Complete ===")
    print(json.dumps(summary, indent=2))

    # Save to file
    out_path = grants_dir / "deployment.json"
    out_path.write_text(json.dumps(summary, indent=2))
    print(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
