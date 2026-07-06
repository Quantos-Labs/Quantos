#!/usr/bin/env python3
"""Deploy VybssNFTMarketplace + save deployment info.

Usage:
    python3 scripts/setup_nft_marketplace.py

This script:
  1. Creates + funds an admin wallet
  2. Deploys VybssNFTMarketplace(QTEST_ADDRESS)
  3. Saves credentials to deployment.json
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

WALLET_SERVER = os.environ.get("WALLET_SERVER", "http://127.0.0.1:3001")
PIN = os.environ.get("PIN", "999999")
QTEST_ADDRESS = os.environ.get(
    "QTEST_ADDRESS",
    "QTS:c49ffa02bdb365b7e5bf1655dd296b7358eebdfdbe2abb3a1998db8daddc3a68",
)


def fail(msg):
    print(f"FATAL: {msg}", file=sys.stderr)
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
    http_code = parts[1].strip() if len(parts) > 1 else "?"
    if not body.strip():
        fail(f"Empty response (HTTP {http_code})! stderr: {r.stderr[:300]}")
    if http_code.startswith("4") or http_code.startswith("5"):
        fail(f"HTTP {http_code}: {body[:500]}")
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        fail(f"Bad JSON (HTTP {http_code}): {body[:500]}")


def parse_qts_address(value):
    cleaned = value.strip()
    if cleaned.startswith("QTS:") or cleaned.startswith("qts:"):
        cleaned = cleaned[4:]
    elif cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    raw = bytes.fromhex(cleaned)
    if len(raw) != 32:
        fail(f"Invalid address length: expected 32 bytes, got {len(raw)}")
    return raw


def get_selector(meta, label):
    for msg in meta["spec"]["messages"]:
        if msg["label"] == label:
            return msg["selector"][2:]  # strip "0x"
    for ctor in meta["spec"]["constructors"]:
        if ctor["label"] == label:
            return ctor["selector"][2:]
    fail(f"Selector not found: {label}")


def deploy_contract(session, wasm_path, ctor_data_hex):
    with open(wasm_path, "rb") as f:
        bytecode_hex = f.read().hex()
    return curl_post(f"{WALLET_SERVER}/wallet/deploy", {
        "session_token": session,
        "bytecode_hex": bytecode_hex,
        "constructor_data_hex": ctor_data_hex,
    })


def main():
    mkt_dir = Path(__file__).parent.parent / "solidity-contracts" / "marketplace"
    wasm = mkt_dir / "VybssNFTMarketplace.wasm"
    contract_meta = mkt_dir / "VybssNFTMarketplace.contract"
    if not wasm.exists() or not contract_meta.exists():
        fail(f"Missing {wasm} or {contract_meta}. Run:\n  solang compile VybssNFTMarketplace.sol --target polkadot --output .")

    meta = json.loads(contract_meta.read_text())

    print("=== VybssNFTMarketplace Deployment ===")
    print(f"  QTEST: {QTEST_ADDRESS}")

    # ── 1. Create admin wallet ──────────────────────────────────
    print("\n1. Creating admin wallet...")
    wallet_resp = curl_post(f"{WALLET_SERVER}/wallet/create", {"pin": PIN})
    admin_addr = wallet_resp["wallet"]["address"]
    encrypted_key = wallet_resp["encrypted_key"]
    session_resp = curl_post(f"{WALLET_SERVER}/wallet/unlock", {
        "address": admin_addr,
        "encrypted_key": encrypted_key,
        "pin": PIN,
    })
    admin_session = session_resp["session_token"]
    print(f"   Admin address: {admin_addr}")
    print(f"   Session: {admin_session}")

    # Fund from faucet
    for _ in range(3):
        try:
            curl_post(f"{WALLET_SERVER}/faucet/claim", {"session_token": admin_session})
        except SystemExit:
            pass
    print("   Faucet claimed (x3)")

    # ── 2. Deploy VybssNFTMarketplace ───────────────────────────
    print("\n2. Deploying VybssNFTMarketplace...")
    ctor_sel = get_selector(meta, "new")
    qtest_bytes = parse_qts_address(QTEST_ADDRESS)
    ctor_data = ctor_sel + qtest_bytes.hex()

    resp = deploy_contract(admin_session, wasm, ctor_data)
    mkt_addr = resp.get("contract_address") or resp.get("address")
    if not mkt_addr:
        fail(f"Deploy failed: {resp}")
    print(f"   VybssNFTMarketplace: {mkt_addr}")

    # ── 3. Extract selectors ────────────────────────────────────
    print("\n3. Extracting selectors...")
    selectors = {}
    for msg in meta["spec"]["messages"]:
        selectors[msg["label"]] = msg["selector"]
    print(f"   Found {len(selectors)} selectors")

    # ── 4. Save credentials ─────────────────────────────────────
    summary = {
        "marketplace_address": mkt_addr,
        "payment_token": QTEST_ADDRESS,
        "admin_address": admin_addr,
        "admin_encrypted_key": encrypted_key,
        "admin_session": admin_session,
        "selectors": selectors,
    }

    out_path = mkt_dir / "deployment.json"
    out_path.write_text(json.dumps(summary, indent=2))

    # Also save selectors separately
    sel_path = mkt_dir / "marketplace_selectors.json"
    sel_path.write_text(json.dumps(selectors, indent=2))

    print(f"\n=== Deployment Complete ===")
    print(json.dumps(summary, indent=2))
    print(f"\nSaved to {out_path}")
    print(f"\n→ Add to .env: VITE_NFT_MARKETPLACE_ADDRESS={mkt_addr}")


if __name__ == "__main__":
    main()
