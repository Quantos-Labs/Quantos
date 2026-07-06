#!/usr/bin/env python3
"""Deploy VybssGrants + initialize on-chain state (round, project, approval).

Usage:
    python3 scripts/setup_grants_onchain.py

This script:
  1. Creates + funds an admin wallet
  2. Deploys VybssGrants(QTEST_ADDRESS)
  3. Creates round 0 (active now → +90 days)
  4. Activates round 0
  5. Submits project 0 in round 0
  6. Approves project 0
  7. Saves credentials to deployment.json
"""
import json
import os
import struct
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


def pad_addr(addr_hex):
    """32-byte address as 64-char hex (for calldata)."""
    cleaned = addr_hex.replace("QTS:", "").replace("qts:", "").replace("0x", "")
    return cleaned.zfill(64)


def pad_uint256_le(value):
    """Encode uint256 as little-endian 32 bytes → 64-char hex."""
    h = format(value, "064x")
    bs = bytes.fromhex(h)
    return bs[::-1].hex()


def get_selector(meta, label):
    for msg in meta["spec"]["messages"]:
        if msg["label"] == label:
            return msg["selector"][2:]  # strip "0x"
    for ctor in meta["spec"]["constructors"]:
        if ctor["label"] == label:
            return ctor["selector"][2:]
    fail(f"Selector not found: {label}")


def call_contract(session, contract_addr, calldata_hex):
    return curl_post(f"{WALLET_SERVER}/wallet/call", {
        "session_token": session,
        "contract_address": contract_addr,
        "calldata_hex": calldata_hex,
        "amount": "0",
    })


def deploy_contract(session, wasm_path, ctor_data_hex):
    with open(wasm_path, "rb") as f:
        bytecode_hex = f.read().hex()
    return curl_post(f"{WALLET_SERVER}/wallet/deploy", {
        "session_token": session,
        "bytecode_hex": bytecode_hex,
        "constructor_data_hex": ctor_data_hex,
    })


def main():
    grants_dir = Path(__file__).parent.parent / "solidity-contracts" / "grants"
    wasm = grants_dir / "VybssGrants.wasm"
    contract_meta = grants_dir / "VybssGrants.contract"
    if not wasm.exists() or not contract_meta.exists():
        fail(f"Missing {wasm} or {contract_meta}. Compile first!")

    meta = json.loads(contract_meta.read_text())

    print("=== VybssGrants Full Setup ===")
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

    # ── 2. Deploy VybssGrants ───────────────────────────────────
    print("\n2. Deploying VybssGrants...")
    ctor_sel = get_selector(meta, "new")
    qtest_bytes = parse_qts_address(QTEST_ADDRESS)
    ctor_data = ctor_sel + qtest_bytes.hex()

    resp = deploy_contract(admin_session, wasm, ctor_data)
    grants_addr = resp.get("contract_address") or resp.get("address")
    if not grants_addr:
        fail(f"Deploy failed: {resp}")
    print(f"   VybssGrants: {grants_addr}")

    # ── 3. Create round 0 ──────────────────────────────────────
    print("\n3. Creating round 0...")
    now = int(time.time())
    start_time = now - 3600          # started 1 hour ago
    end_time = now + 90 * 86400      # ends in 90 days
    matching_pool = 0                 # no initial matching pool

    sel_create = get_selector(meta, "createRound")
    calldata = (
        sel_create
        + pad_uint256_le(start_time)
        + pad_uint256_le(end_time)
        + pad_uint256_le(matching_pool)
    )
    resp = call_contract(admin_session, grants_addr, calldata)
    print(f"   createRound tx: {resp.get('tx_hash', '?')}")

    # ── 4. Activate round 0 ────────────────────────────────────
    print("\n4. Activating round 0...")
    sel_activate = get_selector(meta, "activateRound")
    calldata = sel_activate + pad_uint256_le(0)  # roundId = 0
    resp = call_contract(admin_session, grants_addr, calldata)
    print(f"   activateRound tx: {resp.get('tx_hash', '?')}")

    # ── 5. Submit project 0 in round 0 ─────────────────────────
    print("\n5. Submitting project 0...")
    sel_submit = get_selector(meta, "submitProject")
    calldata = sel_submit + pad_uint256_le(0)  # roundId = 0
    resp = call_contract(admin_session, grants_addr, calldata)
    print(f"   submitProject tx: {resp.get('tx_hash', '?')}")

    # ── 6. Approve project 0 ───────────────────────────────────
    print("\n6. Approving project 0...")
    sel_status = get_selector(meta, "setProjectStatus")
    # uint8 in SCALE = single byte, not padded to 32 bytes
    calldata = (
        sel_status
        + pad_uint256_le(0)  # projectId = 0
        + "01"               # status = PROJECT_APPROVED (uint8 = 1 byte)
    )
    resp = call_contract(admin_session, grants_addr, calldata)
    print(f"   setProjectStatus tx: {resp.get('tx_hash', '?')}")

    # ── 7. Save credentials ────────────────────────────────────
    summary = {
        "grants_address": grants_addr,
        "donation_token": QTEST_ADDRESS,
        "admin_address": admin_addr,
        "admin_encrypted_key": encrypted_key,
        "admin_session": admin_session,
        "onchain_round_id": 0,
        "onchain_project_id": 0,
    }

    out_path = grants_dir / "deployment.json"
    out_path.write_text(json.dumps(summary, indent=2))
    print(f"\n=== Setup Complete ===")
    print(json.dumps(summary, indent=2))
    print(f"\nSaved to {out_path}")
    print(f"\n→ Update VITE_GRANTS_ADDRESS={grants_addr}")


if __name__ == "__main__":
    main()
