#!/usr/bin/env python3
"""Deploy VybssOTCSwap to Quantos testnet.

Usage:
    QTEST_ADDRESS=QTS:c49ffa02bdb365b7e5bf1655dd296b7358eebdfdbe2abb3a1998db8daddc3a68 \
    SQTEST_ADDRESS=QTS:7c6e716241b00d39466021064aff611b0271c94cf9d61c2442c57b6be14206e7 \
    python3 scripts/deploy_otc.py
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


def get_selector(contract_json, label):
    for ctor in contract_json["spec"]["constructors"]:
        if ctor["label"] == label:
            return bytes.fromhex(ctor["selector"][2:])
    for msg in contract_json["spec"]["messages"]:
        if msg["label"] == label:
            return bytes.fromhex(msg["selector"][2:])
    fail(f"Selector not found: {label}")


def main():
    otc_dir = Path(__file__).parent.parent / "solidity-contracts" / "otc"

    wasm = otc_dir / "VybssOTCSwap.wasm"
    contract_meta = otc_dir / "VybssOTCSwap.contract"
    if not wasm.exists() or not contract_meta.exists():
        fail(f"Missing {wasm} or {contract_meta}. Compile first:\n"
             f"  solang compile {otc_dir / 'VybssOTCSwap.sol'} --target polkadot --output {otc_dir}")

    meta = json.loads(contract_meta.read_text())

    qtest_addr = os.environ.get("QTEST_ADDRESS", "QTS:c49ffa02bdb365b7e5bf1655dd296b7358eebdfdbe2abb3a1998db8daddc3a68").strip()
    sqtest_addr = os.environ.get("SQTEST_ADDRESS", "QTS:7c6e716241b00d39466021064aff611b0271c94cf9d61c2442c57b6be14206e7").strip()

    print("=== VybssOTCSwap Deployment ===")
    print(f"  QTEST:  {qtest_addr}")
    print(f"  SQTEST: {sqtest_addr}")

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
    curl_post(f"{WALLET_SERVER}/faucet/claim", {"session_token": token})
    print("  Faucet claimed")

    # Deploy VybssOTCSwap(qtest, sqtest)
    print("\n1. Deploying VybssOTCSwap...")
    ctor_sel = get_selector(meta, "new")
    ctor_data = ctor_sel + parse_qts_address(qtest_addr) + parse_qts_address(sqtest_addr)
    resp = deploy_contract(token, wasm, ctor_data)
    otc_addr = resp.get("contract_address") or resp.get("address")
    if not otc_addr:
        fail(f"Deploy failed: {resp}")
    print(f"   VybssOTCSwap: {otc_addr}")

    # Extract selectors
    print("\n2. Selectors:")
    selectors = {}
    for msg in meta["spec"]["messages"]:
        label = msg["label"]
        sel = msg["selector"][2:]
        selectors[label] = sel
        print(f"   {label}: {sel}")

    # Write address + selectors
    out_file = otc_dir / "deployed_otc_address.txt"
    with open(out_file, "w") as f:
        f.write(f"DEPLOYER={deployer}\n")
        f.write(f"OTC_SWAP={otc_addr}\n")
        f.write(f"QTEST={qtest_addr}\n")
        f.write(f"SQTEST={sqtest_addr}\n")
        f.write("\n# Selectors\n")
        for label, sel in selectors.items():
            f.write(f"SEL_{label}={sel}\n")

    print(f"\n=== Deployed! Address saved to {out_file} ===")
    print(f"\nAdd to vybss/.env:")
    print(f"  VITE_OTC_CONTRACT_ADDRESS={otc_addr}")
    print(json.dumps({
        "deployer": deployer,
        "otc_swap": otc_addr,
        "qtest": qtest_addr,
        "sqtest": sqtest_addr,
        "selectors": selectors,
    }, indent=2))


if __name__ == "__main__":
    main()
