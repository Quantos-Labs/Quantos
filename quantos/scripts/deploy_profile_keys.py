#!/usr/bin/env python3
"""Deploy VybssProfileKeys to Quantos testnet.

Usage:
    python3 scripts/deploy_profile_keys.py

The contract takes two constructor args: (paymentToken, protocolWallet).
  - paymentToken defaults to QTEST_ADDRESS env var.
  - protocolWallet defaults to the deployer address.
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
    keys_dir = Path(__file__).parent.parent / "solidity-contracts" / "profile-keys"

    wasm = keys_dir / "VybssProfileKeys.wasm"
    contract_meta = keys_dir / "VybssProfileKeys.contract"
    if not wasm.exists() or not contract_meta.exists():
        fail(f"Missing {wasm} or {contract_meta}. Compile first:\n"
             f"  cd {keys_dir} && solang compile VybssProfileKeys.sol --target polkadot --output .")

    meta = json.loads(contract_meta.read_text())

    qtest_addr = os.environ.get(
        "QTEST_ADDRESS",
        "QTS:c49ffa02bdb365b7e5bf1655dd296b7358eebdfdbe2abb3a1998db8daddc3a68"
    ).strip()

    print("=== VybssProfileKeys Deployment ===")
    print(f"  Payment Token (QTEST): {qtest_addr}")

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
    print(f"  Deployer / Protocol Wallet: {deployer}")

    # Fund deployer
    curl_post(f"{WALLET_SERVER}/faucet/claim", {"session_token": token})
    print("  Faucet claimed")

    # Deploy VybssProfileKeys(paymentToken, protocolWallet)
    # protocolWallet = deployer for now
    print("\n1. Deploying VybssProfileKeys...")
    ctor_sel = get_selector(meta, "new")
    ctor_data = ctor_sel + parse_qts_address(qtest_addr) + parse_qts_address(deployer)
    resp = deploy_contract(token, wasm, ctor_data)
    keys_addr = resp.get("contract_address") or resp.get("address")
    if not keys_addr:
        fail(f"Deploy failed: {resp}")
    print(f"   VybssProfileKeys: {keys_addr}")

    # Extract selectors
    print("\n2. Selectors:")
    selectors = {}
    for msg in meta["spec"]["messages"]:
        label = msg["label"]
        sel = msg["selector"][2:]
        selectors[label] = sel
        print(f"   {label}: {sel}")

    # Write address + selectors
    out_file = keys_dir / "deployed_profile_keys_address.txt"
    with open(out_file, "w") as f:
        f.write(f"DEPLOYER={deployer}\n")
        f.write(f"PROFILE_KEYS={keys_addr}\n")
        f.write(f"QTEST={qtest_addr}\n")
        f.write("\n# Selectors\n")
        for label, sel in selectors.items():
            f.write(f"SEL_{label}={sel}\n")

    print(f"\n=== Deployed! Address saved to {out_file} ===")
    print(f"\nAdd to vybss/.env:")
    print(f"  VITE_PROFILE_KEYS_CONTRACT_ADDRESS={keys_addr}")
    print(json.dumps({
        "deployer": deployer,
        "profile_keys": keys_addr,
        "qtest": qtest_addr,
        "selectors": selectors,
    }, indent=2))


if __name__ == "__main__":
    main()
