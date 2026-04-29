#!/usr/bin/env python3
"""Deploy MemecoinToken + MemecoinLaunchpad to Quantos testnet.

Usage:
    python3 scripts/deploy_memecoin.py

Env vars:
    WALLET_SERVER  – wallet-server URL   (default http://127.0.0.1:3001)
    PIN            – wallet pin           (default 999999)
    QTEST_ADDRESS  – QTEST token address  (default from known testnet)
    PLATFORM_WALLET – Vybss platform wallet address
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


def call_contract(session_token, contract_address, calldata_hex):
    return curl_post(f"{WALLET_SERVER}/wallet/call", {
        "session_token": session_token,
        "contract_address": contract_address,
        "calldata_hex": calldata_hex,
    })


def get_selector(contract_json, label):
    for ctor in contract_json.get("spec", {}).get("constructors", []):
        if ctor["label"] == label:
            return bytes.fromhex(ctor["selector"][2:])
    for msg in contract_json.get("spec", {}).get("messages", []):
        if msg["label"] == label:
            return bytes.fromhex(msg["selector"][2:])
    fail(f"Selector not found: {label}")


def main():
    memecoin_dir = Path(__file__).parent.parent / "solidity-contracts" / "memecoin"

    # Check compiled artefacts
    launchpad_wasm = memecoin_dir / "MemecoinLaunchpad.wasm"
    launchpad_meta = memecoin_dir / "MemecoinLaunchpad.contract"
    token_wasm     = memecoin_dir / "MemecoinToken.wasm"
    token_meta     = memecoin_dir / "MemecoinToken.contract"

    for f in [launchpad_wasm, launchpad_meta, token_wasm, token_meta]:
        if not f.exists():
            fail(
                f"Missing {f.name}. Compile first:\n"
                f"  cd {memecoin_dir}\n"
                f"  solang compile MemecoinToken.sol --target polkadot --output .\n"
                f"  solang compile MemecoinLaunchpad.sol --target polkadot --output ."
            )

    launchpad_json = json.loads(launchpad_meta.read_text())
    token_json     = json.loads(token_meta.read_text())

    qtest_addr = os.environ.get(
        "QTEST_ADDRESS",
        "QTS:c49ffa02bdb365b7e5bf1655dd296b7358eebdfdbe2abb3a1998db8daddc3a68",
    ).strip()

    platform_wallet = os.environ.get(
        "PLATFORM_WALLET",
        "QTS:4a3da243bd67a82c741ccafff4fccafa71b6315ca045f812e3ba223890085cff",
    ).strip()

    print("=== Memecoin Launchpad Deployment ===")
    print(f"  QTEST:            {qtest_addr}")
    print(f"  Platform wallet:  {platform_wallet}")

    # ── Create deployer wallet ───────────────────────────────
    wallet_resp = curl_post(f"{WALLET_SERVER}/wallet/create", {"pin": PIN})
    deployer = wallet_resp["wallet"]["address"]
    encrypted_key = wallet_resp["encrypted_key"]
    session = curl_post(f"{WALLET_SERVER}/wallet/unlock", {
        "address": deployer,
        "encrypted_key": encrypted_key,
        "pin": PIN,
    })
    token = session["session_token"]
    print(f"  Deployer:         {deployer}")

    curl_post(f"{WALLET_SERVER}/faucet/claim", {"session_token": token})
    print("  Faucet claimed")

    # ── 1. Deploy MemecoinLaunchpad ──────────────────────────
    print("\n1. Deploying MemecoinLaunchpad...")
    ctor_sel = get_selector(launchpad_json, "new")
    ctor_data = ctor_sel + parse_qts_address(qtest_addr) + parse_qts_address(platform_wallet)
    resp = deploy_contract(token, launchpad_wasm, ctor_data)
    launchpad_addr = resp.get("contract_address") or resp.get("address")
    if not launchpad_addr:
        fail(f"Launchpad deploy failed: {resp}")
    print(f"   MemecoinLaunchpad: {launchpad_addr}")

    # ── 2. Print selectors ───────────────────────────────────
    print("\n2. Launchpad selectors:")
    lp_selectors = {}
    for msg in launchpad_json["spec"]["messages"]:
        label = msg["label"]
        sel = msg["selector"][2:]
        lp_selectors[label] = sel
        print(f"   {label}: {sel}")

    print("\n   Token selectors:")
    tk_selectors = {}
    for msg in token_json["spec"]["messages"]:
        label = msg["label"]
        sel = msg["selector"][2:]
        tk_selectors[label] = sel
        print(f"   {label}: {sel}")

    # Also print token constructor selector (needed by frontend)
    for ctor in token_json["spec"]["constructors"]:
        label = ctor["label"]
        sel = ctor["selector"][2:]
        print(f"   [constructor] {label}: {sel}")

    # ── 3. Save addresses ────────────────────────────────────
    out_file = memecoin_dir / "deployed_memecoin_addresses.txt"
    with open(out_file, "w") as f:
        f.write(f"DEPLOYER={deployer}\n")
        f.write(f"LAUNCHPAD={launchpad_addr}\n")
        f.write(f"QTEST={qtest_addr}\n")
        f.write(f"PLATFORM_WALLET={platform_wallet}\n")
        f.write("\n# Launchpad Selectors\n")
        for label, sel in lp_selectors.items():
            f.write(f"LP_SEL_{label}={sel}\n")
        f.write("\n# Token Selectors\n")
        for label, sel in tk_selectors.items():
            f.write(f"TK_SEL_{label}={sel}\n")

    print(f"\n=== Deployed! Addresses saved to {out_file} ===")
    print(f"\nAdd to vybss/.env:")
    print(f"  VITE_MEMECOIN_LAUNCHPAD_ADDRESS={launchpad_addr}")
    print(json.dumps({
        "deployer": deployer,
        "launchpad": launchpad_addr,
        "qtest": qtest_addr,
        "platform_wallet": platform_wallet,
        "launchpad_selectors": lp_selectors,
        "token_selectors": tk_selectors,
    }, indent=2))


if __name__ == "__main__":
    main()
