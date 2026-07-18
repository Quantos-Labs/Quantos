#!/usr/bin/env python3
"""Deploy QNS (Quantos Name Service) to Quantos testnet."""
import json, os, subprocess, sys
from pathlib import Path

WALLET_SERVER = os.environ.get("WALLET_SERVER", "http://127.0.0.1:3001")
PIN = os.environ.get("PIN", "999999")

def fail(msg):
    print(msg, file=sys.stderr)
    sys.exit(1)

def curl_post(url, data):
    r = subprocess.run(
        ["curl", "-s", "-w", "\nHTTP_CODE:%{http_code}", url,
         "-X", "POST", "-H", "Content-Type: application/json",
         "--max-time", "30", "-d", json.dumps(data)],
        capture_output=True, text=True)
    if r.returncode != 0:
        fail(f"curl error: {r.stderr}")
    parts = r.stdout.rsplit("\nHTTP_CODE:", 1)
    body, code = parts[0], parts[1] if len(parts) > 1 else "?"
    if not body.strip():
        fail(f"Empty response! stderr: {r.stderr[:300]}")
    if code.startswith("4") or code.startswith("5"):
        fail(f"HTTP {code}: {body[:500]}")
    return json.loads(body)

def main():
    base = Path(__file__).parent.parent / "test-contracts"
    meta = json.loads((base / "QNS.contract").read_text())
    ctor_sel = bytes.fromhex(meta["spec"]["constructors"][0]["selector"][2:])

    w = curl_post(f"{WALLET_SERVER}/wallet/create", {"pin": PIN})
    deployer = w["wallet"]["address"]
    s = curl_post(f"{WALLET_SERVER}/wallet/unlock", {
        "address": deployer, "encrypted_key": w["encrypted_key"], "pin": PIN})
    token = s["session_token"]
    curl_post(f"{WALLET_SERVER}/faucet/claim", {"session_token": token})
    print(f"Deployer: {deployer}")

    bytecode = (base / "QNS.wasm").read_bytes().hex()
    resp = curl_post(f"{WALLET_SERVER}/wallet/deploy", {
        "session_token": token, "bytecode_hex": bytecode,
        "constructor_data_hex": ctor_sel.hex()})
    addr = resp.get("contract_address") or resp.get("address")
    if not addr:
        fail(f"Deploy failed: {resp}")
    print(f"QNS deployed at: {addr}")

    out = base.parent / "solidity-contracts" / "deployed_qns_address.txt"
    with open(out, "w") as f:
        f.write(f"DEPLOYER={deployer}\nQNS={addr}\n")
    print(f"Saved to: {out}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\nERROR: {e}")
        sys.exit(1)
