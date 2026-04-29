#!/usr/bin/env python3
"""Deploy PriceOracle, PerpEngine, and VaultManager contracts to Quantos."""

import json
import os
import subprocess
import sys
from pathlib import Path

WALLET_SERVER = os.environ.get("WALLET_SERVER", "http://127.0.0.1:3001")
PIN = os.environ.get("PIN", "999999")


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
    if not body.strip():
        fail(f"Empty response body! stderr: {r.stderr[:300]}")
    if http_code.startswith("4") or http_code.startswith("5"):
        fail(f"HTTP {http_code}: {body[:500]}")
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
    return value.to_bytes(32, byteorder="little", signed=False)


def deploy_contract(session_token: str, wasm_path: Path, constructor_data: bytes = b"") -> dict:
    with wasm_path.open("rb") as f:
        bytecode_hex = f.read().hex()
    return curl_post(f"{WALLET_SERVER}/wallet/deploy", {
        "session_token": session_token,
        "bytecode_hex": bytecode_hex,
        "constructor_data_hex": constructor_data.hex() if constructor_data else None,
    })


def call_contract(session_token: str, contract_address: str, calldata: bytes) -> dict:
    return curl_post(f"{WALLET_SERVER}/wallet/call", {
        "session_token": session_token,
        "contract_address": contract_address,
        "calldata_hex": calldata.hex(),
        "amount": "0",
    })


def main():
    perp_dir = Path(__file__).parent.parent / "solidity-contracts" / "perp"

    # ── Load contract metadata for selectors ────────────────
    oracle_meta = json.loads((perp_dir / "PriceOracle.contract").read_text())
    engine_meta = json.loads((perp_dir / "PerpEngine.contract").read_text())
    vault_meta  = json.loads((perp_dir / "VaultManager.contract").read_text())

    oracle_ctor = bytes.fromhex(oracle_meta["spec"]["constructors"][0]["selector"][2:])
    engine_ctor = bytes.fromhex(engine_meta["spec"]["constructors"][0]["selector"][2:])
    vault_ctor  = bytes.fromhex(vault_meta["spec"]["constructors"][0]["selector"][2:])

    # Find setOracle selector on PerpEngine
    set_oracle_sel = None
    for msg in engine_meta["spec"]["messages"]:
        if msg["label"] == "setOracle":
            set_oracle_sel = bytes.fromhex(msg["selector"][2:])
            break

    # Find setPerpEngine selector on VaultManager
    set_perp_engine_sel = None
    for msg in vault_meta["spec"]["messages"]:
        if msg["label"] == "setPerpEngine":
            set_perp_engine_sel = bytes.fromhex(msg["selector"][2:])
            break

    # ── Required env vars ────────────────────────────────────
    qtest_address = os.environ.get("QTEST_ADDRESS", "").strip()
    if not qtest_address:
        fail("QTEST_ADDRESS is required in env (QTS:... format)")

    # ── Create deployer wallet ───────────────────────────────
    print("Creating deployer wallet...")
    wallet_resp = curl_post(f"{WALLET_SERVER}/wallet/create", {"pin": PIN})
    deployer_address = wallet_resp["wallet"]["address"]
    encrypted_key = wallet_resp["encrypted_key"]

    print(f"Deployer: {deployer_address}")

    session_resp = curl_post(f"{WALLET_SERVER}/wallet/unlock", {
        "address": deployer_address,
        "encrypted_key": encrypted_key,
        "pin": PIN,
    })
    session_token = session_resp["session_token"]

    # Claim faucet for gas
    print("Claiming faucet...")
    curl_post(f"{WALLET_SERVER}/faucet/claim", {"session_token": session_token})

    # ── 1. Deploy PriceOracle ────────────────────────────────
    print("\n[1/3] Deploying PriceOracle...")
    oracle_deploy = deploy_contract(
        session_token,
        perp_dir / "PriceOracle.wasm",
        oracle_ctor,  # constructor() — no args
    )
    oracle_address = oracle_deploy.get("contract_address") or oracle_deploy.get("address")
    if not oracle_address:
        fail(f"PriceOracle deploy failed: {oracle_deploy}")
    print(f"  PriceOracle: {oracle_address}")

    # ── 2. Deploy PerpEngine(qtest, oracle) ──────────────────
    print("\n[2/3] Deploying PerpEngine...")
    engine_ctor_data = engine_ctor + parse_qts_address(qtest_address) + parse_qts_address(oracle_address)
    engine_deploy = deploy_contract(
        session_token,
        perp_dir / "PerpEngine.wasm",
        engine_ctor_data,
    )
    engine_address = engine_deploy.get("contract_address") or engine_deploy.get("address")
    if not engine_address:
        fail(f"PerpEngine deploy failed: {engine_deploy}")
    print(f"  PerpEngine: {engine_address}")

    # ── 3. Deploy VaultManager(qtest, perpEngine) ────────────
    print("\n[3/3] Deploying VaultManager...")
    vault_ctor_data = vault_ctor + parse_qts_address(qtest_address) + parse_qts_address(engine_address)
    vault_deploy = deploy_contract(
        session_token,
        perp_dir / "VaultManager.wasm",
        vault_ctor_data,
    )
    vault_address = vault_deploy.get("contract_address") or vault_deploy.get("address")
    if not vault_address:
        fail(f"VaultManager deploy failed: {vault_deploy}")
    print(f"  VaultManager: {vault_address}")

    # ── Save deployed addresses ──────────────────────────────
    addresses_file = perp_dir / "deployed_addresses.txt"
    with open(addresses_file, "w") as f:
        f.write(f"DEPLOYER={deployer_address}\n")
        f.write(f"QTEST={qtest_address}\n")
        f.write(f"PRICE_ORACLE={oracle_address}\n")
        f.write(f"PERP_ENGINE={engine_address}\n")
        f.write(f"VAULT_MANAGER={vault_address}\n")

    print(f"\nAddresses saved to: {addresses_file}")
    print(json.dumps({
        "deployer": deployer_address,
        "qtest": qtest_address,
        "price_oracle": oracle_address,
        "perp_engine": engine_address,
        "vault_manager": vault_address,
        "addresses_file": str(addresses_file),
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nDeployment cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nERROR: {e}")
        sys.exit(1)
