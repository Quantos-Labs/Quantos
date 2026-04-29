#!/usr/bin/env python3
"""Deploy VybssFactory, VybssPool, VybssRouter to Quantos testnet.

Creates a QTEST/SQTEST pool with 0.30% fee tier as the initial pool.

Usage:
    QTEST_ADDRESS=QTS:... SQTEST_ADDRESS=QTS:... python3 scripts/deploy_dex.py
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


def encode_uint256_le(value):
    return value.to_bytes(32, byteorder="little", signed=False)


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
    dex_dir = Path(__file__).parent.parent / "solidity-contracts" / "dex"

    # Check compiled artifacts exist
    for name in ["VybssPool", "VybssFactory", "VybssRouter"]:
        wasm = dex_dir / f"{name}.wasm"
        contract = dex_dir / f"{name}.contract"
        if not wasm.exists() or not contract.exists():
            fail(f"Missing {wasm} or {contract}. Run compilation first:\n"
                 f"  quantos-sol compile {dex_dir / f'{name}.sol'}")

    # Load contract metadata
    factory_meta = json.loads((dex_dir / "VybssFactory.contract").read_text())
    pool_meta = json.loads((dex_dir / "VybssPool.contract").read_text())
    router_meta = json.loads((dex_dir / "VybssRouter.contract").read_text())

    # Get token addresses from env
    qtest_addr = os.environ.get("QTEST_ADDRESS", "").strip()
    sqtest_addr = os.environ.get("SQTEST_ADDRESS", "").strip()
    if not qtest_addr or not sqtest_addr:
        fail("QTEST_ADDRESS and SQTEST_ADDRESS env vars required")

    print("=== Vybss DEX Deployment ===")
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

    # 1. Deploy Factory
    print("\n1. Deploying VybssFactory...")
    factory_ctor = get_selector(factory_meta, "new")
    factory_resp = deploy_contract(token, dex_dir / "VybssFactory.wasm", factory_ctor)
    factory_addr = factory_resp.get("contract_address") or factory_resp.get("address")
    if not factory_addr:
        fail(f"Factory deploy failed: {factory_resp}")
    print(f"   Factory: {factory_addr}")

    # 2. Deploy Pool (QTEST/SQTEST, 30bps fee, initial price = 1:1)
    print("\n2. Deploying VybssPool (QTEST/SQTEST 0.30%)...")
    # Sort tokens
    qtest_bytes = parse_qts_address(qtest_addr)
    sqtest_bytes = parse_qts_address(sqtest_addr)
    t0_bytes, t1_bytes = (qtest_bytes, sqtest_bytes) if qtest_bytes < sqtest_bytes else (sqtest_bytes, qtest_bytes)
    t0_addr = f"QTS:{t0_bytes.hex()}" if qtest_bytes < sqtest_bytes else f"QTS:{sqtest_bytes.hex()}"
    t1_addr = f"QTS:{t1_bytes.hex()}" if qtest_bytes < sqtest_bytes else f"QTS:{qtest_bytes.hex()}"

    # Initial sqrtPriceX64 = 2^64 (price ratio 1:1)
    init_price = 1 << 64

    pool_ctor = get_selector(pool_meta, "new")
    pool_ctor_data = pool_ctor + t0_bytes + t1_bytes + encode_uint256_le(30) + encode_uint256_le(init_price)
    pool_resp = deploy_contract(token, dex_dir / "VybssPool.wasm", pool_ctor_data)
    pool_addr = pool_resp.get("contract_address") or pool_resp.get("address")
    if not pool_addr:
        fail(f"Pool deploy failed: {pool_resp}")
    print(f"   Pool: {pool_addr}")

    # 3. Deploy Router
    print("\n3. Deploying VybssRouter...")
    router_ctor = get_selector(router_meta, "new")
    router_ctor_data = router_ctor + parse_qts_address(factory_addr)
    router_resp = deploy_contract(token, dex_dir / "VybssRouter.wasm", router_ctor_data)
    router_addr = router_resp.get("contract_address") or router_resp.get("address")
    if not router_addr:
        fail(f"Router deploy failed: {router_resp}")
    print(f"   Router: {router_addr}")

    # 4. Register pool in factory
    print("\n4. Registering pool in factory...")
    reg_sel = get_selector(factory_meta, "registerPool")
    reg_data = reg_sel + t0_bytes + t1_bytes + encode_uint256_le(30) + parse_qts_address(pool_addr)
    call_contract(token, factory_addr, reg_data)
    print("   Pool registered!")

    # Write addresses
    out_file = dex_dir / "deployed_dex_addresses.txt"
    with open(out_file, "w") as f:
        f.write(f"DEPLOYER={deployer}\n")
        f.write(f"FACTORY={factory_addr}\n")
        f.write(f"POOL_QTEST_SQTEST={pool_addr}\n")
        f.write(f"ROUTER={router_addr}\n")
        f.write(f"TOKEN0={t0_addr}\n")
        f.write(f"TOKEN1={t1_addr}\n")

    print(f"\n=== Deployed! Addresses saved to {out_file} ===")
    print(json.dumps({
        "deployer": deployer,
        "factory": factory_addr,
        "pool": pool_addr,
        "router": router_addr,
        "token0": t0_addr,
        "token1": t1_addr,
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: {e}")
        sys.exit(1)
