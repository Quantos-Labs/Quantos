#!/usr/bin/env python3
"""Deploy VybssLendingPool, VybssLToken, VybssDebtToken to Quantos testnet.

Initializes QTEST and SQTEST reserves with risk parameters.

Usage:
    QTEST_ADDRESS=QTS:... SQTEST_ADDRESS=QTS:... python3 scripts/deploy_lending.py

Environment:
    WALLET_SERVER  - wallet server URL (default: http://127.0.0.1:3001)
    PIN            - wallet pin (default: 999999)
    QTEST_ADDRESS  - QTEST token contract address
    SQTEST_ADDRESS - SQTEST token contract address
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


def encode_bool_le(value):
    """SCALE encoding for bool: single byte."""
    return b"\x01" if value else b"\x00"


def encode_string_scale(s: bytes) -> bytes:
    """SCALE compact encoding for a byte string: compact(len) ++ raw bytes."""
    length = len(s)
    if length < 64:
        compact = bytes([length << 2])
    elif length < 16384:
        compact = (length << 2 | 0x01).to_bytes(2, "little")
    else:
        compact = (length << 2 | 0x02).to_bytes(4, "little")
    return compact + s


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


# ── Reserve configurations ───────────────────────────────────
# Each entry: (symbol, name, icon, ltv_bps, liq_threshold_bps, liq_penalty_bps,
#              reserve_factor_bps, can_be_collateral, can_be_borrowed,
#              optimal_util_bps, base_rate_bps, slope1_bps, slope2_bps,
#              price_usd_1e8, env_key)
# env_key = which env var holds the underlying token address
RESERVES = [
    # symbol, name, icon, ltv, liq_thresh, liq_penalty, reserve_factor,
    # collateral, borrowable, opt_util, base, slope1, slope2, price, env_key
    ("QTEST",  "Quantos Test",   "🔷", 8000, 8500, 500, 1000, True, True, 8000, 200, 400, 7500, 100000000, "QTEST_ADDRESS"),
    ("SQTEST", "Stable QTEST",   "💎", 8500, 9000, 400, 1000, True, True, 9000, 100, 300, 6000, 100000000, "SQTEST_ADDRESS"),
]


def main():
    lending_dir = Path(__file__).parent.parent / "solidity-contracts" / "lending"

    # Check compiled artifacts
    for name in ["VybssLendingPool", "VybssLToken", "VybssDebtToken"]:
        wasm = lending_dir / f"{name}.wasm"
        contract = lending_dir / f"{name}.contract"
        if not wasm.exists() or not contract.exists():
            fail(f"Missing {wasm} or {contract}. Compile first:\n"
                 f"  quantos-sol compile {lending_dir / f'{name}.sol'}")

    # Load contract metadata for selectors
    pool_meta = json.loads((lending_dir / "VybssLendingPool.contract").read_text())
    ltoken_meta = json.loads((lending_dir / "VybssLToken.contract").read_text())
    debt_meta = json.loads((lending_dir / "VybssDebtToken.contract").read_text())

    # Token addresses
    qtest_addr = os.environ.get("QTEST_ADDRESS", "").strip()
    sqtest_addr = os.environ.get("SQTEST_ADDRESS", "").strip()
    if not qtest_addr:
        fail("QTEST_ADDRESS env var required")
    if not sqtest_addr:
        fail("SQTEST_ADDRESS env var required")

    token_addresses = {
        "QTEST_ADDRESS": qtest_addr,
        "SQTEST_ADDRESS": sqtest_addr,
    }

    print("=== Vybss Lending Protocol Deployment ===")
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

    # Fund deployer (claim multiple times for enough gas)
    for _ in range(3):
        try:
            curl_post(f"{WALLET_SERVER}/faucet/claim", {"session_token": token})
        except SystemExit:
            pass
    print("  Faucet claimed")

    # ── 1. Deploy Lending Pool ─────────────────────────────────
    print("\n1. Deploying VybssLendingPool...")
    pool_ctor = get_selector(pool_meta, "new")
    pool_resp = deploy_contract(token, lending_dir / "VybssLendingPool.wasm", pool_ctor)
    pool_addr = pool_resp.get("contract_address") or pool_resp.get("address")
    if not pool_addr:
        fail(f"Pool deploy failed: {pool_resp}")
    print(f"   Pool: {pool_addr}")

    # ── 2. Deploy LTokens + DebtTokens + Init reserves ────────
    init_sel = get_selector(pool_meta, "initReserve")
    set_rate_sel = get_selector(pool_meta, "setInterestRateModel")

    deployed_reserves = []

    for i, (symbol, name, icon, ltv, liq_thresh, liq_penalty,
            reserve_factor, can_collat, can_borrow,
            opt_util, base_rate, slope1, slope2, price_usd, env_key) in enumerate(RESERVES):

        reserve_num = i + 1
        print(f"\n2.{reserve_num}. Setting up {symbol} reserve...")

        # Each reserve uses its own token address
        asset_addr = token_addresses[env_key]
        asset_bytes = parse_qts_address(asset_addr)

        # Deploy LToken
        ltoken_ctor = get_selector(ltoken_meta, "new")
        ltoken_name = f"Vybss {name}".encode("utf-8")
        ltoken_symbol = f"v{symbol}".encode("utf-8")
        # Constructor: (string name, string symbol, address pool, address underlying)
        # SCALE encoding: compact(len) + raw bytes for strings, raw 32-byte for addresses
        ltoken_data = (ltoken_ctor
                       + encode_string_scale(ltoken_name)
                       + encode_string_scale(ltoken_symbol)
                       + parse_qts_address(pool_addr)
                       + asset_bytes)
        ltoken_resp = deploy_contract(token, lending_dir / "VybssLToken.wasm", ltoken_data)
        ltoken_addr = ltoken_resp.get("contract_address") or ltoken_resp.get("address")
        print(f"     LToken (v{symbol}): {ltoken_addr}")

        # Deploy DebtToken
        debt_ctor = get_selector(debt_meta, "new")
        debt_name = f"Vybss {name} Debt".encode("utf-8")
        debt_symbol = f"vDebt{symbol}".encode("utf-8")
        # Constructor: (string name, string symbol, address pool, address underlying)
        debt_data = (debt_ctor
                     + encode_string_scale(debt_name)
                     + encode_string_scale(debt_symbol)
                     + parse_qts_address(pool_addr)
                     + asset_bytes)
        debt_resp = deploy_contract(token, lending_dir / "VybssDebtToken.wasm", debt_data)
        debt_addr = debt_resp.get("contract_address") or debt_resp.get("address")
        print(f"     DebtToken (vDebt{symbol}): {debt_addr}")

        # Initialize reserve in pool
        # initReserve(asset, lToken, debtToken, ltv, liqThresh, liqPenalty, reserveFactor, canCollat, canBorrow)
        init_data = (init_sel
                     + asset_bytes
                     + parse_qts_address(ltoken_addr)
                     + parse_qts_address(debt_addr)
                     + encode_uint256_le(ltv)
                     + encode_uint256_le(liq_thresh)
                     + encode_uint256_le(liq_penalty)
                     + encode_uint256_le(reserve_factor)
                     + encode_bool_le(can_collat)
                     + encode_bool_le(can_borrow))
        call_contract(token, pool_addr, init_data)
        print(f"     Reserve #{reserve_num} initialized")

        # Set interest rate model
        rate_data = (set_rate_sel
                     + encode_uint256_le(reserve_num)
                     + encode_uint256_le(opt_util)
                     + encode_uint256_le(base_rate)
                     + encode_uint256_le(slope1)
                     + encode_uint256_le(slope2))
        call_contract(token, pool_addr, rate_data)
        print(f"     Interest rate model set")

        deployed_reserves.append({
            "id": reserve_num,
            "symbol": symbol,
            "name": name,
            "icon": icon,
            "asset_address": asset_addr,
            "l_token_address": ltoken_addr,
            "debt_token_address": debt_addr,
            "ltv_bps": ltv,
            "liquidation_threshold_bps": liq_thresh,
            "liquidation_penalty_bps": liq_penalty,
            "reserve_factor_bps": reserve_factor,
            "optimal_utilization_bps": opt_util,
            "base_rate_bps": base_rate,
            "slope1_bps": slope1,
            "slope2_bps": slope2,
            "price_usd": price_usd,
        })

    # ── 3. Write addresses ─────────────────────────────────────
    out_file = lending_dir / "deployed_lending_addresses.txt"
    with open(out_file, "w") as f:
        f.write(f"DEPLOYER={deployer}\n")
        f.write(f"LENDING_POOL={pool_addr}\n")
        f.write("\n")
        for r in deployed_reserves:
            f.write(f"RESERVE_{r['symbol']}_ID={r['id']}\n")
            f.write(f"RESERVE_{r['symbol']}_LTOKEN={r['l_token_address']}\n")
            f.write(f"RESERVE_{r['symbol']}_DEBTTOKEN={r['debt_token_address']}\n")

    # Write env fragment
    env_file = lending_dir / "lending_env_fragment.txt"
    with open(env_file, "w") as f:
        f.write(f"VITE_LENDING_POOL_ADDRESS={pool_addr}\n")

    # Write Supabase seed SQL
    seed_file = lending_dir / "lending_seed.sql"
    with open(seed_file, "w") as f:
        f.write("-- Seed lending_reserves table after deployment\n")
        for r in deployed_reserves:
            f.write(f"""INSERT INTO lending_reserves (
  id, asset_address, asset_symbol, asset_name, asset_icon,
  l_token_address, debt_token_address,
  ltv_bps, liquidation_threshold_bps, liquidation_penalty_bps, reserve_factor_bps,
  supply_cap, borrow_cap, can_be_collateral, can_be_borrowed,
  optimal_utilization_bps, base_rate_bps, slope1_bps, slope2_bps,
  price_usd
) VALUES (
  {r['id']}, '{r['asset_address']}', '{r['symbol']}', '{r['name']}', '{r['icon']}',
  '{r['l_token_address']}', '{r['debt_token_address']}',
  {r['ltv_bps']}, {r['liquidation_threshold_bps']}, {r['liquidation_penalty_bps']}, {r['reserve_factor_bps']},
  0, 0, {'true' if True else 'false'}, {'true' if True else 'false'},
  {r['optimal_utilization_bps']}, {r['base_rate_bps']}, {r['slope1_bps']}, {r['slope2_bps']},
  {r['price_usd'] / 1e8}
) ON CONFLICT (id) DO UPDATE SET
  l_token_address = EXCLUDED.l_token_address,
  debt_token_address = EXCLUDED.debt_token_address,
  price_usd = EXCLUDED.price_usd;\n\n""")

    print(f"\n=== Lending Protocol Deployed! ===")
    print(f"  Addresses:  {out_file}")
    print(f"  Env vars:   {env_file}")
    print(f"  DB seed:    {seed_file}")
    print(json.dumps({
        "lending_pool": pool_addr,
        "reserves": deployed_reserves,
    }, indent=2))


if __name__ == "__main__":
    main()
