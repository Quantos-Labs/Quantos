#!/usr/bin/env python3
"""Deploy insQTEST + VybssInsurancePool via quantos-wallet-server.

Compile first:
  cd quantos/solidity-contracts/insurance
  solang compile insQTEST.sol --target polkadot --output .
  solang compile VybssInsurancePool.sol --target polkadot --output .

Required env:
  STQTEST_ADDRESS=QTS:<stqtest_contract>

Optional env:
  WALLET_SERVER=http://127.0.0.1:3001
  DEPLOY_PIN=999999
  PREMIUM_RATE_BPS=200        (2 % annual, default)
  COVERAGE_RATIO_BPS=10000    (10x leverage, default)
  COOLDOWN_SECONDS=604800     (7 days, default)
"""

import json
import os
import subprocess
import sys
from pathlib import Path

WALLET_SERVER = os.getenv("WALLET_SERVER", "http://127.0.0.1:3001")
PIN = os.getenv("DEPLOY_PIN", "999999")
SCRIPT_DIR = Path(__file__).parent


def fail(message: str):
    print(message, file=sys.stderr)
    sys.exit(1)


def curl_post(url, data):
    payload = json.dumps(data)
    r = subprocess.run(
        [
            "curl", "-s",
            "-w", "\nHTTP_CODE:%{http_code}",
            url, "-X", "POST",
            "-H", "Content-Type: application/json",
            "--max-time", "60",
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
    if http_code.startswith("4") or http_code.startswith("5"):
        fail(f"HTTP {http_code}: {body[:1000]}")
    try:
        return json.loads(body) if body.strip() else {}
    except json.JSONDecodeError:
        fail(f"Bad JSON: {body[:1000]}")


def parse_qts_address(value: str) -> bytes:
    cleaned = value.strip()
    for prefix in ("QTS:", "qts:", "0x"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix):]
            break
    raw = bytes.fromhex(cleaned)
    if len(raw) != 32:
        fail(f"Invalid address length for {value!r}: expected 32 bytes, got {len(raw)}")
    return raw


def encode_uint256_le(value: int) -> bytes:
    return value.to_bytes(32, byteorder="little", signed=False)


def load_meta(name: str) -> dict:
    path = SCRIPT_DIR / f"{name}.contract"
    if not path.exists():
        fail(f"Missing {path}. Compile {name}.sol first.")
    return json.loads(path.read_text())


def selector(meta: dict, label: str, section: str = "messages") -> bytes:
    for item in meta.get("spec", {}).get(section, []):
        if item.get("label") == label:
            return bytes.fromhex(item["selector"].removeprefix("0x"))
    fail(f"Selector not found: {label}")


def selector_hex(meta: dict, label: str, section: str = "messages") -> str:
    for item in meta.get("spec", {}).get(section, []):
        if item.get("label") == label:
            return item["selector"]
    fail(f"Selector not found: {label}")


def deploy_contract(session_token: str, name: str, constructor_data: bytes) -> str:
    wasm_path = SCRIPT_DIR / f"{name}.wasm"
    if not wasm_path.exists():
        fail(f"Missing {wasm_path}. Compile {name}.sol first.")
    bytecode_hex = wasm_path.read_bytes().hex()
    resp = curl_post(
        f"{WALLET_SERVER}/wallet/deploy",
        {
            "session_token": session_token,
            "bytecode_hex": bytecode_hex,
            "constructor_data_hex": constructor_data.hex() if constructor_data else None,
        },
    )
    address = resp.get("contract_address") or resp.get("address")
    if not address:
        fail(f"Deploy response missing address for {name}: {resp}")
    return address


def call_contract(session_token: str, contract_address: str, calldata: bytes):
    return curl_post(
        f"{WALLET_SERVER}/wallet/call",
        {
            "session_token": session_token,
            "contract_address": contract_address,
            "calldata_hex": calldata.hex(),
            "amount": "0",
        },
    )


def main():
    stqtest = os.getenv("STQTEST_ADDRESS", "").strip()
    if not stqtest:
        fail("STQTEST_ADDRESS is required")

    premium_rate_bps   = int(os.getenv("PREMIUM_RATE_BPS",   "200"))
    coverage_ratio_bps = int(os.getenv("COVERAGE_RATIO_BPS", "10000"))
    cooldown_seconds   = int(os.getenv("COOLDOWN_SECONDS",   "604800"))

    ins_meta   = load_meta("insQTEST")
    pool_meta  = load_meta("VybssInsurancePool")

    # Create + fund deployer wallet
    wallet    = curl_post(f"{WALLET_SERVER}/wallet/create", {"pin": PIN})
    deployer  = wallet["wallet"]["address"]
    enc_key   = wallet["encrypted_key"]
    session   = curl_post(
        f"{WALLET_SERVER}/wallet/unlock",
        {"address": deployer, "encrypted_key": enc_key, "pin": PIN},
    )["session_token"]

    try:
        curl_post(f"{WALLET_SERVER}/faucet/claim", {"session_token": session})
    except SystemExit:
        raise
    except Exception:
        pass

    # Deploy insQTEST
    ins_ctor = selector(ins_meta, "new", "constructors")
    insqtest = deploy_contract(session, "insQTEST", ins_ctor)
    print(f"insQTEST deployed at {insqtest}")

    # Deploy VybssInsurancePool(stqtest, insqtest, premiumRateBps, coverageRatioBps, cooldownSeconds)
    pool_ctor = (
        selector(pool_meta, "new", "constructors")
        + parse_qts_address(stqtest)
        + parse_qts_address(insqtest)
        + encode_uint256_le(premium_rate_bps)
        + encode_uint256_le(coverage_ratio_bps)
        + encode_uint256_le(cooldown_seconds)
    )
    pool = deploy_contract(session, "VybssInsurancePool", pool_ctor)
    print(f"VybssInsurancePool deployed at {pool}")

    # Set pool as insQTEST manager
    set_manager = selector(ins_meta, "setManager") + parse_qts_address(pool)
    call_contract(session, insqtest, set_manager)
    print("insQTEST manager set to pool")

    selectors = {
        "depositStQtest":          selector_hex(pool_meta, "depositStQtest"),
        "requestWithdraw":         selector_hex(pool_meta, "requestWithdraw"),
        "claimWithdraw":           selector_hex(pool_meta, "claimWithdraw"),
        "buyCoverage":             selector_hex(pool_meta, "buyCoverage"),
        "submitClaim":             selector_hex(pool_meta, "submitClaim"),
        "totalCapital":            selector_hex(pool_meta, "totalCapital"),
        "totalExposure":           selector_hex(pool_meta, "totalExposure"),
        "premiumRateBps":          selector_hex(pool_meta, "premiumRateBps"),
        "coverageRatioBps":        selector_hex(pool_meta, "coverageRatioBps"),
        "cooldownSeconds":         selector_hex(pool_meta, "cooldownSeconds"),
        "paused":                  selector_hex(pool_meta, "paused"),
        "availableCapacity":       selector_hex(pool_meta, "availableCapacity"),
        "premiumFor":              selector_hex(pool_meta, "premiumFor"),
        "accountWithdrawalCount":  selector_hex(pool_meta, "accountWithdrawalCount"),
        "accountWithdrawalId":     selector_hex(pool_meta, "accountWithdrawalId"),
        "getWithdrawal":           selector_hex(pool_meta, "withdrawals"),
        "accountPolicyCount":      selector_hex(pool_meta, "accountPolicyCount"),
        "accountPolicyId":         selector_hex(pool_meta, "accountPolicyId"),
        "getPolicy":               selector_hex(pool_meta, "policies"),
        "insBalanceOf":            selector_hex(ins_meta,  "balanceOf"),
        "insTotalSupply":          selector_hex(ins_meta,  "totalSupply"),
    }

    vite_env = {
        "VITE_INSQTEST_CONTRACT_ADDRESS":              insqtest,
        "VITE_INSURANCE_POOL_CONTRACT_ADDRESS":        pool,
        "VITE_INSURANCE_SELECTOR_DEPOSIT_STQTEST":     selectors["depositStQtest"],
        "VITE_INSURANCE_SELECTOR_REQUEST_WITHDRAW":    selectors["requestWithdraw"],
        "VITE_INSURANCE_SELECTOR_CLAIM_WITHDRAW":      selectors["claimWithdraw"],
        "VITE_INSURANCE_SELECTOR_BUY_COVERAGE":        selectors["buyCoverage"],
        "VITE_INSURANCE_SELECTOR_SUBMIT_CLAIM":        selectors["submitClaim"],
        "VITE_INSURANCE_SELECTOR_TOTAL_CAPITAL":       selectors["totalCapital"],
        "VITE_INSURANCE_SELECTOR_TOTAL_EXPOSURE":      selectors["totalExposure"],
        "VITE_INSURANCE_SELECTOR_PREMIUM_RATE_BPS":    selectors["premiumRateBps"],
        "VITE_INSURANCE_SELECTOR_COVERAGE_RATIO_BPS":  selectors["coverageRatioBps"],
        "VITE_INSURANCE_SELECTOR_COOLDOWN_SECONDS":    selectors["cooldownSeconds"],
        "VITE_INSURANCE_SELECTOR_PAUSED":              selectors["paused"],
        "VITE_INSURANCE_SELECTOR_AVAILABLE_CAPACITY":  selectors["availableCapacity"],
        "VITE_INSURANCE_SELECTOR_PREMIUM_FOR":         selectors["premiumFor"],
        "VITE_INSURANCE_SELECTOR_ACCOUNT_WD_COUNT":    selectors["accountWithdrawalCount"],
        "VITE_INSURANCE_SELECTOR_ACCOUNT_WD_ID":       selectors["accountWithdrawalId"],
        "VITE_INSURANCE_SELECTOR_GET_WITHDRAWAL":      selectors["getWithdrawal"],
        "VITE_INSURANCE_SELECTOR_ACCOUNT_POLICY_COUNT":selectors["accountPolicyCount"],
        "VITE_INSURANCE_SELECTOR_ACCOUNT_POLICY_ID":   selectors["accountPolicyId"],
        "VITE_INSURANCE_SELECTOR_GET_POLICY":          selectors["getPolicy"],
        "VITE_INSURANCE_SELECTOR_INS_BALANCE_OF":      selectors["insBalanceOf"],
        "VITE_INSURANCE_SELECTOR_INS_TOTAL_SUPPLY":    selectors["insTotalSupply"],
    }

    deployment = {
        "wallet_server":        WALLET_SERVER,
        "deployer":             deployer,
        "stqtest":              stqtest,
        "insqtest":             insqtest,
        "insurance_pool":       pool,
        "premium_rate_bps":     premium_rate_bps,
        "coverage_ratio_bps":   coverage_ratio_bps,
        "cooldown_seconds":     cooldown_seconds,
        "selectors":            selectors,
        "vite_env":             vite_env,
    }

    out = SCRIPT_DIR / "insurance-deployment.json"
    out.write_text(json.dumps(deployment, indent=2) + "\n")
    print(json.dumps(deployment, indent=2))
    print(f"\nWrote {out}")
    print("\n--- Paste into vybss/.env ---")
    for k, v in vite_env.items():
        print(f"{k}={v}")


if __name__ == "__main__":
    main()
