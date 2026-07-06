#!/usr/bin/env python3
"""Deploy stQTEST + VybssLiquidStaking via quantos-wallet-server.

Compile first:
  cd quantos/solidity-contracts/staking
  solang compile stQTEST.sol --target polkadot --output .
  solang compile VybssLiquidStaking.sol --target polkadot --output .

Required env:
  QTEST_ADDRESS=QTS:<qtest>

Optional env:
  WALLET_SERVER=http://127.0.0.1:3001
  DEPLOY_PIN=999999
  UNBONDING_SECONDS=432000
  FEE_RECIPIENT=QTS:<fee-recipient>   # defaults deployer
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
            "curl", "-s", "-w", "\nHTTP_CODE:%{http_code}", url,
            "-X", "POST",
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


def selector_hex(meta: dict, label: str) -> str:
    for item in meta.get("spec", {}).get("messages", []):
        if item.get("label") == label:
            return item["selector"]
    fail(f"Selector not found: {label}")


def deploy_contract(session_token: str, name: str, constructor_data: bytes) -> str:
    wasm_path = SCRIPT_DIR / f"{name}.wasm"
    if not wasm_path.exists():
        fail(f"Missing {wasm_path}. Compile {name}.sol first.")
    bytecode_hex = wasm_path.read_bytes().hex()
    resp = curl_post(f"{WALLET_SERVER}/wallet/deploy", {
        "session_token": session_token,
        "bytecode_hex": bytecode_hex,
        "constructor_data_hex": constructor_data.hex() if constructor_data else None,
    })
    address = resp.get("contract_address") or resp.get("address")
    if not address:
        fail(f"Deploy response missing address for {name}: {resp}")
    return address


def call_contract(session_token: str, contract_address: str, calldata: bytes):
    return curl_post(f"{WALLET_SERVER}/wallet/call", {
        "session_token": session_token,
        "contract_address": contract_address,
        "calldata_hex": calldata.hex(),
        "amount": "0",
    })


def main():
    qtest = os.getenv("QTEST_ADDRESS", "").strip()
    if not qtest:
        fail("QTEST_ADDRESS is required")

    unbonding_seconds = int(os.getenv("UNBONDING_SECONDS", "432000"))  # 5 days

    st_meta = load_meta("stQTEST")
    manager_meta = load_meta("VybssLiquidStaking")

    wallet = curl_post(f"{WALLET_SERVER}/wallet/create", {"pin": PIN})
    deployer = wallet["wallet"]["address"]
    encrypted_key = wallet["encrypted_key"]
    session = curl_post(f"{WALLET_SERVER}/wallet/unlock", {
        "address": deployer,
        "encrypted_key": encrypted_key,
        "pin": PIN,
    })["session_token"]

    try:
        curl_post(f"{WALLET_SERVER}/faucet/claim", {"session_token": session})
    except SystemExit:
        raise
    except Exception:
        pass

    fee_recipient = os.getenv("FEE_RECIPIENT", f"QTS:{deployer}")

    st_ctor = selector(st_meta, "new", "constructors")
    stqtest = deploy_contract(session, "stQTEST", st_ctor)

    manager_ctor = (
        selector(manager_meta, "new", "constructors")
        + parse_qts_address(qtest)
        + parse_qts_address(stqtest)
        + encode_uint256_le(unbonding_seconds)
        + parse_qts_address(fee_recipient)
    )
    manager = deploy_contract(session, "VybssLiquidStaking", manager_ctor)

    set_manager = selector(st_meta, "setManager") + parse_qts_address(manager)
    call_contract(session, stqtest, set_manager)

    selectors = {
        "stake": selector_hex(manager_meta, "stake"),
        "requestUnstake": selector_hex(manager_meta, "requestUnstake"),
        "claim": selector_hex(manager_meta, "claim"),
        "previewStake": selector_hex(manager_meta, "previewStake"),
        "previewUnstake": selector_hex(manager_meta, "previewUnstake"),
        "getProtocolInfo": selector_hex(manager_meta, "getProtocolInfo"),
        "getAccountInfo": selector_hex(manager_meta, "getAccountInfo"),
        "accountWithdrawalCount": selector_hex(manager_meta, "accountWithdrawalCount"),
        "accountWithdrawalId": selector_hex(manager_meta, "accountWithdrawalId"),
        "getWithdrawal": selector_hex(manager_meta, "getWithdrawal"),
    }

    vite_env = {
        "VITE_STQTEST_CONTRACT_ADDRESS": stqtest,
        "VITE_LIQUID_STAKING_CONTRACT_ADDRESS": manager,
        "VITE_LIQUID_STAKING_SELECTOR_STAKE": selectors["stake"],
        "VITE_LIQUID_STAKING_SELECTOR_REQUEST_UNSTAKE": selectors["requestUnstake"],
        "VITE_LIQUID_STAKING_SELECTOR_CLAIM": selectors["claim"],
        "VITE_LIQUID_STAKING_SELECTOR_PREVIEW_STAKE": selectors["previewStake"],
        "VITE_LIQUID_STAKING_SELECTOR_PREVIEW_UNSTAKE": selectors["previewUnstake"],
        "VITE_LIQUID_STAKING_SELECTOR_GET_PROTOCOL_INFO": selectors["getProtocolInfo"],
        "VITE_LIQUID_STAKING_SELECTOR_GET_ACCOUNT_INFO": selectors["getAccountInfo"],
        "VITE_LIQUID_STAKING_SELECTOR_ACCOUNT_WITHDRAWAL_COUNT": selectors["accountWithdrawalCount"],
        "VITE_LIQUID_STAKING_SELECTOR_ACCOUNT_WITHDRAWAL_ID": selectors["accountWithdrawalId"],
        "VITE_LIQUID_STAKING_SELECTOR_GET_WITHDRAWAL": selectors["getWithdrawal"],
    }

    deployment = {
        "wallet_server": WALLET_SERVER,
        "deployer": deployer,
        "qtest": qtest,
        "stqtest": stqtest,
        "liquid_staking": manager,
        "unbonding_seconds": unbonding_seconds,
        "fee_recipient": fee_recipient,
        "selectors": selectors,
        "vite_env": vite_env,
    }

    out = SCRIPT_DIR / "liquid-staking-deployment.json"
    out.write_text(json.dumps(deployment, indent=2) + "\n")
    print(json.dumps(deployment, indent=2))
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
