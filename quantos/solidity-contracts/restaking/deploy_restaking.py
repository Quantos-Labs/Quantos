#!/usr/bin/env python3
"""Deploy rstQTEST + VybssRestakingVault via quantos-wallet-server.

Compile first:
  cd quantos/solidity-contracts/restaking
  solang compile rstQTEST.sol --target polkadot --output .
  solang compile VybssRestakingVault.sol --target polkadot --output .

Required env:
  STQTEST_ADDRESS=QTS:<stqtest>

Optional env:
  WALLET_SERVER=http://127.0.0.1:3001
  DEPLOY_PIN=999999
  COOLDOWN_SECONDS=604800
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
            "curl",
            "-s",
            "-w",
            "\nHTTP_CODE:%{http_code}",
            url,
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "--max-time",
            "60",
            "-d",
            payload,
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

    cooldown_seconds = int(os.getenv("COOLDOWN_SECONDS", "604800"))  # 7 days

    rst_meta = load_meta("rstQTEST")
    vault_meta = load_meta("VybssRestakingVault")

    wallet = curl_post(f"{WALLET_SERVER}/wallet/create", {"pin": PIN})
    deployer = wallet["wallet"]["address"]
    encrypted_key = wallet["encrypted_key"]
    session = curl_post(
        f"{WALLET_SERVER}/wallet/unlock",
        {"address": deployer, "encrypted_key": encrypted_key, "pin": PIN},
    )["session_token"]

    try:
        curl_post(f"{WALLET_SERVER}/faucet/claim", {"session_token": session})
    except SystemExit:
        raise
    except Exception:
        pass

    rst_ctor = selector(rst_meta, "new", "constructors")
    rstqtest = deploy_contract(session, "rstQTEST", rst_ctor)

    vault_ctor = (
        selector(vault_meta, "new", "constructors")
        + parse_qts_address(stqtest)
        + parse_qts_address(rstqtest)
        + encode_uint256_le(cooldown_seconds)
    )
    vault = deploy_contract(session, "VybssRestakingVault", vault_ctor)

    set_manager = selector(rst_meta, "setManager") + parse_qts_address(vault)
    call_contract(session, rstqtest, set_manager)

    selectors = {
        "depositStQTEST": selector_hex(vault_meta, "depositStQTEST"),
        "requestWithdraw": selector_hex(vault_meta, "requestWithdraw"),
        "claim": selector_hex(vault_meta, "claim"),
        "previewDeposit": selector_hex(vault_meta, "previewDeposit"),
        "previewWithdraw": selector_hex(vault_meta, "previewWithdraw"),
        "accountWithdrawalCount": selector_hex(vault_meta, "accountWithdrawalCount"),
        "accountWithdrawalId": selector_hex(vault_meta, "accountWithdrawalId"),
        "getWithdrawal": selector_hex(vault_meta, "withdrawals"),
        "totalRestakedStqtest": selector_hex(vault_meta, "totalRestakedStqtest"),
        "cooldownSeconds": selector_hex(vault_meta, "cooldownSeconds"),
        "paused": selector_hex(vault_meta, "paused"),
    }

    vite_env = {
        "VITE_RSTQTEST_CONTRACT_ADDRESS": rstqtest,
        "VITE_RESTAKING_VAULT_CONTRACT_ADDRESS": vault,
        "VITE_RESTAKING_SELECTOR_DEPOSIT_STQTEST": selectors["depositStQTEST"],
        "VITE_RESTAKING_SELECTOR_REQUEST_WITHDRAW": selectors["requestWithdraw"],
        "VITE_RESTAKING_SELECTOR_CLAIM": selectors["claim"],
        "VITE_RESTAKING_SELECTOR_PREVIEW_DEPOSIT": selectors["previewDeposit"],
        "VITE_RESTAKING_SELECTOR_PREVIEW_WITHDRAW": selectors["previewWithdraw"],
        "VITE_RESTAKING_SELECTOR_ACCOUNT_WITHDRAWAL_COUNT": selectors["accountWithdrawalCount"],
        "VITE_RESTAKING_SELECTOR_ACCOUNT_WITHDRAWAL_ID": selectors["accountWithdrawalId"],
        "VITE_RESTAKING_SELECTOR_GET_WITHDRAWAL": selectors["getWithdrawal"],
        "VITE_RESTAKING_SELECTOR_TOTAL_RESTAKED_STQTEST": selectors["totalRestakedStqtest"],
        "VITE_RESTAKING_SELECTOR_COOLDOWN_SECONDS": selectors["cooldownSeconds"],
        "VITE_RESTAKING_SELECTOR_PAUSED": selectors["paused"],
    }

    deployment = {
        "wallet_server": WALLET_SERVER,
        "deployer": deployer,
        "stqtest": stqtest,
        "rstqtest": rstqtest,
        "restaking_vault": vault,
        "cooldown_seconds": cooldown_seconds,
        "selectors": selectors,
        "vite_env": vite_env,
    }

    out = SCRIPT_DIR / "restaking-deployment.json"
    out.write_text(json.dumps(deployment, indent=2) + "\n")
    print(json.dumps(deployment, indent=2))
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()

