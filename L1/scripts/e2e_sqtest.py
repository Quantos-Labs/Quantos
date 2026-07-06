#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

WALLET_SERVER = os.environ.get("WALLET_SERVER", "http://127.0.0.1:3001")
NODE_RPC_URL = os.environ.get("NODE_RPC_URL", "http://127.0.0.1:8545")
PIN = os.environ.get("PIN", "999999")
QTEST_ADDRESS = os.environ.get("QTEST_ADDRESS", "").strip()


def fail(message: str):
    print(message, file=sys.stderr)
    sys.exit(1)


def http_post_json(url: str, data: dict) -> dict:
    payload = json.dumps(data)
    r = subprocess.run(
        ["curl", "-s", "-w", "\nHTTP_CODE:%{http_code}", url, "-X", "POST", "-H", "Content-Type: application/json", "--max-time", "30", "-d", payload],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        fail(f"curl error (rc={r.returncode}): {r.stderr}")
    body, _, http_code = r.stdout.rpartition("\nHTTP_CODE:")
    if not body.strip():
        fail(f"Empty response body from {url}")
    if http_code.startswith("4") or http_code.startswith("5"):
        fail(f"HTTP {http_code} from {url}: {body[:500]}")
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        fail(f"Bad JSON from {url}: {body[:500]}")


def rpc(method: str, params: list):
    r = subprocess.run(
        [
            "curl", "-s", NODE_RPC_URL,
            "-H", "Content-Type: application/json",
            "-d", json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
        ],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        fail(f"RPC curl error: {r.stderr}")
    data = json.loads(r.stdout)
    if data.get("error"):
        fail(f"RPC {method} error: {data['error']}")
    return data.get("result")


def parse_qts_address(value: str) -> bytes:
    cleaned = value.strip()
    if cleaned.startswith("QTS:") or cleaned.startswith("qts:"):
        cleaned = cleaned[4:]
    elif cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    raw = bytes.fromhex(cleaned)
    if len(raw) != 32:
        fail(f"Invalid address length for {value!r}: got {len(raw)}")
    return raw


def encode_uint256_le(value: int) -> bytes:
    return value.to_bytes(32, byteorder="little", signed=False)


def decode_uint256_le(hex_value: str) -> int:
    cleaned = hex_value.strip()
    if cleaned.startswith("QTS:") or cleaned.startswith("qts:"):
        cleaned = cleaned[4:]
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    raw = bytes.fromhex(cleaned)
    raw = raw[:32].ljust(32, b"\x00")
    return int.from_bytes(raw, byteorder="little", signed=False)


def normalize_status(value: str) -> str:
    status = str(value or "")
    if status.startswith("QTS:") or status.startswith("qts:"):
        status = status[4:]
    return status.lower()


def wait_receipt(tx_hash: str, timeout: int = 40) -> dict:
    start = time.time()
    while time.time() - start < timeout:
        receipt = rpc("qnt_getTransactionReceipt", [tx_hash])
        if receipt and isinstance(receipt, dict):
            status = normalize_status(receipt.get("status", ""))
            if status in ("success", "confirmed", "1"):
                return receipt
            if status in ("failed", "reverted", "0"):
                fail(f"Transaction failed: {json.dumps(receipt, indent=2)}")
        time.sleep(0.5)
    fail(f"Timed out waiting for receipt: {tx_hash}")


def qnt_call(to: str, data_hex: str, from_addr: Optional[str] = None) -> str:
    req = {"to": to, "data": data_hex}
    if from_addr:
        req["from"] = from_addr
    result = rpc("qnt_call", [req])
    if not isinstance(result, str):
        fail(f"Unexpected qnt_call result: {result}")
    return result


def read_selector(contract_path: Path, label: str, constructor: bool = False) -> bytes:
    artifact = json.loads(contract_path.read_text())
    if constructor:
        return bytes.fromhex(artifact["spec"]["constructors"][0]["selector"][2:])
    for message in artifact["spec"]["messages"]:
        if message["label"] == label:
            return bytes.fromhex(message["selector"][2:])
    fail(f"Selector not found for {label} in {contract_path}")


def deploy_contract(session_token: str, wasm_path: Path, constructor_data: bytes = b"") -> str:
    bytecode_hex = wasm_path.read_bytes().hex()
    result = http_post_json(f"{WALLET_SERVER}/wallet/deploy", {
        "session_token": session_token,
        "bytecode_hex": bytecode_hex,
        "constructor_data_hex": constructor_data.hex() if constructor_data else None,
    })
    tx_hash = result["tx_hash"]
    wait_receipt(tx_hash)
    address = result.get("contract_address") or result.get("address")
    if not address:
        fail(f"Deploy response missing address: {result}")
    return address


def call_contract(session_token: str, contract_address: str, calldata: bytes, amount: str = "0") -> dict:
    result = http_post_json(f"{WALLET_SERVER}/wallet/call", {
        "session_token": session_token,
        "contract_address": contract_address,
        "calldata_hex": calldata.hex(),
        "amount": amount,
    })
    wait_receipt(result["tx_hash"])
    return result


def format_units(value: int, decimals: int = 18) -> str:
    whole = value // 10**decimals
    frac = value % 10**decimals
    if frac == 0:
        return str(whole)
    return f"{whole}.{str(frac).rjust(decimals, '0').rstrip('0')}"


def debug_value(label: str, value):
    print(f"[debug] {label}: {value}")


def main():
    contracts_dir = Path(__file__).parent.parent / "solidity-contracts"
    sqtest_wasm = contracts_dir / "SQTEST.wasm"
    engine_wasm = contracts_dir / "SQTESTEngine.wasm"
    sqtest_contract = contracts_dir / "SQTEST.contract"
    engine_contract = contracts_dir / "SQTESTEngine.contract"
    qtest_wasm = Path(__file__).parent.parent / "test-contracts" / "build" / "QTEST.wasm"
    qtest_contract = Path(__file__).parent.parent / "test-contracts" / "build" / "QTEST.contract"

    if not sqtest_wasm.exists() or not engine_wasm.exists() or not qtest_wasm.exists() or not qtest_contract.exists():
        fail("Missing compiled QTEST/SQTEST/SQTESTEngine wasm artifacts")

    qtest_ctor = read_selector(qtest_contract, "new", constructor=True)
    sqtest_ctor = read_selector(sqtest_contract, "new", constructor=True)
    engine_ctor = read_selector(engine_contract, "new", constructor=True)
    set_engine_selector = read_selector(sqtest_contract, "setEngine")
    engine_view_selector = read_selector(sqtest_contract, "engine")
    sqtest_view_selector = read_selector(engine_contract, "sqtest")
    qtest_view_selector = read_selector(engine_contract, "qtest")
    mint_selector = read_selector(sqtest_contract, "mint")
    open_vault_selector = read_selector(engine_contract, "openVault")
    mint_debt_selector = read_selector(engine_contract, "mintDebt")
    repay_debt_selector = read_selector(engine_contract, "repayDebt")
    withdraw_selector = read_selector(engine_contract, "withdrawCollateral")
    claim_selector = bytes.fromhex("4e71d92d")
    approve_selector = bytes.fromhex("095ea7b3")
    balance_of_selector = bytes.fromhex("70a08231")
    allowance_selector = bytes.fromhex("dd62ed3e")
    transfer_from_selector = bytes.fromhex("23b872dd")
    total_supply_selector = bytes.fromhex("18160ddd")
    vault_health_selector = read_selector(engine_contract, "getVaultHealth")

    wallet = http_post_json(f"{WALLET_SERVER}/wallet/create", {"pin": PIN})
    deployer = wallet["wallet"]["rpc_address"]
    encrypted_key = wallet["encrypted_key"]
    session = http_post_json(f"{WALLET_SERVER}/wallet/unlock", {
        "address": wallet["wallet"]["address"],
        "encrypted_key": encrypted_key,
        "pin": PIN,
    })
    session_token = session["session_token"]

    qtest_address = QTEST_ADDRESS
    if not qtest_address:
        qtest_address = deploy_contract(session_token, qtest_wasm, qtest_ctor)
        debug_value("qtest_address", qtest_address)

    claim_receipt = call_contract(session_token, qtest_address, claim_selector)
    debug_value("claim_tx", claim_receipt)

    initial_qtest = decode_uint256_le(qnt_call(qtest_address, "0x" + (balance_of_selector + parse_qts_address(deployer)).hex(), deployer))
    debug_value("initial_qtest_balance", format_units(initial_qtest))

    sqtest_address = deploy_contract(session_token, sqtest_wasm, sqtest_ctor)
    debug_value("sqtest_address", sqtest_address)
    engine_constructor = engine_ctor + parse_qts_address(sqtest_address) + parse_qts_address(qtest_address)
    engine_address = deploy_contract(session_token, engine_wasm, engine_constructor)
    debug_value("engine_address", engine_address)
    debug_value("engine_sqtest_raw", qnt_call(engine_address, "0x" + sqtest_view_selector.hex(), deployer))
    debug_value("engine_qtest_raw", qnt_call(engine_address, "0x" + qtest_view_selector.hex(), deployer))

    set_engine_receipt = call_contract(session_token, sqtest_address, set_engine_selector + parse_qts_address(engine_address))
    debug_value("set_engine_tx", set_engine_receipt)
    current_engine = qnt_call(sqtest_address, "0x" + engine_view_selector.hex(), deployer)
    debug_value("current_engine_raw", current_engine)

    collateral = 300 * 10**18
    open_debt = 100 * 10**18
    mint_more = 20 * 10**18
    repay_amount = 50 * 10**18
    withdraw_amount = 30 * 10**18

    approve_receipt = call_contract(session_token, qtest_address, approve_selector + parse_qts_address(engine_address) + encode_uint256_le(collateral))
    debug_value("approve_tx", approve_receipt)
    allowance_raw = qnt_call(qtest_address, "0x" + (allowance_selector + parse_qts_address(deployer) + parse_qts_address(engine_address)).hex(), deployer)
    debug_value("allowance_raw", allowance_raw)
    debug_value("allowance", format_units(decode_uint256_le(allowance_raw)))
    debug_value(
        "simulated_transferFrom_from_engine",
        qnt_call(
            qtest_address,
            "0x" + (transfer_from_selector + parse_qts_address(deployer) + parse_qts_address(engine_address) + encode_uint256_le(1)).hex(),
            engine_address,
        ),
    )
    debug_value(
        "simulated_sqtest_mint_from_engine",
        qnt_call(
            sqtest_address,
            "0x" + (mint_selector + parse_qts_address(deployer) + encode_uint256_le(1)).hex(),
            engine_address,
        ),
    )

    open_vault_receipt = call_contract(session_token, engine_address, open_vault_selector + encode_uint256_le(collateral) + encode_uint256_le(open_debt))
    debug_value("open_vault_tx", open_vault_receipt)
    debug_value("total_supply_after_open", format_units(decode_uint256_le(qnt_call(sqtest_address, "0x" + total_supply_selector.hex(), deployer))))
    debug_value("sqtest_balance_after_open", format_units(decode_uint256_le(qnt_call(sqtest_address, "0x" + (balance_of_selector + parse_qts_address(deployer)).hex(), deployer))))

    mint_receipt = call_contract(session_token, engine_address, mint_debt_selector + encode_uint256_le(mint_more))
    debug_value("mint_debt_tx", mint_receipt)
    repay_receipt = call_contract(session_token, engine_address, repay_debt_selector + encode_uint256_le(repay_amount))
    debug_value("repay_debt_tx", repay_receipt)
    withdraw_receipt = call_contract(session_token, engine_address, withdraw_selector + encode_uint256_le(withdraw_amount))
    debug_value("withdraw_tx", withdraw_receipt)

    final_sqtest_balance = decode_uint256_le(qnt_call(sqtest_address, "0x" + (balance_of_selector + parse_qts_address(deployer)).hex(), deployer))
    total_supply = decode_uint256_le(qnt_call(sqtest_address, "0x" + total_supply_selector.hex(), deployer))
    final_qtest = decode_uint256_le(qnt_call(qtest_address, "0x" + (balance_of_selector + parse_qts_address(deployer)).hex(), deployer))
    vault_health = decode_uint256_le(qnt_call(engine_address, "0x" + (vault_health_selector + parse_qts_address(deployer)).hex(), deployer))

    if total_supply <= 0:
        fail("E2E failed: SQTEST total supply is zero")
    if final_sqtest_balance <= 0:
        fail("E2E failed: user SQTEST balance is zero")
    if final_qtest >= initial_qtest:
        fail("E2E failed: QTEST collateral did not decrease")

    wallet_env_block = f"""cat <<'EOF' >> /Users/wayle/Quantos_labs/quantos-wallet-server/.env
SQTEST_CONTRACT_ADDRESS={sqtest_address}
SQTEST_ENGINE_CONTRACT_ADDRESS={engine_address}
EOF"""
    vybss_env_block = f"""cat <<'EOF' >> /Users/wayle/Quantos_labs/vybss/.env
VITE_SQTEST_CONTRACT_ADDRESS={sqtest_address}
VITE_SQTEST_ENGINE_CONTRACT_ADDRESS={engine_address}
EOF"""

    print(json.dumps({
        "deployer": deployer,
        "qtest": qtest_address,
        "sqtest": sqtest_address,
        "sqtest_engine": engine_address,
        "initial_qtest_balance": format_units(initial_qtest),
        "final_qtest_balance": format_units(final_qtest),
        "final_sqtest_balance": format_units(final_sqtest_balance),
        "total_sqtest_supply": format_units(total_supply),
        "vault_health_percent": str(vault_health),
        "wallet_server_env_cat": wallet_env_block,
        "vybss_env_cat": vybss_env_block,
    }, indent=2))


if __name__ == "__main__":
    main()
