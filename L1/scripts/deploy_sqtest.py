#!/usr/bin/env python3
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
    contracts_dir = Path(__file__).parent.parent / "solidity-contracts"
    sqtest_contract = json.loads((contracts_dir / "SQTEST.contract").read_text())
    engine_contract = json.loads((contracts_dir / "SQTESTEngine.contract").read_text())
    sqtest_ctor_selector = bytes.fromhex(sqtest_contract["spec"]["constructors"][0]["selector"][2:])
    engine_ctor_selector = bytes.fromhex(engine_contract["spec"]["constructors"][0]["selector"][2:])
    set_engine_selector = None
    for message in sqtest_contract["spec"]["messages"]:
        if message["label"] == "setEngine":
            set_engine_selector = bytes.fromhex(message["selector"][2:])
            break
    if set_engine_selector is None:
        fail("setEngine selector not found in SQTEST.contract")

    qtest_address = os.environ.get("QTEST_ADDRESS", "").strip()
    if not qtest_address:
        fail("QTEST_ADDRESS is required in env")

    wallet_resp = curl_post(f"{WALLET_SERVER}/wallet/create", {"pin": PIN})
    deployer_address = wallet_resp["wallet"]["address"]
    encrypted_key = wallet_resp["encrypted_key"]
    session_resp = curl_post(f"{WALLET_SERVER}/wallet/unlock", {
        "address": deployer_address,
        "encrypted_key": encrypted_key,
        "pin": PIN,
    })
    session_token = session_resp["session_token"]

    curl_post(f"{WALLET_SERVER}/faucet/claim", {"session_token": session_token})

    sqtest_deploy = deploy_contract(session_token, contracts_dir / "SQTEST.wasm", sqtest_ctor_selector)
    sqtest_address = sqtest_deploy.get("contract_address") or sqtest_deploy.get("address")
    if not sqtest_address:
        fail(f"SQTEST deploy response missing contract address: {sqtest_deploy}")

    engine_constructor = engine_ctor_selector + parse_qts_address(sqtest_address) + parse_qts_address(qtest_address)
    engine_deploy = deploy_contract(session_token, contracts_dir / "SQTESTEngine.wasm", engine_constructor)
    engine_address = engine_deploy.get("contract_address") or engine_deploy.get("address")
    if not engine_address:
        fail(f"SQTESTEngine deploy response missing contract address: {engine_deploy}")

    set_engine_calldata = set_engine_selector + parse_qts_address(engine_address)
    set_engine_resp = call_contract(session_token, sqtest_address, set_engine_calldata)

    addresses_file = contracts_dir / "deployed_addresses.txt"
    with open(addresses_file, "w") as f:
        f.write(f"DEPLOYER={deployer_address}\n")
        f.write(f"SQTEST={sqtest_address}\n")
        f.write(f"SQTESTEngine={engine_address}\n")
        f.write(f"QTEST={qtest_address}\n")

    print(json.dumps({
        "deployer": deployer_address,
        "sqtest": sqtest_address,
        "sqtest_engine": engine_address,
        "qtest": qtest_address,
        "set_engine": set_engine_resp,
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
