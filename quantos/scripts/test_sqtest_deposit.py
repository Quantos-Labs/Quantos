#!/usr/bin/env python3
"""Test SQTESTEngine: approve, open vault, and deposit collateral."""
import json
import subprocess
import sys

WALLET_SERVER = "http://127.0.0.1:3001"
PIN = "999999"

QTEST = "QTS:c49ffa02bdb365b7e5bf1655dd296b7358eebdfdbe2abb3a1998db8daddc3a68"
ENGINE = "QTS:6fa5be5c808bfb097173dd0e943f76687ce213a73e6758dbc349cd1f05b52d1c"


def curl_post(url, data):
    r = subprocess.run(
        ["curl", "-s", "-w", "\nHTTP_CODE:%{http_code}", url,
         "-X", "POST", "-H", "Content-Type: application/json",
         "--max-time", "30", "-d", json.dumps(data)],
        capture_output=True, text=True,
    )
    parts = r.stdout.rsplit("\nHTTP_CODE:", 1)
    body = parts[0]
    code = parts[1] if len(parts) > 1 else "?"
    print(f"  HTTP {code}")
    if not body.strip():
        print(f"  Empty response! stderr: {r.stderr[:300]}")
        sys.exit(1)
    return json.loads(body)


def encode_uint256_le(v):
    return v.to_bytes(32, byteorder="little", signed=False)


def parse_qts(v):
    h = v.replace("QTS:", "").replace("qts:", "").replace("0x", "")
    return bytes.fromhex(h)


def main():
    print("1. Creating wallet...")
    w = curl_post(f"{WALLET_SERVER}/wallet/create", {"pin": PIN})
    addr = w["wallet"]["address"]
    ek = w["encrypted_key"]
    print(f"  Address: {addr}")

    print("2. Unlocking...")
    s = curl_post(f"{WALLET_SERVER}/wallet/unlock", {
        "address": addr, "encrypted_key": ek, "pin": PIN,
    })
    token = s["session_token"]

    print("3. Faucet...")
    curl_post(f"{WALLET_SERVER}/faucet/claim", {"session_token": token})

    # Approve QTEST to engine: approve(address,uint256) = 0x095ea7b3
    amount = 100 * 10**18
    approve_data = bytes.fromhex("095ea7b3") + parse_qts(ENGINE) + encode_uint256_le(amount)
    print(f"4. Approving 100 QTEST to engine...")
    resp = curl_post(f"{WALLET_SERVER}/wallet/call", {
        "session_token": token,
        "contract_address": QTEST,
        "calldata_hex": approve_data.hex(),
        "amount": "0",
    })
    print(f"  Result: {resp.get('status', resp)}")

    # Open vault: openVault(uint256 collateral, uint256 debt) = 0x59cb83d0
    collateral = 50 * 10**18
    debt = 10 * 10**18
    vault_data = bytes.fromhex("59cb83d0") + encode_uint256_le(collateral) + encode_uint256_le(debt)
    print(f"5. Opening vault (50 QTEST collateral, 10 SQTEST debt)...")
    resp = curl_post(f"{WALLET_SERVER}/wallet/call", {
        "session_token": token,
        "contract_address": ENGINE,
        "calldata_hex": vault_data.hex(),
        "amount": "0",
    })
    print(f"  Result: {resp.get('status', resp)}")

    # Deposit more collateral: depositCollateral(uint256 amount) = 0xbad4a01f
    deposit = 20 * 10**18
    deposit_data = bytes.fromhex("bad4a01f") + encode_uint256_le(deposit)
    print(f"6. Depositing 20 more QTEST collateral...")
    resp = curl_post(f"{WALLET_SERVER}/wallet/call", {
        "session_token": token,
        "contract_address": ENGINE,
        "calldata_hex": deposit_data.hex(),
        "amount": "0",
    })
    print(f"  Result: {resp.get('status', resp)}")

    print("\nAll vault operations completed successfully!")


if __name__ == "__main__":
    main()
