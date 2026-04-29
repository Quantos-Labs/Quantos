#!/usr/bin/env python3
"""Approve project 0 on the VybssGrants contract."""
import json
import subprocess

WALLET_SERVER = "http://127.0.0.1:3001"

def curl_post(url, data):
    r = subprocess.run(
        ["curl", "-s", "-w", "\nHTTP_CODE:%{http_code}", url,
         "-X", "POST", "-H", "Content-Type: application/json",
         "--max-time", "30", "-d", json.dumps(data)],
        capture_output=True, text=True,
    )
    parts = r.stdout.rsplit("\nHTTP_CODE:", 1)
    body = parts[0]
    code = parts[1].strip() if len(parts) > 1 else "?"
    print(f"  HTTP {code}: {body[:300]}")
    return json.loads(body)

# Values from setup script output (deployment.json wasn't saved because script crashed at step 6)
session = "7a70570e-0e33-4fd6-bdde-893c9b3d8387"
grants = "QTS:67bfa56f15d1d4c718858107a2aaf07e6d7a627b27afd9a9882c5673d832042b"

# setProjectStatus(uint256 _projectId, uint8 _status)
# selector: 9d240c4c
sel = "9d240c4c"

# uint256(0) LE = 32 zero bytes
project_id = "00" * 32

# uint8(1) = 1 byte
status = "01"

calldata = sel + project_id + status
print(f"Calldata ({len(calldata)//2} bytes): {calldata}")

resp = curl_post(f"{WALLET_SERVER}/wallet/call", {
    "session_token": session,
    "contract_address": grants,
    "calldata_hex": calldata,
    "amount": "0",
})
print(f"Result: {json.dumps(resp, indent=2)}")
