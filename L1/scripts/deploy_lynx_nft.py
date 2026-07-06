#!/usr/bin/env python3
"""Deploy LynxNFT (ERC721) to Quantos testnet."""
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
    r = subprocess.run(
        ["curl", "-s", "-w", "\nHTTP_CODE:%{http_code}", url,
         "-X", "POST", "-H", "Content-Type: application/json",
         "--max-time", "30", "-d", json.dumps(data)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        fail(f"curl error: {r.stderr}")
    parts = r.stdout.rsplit("\nHTTP_CODE:", 1)
    body = parts[0]
    code = parts[1] if len(parts) > 1 else "?"
    if not body.strip():
        fail(f"Empty response! stderr: {r.stderr[:300]}")
    if code.startswith("4") or code.startswith("5"):
        fail(f"HTTP {code}: {body[:500]}")
    return json.loads(body)


def parse_qts_address(value: str) -> bytes:
    cleaned = value.strip()
    if cleaned.startswith(("QTS:", "qts:")):
        cleaned = cleaned[4:]
    elif cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    raw = bytes.fromhex(cleaned)
    if len(raw) != 32:
        fail(f"Invalid address: expected 32 bytes, got {len(raw)}")
    return raw


def deploy_contract(session_token, wasm_path, constructor_data=b""):
    bytecode_hex = wasm_path.read_bytes().hex()
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


def main():
    nft_dir = Path(__file__).parent.parent / "solidity-contracts" / "nft"
    contract_meta = json.loads((nft_dir / "LynxNFT.contract").read_text())

    # Extract selectors
    ctor_sel = bytes.fromhex(contract_meta["spec"]["constructors"][0]["selector"][2:])
    selectors = {}
    for msg in contract_meta["spec"]["messages"]:
        selectors[msg["label"]] = bytes.fromhex(msg["selector"][2:])

    print("Selectors:")
    for k, v in selectors.items():
        print(f"  {k}: 0x{v.hex()}")

    # Create or use deployer wallet
    wallet_resp = curl_post(f"{WALLET_SERVER}/wallet/create", {"pin": PIN})
    deployer_address = wallet_resp["wallet"]["address"]
    encrypted_key = wallet_resp["encrypted_key"]

    session_resp = curl_post(f"{WALLET_SERVER}/wallet/unlock", {
        "address": deployer_address,
        "encrypted_key": encrypted_key,
        "pin": PIN,
    })
    session_token = session_resp["session_token"]

    # Faucet
    curl_post(f"{WALLET_SERVER}/faucet/claim", {"session_token": session_token})
    print(f"\nDeployer: {deployer_address}")

    # Deploy LynxNFT
    print("\nDeploying LynxNFT...")
    deploy_resp = deploy_contract(session_token, nft_dir / "LynxNFT.wasm", ctor_sel)
    lynx_address = deploy_resp.get("contract_address") or deploy_resp.get("address")
    if not lynx_address:
        fail(f"Deploy failed: {deploy_resp}")
    print(f"LynxNFT deployed at: {lynx_address}")

    # Set deployer as minter
    print("\nSetting minter...")
    set_minter_calldata = selectors["setMinter"] + parse_qts_address(deployer_address)
    minter_resp = call_contract(session_token, lynx_address, set_minter_calldata)
    print(f"setMinter: {minter_resp.get('status', minter_resp)}")

    # Save addresses
    addresses_file = nft_dir / "deployed_nft_addresses.txt"
    with open(addresses_file, "w") as f:
        f.write(f"DEPLOYER={deployer_address}\n")
        f.write(f"LYNX_NFT={lynx_address}\n")
        f.write(f"SESSION_TOKEN={session_token}\n")
        f.write(f"ENCRYPTED_KEY={encrypted_key}\n")

    # Save selectors for frontend
    sel_file = nft_dir / "lynx_selectors.json"
    with open(sel_file, "w") as f:
        json.dump({k: f"0x{v.hex()}" for k, v in selectors.items()}, f, indent=2)

    print(f"\n✅ Done!")
    print(f"   Contract: {lynx_address}")
    print(f"   Addresses: {addresses_file}")
    print(f"   Selectors: {sel_file}")

    print(json.dumps({
        "deployer": deployer_address,
        "lynx_nft": lynx_address,
        "session_token": session_token,
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: {e}")
        sys.exit(1)
