#!/usr/bin/env python3
"""
Deploy SimpleFlashReceiver, fund it with QTEST for fees, then execute a flash loan.
"""
import json, requests, sys, time
from pathlib import Path

WALLET_SERVER = "http://127.0.0.1:3001"
LENDING_DIR = Path(__file__).resolve().parent.parent / "solidity-contracts" / "lending"

# Pool & QTEST addresses from env fragment
POOL_ADDRESS = "QTS:2d81f437a8a10f81105c799b74f5e632d353fd8767fa991b18e195f503225883"
QTEST_ADDRESS = "QTS:c49ffa02bdb365b7e5bf1655dd296b7358eebdfdbe2abb3a1998db8daddc3a68"
RESERVE_ID = 1  # QTEST

def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)

def curl_post(url, body):
    r = requests.post(url, json=body, timeout=30)
    if r.status_code != 200:
        fail(f"{url} => {r.status_code}: {r.text[:300]}")
    return r.json()

def pad_u256_le(n):
    return n.to_bytes(32, "little")

def pad_addr(addr):
    raw = addr.replace("QTS:", "").replace("0x", "")
    return bytes.fromhex(raw.ljust(64, "0")[:64])

def decode_le_u256(hex_str):
    b = bytes.fromhex(hex_str)
    return int.from_bytes(b, "little")

def deploy_contract(session_token, wasm_path, constructor_data=b""):
    with wasm_path.open("rb") as f:
        bytecode_hex = f.read().hex()
    return curl_post(f"{WALLET_SERVER}/wallet/deploy", {
        "session_token": session_token,
        "bytecode_hex": bytecode_hex,
        "constructor_data_hex": constructor_data.hex() if constructor_data else None,
    })

def call_contract(session_token, contract_address, calldata_hex, amount="0"):
    return curl_post(f"{WALLET_SERVER}/wallet/call", {
        "session_token": session_token,
        "contract_address": contract_address,
        "calldata_hex": calldata_hex,
        "amount": amount,
    })

def read_contract(contract_address, calldata_hex):
    return curl_post(f"{WALLET_SERVER}/wallet/read-contract", {
        "contract_address": contract_address,
        "calldata_hex": calldata_hex,
    })

def get_selector(contract_path, label):
    with open(contract_path) as f:
        meta = json.load(f)
    for msg in meta["spec"]["messages"]:
        if msg["label"] == label:
            return bytes.fromhex(msg["selector"][2:])
    for ctor in meta["spec"]["constructors"]:
        if ctor["label"] == "new":
            return bytes.fromhex(ctor["selector"][2:])
    fail(f"Selector not found: {label}")

def main():
    print("=== Flash Loan Test ===\n")

    # 1. Create/unlock wallet
    print("[1] Creating wallet...")
    wallet = curl_post(f"{WALLET_SERVER}/wallet/create", {"pin": "123456"})
    address = wallet["wallet"]["address"]
    encrypted_key = wallet["encrypted_key"]
    print(f"    Wallet: {address}")

    unlock = curl_post(f"{WALLET_SERVER}/wallet/unlock", {
        "address": address,
        "encrypted_key": encrypted_key,
        "pin": "123456",
    })
    token = unlock["session_token"]

    # Fund from faucet
    try:
        curl_post(f"{WALLET_SERVER}/faucet/claim", {"session_token": token})
        print("    Faucet claimed")
    except:
        print("    Faucet already claimed or empty")
    time.sleep(2)

    # 2. Get constructor selector from SimpleFlashReceiver.contract
    print("\n[2] Deploying SimpleFlashReceiver...")
    receiver_contract = LENDING_DIR / "SimpleFlashReceiver.contract"
    ctor_sel = get_selector(receiver_contract, "new")
    # Constructor takes address _pool
    ctor_data = ctor_sel + pad_addr(POOL_ADDRESS)
    
    deploy_resp = deploy_contract(token, LENDING_DIR / "SimpleFlashReceiver.wasm", ctor_data)
    receiver_addr = deploy_resp.get("contract_address")
    if not receiver_addr:
        fail(f"Deploy failed: {deploy_resp}")
    print(f"    Receiver deployed: {receiver_addr}")
    time.sleep(2)

    # 3. Check pool QTEST balance (= available liquidity for flash loan)
    print("\n[3] Checking pool liquidity...")
    balanceOf_sel = "70a08231"
    pool_balance_hex = read_contract(QTEST_ADDRESS, balanceOf_sel + pad_addr(POOL_ADDRESS).hex())["result"]
    pool_balance = decode_le_u256(pool_balance_hex)
    print(f"    Pool QTEST balance: {pool_balance / 1e18:.4f}")

    if pool_balance == 0:
        fail("Pool has no QTEST liquidity. Supply some first!")

    # 4. Fund the receiver with some QTEST to pay the fee
    # Flash loan fee = 9 bps = 0.09%
    flash_amount = min(pool_balance // 2, int(10 * 1e18))  # Flash 10 QTEST or half pool
    fee = (flash_amount * 9) // 10000 + 1  # 0.09% + 1 wei safety margin
    fund_amount = fee + int(0.01 * 1e18)  # fee + small buffer

    print(f"\n[4] Funding receiver with {fund_amount / 1e18:.6f} QTEST for fee...")
    transfer_sel = "a9059cbb"  # transfer(address, uint256)
    transfer_data = transfer_sel + pad_addr(receiver_addr).hex() + pad_u256_le(fund_amount).hex()
    tx = call_contract(token, QTEST_ADDRESS, transfer_data)
    print(f"    Fund TX: {tx['tx_hash']}")
    time.sleep(2)

    # Verify receiver balance
    recv_balance_hex = read_contract(QTEST_ADDRESS, balanceOf_sel + pad_addr(receiver_addr).hex())["result"]
    recv_balance = decode_le_u256(recv_balance_hex)
    print(f"    Receiver QTEST balance: {recv_balance / 1e18:.6f}")

    # 5. Execute flash loan!
    print(f"\n[5] Executing flash loan: {flash_amount / 1e18:.4f} QTEST")
    
    # Get flashLoan selector from pool contract
    pool_contract = LENDING_DIR / "VybssLendingPool.contract"
    flashloan_sel = get_selector(pool_contract, "flashLoan")
    
    # flashLoan(uint256 _reserveId, uint256 _amount, address _receiver, bytes _params)
    # For SCALE encoding of empty bytes param: compact(0) = 0x00
    flash_calldata = (
        flashloan_sel.hex()
        + pad_u256_le(RESERVE_ID).hex()
        + pad_u256_le(flash_amount).hex()
        + pad_addr(receiver_addr).hex()
        + "00"  # empty bytes: compact(0) = 0x00
    )
    
    print(f"    Reserve ID: {RESERVE_ID}")
    print(f"    Amount: {flash_amount / 1e18:.4f} QTEST")
    print(f"    Fee (0.09%): {fee / 1e18:.6f} QTEST")
    print(f"    Receiver: {receiver_addr}")
    
    try:
        result = call_contract(token, POOL_ADDRESS, flash_calldata)
        print(f"\n    ✅ Flash loan SUCCESS!")
        print(f"    TX Hash: {result['tx_hash']}")
        print(f"    Status: {result['status']}")
    except Exception as e:
        print(f"\n    ❌ Flash loan FAILED: {e}")
        return

    time.sleep(2)

    # 6. Verify post-flash state
    print("\n[6] Post-flash verification...")
    pool_balance_after_hex = read_contract(QTEST_ADDRESS, balanceOf_sel + pad_addr(POOL_ADDRESS).hex())["result"]
    pool_balance_after = decode_le_u256(pool_balance_after_hex)
    print(f"    Pool QTEST before: {pool_balance / 1e18:.6f}")
    print(f"    Pool QTEST after:  {pool_balance_after / 1e18:.6f}")
    print(f"    Fee earned:        {(pool_balance_after - pool_balance) / 1e18:.6f}")

    recv_balance_after_hex = read_contract(QTEST_ADDRESS, balanceOf_sel + pad_addr(receiver_addr).hex())["result"]
    recv_balance_after = decode_le_u256(recv_balance_after_hex)
    print(f"    Receiver balance:  {recv_balance_after / 1e18:.6f} (was {recv_balance / 1e18:.6f})")

    print("\n=== Flash Loan Test Complete ===")

if __name__ == "__main__":
    main()
