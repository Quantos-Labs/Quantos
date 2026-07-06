#!/usr/bin/env python3
"""
End-to-end flash loan test:
1. Deploy fresh pool + tokens
2. Init reserve with flashLoanEnabled
3. Supply liquidity
4. Deploy SimpleFlashReceiver
5. Fund receiver for premium
6. Execute flash loan
7. Verify premium earned
"""
import json, requests, sys, time
from pathlib import Path

WALLET_SERVER = "http://127.0.0.1:3001"
LENDING_DIR = Path(__file__).resolve().parent.parent / "solidity-contracts" / "lending"
QTEST_ADDRESS = "QTS:c49ffa02bdb365b7e5bf1655dd296b7358eebdfdbe2abb3a1998db8daddc3a68"
PIN = "123456"


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def curl_post(url, body):
    r = requests.post(url, json=body, timeout=30)
    if r.status_code not in (200, 201):
        fail(f"{url} => {r.status_code}: {r.text[:300]}")
    return r.json()


def pad_u256_le(n):
    return n.to_bytes(32, "little")


def pad_addr(addr):
    raw = addr.replace("QTS:", "").replace("0x", "")
    return bytes.fromhex(raw.ljust(64, "0")[:64])


def encode_bool_le(v):
    return b"\x01" if v else b"\x00"


def encode_string_scale(s):
    length = len(s)
    if length < 64:
        compact = bytes([length << 2])
    elif length < 16384:
        compact = ((length << 2) | 0x01).to_bytes(2, "little")
    else:
        compact = ((length << 2) | 0x02).to_bytes(4, "little")
    return compact + s


def decode_le_u256(hex_str):
    # Strip qts: or 0x prefix if present
    cleaned = hex_str.strip()
    if cleaned.startswith("qts:"):
        cleaned = cleaned[4:]
    elif cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    return int.from_bytes(bytes.fromhex(cleaned), "little")


def deploy(session_token, wasm_path, ctor_data=b""):
    with wasm_path.open("rb") as f:
        bh = f.read().hex()
    return curl_post(f"{WALLET_SERVER}/wallet/deploy", {
        "session_token": session_token,
        "bytecode_hex": bh,
        "constructor_data_hex": ctor_data.hex() if ctor_data else None,
    })


def call(session_token, address, calldata):
    return curl_post(f"{WALLET_SERVER}/wallet/call", {
        "session_token": session_token,
        "contract_address": address,
        "calldata_hex": calldata.hex(),
        "amount": "0",
    })


def read(address, calldata_hex):
    return curl_post(f"{WALLET_SERVER}/wallet/read-contract", {
        "contract_address": address,
        "calldata_hex": calldata_hex,
    })


def get_sel(path, label):
    meta = json.loads(path.read_text())
    for m in meta["spec"]["messages"]:
        if m["label"] == label:
            return bytes.fromhex(m["selector"][2:])
    for c in meta["spec"]["constructors"]:
        if c["label"] == "new":
            return bytes.fromhex(c["selector"][2:])
    fail(f"Selector not found: {label}")


def main():
    pool_meta = LENDING_DIR / "VybssLendingPool.contract"
    ltoken_meta = LENDING_DIR / "VybssLToken.contract"
    debt_meta = LENDING_DIR / "VybssDebtToken.contract"
    recv_meta = LENDING_DIR / "SimpleFlashReceiver.contract"

    print("=== Flash Loan End-to-End Test ===")

    # 1. Create wallet + fund
    print("\n[1] Creating wallet...")
    w = curl_post(f"{WALLET_SERVER}/wallet/create", {"pin": PIN})
    addr = w["wallet"]["address"]
    ekey = w["encrypted_key"]
    ul = curl_post(f"{WALLET_SERVER}/wallet/unlock", {
        "address": addr, "encrypted_key": ekey, "pin": PIN,
    })
    tok = ul["session_token"]
    print(f"    Wallet: {addr}")

    for _ in range(3):
        try:
            curl_post(f"{WALLET_SERVER}/faucet/claim", {"session_token": tok})
        except SystemExit:
            pass
        time.sleep(1)
    print("    Faucet claimed")

    # Check balance
    balanceOf_sel = "70a08231"
    bal_hex = read(QTEST_ADDRESS, balanceOf_sel + pad_addr(addr).hex())["result"]
    bal = decode_le_u256(bal_hex)
    print(f"    Our QTEST balance: {bal / 1e18:.2f}")

    # 2. Deploy Pool
    print("\n[2] Deploying VybssLendingPool...")
    pool_ctor = get_sel(pool_meta, "new")
    pool_resp = deploy(tok, LENDING_DIR / "VybssLendingPool.wasm", pool_ctor)
    pool_addr = pool_resp.get("contract_address") or pool_resp.get("address")
    if not pool_addr:
        fail(f"Pool deploy failed: {pool_resp}")
    print(f"    Pool: {pool_addr}")
    time.sleep(2)

    # 3. Deploy LToken + DebtToken
    print("\n[3] Deploying LToken + DebtToken...")
    ltoken_ctor = get_sel(ltoken_meta, "new")
    lt_data = (ltoken_ctor
               + encode_string_scale(b"Vybss QTEST")
               + encode_string_scale(b"vQTEST")
               + pad_addr(pool_addr)
               + pad_addr(QTEST_ADDRESS))
    lt_resp = deploy(tok, LENDING_DIR / "VybssLToken.wasm", lt_data)
    lt_addr = lt_resp.get("contract_address") or lt_resp.get("address")
    print(f"    LToken: {lt_addr}")
    time.sleep(1)

    dt_ctor = get_sel(debt_meta, "new")
    dt_data = (dt_ctor
               + encode_string_scale(b"Vybss QTEST Debt")
               + encode_string_scale(b"vDebtQTEST")
               + pad_addr(pool_addr)
               + pad_addr(QTEST_ADDRESS))
    dt_resp = deploy(tok, LENDING_DIR / "VybssDebtToken.wasm", dt_data)
    dt_addr = dt_resp.get("contract_address") or dt_resp.get("address")
    print(f"    DebtToken: {dt_addr}")
    time.sleep(1)

    # 4. Init reserve (flashLoanEnabled = true by default in contract)
    print("\n[4] Initializing QTEST reserve...")
    init_sel = get_sel(pool_meta, "initReserve")
    init_data = (init_sel
                 + pad_addr(QTEST_ADDRESS)
                 + pad_addr(lt_addr)
                 + pad_addr(dt_addr)
                 + pad_u256_le(8000)
                 + pad_u256_le(8500)
                 + pad_u256_le(500)
                 + pad_u256_le(1000)
                 + encode_bool_le(True)
                 + encode_bool_le(True))
    call(tok, pool_addr, init_data)
    print("    Reserve #1 initialized (flashLoanEnabled=true)")
    time.sleep(1)

    # 5. Approve + Supply QTEST
    print("\n[5] Supplying 100 QTEST to pool...")
    approve_sel = bytes.fromhex("095ea7b3")
    supply_amount = int(100 * 1e18)
    approve_data = approve_sel + pad_addr(pool_addr) + pad_u256_le(supply_amount)
    call(tok, QTEST_ADDRESS, approve_data)
    time.sleep(1)

    supply_sel = get_sel(pool_meta, "supply")
    supply_data = supply_sel + pad_u256_le(1) + pad_u256_le(supply_amount)
    call(tok, pool_addr, supply_data)
    print("    Supplied 100 QTEST")
    time.sleep(1)

    pool_bal_hex = read(QTEST_ADDRESS, balanceOf_sel + pad_addr(pool_addr).hex())["result"]
    pool_bal = decode_le_u256(pool_bal_hex)
    print(f"    Pool QTEST liquidity: {pool_bal / 1e18:.2f}")

    # 6. Deploy SimpleFlashReceiver
    print("\n[6] Deploying SimpleFlashReceiver...")
    recv_ctor = get_sel(recv_meta, "new")
    recv_data = recv_ctor + pad_addr(pool_addr)
    recv_resp = deploy(tok, LENDING_DIR / "SimpleFlashReceiver.wasm", recv_data)
    recv_addr = recv_resp.get("contract_address") or recv_resp.get("address")
    print(f"    Receiver: {recv_addr}")
    time.sleep(1)

    # 7. Fund receiver for premium
    flash_amount = int(10 * 1e18)
    premium = (flash_amount * 9) // 10000 + 1  # 0.09% + 1 wei
    fund_amount = premium + int(0.01 * 1e18)
    print(f"\n[7] Funding receiver with {fund_amount / 1e18:.6f} QTEST...")
    transfer_sel = bytes.fromhex("a9059cbb")
    xfer_data = transfer_sel + pad_addr(recv_addr) + pad_u256_le(fund_amount)
    call(tok, QTEST_ADDRESS, xfer_data)
    time.sleep(1)

    recv_bal_hex = read(QTEST_ADDRESS, balanceOf_sel + pad_addr(recv_addr).hex())["result"]
    recv_bal = decode_le_u256(recv_bal_hex)
    print(f"    Receiver balance: {recv_bal / 1e18:.6f} QTEST")

    # 8. FLASH LOAN
    print(f"\n[8] Executing flash loan: {flash_amount / 1e18:.1f} QTEST...")
    fl_sel = get_sel(pool_meta, "flashLoan")
    fl_data = (fl_sel
               + pad_u256_le(1)
               + pad_u256_le(flash_amount)
               + pad_addr(recv_addr)
               + b"\x00")  # empty bytes (SCALE compact(0))

    print(f"    Reserve ID: 1")
    print(f"    Amount: {flash_amount / 1e18:.1f} QTEST")
    print(f"    Premium (0.09%): {premium / 1e18:.6f} QTEST")
    print(f"    Receiver: {recv_addr}")

    try:
        result = call(tok, pool_addr, fl_data)
        print(f"\n    TX Hash: {result['tx_hash']}")
        print(f"    Status: {result.get('status', '?')}")
        print("    >>> FLASH LOAN SUCCESS <<<")
    except SystemExit as e:
        print(f"\n    >>> FLASH LOAN FAILED <<<")
        return

    time.sleep(1)

    # 9. Verify
    print("\n[9] Post-flash verification...")
    pool_bal_after_hex = read(QTEST_ADDRESS, balanceOf_sel + pad_addr(pool_addr).hex())["result"]
    pool_bal_after = decode_le_u256(pool_bal_after_hex)
    premium_earned = pool_bal_after - pool_bal
    print(f"    Pool QTEST before: {pool_bal / 1e18:.6f}")
    print(f"    Pool QTEST after:  {pool_bal_after / 1e18:.6f}")
    print(f"    Premium earned:    {premium_earned / 1e18:.6f} QTEST")

    recv_bal_after_hex = read(QTEST_ADDRESS, balanceOf_sel + pad_addr(recv_addr).hex())["result"]
    recv_bal_after = decode_le_u256(recv_bal_after_hex)
    print(f"    Receiver balance:  {recv_bal_after / 1e18:.6f} (was {recv_bal / 1e18:.6f})")

    print("\n=== Flash Loan Test Complete ===")


if __name__ == "__main__":
    main()
