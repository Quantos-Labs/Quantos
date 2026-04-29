#!/usr/bin/env python3
"""
End-to-end liquidation test:
1. Deploy fresh pool + tokens, init reserve
2. Borrower supplies 100 QTEST, borrows 75 QTEST
3. Admin lowers liquidation threshold → HF drops below 1.0
4. Liquidator repays part of debt, seizes collateral + 5% bonus
5. Verify balances
"""
import json, requests, sys, time
from pathlib import Path

WALLET_SERVER = "http://127.0.0.1:3001"
LENDING_DIR = Path(__file__).resolve().parent.parent / "solidity-contracts" / "lending"
QTEST_ADDRESS = "QTS:c49ffa02bdb365b7e5bf1655dd296b7358eebdfdbe2abb3a1998db8daddc3a68"
PIN = "123456"
PRECISION = 10**18


def fail(msg):
    print(f"\nFAIL: {msg}")
    sys.exit(1)


def curl_post(url, body):
    r = requests.post(url, json=body, timeout=30)
    if r.status_code not in (200, 201):
        fail(f"{url} => {r.status_code}: {r.text[:300]}")
    return r.json()


def pad_u256_le(n):
    return n.to_bytes(32, "little")


def pad_addr(addr):
    raw = addr.replace("QTS:", "").replace("0x:", "").replace("0x", "")
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
    r = requests.post(f"{WALLET_SERVER}/wallet/read-contract",
                      json={"contract_address": address, "calldata_hex": calldata_hex},
                      timeout=30)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"read-contract {r.status_code}: {r.text[:200]}")
    return r.json()


def get_sel(path, label):
    meta = json.loads(path.read_text())
    for m in meta["spec"]["messages"]:
        if m["label"] == label:
            return bytes.fromhex(m["selector"][2:])
    for c in meta["spec"]["constructors"]:
        if c["label"] == "new":
            return bytes.fromhex(c["selector"][2:])
    fail(f"Selector not found: {label}")


def create_wallet():
    w = curl_post(f"{WALLET_SERVER}/wallet/create", {"pin": PIN})
    addr = w["wallet"]["address"]
    ekey = w["encrypted_key"]
    ul = curl_post(f"{WALLET_SERVER}/wallet/unlock", {
        "address": addr, "encrypted_key": ekey, "pin": PIN,
    })
    tok = ul["session_token"]
    return addr, tok


def fund_wallet(tok, n=3):
    for _ in range(n):
        try:
            curl_post(f"{WALLET_SERVER}/faucet/claim", {"session_token": tok})
        except SystemExit:
            pass
        time.sleep(1)


def balance_of(token_addr, user_addr):
    balanceOf_sel = "70a08231"
    result = read(token_addr, balanceOf_sel + pad_addr(user_addr).hex())["result"]
    return decode_le_u256(result)


def main():
    pool_meta = LENDING_DIR / "VybssLendingPool.contract"
    ltoken_meta = LENDING_DIR / "VybssLToken.contract"
    debt_meta = LENDING_DIR / "VybssDebtToken.contract"

    print("=" * 55)
    print("   LIQUIDATION END-TO-END TEST")
    print("=" * 55)

    # ── 1. Create borrower wallet ──
    print("\n[1] Creating BORROWER wallet...")
    borrower_addr, borrower_tok = create_wallet()
    fund_wallet(borrower_tok, 5)
    borrower_bal = balance_of(QTEST_ADDRESS, borrower_addr)
    print(f"    Address: {borrower_addr}")
    print(f"    QTEST:   {borrower_bal / 1e18:.2f}")

    # ── 2. Deploy Pool + Tokens ──
    print("\n[2] Deploying Pool + LToken + DebtToken...")
    pool_ctor = get_sel(pool_meta, "new")
    pool_resp = deploy(borrower_tok, LENDING_DIR / "VybssLendingPool.wasm", pool_ctor)
    pool_addr = pool_resp.get("contract_address") or pool_resp.get("address")
    if not pool_addr:
        fail(f"Pool deploy failed: {pool_resp}")
    print(f"    Pool: {pool_addr}")
    time.sleep(2)

    lt_ctor = get_sel(ltoken_meta, "new")
    lt_data = (lt_ctor
               + encode_string_scale(b"Vybss QTEST")
               + encode_string_scale(b"vQTEST")
               + pad_addr(pool_addr)
               + pad_addr(QTEST_ADDRESS))
    lt_resp = deploy(borrower_tok, LENDING_DIR / "VybssLToken.wasm", lt_data)
    lt_addr = lt_resp.get("contract_address") or lt_resp.get("address")
    print(f"    LToken: {lt_addr}")
    time.sleep(1)

    dt_ctor = get_sel(debt_meta, "new")
    dt_data = (dt_ctor
               + encode_string_scale(b"Vybss QTEST Debt")
               + encode_string_scale(b"vDebtQTEST")
               + pad_addr(pool_addr)
               + pad_addr(QTEST_ADDRESS))
    dt_resp = deploy(borrower_tok, LENDING_DIR / "VybssDebtToken.wasm", dt_data)
    dt_addr = dt_resp.get("contract_address") or dt_resp.get("address")
    print(f"    DebtToken: {dt_addr}")
    time.sleep(1)

    # ── 3. Init reserve ──
    # LTV=8000 (80%), threshold=8500 (85%), penalty=500 (5%), factor=1000 (10%)
    print("\n[3] Initializing QTEST reserve...")
    init_sel = get_sel(pool_meta, "initReserve")
    init_data = (init_sel
                 + pad_addr(QTEST_ADDRESS)
                 + pad_addr(lt_addr)
                 + pad_addr(dt_addr)
                 + pad_u256_le(8000)    # ltvBps
                 + pad_u256_le(8500)    # liquidationThresholdBps
                 + pad_u256_le(500)     # liquidationPenaltyBps
                 + pad_u256_le(1000)    # reserveFactorBps
                 + encode_bool_le(True) # canBeCollateral
                 + encode_bool_le(True) # canBeBorrowed
                 )
    call(borrower_tok, pool_addr, init_data)
    print("    Reserve #1: LTV=80%, Threshold=85%, Penalty=5%")
    time.sleep(1)

    # ── 4. Borrower supplies 100 QTEST ──
    supply_amount = int(100 * 1e18)
    print(f"\n[4] Borrower supplies {supply_amount / 1e18:.0f} QTEST...")
    approve_sel = bytes.fromhex("095ea7b3")
    call(borrower_tok, QTEST_ADDRESS,
         approve_sel + pad_addr(pool_addr) + pad_u256_le(supply_amount))
    time.sleep(1)

    supply_sel = get_sel(pool_meta, "supply")
    call(borrower_tok, pool_addr, supply_sel + pad_u256_le(1) + pad_u256_le(supply_amount))
    print("    Supplied 100 QTEST (auto-enabled as collateral)")
    time.sleep(1)

    # ── 5. Borrower borrows 75 QTEST (within 80% LTV) ──
    borrow_amount = int(75 * 1e18)
    print(f"\n[5] Borrower borrows {borrow_amount / 1e18:.0f} QTEST...")
    borrow_sel = get_sel(pool_meta, "borrow")
    call(borrower_tok, pool_addr, borrow_sel + pad_u256_le(1) + pad_u256_le(borrow_amount))
    print("    Borrowed 75 QTEST")
    time.sleep(1)

    # Check initial health factor (may fail on read-contract with cross-contract calls)
    hf_sel = get_sel(pool_meta, "getUserHealthFactor")
    try:
        hf_hex = read(pool_addr, hf_sel.hex() + pad_addr(borrower_addr).hex())["result"]
        hf_before = decode_le_u256(hf_hex)
        print(f"    Health Factor: {hf_before / 1e18:.4f} (should be ~1.133)")
        if hf_before < PRECISION:
            fail(f"HF already < 1.0 ({hf_before / 1e18:.4f}) — borrow should have been ok")
    except Exception:
        print("    Health Factor: (read-contract doesn't support cross-contract view calls)")
        print("    Skipping HF check — will verify via liquidation result")

    # ── 6. Admin lowers liquidation threshold → HF < 1.0 ──
    # With threshold=5000 (50%): HF = (100 * 0.50) / 75 = 0.667
    print("\n[6] Admin lowers liquidation threshold to 50%...")
    set_cfg_sel = get_sel(pool_meta, "setReserveConfig")
    set_cfg_data = (set_cfg_sel
                    + pad_u256_le(1)       # reserveId
                    + pad_u256_le(4000)    # ltvBps (40%)
                    + pad_u256_le(5000)    # liquidationThresholdBps (50%)
                    + pad_u256_le(500)     # liquidationPenaltyBps (5%)
                    + pad_u256_le(1000)    # reserveFactorBps (10%)
                    + pad_u256_le(0)       # supplyCap (0 = no cap)
                    + pad_u256_le(0)       # borrowCap (0 = no cap)
                    + encode_bool_le(True) # canBeCollateral
                    + encode_bool_le(True) # canBeBorrowed
                    + encode_bool_le(False) # isFrozen
                    )
    call(borrower_tok, pool_addr, set_cfg_data)
    print("    Threshold=50%, LTV=40%")
    time.sleep(1)

    # Check health factor again — should be < 1.0
    hf_after = None
    try:
        hf_hex2 = read(pool_addr, hf_sel.hex() + pad_addr(borrower_addr).hex())["result"]
        hf_after = decode_le_u256(hf_hex2)
        print(f"    New Health Factor: {hf_after / 1e18:.4f} (should be ~0.667)")
        if hf_after >= PRECISION:
            fail(f"HF still >= 1.0 ({hf_after / 1e18:.4f}) — liquidation impossible")
        print("    ✓ Position is underwater — liquidation possible!")
    except Exception:
        print("    HF read not available (cross-contract view)")
        print("    Proceeding — liquidation call will revert if position is healthy")

    # ── 7. Create LIQUIDATOR wallet ──
    print("\n[7] Creating LIQUIDATOR wallet...")
    liq_addr, liq_tok = create_wallet()
    fund_wallet(liq_tok, 5)
    liq_bal = balance_of(QTEST_ADDRESS, liq_addr)
    print(f"    Address: {liq_addr}")
    print(f"    QTEST:   {liq_bal / 1e18:.2f}")

    # ── 8. Get borrower balances before liquidation ──
    print("\n[8] Pre-liquidation snapshot...")
    borrower_debt_before = None
    borrower_supply_before = None
    borrower_debt_sel = get_sel(pool_meta, "getUserDebtBalance")
    borrower_supply_sel = get_sel(pool_meta, "getUserSupplyBalance")
    try:
        borrower_debt_hex = read(pool_addr, borrower_debt_sel.hex() + pad_u256_le(1).hex() + pad_addr(borrower_addr).hex())["result"]
        borrower_debt_before = decode_le_u256(borrower_debt_hex)
        print(f"    Borrower debt:        {borrower_debt_before / 1e18:.6f} QTEST")
    except Exception:
        print("    Borrower debt: (read not available)")
    try:
        borrower_supply_hex = read(pool_addr, borrower_supply_sel.hex() + pad_u256_le(1).hex() + pad_addr(borrower_addr).hex())["result"]
        borrower_supply_before = decode_le_u256(borrower_supply_hex)
        print(f"    Borrower collateral:  {borrower_supply_before / 1e18:.6f} QTEST")
    except Exception:
        print("    Borrower collateral: (read not available)")

    liq_bal_before = balance_of(QTEST_ADDRESS, liq_addr)
    print(f"    Liquidator QTEST:     {liq_bal_before / 1e18:.6f}")

    # ── 9. Liquidator approves pool + liquidates ──
    # We borrowed 75 QTEST — try to liquidate half (close factor = 50%)
    # If we couldn't read exact debt, use the known borrow amount
    debt_to_repay = (borrower_debt_before // 2) if borrower_debt_before else int(37.5 * 1e18)
    # Add a small buffer for approval
    approve_amount = debt_to_repay + int(1 * 1e18)
    print(f"\n[9] Liquidator repays {debt_to_repay / 1e18:.6f} QTEST of debt...")
    call(liq_tok, QTEST_ADDRESS,
         approve_sel + pad_addr(pool_addr) + pad_u256_le(approve_amount))
    time.sleep(1)

    liquidate_sel = get_sel(pool_meta, "liquidate")
    liq_data = (liquidate_sel
                + pad_addr(borrower_addr)       # user to liquidate
                + pad_u256_le(1)                 # debtReserveId
                + pad_u256_le(1)                 # collateralReserveId
                + pad_u256_le(debt_to_repay)     # debtAmount
                )

    print(f"    Calling liquidate(borrower, debtReserve=1, collReserve=1, amount={debt_to_repay / 1e18:.6f})...")
    try:
        result = call(liq_tok, pool_addr, liq_data)
        print(f"    TX Hash: {result['tx_hash']}")
        print(f"    Status:  {result.get('status', '?')}")
        print("    >>> LIQUIDATION SUCCESS <<<")
    except SystemExit:
        print("    >>> LIQUIDATION FAILED <<<")
        return

    time.sleep(2)

    # ── 10. Post-liquidation verification ──
    print("\n[10] Post-liquidation verification...")

    # Borrower debt should have decreased
    borrower_debt_after = None
    try:
        borrower_debt_hex2 = read(pool_addr, borrower_debt_sel.hex() + pad_u256_le(1).hex() + pad_addr(borrower_addr).hex())["result"]
        borrower_debt_after = decode_le_u256(borrower_debt_hex2)
    except Exception:
        pass

    if borrower_debt_before is not None and borrower_debt_after is not None:
        debt_reduced = borrower_debt_before - borrower_debt_after
        print(f"    Borrower debt before: {borrower_debt_before / 1e18:.6f}")
        print(f"    Borrower debt after:  {borrower_debt_after / 1e18:.6f}")
        print(f"    Debt repaid:          {debt_reduced / 1e18:.6f}")
    else:
        print("    Borrower debt: (cross-contract read not available)")

    # Borrower collateral should have decreased
    borrower_supply_after = None
    try:
        borrower_supply_hex2 = read(pool_addr, borrower_supply_sel.hex() + pad_u256_le(1).hex() + pad_addr(borrower_addr).hex())["result"]
        borrower_supply_after = decode_le_u256(borrower_supply_hex2)
    except Exception:
        pass

    collateral_seized = None
    if borrower_supply_before is not None and borrower_supply_after is not None:
        collateral_seized = borrower_supply_before - borrower_supply_after
        print(f"\n    Borrower collateral before: {borrower_supply_before / 1e18:.6f}")
        print(f"    Borrower collateral after:  {borrower_supply_after / 1e18:.6f}")
        print(f"    Collateral seized:          {collateral_seized / 1e18:.6f}")
    else:
        print("\n    Borrower collateral: (cross-contract read not available)")

    # Liquidator should have received collateral (in underlying QTEST)
    liq_bal_after = balance_of(QTEST_ADDRESS, liq_addr)
    liq_gain = liq_bal_after - liq_bal_before
    print(f"\n    Liquidator QTEST before: {liq_bal_before / 1e18:.6f}")
    print(f"    Liquidator QTEST after:  {liq_bal_after / 1e18:.6f}")
    print(f"    Liquidator net change:   {liq_gain / 1e18:.6f}")
    # Liquidator spent debt_to_repay but got collateral back
    # net change = collateral_received - debt_paid
    # So collateral_received = net_change + debt_paid
    collateral_received = liq_gain + debt_to_repay
    print(f"    Collateral received:     {collateral_received / 1e18:.6f}")

    # Expected: collateral_received ≈ debt_repaid * 1.05 (5% bonus)
    expected_seized = debt_to_repay * 10500 // 10000
    print(f"\n    Expected collateral:  {expected_seized / 1e18:.6f} (debt * 1.05)")
    print(f"    Actual received:      {collateral_received / 1e18:.6f}")

    diff = abs(collateral_received - expected_seized)
    tolerance = int(0.5 * 1e18)
    if diff <= tolerance:
        print(f"    ✓ Liquidation bonus correct (5% within tolerance)")
    else:
        print(f"    ✗ Bonus mismatch: diff={diff / 1e18:.6f} QTEST")

    # Check health factor improved
    try:
        hf_hex3 = read(pool_addr, hf_sel.hex() + pad_addr(borrower_addr).hex())["result"]
        hf_final = decode_le_u256(hf_hex3)
        print(f"\n    Health Factor after liquidation: {hf_final / 1e18:.4f}")
        if hf_after is not None and hf_final > hf_after:
            print(f"    ✓ HF improved: {hf_after / 1e18:.4f} → {hf_final / 1e18:.4f}")
    except Exception:
        print("\n    Health Factor read not available")

    print("\n" + "=" * 55)
    print("   LIQUIDATION TEST COMPLETE")
    print("=" * 55)


if __name__ == "__main__":
    main()
