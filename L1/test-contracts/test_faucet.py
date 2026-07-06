#!/usr/bin/env python3
"""Full faucet test: create wallet, claim, verify balanceOf via qnt_call."""
import json, subprocess, time, sys
try:
    import requests
except ImportError:
    print("Installing requests..."); subprocess.run([sys.executable, "-m", "pip", "install", "requests", "-q"])
    import requests

WS = "http://127.0.0.1:3001"
NODE = "http://127.0.0.1:8545"
CONTRACT = "QTS:9a8424ca84a1ae0607d536ccadad28f222dad3f03087795042117b625f451032"

def ws_post(path, data):
    r = requests.post(f"{WS}{path}", json=data)
    return r.json()

# 1. Create wallet + unlock
print("1. Creating wallet...")
w = ws_post("/wallet/create", {"pin": "123456"})
addr = w["wallet"]["address"]
ekey = w["encrypted_key"]
print(f"   Address: {addr[:16]}...")

print("2. Unlocking...")
s = ws_post("/wallet/unlock", {"address": addr, "encrypted_key": ekey, "pin": "123456"})
token = s["session_token"]
print(f"   Session: {token[:16]}...")

# 3. Claim faucet
print("3. Claiming faucet...")
c = ws_post("/faucet/claim", {"session_token": token})
print(f"   Status: {c.get('status')}, Amount: {c.get('amount_formatted')}")

time.sleep(2)

# 4. Check totalSupply via qnt_call
print("4. Checking totalSupply...")
r = requests.post(NODE, json={"jsonrpc":"2.0","method":"qnt_call","id":1,"params":[{"to":CONTRACT,"data":"0x18160ddd"}]})
result = r.json().get("result", "")
print(f"   totalSupply raw: {result}")

# 5. Check balanceOf
print("5. Checking balanceOf...")
calldata = "70a08231" + addr
r = requests.post(NODE, json={"jsonrpc":"2.0","method":"qnt_call","id":2,"params":[{"from":"QTS:"+addr,"to":CONTRACT,"data":"0x"+calldata}]})
result = r.json().get("result", "")
print(f"   balanceOf raw: {result}")

if result and result != "QTS:" and result != "qts:":
    print("\n✅ SUCCESS: Contract storage is working!")
else:
    print("\n❌ FAIL: balanceOf returned empty — storage not persisted or qnt_call issue")
    # Debug: check if contract is recognized
    r = requests.post(NODE, json={"jsonrpc":"2.0","method":"qnt_getCode","id":3,"params":[CONTRACT]})
    print(f"   getCode: {r.json().get('result', '')[:40]}...")
