#!/bin/bash
# Full faucet test: build wallet-server, restart it, create wallet, claim, check balance
set -e
cd /Users/wayle/Quantos_labs/quantos-wallet-server
cargo build 2>&1 | grep -E "^error|Finished"
pkill -f "quantos-wallet-server" 2>/dev/null || true
sleep 1
RUST_LOG=info ./target/debug/quantos-wallet-server > /tmp/wallet_server.log 2>&1 &
sleep 2

WS="http://127.0.0.1:3001"
NODE="http://127.0.0.1:8545"

# Create + unlock + claim
WALLET=$(curl -s $WS/wallet/create -X POST -H "Content-Type: application/json" -d '{"pin":"111111"}')
ADDR=$(echo $WALLET | python3 -c "import sys,json; print(json.load(sys.stdin)['wallet']['address'])")
EKEY=$(echo $WALLET | python3 -c "import sys,json; print(json.load(sys.stdin)['encrypted_key'])")
echo "Wallet: $ADDR"

SESSION=$(curl -s $WS/wallet/unlock -X POST -H "Content-Type: application/json" -d "{\"address\":\"$ADDR\",\"encrypted_key\":\"$EKEY\",\"pin\":\"111111\"}")
TOKEN=$(echo $SESSION | python3 -c "import sys,json; print(json.load(sys.stdin)['session_token'])")

echo "Claiming..."
CLAIM=$(curl -s $WS/faucet/claim -X POST -H "Content-Type: application/json" -d "{\"session_token\":\"$TOKEN\"}")
echo "Claim: $CLAIM"
sleep 3

echo "--- Direct qnt_call balanceOf ---"
curl -s $NODE -X POST -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"method\":\"qnt_call\",\"id\":1,\"params\":[{\"to\":\"QTS:9a8424ca84a1ae0607d536ccadad28f222dad3f03087795042117b625f451032\",\"data\":\"0x70a08231$ADDR\"}]}"
echo ""

echo "--- Wallet-server /balance ---"
curl -s $WS/wallet/$ADDR/balance | python3 -c "import sys,json; d=json.load(sys.stdin); print('qtest_balance:', d.get('qtest_balance')); print('qtest_formatted:', d.get('qtest_balance_formatted'))"

echo "--- Wallet-server logs ---"
grep -i "QTEST\|balanceOf\|warn\|error" /tmp/wallet_server.log | tail -10
