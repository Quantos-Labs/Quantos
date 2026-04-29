#!/bin/bash
set -e

API="http://127.0.0.1:3001"
RPC="http://127.0.0.1:8545"
CONTRACT="QTS:9a8424ca84a1ae0607d536ccadad28f222dad3f03087795042117b625f451032"

echo "=== 1. Create wallet A ==="
WA=$(curl -s $API/wallet/create -X POST -H "Content-Type: application/json" -d '{"pin":"123456"}')
ADDR_A=$(echo "$WA" | jq -r '.wallet.address')
RPC_A=$(echo "$WA" | jq -r '.wallet.rpc_address')
KEY_A=$(echo "$WA" | jq -r '.encrypted_key')
echo "Wallet A: $RPC_A"

echo "=== 2. Unlock wallet A ==="
UNLOCK_A=$(curl -s "$API/wallet/unlock" -X POST -H "Content-Type: application/json" -d "{\"address\":\"$ADDR_A\",\"encrypted_key\":\"$KEY_A\",\"pin\":\"123456\"}")
SESSION_A=$(echo "$UNLOCK_A" | jq -r '.session_token')
echo "Session A: ${SESSION_A:0:20}..."
if [ "$SESSION_A" = "null" ]; then echo "UNLOCK FAILED: $UNLOCK_A"; exit 1; fi

echo "=== 3. Claim faucet for wallet A ==="
CLAIM=$(curl -s $API/faucet/claim -X POST -H "Content-Type: application/json" -d "{\"session_token\":\"$SESSION_A\"}")
echo "Claim: $CLAIM"
TX_CLAIM=$(echo "$CLAIM" | jq -r '.tx_hash // empty')
if [ -z "$TX_CLAIM" ]; then echo "CLAIM FAILED"; exit 1; fi
sleep 3

echo "=== 4. balanceOf A (direct RPC) ==="
BAL_A_RAW=$(curl -s $RPC -X POST -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"method\":\"qnt_call\",\"params\":[{\"to\":\"$CONTRACT\",\"data\":\"0x70a08231$ADDR_A\",\"from\":\"$RPC_A\"}],\"id\":1}")
echo "balanceOf A: $BAL_A_RAW"

echo "=== 5. Balance A via wallet-server ==="
BAL_A=$(curl -s "$API/wallet/$ADDR_A/balance")
echo "QTEST A: $(echo $BAL_A | jq -r '.qtest_balance_formatted')"

echo "=== 6. Create wallet B ==="
WB=$(curl -s $API/wallet/create -X POST -H "Content-Type: application/json" -d '{"pin":"123456"}')
ADDR_B=$(echo "$WB" | jq -r '.wallet.address')
RPC_B=$(echo "$WB" | jq -r '.wallet.rpc_address')
echo "Wallet B: $RPC_B"

echo "=== 7. Transfer 100 QTEST A->B ==="
TRANSFER=$(curl -s $API/wallet/transfer-token -X POST -H "Content-Type: application/json" -d "{\"session_token\":\"$SESSION_A\",\"to\":\"$RPC_B\",\"amount\":\"100\"}")
echo "Transfer: $TRANSFER"
sleep 4

echo "=== 8. Balance A after ==="
BAL_A2=$(curl -s "$API/wallet/$ADDR_A/balance")
echo "QTEST A: $(echo $BAL_A2 | jq -r '.qtest_balance_formatted')"

echo "=== 9. Balance B after ==="
BAL_B=$(curl -s "$API/wallet/$ADDR_B/balance")
echo "QTEST B: $(echo $BAL_B | jq -r '.qtest_balance_formatted')"

echo "=== 10. balanceOf B (direct RPC) ==="
BAL_B_RAW=$(curl -s $RPC -X POST -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"method\":\"qnt_call\",\"params\":[{\"to\":\"$CONTRACT\",\"data\":\"0x70a08231$ADDR_B\",\"from\":\"$RPC_B\"}],\"id\":1}")
echo "balanceOf B: $BAL_B_RAW"

echo ""
echo "=== Node logs (last contract calls) ==="
grep -i "execute_contract\|contract.*call\|transfer\|storage_writes" /tmp/quantos.log | tail -10

echo ""
echo "=== DONE ==="
