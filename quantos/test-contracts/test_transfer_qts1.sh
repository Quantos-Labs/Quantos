#!/bin/bash
set -e

API="http://127.0.0.1:3001"
RPC="http://127.0.0.1:8545"

echo "=== 1. Create wallet A ==="
WA=$(curl -s $API/wallet/create -X POST -H "Content-Type: application/json" -d '{"pin":"123456"}')
ADDR_A=$(echo "$WA" | jq -r '.wallet.address')
QTS1_A=$(echo "$WA" | jq -r '.wallet.qts_address')
KEY_A=$(echo "$WA" | jq -r '.encrypted_key')
echo "A hex:  $ADDR_A"
echo "A qts1: $QTS1_A"

echo "=== 2. Create wallet B ==="
WB=$(curl -s $API/wallet/create -X POST -H "Content-Type: application/json" -d '{"pin":"123456"}')
ADDR_B=$(echo "$WB" | jq -r '.wallet.address')
QTS1_B=$(echo "$WB" | jq -r '.wallet.qts_address')
echo "B hex:  $ADDR_B"
echo "B qts1: $QTS1_B"

echo "=== 3. Verify qts1 roundtrip (new format) ==="
echo "A qts1 length: ${#QTS1_A} chars (old was ~43, new should be ~62)"
echo "B qts1 length: ${#QTS1_B} chars"

echo "=== 4. Unlock A ==="
SESSION_A=$(curl -s "$API/wallet/unlock" -X POST -H "Content-Type: application/json" -d "{\"address\":\"$ADDR_A\",\"encrypted_key\":\"$KEY_A\",\"pin\":\"123456\"}" | jq -r '.session_token')
echo "Session: ${SESSION_A:0:20}..."

echo "=== 5. Claim faucet A ==="
curl -s $API/faucet/claim -X POST -H "Content-Type: application/json" -d "{\"session_token\":\"$SESSION_A\"}" | jq -r '.amount_formatted'
sleep 3

echo "=== 6. Transfer 100 QTEST A->B using qts1 address ==="
TRANSFER=$(curl -s $API/wallet/transfer-token -X POST -H "Content-Type: application/json" -d "{\"session_token\":\"$SESSION_A\",\"to\":\"$QTS1_B\",\"amount\":\"100\"}")
echo "Transfer: $TRANSFER"
sleep 3

echo "=== 7. Balance B ==="
BAL_B=$(curl -s "$API/wallet/$ADDR_B/balance")
echo "B QTEST: $(echo $BAL_B | jq -r '.qtest_balance_formatted')"

echo "=== DONE ==="
