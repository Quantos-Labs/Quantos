# Quantos JSON-RPC API Specification

**Version:** 1.0 · **Status:** Testnet · **License:** BUSL-1.1

This document is the canonical specification of the Quantos L1 JSON-RPC API
exposed by every Quantos node. It is intended for RPC providers, wallet
integrators, indexers, and SDK authors.

> **Quantos is NOT EVM-compatible.** It is a PQC-native L1: signatures are
> **ML-DSA-65** (FIPS 204), addresses are **32 bytes**, and the RPC namespace
> is **`qnt_*`** (not `eth_*`). There is no ECDSA, no RLP, no `0x`-only
> formatting. See [Conventions](#conventions) below.

---

## Table of Contents

1. [Transport](#transport)
2. [Conventions](#conventions)
3. [Error Codes](#error-codes)
4. [Rate Limiting](#rate-limiting)
5. [Methods — Account & State](#methods--account--state)
6. [Methods — Transactions](#methods--transactions)
7. [Methods — Node & Network](#methods--node--network)
8. [Methods — Validators](#methods--validators)
9. [Methods — DAG](#methods--dag)
10. [Methods — Mempool / Ingress](#methods--mempool--ingress)
11. [Methods — Contracts](#methods--contracts)
12. [Methods — Tokens (QN4 / QN8)](#methods--tokens-qn4--qn8)
13. [Methods — Explorer Indexing](#methods--explorer-indexing)
14. [Methods — L0 Finality Hub](#methods--l0-finality-hub)
15. [Methods — Subnets](#methods--subnets)
16. [Methods — Server-side Signing](#methods--server-side-signing)
17. [Subscriptions (WebSocket)](#subscriptions-websocket)
18. [Chain IDs](#chain-ids)
19. [Supported External Chain IDs (L0)](#supported-external-chain-ids-l0)

---

## Transport

| Transport | URL | Notes |
|---|---|---|
| HTTP | `http://<host>:8545` | Default port, configurable via `NodeConfig.rpc_port` |
| WebSocket | `ws://<host>:8545` | Same port; required for `qnt_subscribe` |

All requests use JSON-RPC 2.0:

```jsonc
// Request
{ "jsonrpc": "2.0", "id": 1, "method": "qnt_getBalance", "params": ["QTS:..."] }

// Response (success)
{ "jsonrpc": "2.0", "id": 1, "result": "QTS:de0b6b3a7640000" }

// Response (error)
{ "jsonrpc": "2.0", "id": 1, "error": { "code": -32000, "message": "..." } }
```

`params` is always a positional JSON array. `id` may be a number, string, or null.

---

## Conventions

### The `QTS:` prefix

Quantos uses a **`QTS:`** prefix (uppercase, case-insensitive on input) to
disambiguate Quantos-encoded values from Ethereum's `0x`. Every hex string
returned by the API is prefixed with `QTS:`. Inputs accept `QTS:`, `qts:`,
`0x`, or raw hex.

| Type | Format | Example |
|---|---|---|
| Address | `QTS:` + 32-byte hex (64 chars) | `QTS:0102…ff` (64 hex chars) |
| Hash | `QTS:` + 32-byte hex | `QTS:abcd…1234` |
| Amount / integer | `QTS:` + lowercase hex (no leading zeros beyond `0`) | `QTS:de0b6b3a7640000` (= 1 QTS) |
| Balance 0 | `QTS:0` | |
| Empty / no code | `QTS:` (empty payload) | |
| Encrypted contract marker | `QTS:00` | Bytecode is never returned (Bytecode Invisible) |

> **Important for SDK authors:** do not strip `QTS:` and treat the remainder as
> an Ethereum value. Addresses are 32 bytes, not 20. Amounts are `u128`, not
> `u256`.

### Block parameter

Methods that accept an optional `block` parameter (e.g. `qnt_getBalance`)
currently **ignore** it — Quantos always reads the latest finalized state.
The parameter is kept for forward compatibility with historical queries.
Pass `"latest"` or omit it.

### Signatures

All transactions are signed with **ML-DSA-65** (FIPS 204, ~3.3 KB signature,
~1.95 KB public key). ECDSA / secp256k1 signatures are **not accepted**.
See `qnt_sendRawTransaction` for the wire format.

### Zero gas fees

Quantos has **zero gas fees**. `qnt_estimateGas` always returns `qts:0`.
Transactions carry a `max_compute_units` field (compute budget, not a fee).

---

## Error Codes

| Code | Meaning | When |
|---|---|---|
| `-32700` | Parse error | Invalid JSON |
| `-32600` | Invalid request | Not a valid JSON-RPC 2.0 request |
| `-32601` | Method not found | Unknown method, or `qnt_deployContract` (deprecated) |
| `-32602` | Invalid params | Wrong number / type of params |
| `-32603` | Internal error | Unexpected server failure |
| `-32000` | Server error | Generic application error (invalid address, storage failure, signing failure, L0 hub disabled, etc.) — see `message` |
| `-32005` | Too many concurrent contract calls | `qnt_call` semaphore exhausted (`QUANTOS_MAX_CONCURRENT_EXECUTIONS`, default 128) |
| HTTP 429 | Rate limit exceeded | Returned by the HTTP middleware **before** JSON-RPC dispatch (see [Rate Limiting](#rate-limiting)) |

The `-32000` code is overloaded; always inspect the `message` string for the
specific reason (e.g. `"Invalid Quantos address: ..."`,
`"L0 finality hub is not enabled on this node"`,
`"Invalid ML-DSA-65 private key: ..."`).

---

## Rate Limiting

Rate limiting is enforced by a Tower HTTP middleware (`RateLimitLayer`)
**before** requests reach the JSON-RPC handler. When the limit is hit, the
server responds with HTTP `429 Too Many Requests` and a JSON-RPC error body:

```json
{ "jsonrpc": "2.0", "error": { "code": -32000, "message": "Rate limit exceeded for IP x.x.x.x" }, "id": null }
```

| Setting | Env var | Default |
|---|---|---|
| Requests / minute / IP | `QUANTOS_RATE_LIMIT_PER_MINUTE` | 100 |
| Burst allowance / IP | `QUANTOS_RATE_LIMIT_BURST` | 20 |
| Ban threshold (requests in 5 min window) | `QUANTOS_BAN_THRESHOLD` | 500 |
| Ban duration | `QUANTOS_BAN_DURATION_SECS` | 300 (5 min) |
| Max concurrent contract execs | `QUANTOS_MAX_CONCURRENT_EXECUTIONS` | 128 |
| Max batch size (`qnt_sendRawTransactionBatch`) | `QUANTOS_RPC_MAX_BATCH_SIZE` | 2000 |

Client IP is extracted from `X-Forwarded-For` (first entry) or `X-Real-IP`,
falling back to `0.0.0.0` for direct connections. **Always deploy behind a
reverse proxy that sets `X-Forwarded-For`.**

---

## Methods — Account & State

### `qnt_getBalance`

Returns the QTS balance of an account.

| | |
|---|---|
| **Params** | `address: String` (QTS:…), `block: Option<String>` (ignored) |
| **Returns** | `String` — `QTS:<hex u128>` |
| **Example** | `qnt_getBalance ["QTS:0102…ff", "latest"]` → `"QTS:de0b6b3a7640000"` |

### `qnt_getTransactionCount`

Returns the nonce (transaction count) of an account.

| | |
|---|---|
| **Params** | `address: String`, `block: Option<String>` (ignored) |
| **Returns** | `String` — `QTS:<hex u64>` |

### `qnt_getAccount`

Full account state.

| | |
|---|---|
| **Params** | `address: String` |
| **Returns** | `AccountInfo \| null` |

```jsonc
{
  "address": "QTS:…",          // 32-byte hex
  "balance": "QTS:de0b…",       // u128 hex
  "nonce": "QTS:1a",            // u64 hex
  "code_hash": "QTS:…" | null,  // present if contract
  "storage_root": "QTS:…",
  "stake": "QTS:0",             // u128 hex, staked amount
  "is_validator": false,
  "is_contract": false
}
```

### `qnt_getStateRoot`

Returns the current global state root.

| | |
|---|---|
| **Params** | none |
| **Returns** | `String` — `QTS:<32-byte hex>` |

### `qnt_getCode`

Returns a marker indicating whether a contract is deployed at the address.
**The actual bytecode is never returned** (Bytecode Invisible protection).

| | |
|---|---|
| **Params** | `address: String`, `block: Option<String>` (ignored) |
| **Returns** | `String` — `"QTS:00"` if a contract exists (encrypted), `"QTS:"` if none |

### `qnt_getStorageAt`

Returns the value at a 32-byte storage slot of a contract.

| | |
|---|---|
| **Params** | `address: String`, `position: String` (QTS: 32-byte slot key), `block: Option<String>` (ignored) |
| **Returns** | `String` — `QTS:<32-byte hex>` (zero-padded; `QTS:000…0` if unset or target is not a contract) |
| **Errors** | `-32000` if storage access fails or target is not a contract |

---

## Methods — Transactions

### `qnt_sendRawTransaction`

Submits a signed transaction. The transaction is a **bincode-serialized
`SignedTransaction`** (not RLP), hex-encoded with the `QTS:` prefix.

| | |
|---|---|
| **Params** | `tx_hex: String` (`QTS:…` or `0x…` hex of bincode blob) |
| **Returns** | `String` — `QTS:<tx hash>` |
| **Limits** | Max tx size: 1 MB (`MAX_TX_SIZE`) |
| **Errors** | `-32000` — invalid hex, invalid format, too large, submit failure |
| **Signing** | ML-DSA-65 over `Transaction::signing_data()` (domain-separated via `DOMAIN_TX`) |

```bash
curl -X POST http://localhost:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"qnt_sendRawTransaction","params":["QTS:deadbeef…"]}'
```

### `qnt_sendRawTransactionBatch`

Submits a batch of signed transactions. Decoding is parallelized (rayon);
valid txs are submitted as one batch to the ingress buffer.

| | |
|---|---|
| **Params** | `txs_hex: Vec<String>` |
| **Returns** | `Vec<String>` — per-tx `QTS:<hash>` on success, or `"error:<reason>"` on failure |
| **Limits** | Max batch: `QUANTOS_RPC_MAX_BATCH_SIZE` (default 2000); each tx ≤ 1 MB |
| **Errors** | `-32000` if batch too large |

Result entries preserve input order. Per-tx failures are returned inline as
`"error:invalid_hex"`, `"error:tx_too_large"`, `"error:invalid_format"`, or
`"error:<consensus reason>"`.

### `qnt_getTransactionByHash`

| | |
|---|---|
| **Params** | `hash: String` |
| **Returns** | `TransactionInfo \| null` |

```jsonc
{
  "hash": "QTS:…",
  "from": "QTS:…",
  "to": "QTS:…",
  "value": "QTS:de0b…",   // u128 hex
  "nonce": "QTS:1a",      // u64 hex
  "gas": "QTS:5208",      // legacy placeholder, Quantos has zero fees
  "input": "QTS:…"        // calldata hex
}
```

### `qnt_getTransactionReceipt`

| | |
|---|---|
| **Params** | `hash: String` |
| **Returns** | `ReceiptInfo \| null` |

```jsonc
{
  "transaction_hash": "QTS:…",
  "block_number": "QTS:99",   // slot, hex
  "from": "QTS:…",
  "to": "QTS:…",
  "gas_used": "QTS:5208",     // CU used, hex
  "status": "QTS:1",          // "QTS:1" success, "QTS:0" failure
  "logs": [
    { "address": "QTS:…", "topics": ["QTS:…"], "data": "QTS:…" }
  ],
  "revert_reason": "…"        // present only on failure
}
```

### `qnt_call`

Read-only contract call (does not mutate state, does not require a signature).

| | |
|---|---|
| **Params** | `call_request: CallRequest`, `block: Option<String>` (ignored) |
| **Returns** | `String` — `qts:<hex return data>` (lowercase `qts:` prefix) or `QTS:` if target is not a contract |
| **Timeout** | 5 seconds (`CONTRACT_EXEC_TIMEOUT`) |
| **Errors** | `-32005` if concurrent exec semaphore is full; `-32000` on execution failure |

```jsonc
// CallRequest
{
  "from": "QTS:…",   // optional, defaults to zero address
  "to": "QTS:…",     // contract address (32 bytes)
  "data": "QTS:…",   // optional calldata hex
  "gas": "QTS:…",    // optional, ignored (zero fees)
  "value": "QTS:…"   // optional
}
```

### `qnt_estimateGas`

| | |
|---|---|
| **Params** | `call_request: CallRequest` |
| **Returns** | `String` — always `"qts:0"` (Quantos has zero gas fees) |

### `qnt_blockNumber`

Returns the current slot (Quantos' equivalent of block height).

| | |
|---|---|
| **Params** | none |
| **Returns** | `String` — `QTS:<hex u64>` |

### `qnt_chainId`

| | |
|---|---|
| **Params** | none |
| **Returns** | `String` — `QTS:<hex u64>` (e.g. `QTS:1` mainnet, `QTS:2` testnet, `QTS:3` devnet) |

### `qnt_getSlot` / `qnt_getFinalizedSlot`

| | |
|---|---|
| **Params** | none |
| **Returns** | `u64` (raw JSON number, **not** `QTS:`-prefixed) |

`qnt_getSlot` is the current slot; `qnt_getFinalizedSlot` is the last
finalized slot.

### `qnt_getMetrics`

| | |
|---|---|
| **Params** | none |
| **Returns** | `MetricsInfo` |

```jsonc
{
  "current_slot": 12345,
  "current_epoch": 7,
  "finalized_slot": 12340,
  "pending_transactions": 12,
  "pending_vertices": 3,
  "confirmed_vertices": 9900,
  "total_validators": 64,
  "num_shards": 4
}
```

### `qnt_getShardInfo`

| | |
|---|---|
| **Params** | `shard_id: u16` |
| **Returns** | `ShardInfo` |

```jsonc
{ "shard_id": 1, "validator_count": 0, "pending_txs": 5, "tps": 0.0 }
```

---

## Methods — Node & Network

### `qnt_nodeInfo`

| | |
|---|---|
| **Params** | none |
| **Returns** | `NodeInfoResponse` |

```jsonc
{
  "version": "0.1.0",
  "protocol_version": 1,
  "chain_id": 2,
  "current_slot": 12345,
  "current_epoch": 7,
  "finalized_slot": 12340,
  "state_root": "QTS:…",
  "num_shards": 4,
  "uptime_seconds": 3600
}
```

### `qnt_health`

| | |
|---|---|
| **Params** | none |
| **Returns** | `HealthResponse` |

```jsonc
{
  "healthy": true,            // true if slot_lag < 100
  "current_slot": 12345,
  "finalized_slot": 12340,
  "slot_lag": 5,
  "pending_transactions": 12,
  "validators_active": 64
}
```

### `qnt_syncing`

| | |
|---|---|
| **Params** | none |
| **Returns** | `SyncStatus` |

```jsonc
{
  "syncing": false,           // true if current - finalized > 32
  "current_slot": 12345,
  "highest_slot": 12345,
  "finalized_slot": 12340
}
```

### `qnt_peerCount`

| | |
|---|---|
| **Params** | none |
| **Returns** | `String` — `QTS:<hex>` (active validator count) |

### `qnt_getPeers`

| | |
|---|---|
| **Params** | none |
| **Returns** | `Vec<PeerInfoResponse>` |

```jsonc
[
  {
    "peer_id": "12D3Koo…",
    "addr": "/ip4/1.2.3.4/tcp/9000",
    "protocol_version": "/quantos/1.0.0",
    "agent_version": "quantos-node/0.1.0",
    "connected_at": 1700000000,
    "last_seen": 1700000100,
    "latency_ms": 42,
    "messages_received": 1024,
    "messages_sent": 980,
    "reputation": 100
  }
]
```

---

## Methods — Validators

### `qnt_getValidators`

| | |
|---|---|
| **Params** | none |
| **Returns** | `ValidatorsResponse` |

```jsonc
{
  "validators": [
    {
      "address": "QTS:…",
      "stake": "QTS:de0b…",          // u128 hex
      "commission_rate": 500,         // basis points (500 = 5%)
      "active": true,
      "jailed": false,
      "slash_count": 0,
      "last_active_slot": 12344,
      "performance_score": 0.98,      // optional
      "uptime_pct": 99.9,             // optional
      "blocks_proposed": 1200         // optional
    }
  ],
  "total_stake": "QTS:…",
  "total_active": 64,
  "epoch": 7
}
```

### `qnt_getValidatorByAddress`

| | |
|---|---|
| **Params** | `address: String` |
| **Returns** | `ValidatorInfoResponse \| null` |

### `qnt_getValidatorStats`

Returns live (current epoch) and historical (RocksDB) performance for a validator.

| | |
|---|---|
| **Params** | `address: String` |
| **Returns** | `ValidatorStatsResponse \| null` |

```jsonc
{
  "address": "QTS:…",
  "current_epoch": 7,
  "current_blocks_proposed": 120,
  "current_votes_cast": 5000,
  "current_votes_expected": 5050,
  "current_checkpoint_signatures": 100,
  "current_performance_score": 0.98,
  "current_uptime": 99.9,
  "total_blocks_proposed": 1200,
  "total_votes_cast": 50000,
  "total_checkpoint_signatures": 1000,
  "avg_performance_score": 0.97,
  "avg_uptime": 99.5,
  "total_rewards_earned": 5000000000000000000,  // u128
  "history": [
    {
      "epoch": 6,
      "blocks_proposed": 100,
      "votes_cast": 7000,
      "votes_expected": 7100,
      "avg_inclusion_latency_ms": 42.5,
      "total_cu_proposed": 500000,
      "checkpoint_signatures": 150,
      "performance_score": 0.97,
      "uptime": 99.5,
      "epoch_reward": 800000000000000000
    }
  ]  // most recent first
}
```

### `qnt_getEpochRewards`

| | |
|---|---|
| **Params** | `epoch: u64` |
| **Returns** | `EpochRewardsResponse` |

```jsonc
{
  "epoch": 7,
  "total_reward_distributed": 5000000000000000000,  // u128
  "validator_count": 64,
  "rewards": [
    {
      "address": "QTS:…",
      "stake_weight": 0.15,        // f64, share of total stake
      "performance_score": 0.98,
      "uptime": 99.9,
      "blocks_proposed": 120,
      "votes_cast": 5000,
      "epoch_reward": 750000000000000000  // u128
    }
  ]  // sorted by reward descending
}
```

---

## Methods — DAG

### `qnt_getVertexByHash`

| | |
|---|---|
| **Params** | `hash: String` |
| **Returns** | `VertexInfo \| null` |

```jsonc
{
  "hash": "QTS:…",
  "parents": ["QTS:…", "QTS:…"],
  "tx_count": 5,
  "timestamp": 1700000000,
  "shard_id": 1,
  "creator": "QTS:…",
  "height": 12345,
  "status": "Finalized",   // Debug repr of vertex status
  "state_root": "QTS:…"
}
```

### `qnt_getDagTips`

| | |
|---|---|
| **Params** | `shard_id: u16` |
| **Returns** | `Vec<String>` — list of `QTS:<vertex hash>` |

---

## Methods — Mempool / Ingress

Quantos uses a DAG-native ingress buffer (bounded per-shard channels), not a
queryable mempool. These methods report per-shard pending counts.

### `qnt_pendingTransactions`

| | |
|---|---|
| **Params** | `limit: Option<usize>` (default 100, max 1000) |
| **Returns** | `Vec<TransactionInfo>` — summary entries (one per non-empty shard) |

Each entry is a synthetic `TransactionInfo` with `hash =
"shard:<id>:pending:<count>"` and zeroed fields. This is **not** a list of
individual pending transactions.

### `qnt_txPoolStatus`

| | |
|---|---|
| **Params** | none |
| **Returns** | `TxPoolStatusResponse` |

```jsonc
{
  "pending": 42,
  "shards": [
    { "shard_id": 0, "pending": 20 },
    { "shard_id": 1, "pending": 22 }
  ]  // only shards with pending > 0
}
```

---

## Methods — Contracts

### `qnt_deployContract` — **DEPRECATED**

| | |
|---|---|
| **Params** | `DeployContractRequest` |
| **Returns** | **always errors** with `-32601` |

Unsigned deployment is no longer allowed. Use `qnt_sendRawTransaction` with a
signed `ContractDeploy` transaction, or the wallet server's `POST /wallet/deploy`.

### `qnt_getContractMetadata`

| | |
|---|---|
| **Params** | `address: String` |
| **Returns** | `ContractMetadataInfo \| null` |

```jsonc
{
  "address": "QTS:…",
  "bytecode_hash": "QTS:…",
  "deployer": "QTS:…",
  "deployed_at": 1700000000,    // timestamp
  "deployed_height": 12345,     // slot
  "bytecode_size": 4096,
  "version": "0.1.0"
}
```

### `qnt_verifyContract`

Returns `true` if a contract exists at the address (bytecode-invisible check).

| | |
|---|---|
| **Params** | `address: String` |
| **Returns** | `bool` |

---

## Methods — Tokens (QN4 / QN8)

### `qnt_getNFTs` — QN8 standard

| | |
|---|---|
| **Params** | `owner_address: String`, `collection_address: Option<String>` |
| **Returns** | `Vec<NFTInfo>` |

```jsonc
{
  "token_id": 42,
  "collection_address": "QTS:…",
  "collection_name": "MyNFTs",
  "collection_symbol": "MNT",
  "owner": "QTS:…",
  "token_uri": "ipfs://…"
}
```

If `collection_address` is omitted, returns NFTs across all collections.

### `qnt_getTokenBalances` — QN4 standard

| | |
|---|---|
| **Params** | `owner_address: String` |
| **Returns** | `Vec<TokenBalanceInfo>` |

```jsonc
{
  "token_address": "QTS:…",
  "name": "MyToken",
  "symbol": "MTK",
  "decimals": 6,
  "balance": 1000000,           // u64 raw
  "balance_formatted": "1.000000 MTK"
}
```

---

## Methods — Explorer Indexing

### `qnt_getRecentTransactions`

| | |
|---|---|
| **Params** | `limit: Option<usize>` (default 50, max 500) |
| **Returns** | `Vec<ConfirmedTransactionInfo>` |

### `qnt_getReceiptsSinceSlot`

| | |
|---|---|
| **Params** | `since_slot: u64`, `limit: Option<usize>` (default 200, max 1000) |
| **Returns** | `Vec<ConfirmedTransactionInfo>` |

```jsonc
{
  "hash": "QTS:…",
  "from": "QTS:…",
  "to": "QTS:…",
  "value": "QTS:de0b…",      // u128 hex
  "nonce": 26,               // raw u64
  "gas_used": 21000,         // raw u64 (CU)
  "tx_type": "transfer",     // transfer|stake|unstake|stake_transfer|validator_register|validator_exit|contract_call|contract_deploy|unknown
  "status": "success",       // "success" | "failed"
  "success": true,
  "slot": 12345,
  "shard_id": 1,
  "timestamp": 1700000000,
  "logs": [ { "address": "QTS:…", "topics": ["QTS:…"], "data": "QTS:…" } ],
  "revert_reason": "…"       // present only on failure
}
```

---

## Methods — L0 Finality Hub

The L0 hub produces post-quantum finality proofs for external chains. These
methods are only available on nodes with the L0 hub enabled.

### `qnt_submitExternalCheckpoint`

Submits an external chain checkpoint for attestation. The node verifies it via
the light client registry (or subnet manager for sovereign subnets), then
collects ML-DSA-65 signatures from the Quantos validator set. If 2/3+ stake
is reached, an L0 finality proof is built immediately.

| | |
|---|---|
| **Params** | `ExternalCheckpointRequest` |
| **Returns** | `ExternalCheckpointResponse` |
| **Errors** | `-32000` if L0 hub / checkpoint pool / light client registry is not available, or checkpoint verification fails |

```jsonc
// Request
{
  "chain_id": "base",              // see Supported External Chain IDs
  "block_number": 12345678,
  "block_hash": "QTS:…",           // 32-byte hex
  "state_root": "QTS:…",           // 32-byte hex
  "timestamp_ms": 1700000000000,
  "proof_json": "{…}",             // JSON-encoded ChainProof (no hex strings)
  "metadata": null                 // optional JSON string
}

// Response
{
  "proof_hash": "QTS:…",
  "status": "finalized",           // "finalized" | "pending_signatures"
  "signed_stake": "QTS:…",         // u128 hex
  "required_stake": "QTS:…"        // u128 hex (2/3 of total + 1)
}
```

### `qnt_getL0Proof`

| | |
|---|---|
| **Params** | `proof_hash: String` |
| **Returns** | `L0ProofInfo \| null` (null if L0 hub disabled or proof not found) |

### `qnt_getLatestL0Proof`

| | |
|---|---|
| **Params** | none |
| **Returns** | `L0ProofInfo \| null` |

```jsonc
{
  "proof_hash": "QTS:…",
  "chain_id": "base",              // Option<String>, null for Quantos-internal proofs
  "epoch": 7,
  "slot": 12345,
  "state_root": "QTS:…",
  "block_hash": "QTS:…",           // DAG root
  "validator_set_root": "QTS:…",
  "total_stake": "QTS:…",          // u128 hex
  "signed_stake": "QTS:…",         // u128 hex
  "stake_threshold": "QTS:…",      // u128 hex
  "signature_count": 43,
  "emitted_at_ms": 1700000000000
}
```

### `qnt_getL0Metrics`

| | |
|---|---|
| **Params** | none |
| **Returns** | `L0MetricsInfo` |
| **Errors** | `-32000` if L0 hub disabled |

```jsonc
{ "proofs_produced": 100, "proofs_failed": 2, "archived_proofs": 98 }
```

---

## Methods — Subnets

### `qnt_registerSubnet`

Registers a sovereign subnet (custom chain with its own validators, double-staked in QTS).

| | |
|---|---|
| **Params** | `RegisterSubnetRequest` |
| **Returns** | `bool` (true on success) |
| **Errors** | `-32000` if subnet manager disabled, invalid stake hex, or registration fails |

```jsonc
{
  "id": "my-subnet",
  "name": "My Sovereign Chain",
  "fee_token": "QTS:…",
  "custom_validators": [            // optional
    {
      "address": "QTS:…",          // 32-byte hex
      "stake": "QTS:de0b…",        // u128 hex
      "qts_double_stake": "QTS:de0b…"  // u128 hex, QTS collateral
    }
  ],
  "reward_multiplier": 100,
  "stacc_collateral_leased": "QTS:…",   // u128 hex
  "min_double_stake_qts": "QTS:…"       // u128 hex
}
```

### `qnt_getSubnet`

| | |
|---|---|
| **Params** | `id: String` |
| **Returns** | `SubnetInfo \| null` |

```jsonc
{
  "id": "my-subnet",
  "name": "My Sovereign Chain",
  "fee_token": "QTS:…",
  "custom_validators": [ { "address": "QTS:…", "stake": "QTS:…", "qts_double_stake": "QTS:…" } ],
  "reward_multiplier": 100,
  "stacc_collateral_leased": "QTS:…",
  "min_double_stake_qts": "QTS:…"
}
```

---

## Methods — Server-side Signing

> ⚠️ **Custodial.** These methods require a private key in the request. For
> non-custodial setups, sign client-side and use `qnt_sendRawTransaction`.
> Public RPC providers should **disable** these methods at the edge gateway.

### `qnt_sendTransaction`

Builds, signs (ML-DSA-65), and submits a transaction using a provided private key.

| | |
|---|---|
| **Params** | `SendTransactionRequest` |
| **Returns** | `String` — `QTS:<tx hash>` |
| **Errors** | `-32000` — invalid private key, invalid amount/nonce, signing failure, submit failure |

```jsonc
{
  "from_private_key": "QTS:…",    // ML-DSA-65 secret key hex
  "to": "QTS:…",
  "amount": "QTS:de0b6b3a7640000", // u128 hex
  "data": "QTS:…",                 // optional calldata
  "nonce": "QTS:1a",               // optional, auto-fetched if omitted
  "tx_type": "transfer",           // transfer|stake|unstake|stake_transfer|validator_register|validator_exit|contract_call|contract_deploy
  "shard_id": 0,                   // optional, default 0
  "max_compute_units": "QTS:186a0" // optional, default 100000
}
```

### `qnt_generateKeyPair`

Generates a fresh ML-DSA-65 keypair. **Returns the private key** — use only on
trusted nodes.

| | |
|---|---|
| **Params** | none |
| **Returns** | `KeyPairResponse` |

```jsonc
{
  "address": "QTS:…",
  "public_key": "QTS:…",    // 1952 bytes hex
  "private_key": "QTS:…"    // secret key hex
}
```

---

## Subscriptions (WebSocket)

### `qnt_subscribe` / `qnt_unsubscribe`

| | |
|---|---|
| **Params** | `kind: String`, `params: Option<Value>` (currently ignored) |
| **Returns** | subscription stream of `SubscriptionNotification` |

Supported `kind` values:

| Kind | Payload | Polling |
|---|---|---|
| `newHeads` | `{ "slot": u64, "epoch": u64, "finalized_slot": u64, "state_root": "QTS:…" }` | every 500ms, on slot change |
| `newPendingTransactions` | `{ "shard": u16, "pending": usize }` | every 200ms, on count change |
| `logs` | (reserved, not yet broadcast) | — |

Wire format (server → client):

```jsonc
{
  "jsonrpc": "2.0",
  "method": "qnt_subscribe",
  "params": {
    "subscription": "<sub_id>",
    "result": { /* payload */ }
  }
}
```

Unknown `kind` values are logged and dropped (no error sent to the client).

---

## Chain IDs

Quantos internal chain IDs (returned by `qnt_chainId`):

| Network | Chain ID |
|---|---|
| Mainnet | `1` |
| Testnet | `2` |
| Devnet | `3` |

---

## Supported External Chain IDs (L0)

Accepted by `qnt_submitExternalCheckpoint`'s `chain_id` field. Any other
string is treated as a `Custom(<name>)` chain (sovereign subnet lookup).

| `chain_id` string | Chain |
|---|---|
| `ethereum`, `ethereum-sepolia` | Ethereum mainnet / Sepolia |
| `base`, `base-sepolia` | Base |
| `arbitrum`, `arbitrum-sepolia` | Arbitrum One / Sepolia |
| `optimism`, `optimism-sepolia` | Optimism |
| `polygon`, `polygon-amoy` | Polygon / Amoy |
| `avalanche`, `avalanche-fuji` | Avalanche / Fuji |
| `bsc`, `bsc-testnet` | BNB Smart Chain |
| `solana`, `solana-devnet` | Solana |
| `near`, `near-testnet` | NEAR Protocol |
| `aptos`, `aptos-testnet` | Aptos |
| `sui`, `sui-testnet` | Sui |
| `ton`, `ton-testnet` | TON |
| `bitcoin`, `bitcoin-testnet` | Bitcoin |
| `stellar`, `stellar-testnet` | Stellar |
| `polkadot`, `polkadot-testnet` | Polkadot |
| `tron`, `tron-shasta` | TRON |
| `cosmos`, `cosmos-testnet` | Cosmos Hub |
| `cardano`, `cardano-testnet` | Cardano |

---

## Reference

- **Source:** `L1/src/rpc/server.rs` — trait `QuantosRpc`, impl `QuantosRpcImpl`
- **Subscriptions:** `L1/src/rpc/subscriptions.rs`
- **Rate limiter:** `RateLimiterState`, `RateLimitLayer` (same file)
- **Types:** `L1/src/types/transaction.rs` (`Transaction`, `SignedTransaction`, `VmKind`)
- **Crypto:** `L1/src/crypto/` (ML-DSA-65 keypair, `verify_ml_dsa_65_batch`, `DOMAIN_TX`)
- **L0 hub:** `L1/src/l0/`
