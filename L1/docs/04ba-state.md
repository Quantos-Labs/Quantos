---
sidebar_position: 11
slug: /state
---

# 10. State Model & Accounts

## 10.1 Account-Based State

Quantos uses an **account model** (`quantos/src/types/account.rs`, `state/manager.rs`) rather than Bitcoin-style UTXOs, which simplifies smart-contract state and stake accounting. Each `Account` carries:

| Field | Meaning |
|-------|---------|
| `address` | 32-byte account identifier |
| `balance` | Spendable token balance |
| `nonce` | Monotonic counter for replay protection and ordering |
| `code_hash` | Hash of contract bytecode (None for externally-owned accounts) |
| `storage_root` | Merkle root of the account's contract storage |
| `stake` | Amount staked for validation |
| `is_validator` | Whether the account is an active validator |

Addresses are 32 bytes (versus Ethereum's 20), reflecting the larger key material of post-quantum schemes and providing ample collision resistance.

## 10.2 Deterministic Account Hashing

Account state is committed via a **deterministic serialization** rather than a general-purpose codec. The `Account::hash` routine explicitly concatenates fields in fixed order with fixed-endian encoding (little-endian) before hashing with SHA3-256. This is a deliberate safety choice: non-deterministic serialization (e.g. map iteration order) is a classic source of consensus forks, so Quantos hashes a canonical byte layout that is identical on every node and architecture.

## 10.3 Transaction Types

A `Transaction` (`types/transaction.rs`) declares its intent through a typed `TransactionType`, so the state machine validates and routes each transaction precisely:

- `Transfer` — move balance between accounts.
- `Stake` / `Unstake` — adjust staked balance.
- `ValidatorRegister` / `ValidatorExit` — join or leave the validator set.
- `ContractDeploy` / `ContractCall` — deploy or invoke smart contracts.

Each transaction also carries `max_compute_units` (its STACC CU budget), an optional `boost` (priority lock — tokens are locked, never burned), a `vm_kind` selector (`Qvm` native WASM or `Evm`), `shard_id`, `nonce`, `chain_id`, `timestamp`, and the post-quantum `signature` + `public_key`.

## 10.4 Replay and Drift Protection

Several fields exist specifically to defeat replay and manipulation:

- **`nonce`** ensures each transaction is applied at most once and in order per sender.
- **`chain_id`** binds a transaction to Quantos, preventing cross-chain replay.
- **Timestamp drift bound**: `MAX_TIMESTAMP_DRIFT = 30 seconds` — a transaction whose timestamp deviates too far from network time is rejected, narrowing the window for timestamp-based manipulation (reduced from an earlier 5-minute bound).
- **Batch-verified signatures**: transaction signatures are verified with `verify_ml-dsa-65_batch` (ML-DSA-65) under the `DOMAIN_TX` domain tag, amortising verification cost across many transactions.

## 10.5 State Management and Execution

The state manager (`state/manager.rs`) is the authority on account state, validation, and the validator set; the executor (`state/executor.rs`) applies ordered transactions to produce the next state. Parallel execution within a shard is mediated by software-transactional-memory and MVCC layers (`state/stm.rs`, and the VM's MVCC), so independent transactions commit concurrently while conflicting ones are serialised — the execution-side counterpart to the DAG's ordering guarantees.

## 10.6 State Growth Management

Unbounded state growth is an existential problem for long-lived chains. Quantos manages it with three cooperating mechanisms: **state rent** (`state/state_rent.rs`) prices persistent storage per byte per slot; **archival pruning** (`state/archival_pruning.rs`) moves long-idle accounts to cold storage, restorable later with a Merkle proof; and **flat storage** (`state/flat_storage.rs`) provides an efficient on-disk layout for the active working set. State compression and snapshot sync are covered in the Data Availability & State Compression section.
