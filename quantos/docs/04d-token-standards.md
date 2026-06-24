---
sidebar_position: 13
slug: /token-standards
---

# 12. Native Token Standards (QN-4 / QN-8 / QN-12)

## 12.1 Resource-Based Tokens

Quantos ships native, first-class token standards rather than leaving tokens entirely to user-deployed contracts. These standards are implemented in the protocol (`quantos/src/standards/`) as typed resources with explicit, audited semantics, and they map one-to-one onto the familiar Ethereum standards so that existing mental models and tooling transfer directly:

| Quantos standard | Ethereum equivalent | Purpose |
|------------------|---------------------|---------|
| **QN4** | ERC-20 | Fungible tokens |
| **QN8** | ERC-721 | Non-fungible tokens (NFTs) |
| **QN12** | ERC-1155 | Multi-token (mixed fungible + non-fungible) |

Because they are native resources executed in WASM under the zero-gas model, transfers and approvals consume CU quota (STACC section) rather than per-transaction fees, and every operation is authenticated under the chain's post-quantum signature scheme. The ERC-compatibility router (Virtual Machine section) exposes these native tokens through standard Ethereum ABI calldata, so a QN4 token appears to MetaMask or ethers.js as an ordinary ERC-20.

## 12.2 QN4 — Fungible Tokens

`QN4Token` models a fungible asset with the full ERC-20 surface plus safety extensions. Core fields include `name`, `symbol`, `decimals`, `total_supply`, `owner`, balances, and allowances, together with feature flags (`mintable`, `burnable`, `pausable`, `paused`) and an optional hard supply cap `max_supply`.

The base `QN4` trait defines the canonical interface — `name`, `symbol`, `decimals`, `total_supply`, `balance_of`, `transfer`, `allowance`, `approve`, `transfer_from` — and optional capabilities are layered as separate traits so a token only exposes what it opts into:

- `QN4Mintable` — controlled minting (`mint`), bounded by `max_supply` when set.
- `QN4Burnable` — `burn` and `burn_from`.
- `QN4Pausable` — emergency `pause`/`unpause` of transfers.

Operations return typed `TokenEvent`s (`Transfer`, `Approval`) and typed `TokenError`s rather than panicking, making failure handling explicit for callers.

## 12.3 QN8 — Non-Fungible Tokens

`QN8` is the NFT standard (ERC-721 equivalent), modelling unique `token_id`s with ownership, per-token approvals, and operator approvals. It emits `TransferNFT`, `ApprovalNFT`, and `ApprovalForAll` events. To prevent unbounded state growth and griefing, the implementation enforces guards such as a maximum number of tokens per owner (`MaxTokensPerOwnerReached`) and duplicate-id rejection (`DuplicateTokenId`).

## 12.4 QN12 — Multi-Token

`QN12` (ERC-1155 equivalent) manages many token types — fungible and non-fungible — within a single contract, supporting efficient batch transfers via `TransferSingle` and `TransferBatch` events. Batch operations are bounded (`BatchSizeTooLarge`) so that a single call cannot exhaust a validator's CU budget.

## 12.5 Built-in Safety Guarantees

A recurring source of loss on other chains is subtle, repeated re-implementation of token logic. By making the standards native, Quantos centralises the hard parts and enforces them uniformly. The shared `TokenError` enumeration encodes the protections every token inherits:

- **Arithmetic safety**: `Overflow` / `Underflow` are checked on every balance and supply mutation.
- **Approval race protection**: the classic ERC-20 approve/transfer-from front-running race is rejected with `ApprovalRaceCondition`.
- **Reentrancy protection**: re-entrant calls into token methods are detected and rejected (`ReentrancyDetected`).
- **Supply integrity**: minting beyond a configured cap fails with `MaxSupplyExceeded`.
- **Authorization**: privileged actions verify the caller (`Unauthorized`, `NotOwner`, `NotApproved`).
- **Batch bounds**: array-length mismatches (`ArrayLengthMismatch`) and oversized batches (`BatchSizeTooLarge`) are rejected.

## 12.6 Ownership and Administration

All three standards support a **two-step ownership transfer** to prevent accidental transfer to an unrecoverable address: the current owner nominates a `pending_owner`, and the transfer only completes when the nominee explicitly accepts. The lifecycle emits `OwnershipTransferStarted` and `OwnershipTransferred` events, and pausable tokens additionally emit `Paused` / `Unpaused`. These administrative events use the same canonical event model as transfers, so indexers and explorers observe a single, consistent event stream across the entire token ecosystem.
