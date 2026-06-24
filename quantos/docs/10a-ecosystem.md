---
sidebar_position: 26
slug: /ecosystem
---

# 25. Application Ecosystem & Developer Tooling

A blockchain is only as useful as what can be built on it. The Quantos repository ships not just the L1 node but a full stack of on-chain applications, client SDKs, and wallet infrastructure that exercise every protocol feature described in this paper.

## 25.1 On-Chain Application Suite

A library of production Solidity contracts (compiled to WASM via Solang, Virtual Machine section) is included and deployed on the Quantos testnet, spanning the major DeFi and social-finance primitives:

| Domain | Contracts |
|--------|-----------|
| **DEX** | Concentrated-liquidity AMM (`VybssPool`), pool factory (`VybssFactory`), and auto-routing swap router (`VybssRouter`) |
| **Lending** | Collateralised lending/borrowing markets |
| **Perpetuals** | On-chain perpetual-futures engine |
| **Restaking** | Restaking and shared-security vaults |
| **Staking** | Liquid staking (e.g. `SQTEST` / staking engine contracts) |
| **Stablecoin** | Collateralised stablecoin engine |
| **Predictions** | Prediction markets (multichain) |
| **NFT & Marketplace** | NFT minting, collections, and marketplace |
| **Launchpads** | IDO, memecoin, and AI-agent launchpads |
| **Social-fi** | P2P, OTC, grants, insurance, DAO, and profile-key contracts |

These are not toy examples: the DEX, for instance, is a concentrated-liquidity AMM (`VybssPool.sol`) with a factory and an auto-routing router, deployed with on-chain addresses recorded in the repository. They collectively demonstrate that standard Solidity tooling compiles and runs unmodified on QuantosVM under the zero-gas model.

## 25.2 Layer 0 SDKs

The cross-chain finality hub (Layer 0 Finality Hub section) is exposed to applications through two SDKs:

- **`quantos-l0-sdk` (Rust)** and **`quantos-l0-sdk-js` (TypeScript, `@quantos/l0-sdk`)** provide a uniform client for fetching, verifying, and relaying L0 finality proofs. An application fetches the latest proof, verifies it off-chain with a stake-weighted threshold check (e.g. 2-of-3), and optionally submits it for on-chain verification on any of the supported target chains.
- **Chain adapters**: The SDK abstracts twelve chain families behind a common interface — `EvmAdapter` (Ethereum, Base, Monad, Arbitrum), `SolanaAdapter` (SVM), `SuiAdapter` / `AptosAdapter` (Move), `NearAdapter`, `CosmosAdapter`, `PolkadotAdapter` (Wasm/ink!), `StellarAdapter` (Soroban), `TonAdapter`, `CardanoAdapter`, and `StacksAdapter` (Bitcoin). Each adapter knows how to call its chain's verifier contract and read back verification and relay status.

The data flow is: `Quantos L1 → FinalityHub → L0FinalityProof → RelayDispatcher → chain adapter → target-chain verifier contract → application (bridge, DEX, DAO, oracle)`.

## 25.3 PQC-Guard SDK

The PQC-Guard smart account (PQC-Guard section) ships with a TypeScript SDK (`pqc-guard/sdk`) whose `canonical.ts` implements the chain-agnostic binary serialization of WOTS attestation blobs and the per-chain authorization-digest computation for all seven supported VM families. This lets a single client library construct valid attestation payloads for an EVM chain, a Move chain, Solana, NEAR, or Soroban without re-implementing the wire format per target.

## 25.4 Wallet Infrastructure

Post-quantum keys are larger and structurally different from ECDSA keys, so the wallet stack is purpose-built rather than retrofitted:

- **`quantos-wallet-core` (Rust)** — the core key-management and signing library, compiled to WASM (`falcon-wasm` and related artifacts) for use in browser and mobile contexts.
- **`quantos-wallet-extension`** — a browser extension wallet that manages ML-DSA-65 keys, signs transactions, and speaks the node's JSON-RPC interface.
- **`quantos-wallet-server`** — supporting server-side wallet services.

Together these implement the user-facing side of the PQC key-migration model (PQC Key Migration section): generating post-quantum keypairs, producing the ECDSA-binding signature and proof-of-possession at registration, configuring guardian sets, and signing under the chain's native post-quantum scheme.

## 25.5 Node Interface

The L1 node exposes a JSON-RPC API (`qdag_*` namespace) covering balances, nonces, transaction submission and lookup, DAG vertex and tip queries, slot/epoch/finality state, full account info, chain id, and node metrics. This is the integration surface used by the SDKs, wallets, explorers, and the application suite above, and it is the recommended entry point for third-party developers building on Quantos.
