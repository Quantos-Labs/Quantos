# Changelog

All notable changes to the Quantos blockchain project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Cargo workspace unifying `L1`, `quantos-wallet-core`, `quantos-wallet-server`, and `quantos-l0-sdk`
- `CHANGELOG.md` for project version tracking

## [0.1.0] - 2025-07-11

### Added
- L1 blockchain core with post-quantum cryptography (ML-DSA-65, ML-DSA-65, Kyber, SPHINCS+)
- DAG-based consensus with BFT committee, fast path, and optimistic responsiveness
- Dynamic sharding with cross-shard atomic transactions and self-healing
- STACC (Shared Transaction Access & Concurrency Control) scheduler
- EVM compatibility via revm with Solidity support (solang)
- WASM runtime via wasmer with JIT compiler and speculative execution
- zk-STARK proof system for sharding and light client verification
- Layer-0 hub with PQC finality proofs, checkpoint pool, and relayer infrastructure
- Privacy module: confidential state, shielded pool, stealth addresses
- Multi-chain bridge supporting Aptos, Solana, NEAR, SUI, Cosmos, Cardano, Polkadot, Stellar, TON, Tron, Bitcoin/Stacks
- PQC-Guard smart contracts (Foundry/Solidity) for cross-chain post-quantum verification
- Encrypted mempool with fair ordering and proposer-builder separation (PBS)
- Network layer with PQ P2P, turbo gossip, erasure coding, and NAT traversal
- Security modules: DDoS protection, eclipse protection, sybil resistance, quantum security, time sync
- Token standards: QN-4 (fungible), QN-8 (non-fungible), QN-12 (multi-token)
- Wallet core (Rust/WASM), wallet server (Rust/Axum), wallet browser extension (React/TypeScript)
- L0 SDK in Rust and JavaScript
- Bridge relayer and L0 relayer (TypeScript)
- Docker deployment with monitoring support
- Benchmark suites: raw TPS, testnet TPS, PQC bloat analysis
- Comprehensive technical documentation (35 docs covering protocol design, cryptography, consensus, sharding, VM, security, governance, and more)
