---
sidebar_position: 31
slug: /roadmap
---

# 30. Roadmap

The roadmap reflects the state of the codebase and the project's stated commitment to validating claims against testnet benchmarks. Items marked complete are implemented in the source tree; forward items are sequenced by dependency.

## 30.1 Completed (in source)

- **Post-quantum cryptographic core** — ML-DSA-65, ML-KEM-768, hash-based VRF, signature aggregation, SIMD/precompute acceleration.
- **3-layer QuantumDAG consensus** — DAG structure and ordering, VRF committees, pipelined BFT, optimistic responsiveness, view-change, finality checkpoints, runtime safety invariants, slashing.
- **Execution layer** — QuantosVM (Wasmer), Solang/ERC/EVM compatibility, MVCC, speculative execution, transaction dependency graph, bytecode protection.
- **Native token standards** — QN4/QN8/QN12 with safety guarantees.
- **STACC zero-gas** — quotas, CU metering, anti-spam, state rent, WFQ scheduler, three-source tokenomics.
- **Dynamic sharding** — split/merge, safe re-sharding, atomic cross-shard 2PC, self-healing rebalancing, STARK acceleration.
- **Storage** — RocksDB backend, key schema, pruning, snapshot sync, state compression.
- **Layer 0 Finality Hub** — light clients, epoch watcher, STARK aggregation, relay + bonding, 12-chain adapters.
- **PQC migration & PQC-Guard** — three-mechanism migration; multi-VM smart account ported to 7 runtime families.
- **Application suite & SDKs** — DEX, lending, perps, staking, stablecoin, predictions, NFT, launchpads, social-fi; L0 SDKs (Rust + JS); PQC wallet stack.

## 30.2 In Progress

- **Testnet benchmarking** — publishing measured intra-shard and cross-shard throughput, finality latency, and signature-verification cost across reference configurations (`benches/`).
- **Light-client upgrades** — promoting additional L0 chains from oracle attestation to cryptographic light-client verification as succinct clients become available.
- **External security audits** — independent review of the cryptographic core, consensus safety model, and bridge/PQC-Guard contracts.

## 30.3 Planned

- **Cross-shard throughput optimisation** — reducing the atomic-commit overhead that bounds aggregate throughput under high cross-shard ratios.
- **Light-client distribution** — succinct Quantos light clients for resource-constrained verifiers.
- **Formal verification** — machine-checked proofs of the core consensus safety invariants.
- **Ecosystem expansion** — broader sidechain runtimes, additional L0 target chains, and developer tooling maturation.

## 30.4 Guiding Principle

The roadmap is deliberately conservative in its claims: features are described as complete only where they exist in code, performance figures are stated as targets pending published benchmarks, and trust models are committed to be upgraded transparently as the surrounding technology (notably succinct light clients) matures.
