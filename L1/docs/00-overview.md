---
sidebar_position: 1
slug: /
---

# Quantos Technical Whitepaper

**Post-Quantum Layer 1 Blockchain with Zero-Gas Execution and Cryptographic Cross-Chain Finality**

*Version 2.2 — July 2026*

## Abstract

Quantos is a next-generation Layer 1 blockchain designed from the ground up for the post-quantum era. Unlike existing chains that retrofit quantum resistance as an afterthought, Quantos embeds NIST-finalized post-quantum cryptography (PQC) at every layer: consensus, execution, storage, and interoperability. The protocol uses two NIST-finalized algorithms — ML-DSA-65 (FIPS 204) and ML-KEM-768 (FIPS 203) — applied consistently at NIST security level 3 for all operations requiring cryptographic authentication or confidentiality. A Rescue-Prime hash-based Verifiable Random Function (VRF) with STARK proof-of-knowledge secures committee selection, replacing earlier signature-based approaches that lack the required uniqueness property.

Quantos introduces a 3-layer QuantumDAG consensus mechanism derived from peer-reviewed literature (Narwhal/Bullshark DAG-based mempool, HotStuff rotating-leader BFT), operating under explicit partial synchrony assumptions with formally stated safety invariants. Horizontal scaling is achieved through dynamic sharding with safe state migration, bounded vulnerability windows, and atomic cross-shard commitment protocols. The zero-gas execution model (STACC) replaces per-transaction fees with stake-proportional bandwidth quotas, sustained by a three-source validator revenue model that progressively shifts from inflation to state rent. A Layer 0 Finality Hub provides cross-chain attestation for 12 external networks, backed by a transparent trust model that distinguishes cryptographic light-client verification from RPC-based oracle attestation on a per-chain basis.

### What Quantos Claims — and What It Does Not

- The protocol targets **tens of thousands of TPS per shard** at NIST level 3 PQC parameters, with horizontal scaling through sharding. Aggregate throughput depends on the number of active shards and validator hardware; published benchmarks on testnet will validate specific configurations.
- Cross-chain finality is **directional**: Quantos → external chains in seconds (native finality plus proof generation); external → Quantos is bounded by the source chain's own finality (e.g., Bitcoin ~60 min, Ethereum ~13 min). No chain can compress another chain's consensus.
- The L0 hub uses a **commitment-based STARK aggregation**: signatures are verified natively off-chain; a 32-byte STARK commitment is stored on-chain, verified off-chain by any party. This is not a full STARK verification inside an EVM contract.

### Version History

Version 1.4 addressed the findings of an internal cryptographic audit. Version 2.0 expanded the whitepaper from 11 to 33 sections, documenting the full protocol stack. Version 2.2 synchronizes the whitepaper with the current codebase: the VRF is documented as Rescue-Prime + STARK (not SHA3/SHAKE), the removed experimental primitives (threshold ML-KEM, lattice NIZK, QRNG) are no longer listed as active subsystems, and the tiered JIT compiler has been removed from the VM description. All earlier honesty qualifications (directional finality, per-chain L0 trust, theoretical aggregate throughput, advisory-only ML) are retained.

---

## Table of Contents

This whitepaper is organized into the following sections:

1. [Introduction](/introduction)
2. [Post-Quantum Cryptography](/post-quantum-cryptography)
3. [Cryptographic Primitives Deep-Dive](/crypto-primitives)
4. [QuantumDAG Consensus](/consensus)
5. [DAG Structure & Ordering](/dag)
6. [Committee Selection & VRF Rotation](/committees)
7. [Advanced Consensus Mechanisms](/advanced-consensus)
8. [Performance](/performance)
9. [Dynamic Sharding](/sharding)
10. [State Model & Accounts](/state)
11. [Virtual Machine & Smart Contracts](/virtual-machine)
12. [Native Token Standards (QN-4/8/12)](/token-standards)
13. [Storage Layer](/storage)
14. [Mempool, MEV & Transaction Lifecycle](/mempool)
15. [STACC: Zero-Gas Execution](/stacc)
16. [Tokenomics & QTS Economics](/tokenomics)
17. [Staking, Delegation & Slashing](/staking)
18. [Layer 0 Finality Hub](/layer0)
19. [PQC Key Migration](/migration)
20. [PQC-Guard: Multi-VM Smart Account](/pqc-guard)
21. [Sidechains](/sidechains)
22. [Network Layer](/network)
23. [Data Availability & State Compression](/data-availability)
24. [Security Model](/security)
25. [Application Ecosystem & Developer Tooling](/ecosystem)
26. [Governance](/governance)
27. [Node Operation & Validator Requirements](/node-operation)
28. [Comparison with Existing Chains](/comparison)
29. [Use Cases](/use-cases)
30. [Roadmap](/roadmap)
31. [Glossary](/glossary)
32. [References](/references)
33. [Conclusion](/conclusion)
