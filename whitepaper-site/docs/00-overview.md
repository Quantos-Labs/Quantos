# Quantos Technical Whitepaper

**Post-Quantum Layer 1 Blockchain with Zero-Gas Execution and Cryptographic Cross-Chain Finality**

*Version 1.4 — June 2026*

## Abstract

Quantos is a next-generation Layer 1 blockchain designed from the ground up for the post-quantum era. Unlike existing chains that retrofit quantum resistance as an afterthought, Quantos embeds NIST-finalized post-quantum cryptography (PQC) at every layer: consensus, execution, storage, and interoperability. The protocol uses two NIST-finalized algorithms — ML-DSA-65 (FIPS 204) and ML-KEM-768 (FIPS 203) — applied consistently at NIST security level 3 for all operations requiring cryptographic authentication or confidentiality. A hash-based Verifiable Random Function (VRF) with STARK proof-of-knowledge secures committee selection, replacing earlier signature-based approaches that lack the required uniqueness property.

Quantos introduces a 3-layer QuantumDAG consensus mechanism derived from peer-reviewed literature (Narwhal/Bullshark DAG-based mempool, HotStuff rotating-leader BFT), operating under explicit partial synchrony assumptions with formally stated safety invariants. Horizontal scaling is achieved through dynamic sharding with safe state migration, bounded vulnerability windows, and atomic cross-shard commitment protocols. The zero-gas execution model (STACC) replaces per-transaction fees with stake-proportional bandwidth quotas, sustained by a three-source validator revenue model that progressively shifts from inflation to state rent. A Layer 0 Finality Hub provides cross-chain attestation for 12 external networks, backed by a transparent trust model that distinguishes cryptographic light-client verification from RPC-based oracle attestation on a per-chain basis.

### What Quantos Claims — and What It Does Not

- The protocol targets **tens of thousands of TPS per shard** at NIST level 3 PQC parameters, with horizontal scaling through sharding. Aggregate throughput depends on the number of active shards and validator hardware; published benchmarks on testnet will validate specific configurations.
- Cross-chain finality is **directional**: Quantos → external chains in seconds (native finality plus proof generation); external → Quantos is bounded by the source chain's own finality (e.g., Bitcoin ~60 min, Ethereum ~13 min). No chain can compress another chain's consensus.
- The L0 hub uses a **commitment-based STARK aggregation**: signatures are verified natively off-chain; a 32-byte STARK commitment is stored on-chain, verified off-chain by any party. This is not a full STARK verification inside an EVM contract.

### Version 1.4 Additions

This revision addresses the findings of an internal technical audit (June 2026). All four NIST algorithm status claims have been corrected; the VRF primitive has been replaced by a hash-based construction with STARK proofs; the consensus safety model has been formalized with explicit synchrony assumptions and BFT thresholds; the STACC tokenomics section now includes state rent, sustainability metrics, and a three-source revenue model; the L0 trust model has been decomposed into a per-chain cryptographic-verification vs oracle-attestation matrix; the PQC migration mechanism has been redesigned with a three-layer model (direct registration, 48h pending delay, guardian M-of-N recovery) eliminating the symmetric griefing vulnerability of earlier commit-reveal designs.

---

## Table of Contents

This whitepaper is organized into the following sections:

1. [Introduction](01-introduction)
2. [Post-Quantum Cryptography](02-post-quantum-cryptography)
3. [QuantumDAG Consensus](03-consensus)
4. [Performance](04-performance)
5. [STACC: Zero-Gas Execution](05-stacc)
6. [Layer 0 Finality Hub](06-layer0)
7. [PQC Key Migration](07-migration)
8. [PQC-Guard: Multi-VM Smart Account](08-pqc-guard)
9. [Network Layer](09-network)
10. [Security Model](10-security)
11. [Conclusion](11-conclusion)
