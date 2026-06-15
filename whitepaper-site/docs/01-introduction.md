# 1. Introduction

## 1.1 The Quantum Threat

Virtually all existing blockchains rely on elliptic curve cryptography (ECC): secp256k1 (Bitcoin, Ethereum), Curve25519 (Solana, Cardano). Shor's algorithm solves the discrete logarithm problem in polynomial time on a quantum computer, rendering ECDSA and Ed25519 completely insecure. Even before fault-tolerant quantum computers, "harvest now, decrypt later" attacks mean that sensitive transaction data encrypted today may be decrypted retroactively once quantum capabilities arrive.

## 1.2 Why Retrofitting Fails

1. **Soft-forking** requires overwhelming consensus and invalidates all existing infrastructure.
2. **Address migration** fails to protect transaction history and smart contract state.
3. **Hybrid signatures** are recommended by ANSSI and other national agencies during the transition phase, but they double overhead and the classical component remains vulnerable.

Quantos takes the approach of designing the entire protocol around PQC from genesis. We acknowledge that the ANSSI and BSI recommend hybrid schemes as a conservative transition strategy; Quantos is positioned as a PQC-native first-mover for new deployments, compatible with hybrid wrapping where institutional requirements mandate it.

## 1.3 Design Principles

- **Quantum-First Security**: Every consensus message, transaction, and cross-chain attestation uses NIST-finalized PQC at level 3.
- **Honest Claims**: Throughput, finality, and verification claims are qualified with their assumptions, directionality, and trust models.
- **Massive Parallelization**: Horizontal scaling through dynamic sharding and DAG-based inclusion.
- **Zero-Gas Execution**: STACC replaces per-transaction fees with stake-proportional bandwidth quotas, supplemented by state rent.
- **Cryptographic Interoperability**: Native light client proofs where available; honest oracle attestation where light clients are infeasible.
- **Deterministic Finality**: Irreversible finality in ~1 second *within the Quantos network*.
- **Succinct Cross-Chain Proofs**: STARK batch aggregation of validator signatures; on-chain footprint is a 32-byte commitment verified off-chain.
