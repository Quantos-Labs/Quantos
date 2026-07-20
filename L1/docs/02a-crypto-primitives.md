---
sidebar_position: 4
slug: /crypto-primitives
---

# 3. Cryptographic Primitives Deep-Dive

Section 2 described *which* algorithms Quantos uses and *why*. This section documents the supporting primitives in `quantos/src/crypto/` that make a post-quantum chain practical at scale. Post-quantum objects are large and expensive; without these accelerations and constructions, a PQC-native L1 would not meet its latency or bandwidth targets.

## 3.1 Hashing and Domain Separation

All hashing uses the SHA-3 family — **SHA3-256** for fixed-length digests and **SHAKE256** as an extendable-output function (XOF) — both of which retain a 128-bit security margin against Grover search at 256-bit output (`crypto/hash.rs`).

Every signed or hashed object is **domain-separated** (`crypto/domains.rs`): a context tag is prepended before hashing so that a signature valid in one context (e.g. a transaction, `DOMAIN_TX`) can never be replayed as a valid signature in another (e.g. a pipeline vote, `DOMAIN_PIPELINE_VOTE`). This eliminates an entire class of cross-protocol signature-confusion attacks.

## 3.2 Post-Quantum Merkle Trees

`crypto/merkle_pq.rs` implements quantum-resistant Merkle trees over SHA3-256. These back account storage roots, the signature-aggregation commitments, the L0 attestor trees, and the cross-shard availability proofs. Because security rests only on the collision resistance of a hash function — not on any number-theoretic assumption — Merkle proofs remain secure against quantum adversaries with no parameter changes.

## 3.3 ML-KEM-768 Internals

`crypto/kyber_kem.rs` implements ML-KEM-768 (FIPS 203) for key encapsulation. It is the primitive behind both the validator P2P handshake and the encrypted mempool.

## 3.4 Threshold Cryptography

- **Threshold QR-VRF** (`crypto/threshold_qrvrf.rs`): a threshold variant of the hash-based VRF, so committee randomness can be produced collectively rather than by a single beacon holder.

## 3.5 Hardware Acceleration

Post-quantum verification is CPU-bound, so the crypto layer is heavily optimised:

| Module | Optimisation |
|--------|--------------|
| `crypto/simd.rs` | SIMD vectorisation of lattice polynomial arithmetic |
| `crypto/precomputed.rs` | Precomputed NTT twiddle-factor tables |
| `crypto/zero_copy.rs` | Zero-copy verification paths avoiding buffer allocation |
| `crypto/memory_pool.rs` | Reusable buffer pools to avoid per-verification allocation |
| `crypto/batch.rs`, `crypto/batch_verify.rs` | Parallel batch verification across cores |
| `crypto/verify_worker.rs` | Dedicated verification worker threads |

Together these bring ML-DSA-65 verification to roughly tens of microseconds per signature on a single core, with near-linear scaling across the many cores assumed in the validator hardware profile.

## 3.7 Primitive Inventory

For completeness, the cryptographic module ships the following building blocks: `ml_dsa.rs` (ML-DSA-65 signatures), `kyber_kem.rs` (ML-KEM-768), `vrf_hashbased.rs` and `vrf.rs` (Rescue-Prime hash-based VRF with STARK proof-of-knowledge), `signature_aggregation.rs` / `aggregation.rs` (two-tier signature compaction), `merkle_pq.rs` (PQ Merkle trees), `threshold_qrvrf.rs` (threshold QR-VRF), and `keypair.rs` (key lifecycle). The `ml-dsa-65.rs` module provides the same ML-DSA-65 primitives under legacy names for backward compatibility. The `sphincs.rs` module is retained for interoperability and historical compatibility but is superseded by the hash-based VRF on all consensus-critical paths, as described in Section 2.
