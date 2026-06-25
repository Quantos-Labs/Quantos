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

`crypto/mlkem_core.rs` is a from-scratch implementation of the ML-KEM-768 lattice KEM (FIPS 203), including the number-theoretic transform (NTT) for fast polynomial multiplication in the ring, encapsulation/decapsulation, and the Fujisaki–Okamoto transform for CCA security. It is the primitive behind both the validator P2P handshake and the encrypted mempool.

## 3.4 Threshold Cryptography

Two threshold constructions allow a committee to act jointly without any single member holding a complete secret:

- **Threshold ML-KEM** (`crypto/threshold_mlkem.rs`, `crypto/shamir_zq.rs`): the ML-KEM secret vector is split coefficient-wise via Shamir secret sharing over Z_q. A `t-of-n` subset computes partial inner-products in the NTT domain, recombined by Lagrange interpolation. This powers the encrypted-mempool threshold decryption.
- **Threshold QR-VRF** (`crypto/threshold_qrvrf.rs`): a threshold variant of the hash-based VRF, so committee randomness can be produced collectively rather than by a single beacon holder.

## 3.5 Lattice NIZK Proofs

`crypto/lattice_nizk.rs` provides non-interactive zero-knowledge proofs (Fiat-Shamir over polynomial commitments) used by the threshold ML-KEM layer: each participant proves it computed its partial decryption correctly **without revealing its secret share**. This is what makes threshold decryption verifiable rather than trust-based.

## 3.6 Hardware Acceleration

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

For completeness, the cryptographic module ships the following building blocks: `ml_dsa.rs` (ML-DSA-65 signatures for finality and L0 attestations), `dilithium.rs` (Dilithium-3 signatures for transactions and vertices), `sphincs.rs` / `vrf.rs` (SPHINCS+ key material for the hash-based VRF), `mlkem_core.rs` / `kyber_kem.rs` (ML-KEM-768), `qrng.rs` (SHAKE256 QRNG), `signature_aggregation.rs` / `aggregation.rs` (two-tier signature compaction), `merkle_pq.rs` (PQ Merkle trees), `lattice_nizk.rs` (lattice NIZK), the threshold modules, and `keypair.rs` (key lifecycle). The legacy `falcon.rs` module has been removed; Falcon-512 was replaced by ML-DSA-65 on all consensus-critical paths, as described in Section 2.
