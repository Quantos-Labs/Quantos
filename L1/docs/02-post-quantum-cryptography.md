---
sidebar_position: 3
---

# 2. Post-Quantum Cryptography

## 2.1 NIST-Standardized Algorithms

Quantos uses two NIST-finalized post-quantum algorithms. All operations requiring authentication or confidentiality use these primitives at NIST security level 3.

| Algorithm | Standard | NIST Level | Usage | Public Key | Signature |
|-----------|----------|------------|-------|------------|-----------|
| **ML-DSA-65** | FIPS 204 (finalized August 2024) | 3 | Transaction signatures, checkpoint finality, L0 cross-chain attestations | 1,952 B | 3,309 B |
| **ML-KEM-768** | FIPS 203 (finalized August 2024) | 3 | Encrypted mempool, validator P2P handshake | 1,184 B | — |

Earlier versions of this document referenced Falcon-512 (FN-DSA, FIPS 206 draft) for checkpoint finality and SPHINCS+-128f for VRF. Both have been replaced:
- **Falcon-512** was replaced by ML-DSA-65 for finality and cross-chain attestations, because (a) FN-DSA is not a finalized NIST standard, (b) its category-1 security level was below the category-3 level used for transactions, and (c) its Gaussian floating-point sampler is notoriously difficult to harden against side-channel attacks.
- **SPHINCS+** was replaced by a hash-based VRF (see §2.2) because signature-based VRFs lack the required uniqueness property and are vulnerable to grinding attacks.

**Note on batching overhead**: An ML-DSA-65 signature is 3,309 bytes. At 20,000 signatures per second across all shards, raw signature bandwidth is ~66 MB/s. The STACC bandwidth quota and the L0 STARK batching layer absorb this overhead; individual PQC signatures never cross to external chains in raw form.

## 2.2 Hash-Based VRF with STARK Proof-of-Knowledge

Committee selection and epoch randomness require a Verifiable Random Function (VRF) with three properties: unpredictability, uniqueness (for a given public key and input, exactly one output is valid), and public verifiability. Standard PQC signature schemes do not provide uniqueness because their internal randomizer allows an adversary to grind multiple valid signatures on the same input.

Quantos uses a hash-based VRF:

- **KeyGen**: `sk ← {0,1}^256`, `pk = SHA3-256(sk)`
- **Evaluate**: `beta = SHA3-256(sk ‖ input)` — purely deterministic, no grinding surface
- **Prove**: A Winterfell STARK is intended to prove knowledge of `sk` such that `pk = SHA3-256(sk)` and `beta = SHA3-256(sk ‖ input)`

**Formal relation targeted by the circuit:**

```text
R(pk, input, beta; sk) := (pk   == SHA3-256(sk))
                      AND (beta == SHA3-256(sk ‖ input))
```

For this relation to enforce uniqueness, the circuit must bind `beta` to `sk` with no residual witness freedom that the prover could exploit to produce multiple valid outputs for the same `(pk, input)` pair. Enforcing `R` inside a STARK requires a SHA3/Keccak algebraic intermediate representation (AIR) sub-circuit. The current implementation (`HashVrfAir`) integrates the full Winterfell prover/verifier pipeline and maintains a consistent prove/verify roundtrip, but the Keccak AIR that binds the private witness `sk` to `(pk, beta)` is pending integration and independent audit. The codebase exports:

```rust
pub const STARK_PROVES_UNIQUENESS: bool = false;
```

Until the Keccak AIR is integrated and audited, **uniqueness is a property targeted by the construction, not yet enforced by the circuit**.

**Protocol-level anti-grinding** is provided by the epoch beacon, not by the STARK proof alone:
1. `pk` is committed at validator staking time, before any epoch input is known.
2. The beacon aggregates all committee contributions — a single honest contribution randomises the output.
3. A VDF over the aggregated value prevents last-reveal grinding.
4. `input_{e+1}` derives from the previous epoch beacon output (chained randomness).
5. `VALIDATOR_ACTIVATION_DELAY_EPOCHS = 2` between registration and eligibility, preventing stake-weight manipulation after seeing an epoch input.

The STARK proof is large (~50–200 KB) but is never posted on external chains; it is verified off-chain by validators and light clients.

## 2.3 Threshold ML-KEM-768 for Encrypted Mempool

The Quantos mempool supports encrypted transactions to prevent front-running. The encryption uses ML-KEM-768 (FIPS 203) with a threshold decryption layer:

- The ML-KEM secret vector `s` (K polynomials of degree N) is split coefficient-wise via Shamir secret sharing over Z_q.
- Each validator committee member holds a share of every scalar coefficient.
- During block proposal, `t-of-n` participants each compute a partial inner-product `s_i^T · u` in the NTT domain.
- The partials are combined via Lagrange interpolation to recover `s^T · u`, from which the shared symmetric key is derived.
- Each partial computation is accompanied by a lattice NIZK proof (Fiat-Shamir over polynomial commitments) proving correct computation without revealing the share.

This construction replaces earlier proposals that relied on a single decryptor or unspecified threshold mechanisms. The implementation (`crypto/threshold_mlkem.rs`, `crypto/shamir_zq.rs`, `crypto/lattice_nizk.rs`) is a research-grade component, enabled via Cargo feature `experimental-threshold-mlkem`. Open questions — in particular noise aggregation across partial decryptions and the security of the coefficient-wise Shamir sharing under LWE noise — are subject to external audit before this component is placed on the mainnet critical path. **The default mainnet path uses the accountable-leader front-running protection** (`mempool/accountable_leader.rs`): canonical order is determined by `H(ordering_beacon ‖ tx_hash)`, and any deviation is slashable as proven front-running.

## 2.4 Security Level Alignment

All cryptographic objects requiring long-term security or systemic finality now operate at NIST security level 3:

| Object | Algorithm | NIST Level |
|--------|-----------|------------|
| Transaction signatures | ML-DSA-65 | 3 |
| Checkpoint / finality signatures | ML-DSA-65 | 3 |
| L0 cross-chain attestations | ML-DSA-65 | 3 |
| Mempool encryption | ML-KEM-768 | 3 |
| VRF (committee randomness) | SHA3-256 + STARK | — |

## 2.5 Quantum-Resistant Randomness (QRNG)

Randomness is consensus-critical: it seeds committee selection and the VRF. Quantos generates it with a quantum-resistant RNG (`crypto/qrng.rs`) built on the SHAKE256 extendable-output function (XOF). The QRNG mixes multiple entropy sources — system randomness, the previous QRNG output, recent block hashes, and network timing — into a SHAKE256 sponge and expands as much randomness as needed:

- **Post-quantum security**: SHAKE256 has no known quantum shortcut beyond Grover, leaving a 128-bit margin at 256-bit output.
- **Entropy pooling and reseeding**: sources are pooled and the state is periodically reseeded, so a single compromised source cannot dominate the output.
- **Deterministic mode**: for consensus paths that must be reproducible across validators, the QRNG runs in a deterministic mode seeded from on-chain values, so every honest node derives identical randomness.
- **Performance**: lock-free thread-local pools provide high-throughput randomness for hot paths.

## 2.6 Signature Aggregation (QRSA)

Post-quantum signatures are large (an ML-DSA-65 signature is ~3.3 KB), so a committee of hundreds of validators would otherwise attach megabytes of signatures to every block. The quantum-resistant signature-aggregation layer (`crypto/signature_aggregation.rs`) uses a two-tier strategy based on Merkle commitments with Fiat-Shamir:

- **Full aggregation** retains all N signatures plus their Merkle proofs for archival audit, and is used during block production and validation.
- **Compact aggregation** stores only the Merkle root plus a signer bitmap for on-chain storage and network propagation. This compresses a committee's block signature from **N × ~3.3 KB** down to **~130 bytes** for an 800-validator committee — a reduction of three to four orders of magnitude in the propagated and persisted footprint.

This is what makes large committees practical despite post-quantum signature bloat: the heavy signature data is verified once and then represented compactly.

## 2.7 Adaptive Algorithm Selection (Advisory)

The codebase includes an adaptive PQC selection layer (`crypto/adaptive_pqc.rs`) that can choose among signature algorithms based on network congestion, transaction priority, and latency requirements. Its determinism boundary is drawn explicitly and conservatively:

| Strategy | Deterministic? | Consensus-safe? |
|----------|----------------|-----------------|
| Always-fixed (single algorithm) | ✅ trivially | ✅ |
| `Adaptive` (pure function of observable inputs) | ✅ | ✅ |
| `MLBased` (neural-network hint) | ❌ | ❌ **advisory only** |

**The ML predictor is never used on the consensus-critical path.** It produces local optimisation hints (for example, suggesting a lighter algorithm when the local mempool is congested), but the block producer's final choice is re-validated by all nodes using the deterministic `Adaptive` strategy. This preserves the rule from the Virtual Machine section that no non-deterministic computation can ever affect the committed state transition.
