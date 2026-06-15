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
- **Prove**: A Winterfell STARK proves knowledge of `sk` such that `pk = SHA3-256(sk)` and `beta = SHA3-256(sk ‖ input)`

**Anti-grinding safeguards**:
1. `pk` is committed at validator staking time, before any epoch input is known.
2. `input_{e+1}` derives from the previous epoch beacon output (chained randomness).
3. `VALIDATOR_ACTIVATION_DELAY_EPOCHS = 2` between registration and eligibility, preventing stake-weight manipulation after seeing an epoch input.

The STARK proof is large (~50–200 KB) but is never posted on external chains; it is verified off-chain by validators and light clients.

## 2.3 Threshold ML-KEM-768 for Encrypted Mempool

The Quantos mempool supports encrypted transactions to prevent front-running. The encryption uses ML-KEM-768 (FIPS 203) with a threshold decryption layer:

- The ML-KEM secret vector `s` (K polynomials of degree N) is split coefficient-wise via Shamir secret sharing over Z_q.
- Each validator committee member holds a share of every scalar coefficient.
- During block proposal, `t-of-n` participants each compute a partial inner-product `s_i^T · u` in the NTT domain.
- The partials are combined via Lagrange interpolation to recover `s^T · u`, from which the shared symmetric key is derived.
- Each partial computation is accompanied by a lattice NIZK proof (Fiat-Shamir over polynomial commitments) proving correct computation without revealing the share.

This construction replaces earlier proposals that relied on a single decryptor or unspecified threshold mechanisms. The full implementation is production-grade and covered by unit tests (`test_threshold_roundtrip`).

## 2.4 Security Level Alignment

All cryptographic objects requiring long-term security or systemic finality now operate at NIST security level 3:

| Object | Algorithm | NIST Level |
|--------|-----------|------------|
| Transaction signatures | ML-DSA-65 | 3 |
| Checkpoint / finality signatures | ML-DSA-65 | 3 |
| L0 cross-chain attestations | ML-DSA-65 | 3 |
| Mempool encryption | ML-KEM-768 | 3 |
| VRF (committee randomness) | SHA3-256 + STARK | — |
