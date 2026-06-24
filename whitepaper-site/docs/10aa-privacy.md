---
sidebar_position: 26
slug: /privacy
---

# 25. Confidential Mode (Optional Privacy)

Quantos is transparent by default: balances, amounts and the sender→recipient graph are public, exactly like Bitcoin or Ethereum. **Confidential Mode** is an **opt-in** layer (`quantos/src/privacy/`) that lets users, tokens and applications make selected data private while keeping every operation *publicly verifiable* through the protocol's existing post-quantum zk-STARK machinery. It is disabled by default (`PrivacyConfig::enabled = false`); a node that does not opt in behaves identically to a pre-privacy build.

Crucially, privacy here is **post-quantum end-to-end**. The confidentiality of payloads does not rest on elliptic-curve Diffie–Hellman (which Shor's algorithm breaks). Key agreement for stealth addressing and note/payload encryption uses **ML-KEM-768** (FIPS 203), and correctness is proven with transparent **zk-STARKs** (Winterfell, no trusted setup). Confidential Mode is therefore resistant to "harvest-now-decrypt-later" deanonymisation.

## 25.1 What Can Be Made Confidential

| Surface | What is hidden | Mechanism | Module |
|---------|----------------|-----------|--------|
| Transaction amounts | The transferred value | Value commitments + 64-bit range proof | `shielded_pool.rs` |
| Account balances | How much an account holds | UTXO-style note commitments (no plaintext balance map) | `shielded_pool.rs` |
| Sender → recipient graph | Who paid whom | ML-KEM-768 stealth one-time addresses | `stealth.rs` |
| Smart-contract state | A contract's private variables | Encrypted storage slots + slot commitments | `confidential_state.rs` |
| Mempool contents | Pre-ordering transaction data | Encrypted mempool (already in the consensus layer) | consensus / mempool |
| QN token holders | Who holds a token and how much | Per-token shielded note registry | `confidential_token.rs` |
| L0 cross-chain payload | The cross-chain message content | Committed + ML-KEM-encrypted payload, public finality | `confidential_l0.rs` |

The encrypted mempool (front-running protection *before* ordering) already exists in the protocol; Confidential Mode composes with it rather than re-implementing it.

## 25.2 Shielded Pool — Amounts and Balances

In Confidential Mode, funds are represented as **notes** rather than a public `address → balance` map. Each note publishes only a value commitment:

```
C = H(value ‖ blinding_factor)
```

The amount and the owner are never revealed on-chain. Spending a note publishes a **nullifier**:

```
N = H(note_id ‖ spend_key)
```

The nullifier prevents double-spending without disclosing *which* note was consumed. The pool maintains two public structures: an append-only Merkle tree of note commitments (proving a note *exists*) and a set of spent nullifiers (proving a note has *not* been spent).

A confidential transfer is accompanied by a zk-STARK (`StarkProver::prove_private_transfer`) that proves, in zero knowledge, that:

1. every input value is non-negative (64-bit range decomposition);
2. value is conserved — `sum(inputs) = sum(outputs) + fee`;
3. all commitments are correctly formed;
4. nullifiers are correctly derived (no double-spend);
5. input notes are members of the commitment tree (Merkle membership).

The verifier learns only the commitments, the nullifiers and the note-set root — never the amounts, blinding factors or which notes were spent.

## 25.3 Stealth Addresses — Breaking the Transaction Graph

To hide *who pays whom*, a recipient publishes a long-lived **meta-address** once: an ML-KEM-768 scan public key plus a commitment to their spend authority. Every payment lands on a fresh, unlinkable **one-time address**:

- **Send:** the payer encapsulates to the scan key, `(ss, ct) = MLKEM.Encapsulate(scan_pk)`, and derives `one_time_address = H(domain ‖ ss ‖ spend_pubkey_hash)`, publishing `{ one_time_address, ct, view_tag }`.
- **Scan:** the recipient decapsulates `ct` with their scan secret key, rejects ~255/256 of non-matching payments via a 1-byte `view_tag`, and accepts iff the recomputed address matches.

No third party can link two one-time addresses to the same recipient, and only the recipient learns the shared secret used to decrypt the note. Because the shared secret comes from ML-KEM rather than ECDH, the unlinkability holds against quantum adversaries.

## 25.4 Confidential Contract State

A contract may mark selected storage slots confidential. Each slot value is encrypted under a contract viewing key (ML-KEM-derived AES-256-GCM) and exposed on-chain only as a commitment `H(domain ‖ key ‖ value ‖ blinding)`. The public `storage_root` still binds the full slot set, so state-integrity and state-rent accounting are unchanged — observers simply cannot read the values. Correctness of a confidential state transition is bound to the VM's zk-STARK execution proof.

## 25.5 Confidential QN Token Registry

A transparent QN4 token keeps a public `address → balance` map. A **confidential registry** (`ConfidentialTokenRegistry`) instead keeps a per-token shielded note pool: the **total supply stays public** (auditable issuance), but individual holder balances and transfers are shielded exactly like the base-asset shielded pool, and recipients are addressed via stealth one-time addresses. Confidential mint and burn adjust the public supply while keeping holders private; confidential transfers leave supply unchanged.

## 25.6 Confidential L0 Cross-Chain Payloads

The L0 Finality Hub attests that a state was finalized; by default the attested message travels in clear. Confidential Mode lets the **message content** (amount, parties, memo) be encrypted toward the destination-chain recipient with ML-KEM-768 + AES-256-GCM, while only a 32-byte `payload_commitment` is bound into the proof's `state_root`. Any verifier confirms the commitment was finalized using the *unchanged* PQC/STARK finality machinery, without learning what was transferred. This changes *what* is attested, not *how* finality is proven — the directional-finality trust model is untouched (Layer 0 Finality Hub section).

## 25.7 Honesty and Audit Scope

Consistent with the rest of this paper, Confidential Mode separates what is enforced today from what is pending audit:

- **Confidentiality** of amounts, balances, parties, slots and L0 payloads is enforced now by commitments, nullifiers and ML-KEM-768 encryption.
- **Zero-knowledge correctness** (range, conservation, membership) is produced by the transparent Winterfell STARK prover. The in-circuit Keccak-AIR binding of the private witness shares the same `STARK_PROVES_UNIQUENESS` track as the VRF proof-of-knowledge and is gated behind independent audit before the confidential path is placed on the mainnet critical path.
- Confidential Mode is **off by default**. Operators enable it explicitly (`QUANTOS_PRIVACY_ENABLED`, or `PrivacyConfig::all_enabled()`), and each surface (amounts, balances, stealth addresses, contract state, token registry, L0 payload) is independently toggleable.

No privacy claim in this section depends on a trusted setup, on a classical hardness assumption, or on hiding source code.
