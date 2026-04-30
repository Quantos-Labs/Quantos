# Threat Model — Quantos L1 Blockchain

> Version 1.0 — April 2026.  
> Intended audience: CertiK auditors and internal security team.

---

## 1. Assets to Protect

| Asset | Description |
|-------|-------------|
| **Validator keys** | Dilithium-3 signing keys, Falcon-512 finality keys, SPHINCS+ VRF keys |
| **User account state** | Balances, nonces, staked amounts, contract storage |
| **Consensus safety** | At most one finalized block per slot; no equivocation |
| **Consensus liveness** | The chain continues producing and finalising blocks |
| **State root integrity** | All honest full nodes derive the same SMT root from the same set of transactions |
| **Transaction authorisation** | Only the key holder can spend from an account |
| **VRF randomness** | Committee assignments must be unbiasable and unpredictable before reveal |
| **Slashing evidence** | Evidence must be authentic; false slashing must be impossible |
| **VM determinism** | The same WASM contract + inputs always produce the same output and gas cost |
| **Cryptographic material** | Secret keys must never be exposed or derivable from public data |

---

## 2. Trust Boundaries

```
┌──────────────────────────────────────────────────┐
│  External (untrusted)                            │
│  - Any peer on the P2P network                   │
│  - Any JSON-RPC caller                           │
│  - Any submitted transaction or contract         │
├──────────────────────────────────────────────────┤
│  Semi-trusted                                    │
│  - Registered validators (staked, slashable)     │
│  - Committee members in current epoch            │
├──────────────────────────────────────────────────┤
│  Trusted (local)                                 │
│  - The node process itself                       │
│  - The RocksDB storage layer                     │
└──────────────────────────────────────────────────┘
```

The threat model assumes a **Byzantine Fault Tolerant** adversary controlling up to ⅓ of total stake across consensus layers, and an **arbitrary network adversary** (delayed, reordered, replayed messages).

---

## 3. Threat Catalogue by Subsystem

### 3.1 Cryptography (`src/crypto/`)

| ID | Threat | Mitigations |
|----|--------|-------------|
| C-1 | **Signature forgery** — attacker forges a Dilithium-3 / Falcon-512 / SPHINCS+ signature | NIST PQC standards; `pqcrypto` crate; verification called before any state change |
| C-2 | **Cross-context signature replay** — a valid sig over a vote is replayed as a transaction sig | Domain separation: every `signing_data()` is prefixed with a unique 2+N-byte domain tag (`DOMAIN_TX`, `DOMAIN_VERTEX`, `DOMAIN_COMMITTEE_VOTE`, `DOMAIN_CHECKPOINT`, …) |
| C-3 | **VRF grinding** — a validator calls `prove()` multiple times and cherry-picks a committee-favourable output | VRF output is a PRF of `(sk, seed)` via SHAKE256; output is stable regardless of how many times `prove()` is called |
| C-4 | **QRNG predictability** — QRNG output repeats between reseeds | SHAKE256 XOF state advanced by a monotonic counter on every call |
| C-5 | **Timing side-channels on secret comparison** | Comparisons on secret material use `subtle::ConstantTimeEq`; SIMD comparison (`simd_compare_256`) is explicitly not used for secrets |
| C-6 | **Key derivation weakness** | PRF keys use `SHAKE256(domain ‖ sk_bytes)` with distinct domain tags; VRF PRF key is derived once and stored |

### 3.2 Consensus — Fast Path & DAG (`src/consensus/fast_path.rs`, `src/dag/`)

| ID | Threat | Mitigations |
|----|--------|-------------|
| D-1 | **Invalid vote accepted** — vote with wrong or missing Dilithium sig | `verify_committee_vote` calls `verify_dilithium` before updating vote tallies |
| D-2 | **Vote deduplication bypass** — same validator votes twice | Per-slot `seen_voters: HashSet<Address>` in `FastPathState` |
| D-3 | **Stake inflation** — vote counted with artificially high stake weight | Stake read from the canonical `StateManager` registry, not from the vote message |
| D-4 | **Double vertex creation** — validator creates two vertices at the same height | Slashable offence; DAG rejects duplicate (creator, height) pairs |
| D-5 | **Long-range attack / weak subjectivity** | Checkpoint-based finality + weak subjectivity window enforced by the security monitor |

### 3.3 Consensus — Finality & Checkpoints (`src/consensus/finality.rs`, `src/types/checkpoint.rs`)

| ID | Threat | Mitigations |
|----|--------|-------------|
| F-1 | **Checkpoint signature forgery** | Falcon-512 signatures verified via `verify_falcon` with each validator's registered `finality_public_key` |
| F-2 | **Duplicate signer counted multiple times** | `pending.signers: HashSet<Address>` deduplicates before updating `total_stake_signed` |
| F-3 | **Jailed/inactive validator participates in finality** | `receive_checkpoint_signature` checks `validator_info.is_active && !validator_info.is_jailed` |
| F-4 | **Wrong key used for finality** | Falcon key is stored separately as `finality_public_key`; domain prefix `DOMAIN_CHECKPOINT` prevents reuse of Dilithium sigs |
| F-5 | **`mark_vertices_finalized` skipped** | `FinalityManager` captures DAG tips at checkpoint creation and calls `DAGGraph::finalize_reachable_from_tips` |

### 3.4 Committee & VRF (`src/consensus/committee.rs`, `src/crypto/qr_vrf.rs`)

| ID | Threat | Mitigations |
|----|--------|-------------|
| V-1 | **Committee rotation privilege escalation** | `rotate_committees` is protocol-deterministic; no external caller or token is accepted |
| V-2 | **VRF output non-uniqueness (grinding)** | PRF-based construction: output = `SHAKE256(DOMAIN_VRF_OUTPUT ‖ prf_key ‖ seed)` is deterministic |
| V-3 | **False VRF proof for a different output** | SPHINCS+ signature binds `(seed, output)` together; equivocation (two outputs for same seed) is slashable |
| V-4 | **Selection bias via modulo** | Rejection-sampling used to remove modulo bias in `is_stake_selected` and `select_committee_validators` |

### 3.5 Slashing (`src/consensus/slashing.rs`)

| ID | Threat | Mitigations |
|----|--------|-------------|
| S-1 | **"Anyone can slash anyone" for InvalidBlock** | `validate_invalid_block` verifies the accused validator's Dilithium sig over `(DOMAIN_SLASH_IBLOCK ‖ validator ‖ slot ‖ hash)` |
| S-2 | **Equivocation evidence with wrong pubkey** | `validate_equivocation` fetches the full registered public key from the validator registry; does not trust the 32-byte address as a key |
| S-3 | **Replayed slash evidence** | Evidence deduplication via `submitted_evidence: HashSet<Hash>` keyed on evidence hash |
| S-4 | **Stake manipulation around slash** | Slash penalty applied to `effective_stake()` at time of slash, recorded immutably |

### 3.6 State & Execution (`src/state/`, `src/state/executor.rs`)

| ID | Threat | Mitigations |
|----|--------|-------------|
| E-1 | **Speculative writes polluting confirmed state** | `OptimisticExecutor` uses an in-memory overlay; only `apply_transactions_atomically` writes to RocksDB |
| E-2 | **Non-deterministic state root** | SMT root computed from RocksDB iterator (full account set) rather than volatile cache |
| E-3 | **Nonce replay** | Transaction validation rejects `tx.nonce != account.nonce` |
| E-4 | **Balance underflow** | Arithmetic uses checked subtraction; `Amount` is a newtype over `u128` with overflow guards |
| E-5 | **Invalid transaction silently accepted** | `validate_tx` checks signature (Dilithium), nonce, balance, gas; called before state write |

### 3.7 VM / Smart Contracts (`src/vm/`)

| ID | Threat | Mitigations |
|----|--------|-------------|
| W-1 | **Malicious WASM bytecode** | WASM binary validated for magic, version, section structure before deployment |
| W-2 | **Gas exhaustion / infinite loop** | Wasmer metering middleware; `max_compute_units` hard cap per execution |
| W-3 | **Host function misuse** | Each `seal_*` host function validates caller, bounds-checks memory access |
| W-4 | **Cross-contract reentrancy** | Execution context is non-reentrant per transaction; call depth limited |
| W-5 | **Contract storage key collision** | Storage keys scoped to `(contract_address, slot)` |

### 3.8 Mempool (`src/mempool/`)

| ID | Threat | Mitigations |
|----|--------|-------------|
| M-1 | **Tx signature forgery** | `SecureMempool::validate_transaction` calls `verify_dilithium` before admission |
| M-2 | **Timestamp manipulation** | Max timestamp drift enforced: ±30 seconds |
| M-3 | **DoS via mempool flooding** | Per-sender limits; fee-priority ordering; max pool size cap |
| M-4 | **Replay attack across shards** | `signing_data()` includes `shard_id` and `chain_id` |

### 3.9 Network & P2P (`src/network/`, `src/security/`)

| ID | Threat | Mitigations |
|----|--------|-------------|
| N-1 | **Stake concentration / majority attack** | `MajorityAttackDetector` monitors real-time stake distribution |
| N-2 | **Fork detection** | `ForkMonitor` tracks competing chain tips and raises alerts |
| N-3 | **Time warp** | `SecurityMonitor` enforces block time bounds |
| N-4 | **Message replay** | Timestamp + nonce in signed messages; `MAX_TIMESTAMP_DRIFT = 30s` |

---

## 4. Non-Goals (Out of Scope for This Audit)

- Solidity prototype contracts in `solidity-contracts/` (testnet only).
- Frontend, wallet UX, and API gateway layers.
- Physical/hardware key storage.
- Denial-of-service resistance of the P2P discovery layer.

---

## 5. Cryptographic Assumptions

| Assumption | Justification |
|------------|---------------|
| Dilithium-3 EUF-CMA under post-quantum adversary | NIST FIPS 204 |
| Falcon-512 EUF-CMA under post-quantum adversary | NIST FIPS 206 |
| SPHINCS+-shake-256f EUF-CMA under post-quantum adversary | NIST FIPS 205 |
| SHAKE256 collision resistance and PRF security | SHA-3 family, NIST FIPS 202 |
| Winterfell STARK soundness | 100-bit security with Blake3 |
