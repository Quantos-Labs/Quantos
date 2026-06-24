---
sidebar_position: 25
---

# 24. Security Model

## 24.1 Threat Coverage

The security subsystem (`quantos/src/security/`) addresses both quantum and classical attack vectors with dedicated, runtime-active modules:

| Attack | Protection | Module |
|--------|------------|--------|
| Shor's algorithm | Post-quantum signatures (ML-DSA-65) everywhere | `crypto/`, `quantum.rs` |
| Grover's algorithm | 256-bit hashing → 128-bit post-quantum security margin | `quantum.rs` |
| 51% / stake attack | Stake-weighted committees + slashing | `consensus.rs` |
| Eclipse attack | Peer diversity (ASN/geo), anchor peers, rotation | `eclipse_protection.rs` |
| Sybil attack | Stake requirement + identity proofs | `sybil_protection.rs` |
| Double spend | DAG conflict resolution + deterministic finality | `consensus.rs` |
| Replay attack | Nonce + chain id + expiry | `transaction.rs` |
| Long-range attack | Checkpoints + weak subjectivity | `consensus.rs` |
| Time warp | Median NTP time + monotonic clock + bounds | `time_sync.rs` |
| Front-running / MEV | Encrypted mempool + fair ordering | `transaction.rs`, STACC |
| DoS / DDoS | Rate limiting + proof-of-work admission | `ddos_protection.rs` |
| Nothing-at-stake | Slashing + deposit lockup | `consensus.rs` |
| MITM | End-to-end PQC encryption + mutual auth | `network.rs` |

## 24.2 Slashing Conditions

Validators are slashed for:
- **Double-signing**: Signing two conflicting checkpoints at the same height.
- **Equivocation**: Producing two conflicting QCs at the same slot (detected by `SafetyChecker::detect_equivocation`).
- **Invalid block**: Proposing a block with an invalid state transition.
- **WOTS one-time reuse**: In PQC-Guard, reusing a WOTS leaf to sign two different digests (detected by `slash_on_reuse`).

Slashed stake is split 80% to honest validators, 20% burned.

## 24.3 Eclipse and Sybil Resistance

An eclipse attack succeeds only if it controls all of a victim's peer connections. `eclipse_protection.rs` prevents this by enforcing **connection diversity**: peers are drawn from distinct Autonomous System Numbers (ASNs) and geographic regions, a set of long-lived **anchor peers** is always retained, non-anchor peers are rotated regularly, and per-subnet/ASN connection caps prevent a single network operator from dominating a node's peer table. Sybil resistance (`sybil_protection.rs`) ties participation to economic stake and identity proofs, so spinning up many identities does not translate into consensus influence without proportional stake at risk.

## 24.4 Time Integrity

Consensus depends on loosely synchronized clocks. `time_sync.rs` runs an NTP client against multiple servers, filters outliers, aggregates the remaining samples, and enforces a **monotonic clock** so a node's notion of time never moves backwards. Excessive drift is detected and alerted, defeating time-warp attacks that try to manipulate timestamp-dependent logic.

## 24.5 Economic Security

The minimum cost to attack the Quantos L1 is the cost of acquiring > 1/3 of staked QTS *and* breaking ML-DSA-65 (NIST level 3) or the hash-based VRF. At a projected $1B+ staked value, this is economically infeasible for any known adversary.

For the L0 hub, the security of each external chain maps to its own trust model (see the Layer 0 Finality Hub section). Chains with cryptographic light-client verification inherit the security of their native consensus; chains with RPC oracle attestation inherit the security of the RPC endpoint plus the Quantos relay quorum. Relayers additionally post a **bond** (`l0/relay_bond.rs`) that is slashable for relaying invalid proofs, adding an economic deterrent on top of the cryptographic checks.
