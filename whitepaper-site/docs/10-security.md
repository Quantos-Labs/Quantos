# 10. Security Model

## 10.1 Slashing Conditions

Validators are slashed for:
- **Double-signing**: Signing two conflicting checkpoints at the same height.
- **Equivocation**: Producing two conflicting QCs at the same slot (detected by `SafetyChecker::detect_equivocation`).
- **Invalid block**: Proposing a block with an invalid state transition.
- **WOTS one-time reuse**: In PQC-Guard, reusing a WOTS leaf to sign two different digests (detected by `slash_on_reuse`).

Slashed stake is split 80% to honest validators, 20% burned.

## 10.2 Economic Security

The minimum cost to attack the Quantos L1 is the cost of acquiring > 1/3 of staked QTS and breaking ML-DSA-65 (NIST level 3) or the hash-based VRF. At a projected $1B+ staked value, this is economically infeasible for any known adversary.

For the L0 hub, the security of each external chain maps to its own trust model (see §6.1). Chains with cryptographic light-client verification inherit the security of their native consensus; chains with RPC oracle attestation inherit the security of the RPC endpoint plus the Quantos relay quorum.
