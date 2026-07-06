---
sidebar_position: 7
slug: /committees
---

# 6. Committee Selection & VRF Rotation

## 6.1 The Committee Model

Quantos does not ask every validator to vote on everything. Instead it partitions the validator set into many small **committees** that operate in parallel (`quantos/src/consensus/committee.rs`). In the reference configuration there are up to 1,000 committees of 21 validators each (≈21,000 validators total), with each committee responsible for a shard's fast-path consensus. Small committees keep per-decision message complexity low; many committees keep the system massively parallel.

## 6.2 VRF-Based Random Selection

Committee membership is assigned by the hash-based Verifiable Random Function (Section 2). Using a VRF rather than a public, predictable schedule is a security necessity: if an adversary could predict which validators will form the next committee for a given shard, it could target them with bribery, DDoS, or eclipse attacks ahead of time. With a VRF:

- Each validator's assignment is **unpredictable** until the epoch input is revealed.
- The assignment is **verifiable** — anyone can check, from the VRF proof, that a validator was legitimately selected (safety invariant **INV-S2**).
- The assignment is **unique** — the hash-based construction admits exactly one valid output per (key, input), removing the grinding attack that signature-based VRFs suffer.

## 6.3 Frequent Rotation

Committees rotate on a short cadence (≈every 100 ms in the reference config). Frequent rotation shrinks the window in which an adversary can act against any particular committee: even if it identified a committee, that committee is dissolved before a targeted attack can be mounted. Rotation randomness is chained from the previous epoch's beacon output (`consensus/beacon.rs`), so the randomness sequence is itself unpredictable yet verifiable.

## 6.4 Anti-Grinding Safeguards

Three safeguards prevent stake-grinding manipulation of committee selection:

1. **Pre-committed VRF keys**: a validator's VRF public key is fixed at staking time, before any future epoch input is known.
2. **Chained randomness**: each epoch input derives from the previous epoch's beacon output, so it cannot be steered.
3. **Activation delay**: `VALIDATOR_ACTIVATION_DELAY_EPOCHS = 2` epochs elapse between registration and eligibility, so a newly registered validator cannot react to an already-known epoch input.

## 6.5 Dynamic Committees

Because the validator set and shard count change over time (validators join, exit, or are slashed; shards split and merge), committee composition is not static. The dynamic committee manager (`consensus/dynamic_committee.rs`) resizes and reassigns committees as the active validator set and shard topology evolve, keeping each committee correctly sized and stake-balanced. Committee changes are themselves staged with delays so that an adversary cannot manufacture a favourable committee on demand.

## 6.6 Stake Weighting and Thresholds

Within a committee, voting is stake-weighted and Byzantine-fault-tolerant: a quorum certificate requires votes representing more than 2/3 of committee stake (the reference 14-of-21 threshold), tolerating up to `f = ⌊(n-1)/3⌋` Byzantine members. This threshold is what the consensus safety and liveness invariants (Section 4) are stated against.
