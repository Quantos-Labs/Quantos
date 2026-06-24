---
sidebar_position: 5
---

# 4. QuantumDAG Consensus

## 4.1 Theoretical Foundation

QuantumDAG is derived from and cites the following peer-reviewed literature:

- **Narwhal** (Spiegelman et al., 2022): DAG-based mempool with structured data availability. Quantos uses Narwhal's directed-acyclic-graph broadcast for transaction dissemination within each shard.
- **Bullshark** (Spiegelman et al., 2022): DAG-based BFT consensus under partial synchrony. Quantos uses Bullshark's commit rule (2-round latency under synchrony) for the fast-path layer.
- **HotStuff** (Yin et al., 2019): Linear BFT with rotating leaders. Quantos uses HotStuff's view-change mechanism for the committee BFT layer.

## 4.2 Synchrony Model: Partial Synchrony

Quantos does **not** assume full synchrony (fixed message delay bound Δ). It assumes **partial synchrony** (Dwork, Lynch, Stockmeyer 1988):

- There exists an unknown Global Stabilization Time (GST) after which all messages between honest nodes arrive within a finite but unknown bound Δ.
- Safety (no conflicting commits) holds at all times, regardless of synchrony.
- Liveness (eventual commit) holds only after GST.

In practice, Δ is estimated at ~100 ms via a rolling 95th-percentile RTT estimator. The protocol adapts slot duration and view-change timeouts to observed network conditions rather than hard-coding them.

## 4.3 Byzantine Fault Tolerance Per Layer

**Layer 1 — FastPath DAG (Narwhal-derived)**
- `n` validators per shard committee; maximum Byzantine `f = ⌊(n-1)/3⌋`.
- Safety: never produces conflicting commits.
- Liveness: holds after GST.
- Threshold: votes from > 2n/3 stake required for a quorum certificate (QC).

**Layer 2 — Committee BFT (Bullshark / HotStuff-derived)**
- Same `n`, `f` bounds.
- View-change (leader rotation) ensures liveness under partial synchrony.
- VRF-based rotation prevents adaptive adversary targeting.

**Layer 3 — Finality (Checkpoint layer)**
- Super-committee of `s` validators (`s = 100` in production).
- `f_super = ⌊(s-1)/3⌋ ≤ 33`.
- Finality is deterministic once a checkpoint QC is formed.

## 4.4 Core Safety Invariants

The implementation enforces five runtime-checked invariants:

- **INV-S1 (Agreement)**: Two honest nodes never commit different values at the same slot. Detected by checking for conflicting QCs at the same slot; overlap analysis identifies the equivocating validators.
- **INV-S2 (Validity)**: If a value is committed, it was proposed by a leader elected through the VRF.
- **INV-S3 (Total Order)**: All honest nodes see the same total order of committed vertices. A vertex at slot `s` can only be committed if its parents at `s-1` are committed.
- **INV-L1 (Liveness)**: After GST, honest validators eventually commit all valid transactions.
- **INV-L2 (Termination)**: After GST + O(Δ), every proposed vertex is either committed or garbage-collected.

## 4.5 Horizontal Scaling

Consensus operates per shard, and shards run in parallel. The state is partitioned horizontally (accounts assigned by hash-of-address modulo shard count), and the shard count adapts dynamically to load. The full mechanics of split/merge, safe state migration, and atomic cross-shard commitment are described in the Dynamic Sharding section; the key consensus-level point is that each shard reaches consensus independently under the model above, so aggregate capacity scales with the number of active shards.
