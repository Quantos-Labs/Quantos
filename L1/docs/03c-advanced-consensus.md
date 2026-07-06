---
sidebar_position: 8
slug: /advanced-consensus
---

# 7. Advanced Consensus Mechanisms

Beyond the three-layer model of Section 4, Quantos implements several refinements (`quantos/src/consensus/`) that improve latency and liveness without weakening safety.

## 7.1 Pipelined BFT

The committee BFT layer uses a **HotStuff-2-style pipelined** protocol (`consensus/pipelining.rs`) with **O(n) message complexity** and a **2-chain commit rule**: each proposal extends the previously certified block, and a block is committed once its grandchild is certified. Crucially, the Prepare and Commit phases of consecutive views *overlap* (pipelining), so the protocol commits a steady stream of blocks rather than paying full multi-phase latency per block. Votes are domain-separated (`DOMAIN_PIPELINE_VOTE`) to prevent cross-context replay.

## 7.2 Optimistic Responsiveness

`consensus/optimistic_responsiveness.rs` lets the protocol commit at **network speed** when conditions are good, rather than at the speed of a conservative timeout:

| Network condition | Path | Latency |
|-------------------|------|---------|
| `Synchronous` (all honest validators fast) | Fast path | **2 RTT** |
| `PartialSync` / adversarial | Slow path | 4 RTT (standard BFT) |

The protocol detects network conditions automatically and switches paths. Under the synchronous fast path it achieves 2-RTT finality; under adversarial delay it falls back to the standard, safety-preserving BFT timing. Safety holds on both paths; only latency differs.

## 7.3 View Change and Leader Rotation

Liveness under partial synchrony requires the ability to replace a faulty or silent leader. The view-change mechanism (`consensus/view_change.rs`) rotates leadership through a deterministic, VRF-seeded schedule and triggers a view change when the current leader fails to make progress within the adaptive timeout. Because leaders are unpredictable (Committee section) and rotated on failure, neither a crashed leader nor an adaptive adversary can stall the protocol indefinitely after GST.

## 7.4 Adaptive Timing

Rather than hard-coding a message-delay bound, the protocol estimates the network delay Δ from a rolling 95th-percentile RTT estimator and adapts slot durations and view-change timeouts to observed conditions. This keeps the chain fast on healthy networks while remaining safe and live on degraded ones — the practical expression of the partial-synchrony model.

## 7.5 Optimistic Execution and Rollback

The fast path (`consensus/fast_path.rs`) executes transactions **optimistically** — speculatively, before final ordering — to overlap execution latency with consensus latency. Because conflicts are rare in practice, the speculative result is almost always correct; when ordering invalidates a speculation, the affected transactions are rolled back and re-executed. The design targets a rollback rate below 0.1%, so the optimistic path is the overwhelmingly common case.

## 7.6 Formal Safety Model

The safety model (`consensus/safety_model.rs`) encodes the runtime-checked invariants described in Section 4 (Agreement, Validity, Total Order, Liveness, Termination) and the equivocation detector that underpins slashing. These checks run in production, not merely in proofs: a violation is detected and attributed to the equivocating validator(s) for slashing, turning the safety argument into an enforced, observable property of the live network.
