---
sidebar_position: 10
slug: /sharding
---

# 9. Dynamic Sharding

## 9.1 Overview

Quantos achieves horizontal scaling through **dynamic sharding**: the network partitions global state across many parallel shards and adjusts the shard count automatically in response to observed load. Each shard runs its own committee, mempool, and DAG, processing transactions in parallel with all other shards. Aggregate throughput therefore scales (approximately linearly, under uniform load) with the number of active shards.

The sharding subsystem (`quantos/src/sharding/`) is composed of four cooperating modules:

| Module | Responsibility |
|--------|----------------|
| `mod.rs` | Shard lifecycle, split/merge orchestration, rebalance history |
| `cross_shard.rs` | Atomic cross-shard transactions via 2-phase commit + STARK proofs |
| `reshard.rs` | Safe state migration with draining, freezing, and rollback |
| `self_healing.rs` | Predictive hotspot detection and zero-downtime rebalancing |
| `stark_accelerated.rs` | STARK-accelerated cross-shard proof aggregation |

## 9.2 Shard Lifecycle: Split and Merge

Shards are not static. The protocol maintains a configurable band of shard counts and adapts within it:

```
ShardingConfig (defaults):
  min_shards              = 100
  max_shards              = 10,000
  split_threshold_tps     = 150,000   # split a shard above this sustained load
  merge_threshold_tps     = 10,000    # merge a shard below this sustained load
  rebalance_cooldown_secs = 60        # minimum interval between operations
  load_average_epochs     = 10        # smoothing window for load measurement
```

- **Split**: When a shard's smoothed throughput exceeds `split_threshold_tps`, its address space is bisected and a new shard is created. Accounts are reassigned by hash-of-address, and validators are redistributed proportionally to the new load.
- **Merge**: When two adjacent shards both fall below `merge_threshold_tps`, their state is consolidated into one shard, freeing validators for redeployment elsewhere.
- **Cooldown**: A `rebalance_cooldown_secs` window prevents thrashing — rapid oscillation between split and merge under noisy load.

Load is averaged over `load_average_epochs` to ensure decisions are driven by sustained trends, not transient spikes.

## 9.3 Safe Re-Sharding

Moving accounts between shards is the most safety-critical operation in the system, because a naive migration could allow a double-spend (the same balance spent on both the source and the target shard). Quantos enforces a strict migration protocol (`reshard.rs`):

1. **Draining**: The source shard enters a `Draining` state for `IN_FLIGHT_DRAIN_MS` (5 seconds), during which it accepts no new transactions for migrating accounts but allows already-pending cross-shard transactions to complete.
2. **Account freezing**: Migrating accounts are frozen — no transactions are accepted against them — eliminating the double-spend window.
3. **2-phase commit**: State transfer requires confirmation from more than 2/3 of validators on *both* the source and target shards.
4. **Bounded transition**: `MAX_TRANSITION_SECS = 60`. If the migration does not complete within this bound, it is aborted and rolled back atomically; no partial state is ever committed.
5. **Validator redistribution**: After migration, stake-weighted rebalancing redistributes validators across shards proportional to each shard's new load.

## 9.4 Atomic Cross-Shard Transactions

A transaction that touches accounts on two different shards must either fully commit on both or commit on neither. Quantos uses a **2-phase commit protocol** secured by zk-STARK proofs (`cross_shard.rs`):

```
Source Shard                         Destination Shard
     │                                      │
     │  1. Lock funds on source             │
     │  2. Emit CrossShardTx + STARK proof  │
     │ ───────────────────────────────────▶ │
     │                                      │ 3. Verify STARK proof of lock
     │                                      │ 4. Credit funds on destination
     │  5. Confirm                          │
     │ ◀─────────────────────────────────── │
     │  6. Finalize (release lock record)   │
     │                                      │
```

Key safeguards:

- **STARK-verified authenticity**: The destination shard does not trust the source shard's message blindly; it verifies a succinct STARK proof that the funds were genuinely locked on the source shard (`enable_zk_proofs`).
- **Timeouts and rollback**: Each cross-shard transaction has a `timeout_ms` deadline and a `max_retries` bound. If the destination never confirms, the source automatically rolls back the lock, returning funds to the sender.
- **Per-sender DoS limits**: At most `MAX_PENDING_PER_SENDER = 100` outstanding cross-shard transactions per account, and a configurable `max_pending_per_shard`, prevent a single actor from saturating the cross-shard channel.

Because cross-shard transactions carry this additional commitment overhead, they are inherently more expensive than intra-shard transactions. This is the principal reason the aggregate-throughput figure in the Performance section is labelled *theoretical*: real-world throughput depends on the ratio of intra-shard to cross-shard activity.

## 9.5 Self-Healing Rebalancing

Beyond reactive split/merge, Quantos includes a **predictive** rebalancing layer (`self_healing.rs`) that aims to migrate state *before* a hotspot causes congestion:

- **Target utilisation**: The system targets `TARGET_UTILIZATION = 80%` per shard. A deviation beyond `REBALANCE_THRESHOLD = 20%` triggers rebalancing.
- **Hotspot prediction**: A lightweight predictive model uses recent per-shard load history to forecast emerging hotspots. **This predictor is an advisory optimisation only** — it influences *when* to proactively migrate, but every resulting migration still passes through the consensus-validated, 2-phase-commit re-sharding protocol of §9.3. No machine-learning output is ever part of the consensus-critical path.
- **Concurrency control**: At most `MAX_CONCURRENT_MIGRATIONS = 3` migrations run simultaneously, and a `MIN_REBALANCE_INTERVAL` of 60 seconds prevents thrashing.
- **Zero-downtime goal**: Migrations are designed to keep affected accounts available, with the design target of bounded latency increase during migration rather than service interruption.

## 9.6 STARK-Accelerated Aggregation

The `stark_accelerated` module batches the verification work for many cross-shard messages into a single succinct proof, so that a shard receiving a burst of inbound cross-shard transactions can validate them in aggregate rather than one signature at a time. This is the same commitment-based STARK philosophy used by the Layer 0 Finality Hub: heavy post-quantum signature verification is done natively, and a compact STARK attests that the batch was verified honestly.
