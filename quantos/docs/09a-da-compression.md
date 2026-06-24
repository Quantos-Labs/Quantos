---
sidebar_position: 24
slug: /data-availability
---

# 23. Data Availability & State Compression

## 23.1 The Data-Availability Problem

A validator must be able to prove that the data behind a committed state transition actually exists and is retrievable — otherwise a malicious proposer could commit to data it withholds, stalling verification. Quantos addresses this with an erasure-coded data-availability (DA) layer per shard and a suite of compression techniques that keep both bandwidth and state size bounded.

## 23.2 Erasure-Coded Availability

Each shard maintains a DA layer in which block data is **erasure-coded** into blobs. Erasure coding lets the full data be reconstructed from any sufficiently large subset of fragments, so data remains available even if some validators are offline. Cross-shard transactions (Sharding section) carry a Merkle proof of availability that the destination shard verifies *without downloading the full blob* — it checks that the data is committed and retrievable, deferring the actual fetch until needed. Large payloads travel as **blob transactions** (Mempool section) through this layer rather than inline in vertices.

## 23.3 Transaction Batching and Compression

The batching and compression layers (`quantos/src/batching/`, `quantos/src/compression/`) reduce the bytes that must be propagated and stored. Transactions are grouped into batches for amortised verification and propagation, and payloads are compressed before storage. Combined with the two-tier signature aggregation (Cryptographic Primitives section), which shrinks committee signatures from megabytes to ~130 bytes, these layers attack the dominant bandwidth and storage costs of a post-quantum chain directly.

## 23.4 Quantum-Resistant State Compression (QRSC)

The state-compression engine (`state/compression.rs`) applies several techniques specific to a PQC blockchain:

- **Temporal signature aggregation** — aggregating signatures across *time windows* (epochs), not only across signers in one block, exploiting redundancy in a validator's repeated participation.
- **Semantic state-diff encoding** — compressing state transitions by encoding their semantic delta rather than raw before/after bytes.
- **Quantum-resistant Merkle Mountain Range (QR-MMR)** — an append-friendly accumulator with hash-based (and lattice) commitments for compact, quantum-safe history proofs.
- **Incremental compression** — compression runs continuously without stop-the-world pauses, so it does not interrupt block production.

The design targets a **70–80% reduction in state size** and roughly **10× faster initial sync**, at under ~5% CPU overhead, while remaining backward-compatible with uncompressed state. (This subsystem is marked patent-pending in the source.)

## 23.5 Snapshot Sync and Pruning

Compression dovetails with the storage layer: compact snapshots feed snapshot-sync so new nodes join quickly (Storage section), and archival pruning plus state rent (State Model section) bound the live working set. The net effect is that a validator's *hot* data — what it must serve at consensus speed — stays small even as the chain's *total* history grows without limit.
