---
sidebar_position: 14
slug: /storage
---

# 13. Storage Layer

## 13.1 RocksDB Backend

Quantos persists all chain data in **RocksDB** (`quantos/src/storage/rocks.rs`), a log-structured-merge-tree key-value store engineered for high write throughput and large datasets on NVMe SSDs — exactly the workload a high-TPS shard generates. RocksDB's column families let the node segregate different data domains (accounts, vertices, checkpoints, indices) into independently tunable stores.

## 13.2 Key Schema

A disciplined key schema (`storage/keys.rs`) maps every logical object to a unique, prefix-structured byte key. Prefixing by object type keeps related data contiguous on disk (improving iteration and range scans) and prevents key collisions between domains. Typical domains include account state, DAG vertices, checkpoints, the validator set, and shard metadata.

## 13.3 Write Path and Atomicity

State transitions are applied as **atomic batches**: all key-value mutations produced by a committed set of transactions are written in a single RocksDB write batch, so the on-disk state never reflects a half-applied block. This atomicity is what allows the re-sharding and rollback protocols elsewhere in the system to assume that storage either fully reflects a state transition or not at all.

## 13.4 Pruning and Cold Storage

Raw post-quantum signatures dominate storage growth — on the order of terabytes per day at full load. The storage layer is therefore designed for **pruning**: once a checkpoint is finalised, the historical signatures behind it are eligible for deletion, while the compact commitments needed to verify history are retained indefinitely. Idle account state is moved to cold storage by the archival-pruning subsystem and can be restored on demand with a Merkle proof. This keeps the hot working set — the data a validator must serve quickly — bounded even as total history grows without limit.

## 13.5 Snapshots and Fast Sync

To let new nodes join without replaying all history, the storage layer supports state **snapshots** consumed by the snapshot-sync subsystem. A joining node downloads a recent snapshot, verifies it against a finalised state root, and begins validating forward from there — turning what would be a full historical replay into a bounded, verifiable download.
