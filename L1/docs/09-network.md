---
sidebar_position: 23
---

# 22. Network Layer

## 22.1 P2P Communication

The networking stack (`quantos/src/network/`) is built on libp2p. Validator P2P uses **ML-KEM-768** (FIPS 203) for key encapsulation during the handshake, followed by **ChaCha20-Poly1305** for the authenticated session cipher. This provides post-quantum confidentiality and integrity for all consensus traffic: even an adversary recording traffic today cannot decrypt it once quantum computers arrive ("harvest now, decrypt later" is defeated at the transport layer).

## 22.2 Gossip Propagation

Transactions, DAG vertices, votes, and checkpoints propagate through a gossip layer (`gossip.rs`) tuned for low-latency dissemination. Messages are content-addressed by hash so that duplicates are suppressed and a node never forwards the same vertex twice. Because the DAG admits multiple parents per vertex, gossip does not need a single global ordering to make progress — vertices flow as soon as their parents are available.

## 22.3 Chain Synchronization

A joining or lagging node uses the sync subsystem (`sync.rs`) to catch up. Rather than replaying every historical signature, a node syncs to the latest finalized checkpoint and then streams DAG vertices forward from there. Finalized checkpoints act as trust anchors (weak subjectivity): a node that knows a recent finalized checkpoint can validate everything after it without trusting any individual peer.

## 22.4 Data Availability

Each shard maintains a data-availability layer using erasure-coded blobs. Cross-shard transactions (Dynamic Sharding section) include a Merkle proof of availability that the target shard can verify without downloading the full blob, so a shard can confirm that the data backing an inbound message exists and is retrievable without bearing the full bandwidth cost of fetching it.

## 22.5 Network-Layer Defences

The network is hardened against topology-level attacks by the security subsystem (Security Model section): peer diversity across ASNs and geographies, anchor peers, and connection-validity checks defend against eclipse attacks; rate limiting and proof-of-work admission defend against DoS; and NTP-based time synchronization with outlier filtering defends against time-warp attacks. These are described in the Security Model.
