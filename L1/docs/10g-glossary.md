---
sidebar_position: 32
slug: /glossary
---

# 31. Glossary

**BFT (Byzantine Fault Tolerance)** — the property that a protocol remains correct even if up to `f` participants behave arbitrarily; Quantos committees tolerate `f = ⌊(n-1)/3⌋`.

**Bullshark** — a DAG-based BFT consensus protocol under partial synchrony; source of Quantos's fast-path commit rule.

**Checkpoint** — a finality anchor produced by the super-committee every `checkpoint_interval` vertices, providing deterministic, irreversible finality.

**Committee** — a small, VRF-selected set of validators (reference: 21) responsible for a shard's fast-path consensus.

**Compute Unit (CU)** — the resource-accounting unit metered by STACC; replaces gas. Quotas are stake-proportional; CU is not charged as a fee.

**Cross-shard transaction** — a transaction touching accounts on more than one shard, committed atomically via a STARK-verified 2-phase commit.

**DAG (Directed Acyclic Graph)** — the parallel structure of vertices (2–8 parents each) that replaces a linear blockchain for transaction inclusion.

**Domain separation** — prepending a context tag before hashing/signing so a signature in one context cannot be replayed in another.

**Finality (deterministic)** — irreversibility of a committed transaction once a checkpoint quorum certificate forms (~1 s within Quantos).

**GST (Global Stabilization Time)** — in the partial-synchrony model, the unknown time after which message delays are bounded; liveness holds after GST, safety always.

**HotStuff / HotStuff-2** — linear-message-complexity, rotating-leader BFT; basis of Quantos's pipelined committee consensus.

**L0 Finality Hub** — the cross-chain layer that attests Quantos finality to 12 external chains via commitment-based STARK aggregation.

**ML-DSA-65** — NIST FIPS 204 lattice signature scheme, security level 3; Quantos's universal signature primitive.

**ML-KEM-768** — NIST FIPS 203 lattice key-encapsulation mechanism (formerly Kyber-768); used for P2P handshakes and the encrypted mempool.

**MVCC (Multi-Version Concurrency Control)** — snapshot-isolation technique enabling lock-free parallel execution with commit-time conflict detection.

**Narwhal** — a DAG-based mempool with structured data availability; basis of Quantos's transaction dissemination.

**PBS (Proposer-Builder Separation)** — separating block building from proposing via a sealed-bid builder market to democratize MEV.

**PQC (Post-Quantum Cryptography)** — cryptography secure against quantum adversaries; native to Quantos at every layer.

**PQC-Guard** — a quantum-resistant smart account deployable on external chains, releasing funds via M-of-N WOTS attestations from Quantos validators.

**QN4 / QN8 / QN12** — native fungible / non-fungible / multi-token standards (ERC-20 / 721 / 1155 equivalents).

**QTS** — the native Quantos token: security collateral, bandwidth right, and governance weight.

**Quorum Certificate (QC)** — an aggregate of committee votes representing >2/3 stake, certifying a vertex or checkpoint.

**Re-sharding** — safe migration of accounts between shards, with draining, freezing, 2-phase commit, and bounded rollback.

**Slashing** — confiscation of a portion of a validator's stake for provable misbehaviour (5–10% for safety faults, 0.1%/epoch for downtime).

**STACC (Stake-Timed Access and Compute Credit)** — Quantos's zero-gas model: stake-proportional CU quotas plus state rent.

**STARK** — a succinct, transparent proof of computational integrity; used for VRF proof-of-knowledge and L0 signature-aggregation commitments.

**State rent** — per-byte-per-slot pricing of persistent storage; the sustainable, adoption-linked revenue source that lets inflation decline.

**Vertex** — a unit of the DAG bundling transactions and referencing 2–8 parents.

**VRF (Verifiable Random Function)** — Quantos's hash-based, STARK-proven function providing unpredictable, unique, verifiable randomness for committee selection.

**WOTS (Winternitz One-Time Signature)** — a hash-based one-time signature verified with keccak256; the on-chain verification primitive for PQC-Guard.
