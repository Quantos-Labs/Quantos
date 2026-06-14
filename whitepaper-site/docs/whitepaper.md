---
id: whitepaper
title: Quantos Technical Whitepaper
slug: /
---

# Quantos Technical Whitepaper

**Post-Quantum Layer 1 Blockchain with Zero-Gas Execution and Cryptographic Cross-Chain Finality**

*Version 1.3 — June 2026*

## Abstract

Quantos is a next-generation Layer 1 blockchain designed from the ground up for the post-quantum era. Unlike existing chains that retrofit quantum resistance as an afterthought, Quantos embeds NIST-standardized post-quantum cryptography (PQC) at every layer: consensus, execution, storage, and interoperability. The protocol introduces a 3-layer QuantumDAG consensus mechanism capable of processing millions of transactions per second through dynamic sharding, a zero-gas execution model called STACC, and a Layer 0 Finality Hub providing quantum-resistant cross-chain verification for 12 external blockchain networks.

**Version 1.1 additions**: The L0 Finality Hub now includes ZK-STARK batch verification of PQC signatures using the Winterfell library, reducing the on-chain proof footprint from N × 666–3,293 bytes to a single 32-byte commitment. Additional security improvements include canonical chain continuity enforcement via `parent_block_hash` and `chain_work` binding in the proof digest, real-time equivocation detection with slashable offenders tracking, and a `RelayPool` for multi-relay quorum aggregation.

**Version 1.3 additions**: PQC-Guard is now a production multi-VM smart-account system deployed across seven blockchain runtime families: EVM (Ethereum, Base, Arbitrum, Optimism, Polygon, Avalanche, BSC), TVM/Tron, Solana (Anchor), Sui (Move 2024), Aptos (Move), NEAR (Rust/WASM), and Stellar (Soroban). A canonical binary serializer (MULTIVM_SPEC.md §4) has been added to the TypeScript SDK to generate and parse cross-chain attestation blobs. All seven VM ports are covered by native unit test suites (43 tests across 6 test runners), verifying WOTS signing, M-of-N quorum, non-member rejection, and wrong-digest rejection on each runtime.

**Version 1.2 additions**: Six production security upgrades shipped across the L0 Rust core and the L0 TypeScript SDK: (1) **Tezos dedicated `ChainFamily`** — `ChainFamily::Tezos` replaces the `Custom` fallback, enabling first-class routing and registry entries for Tezos mainnet and Ghostnet. (2) **Bitcoin full SPV Merkle proof** — `ChainProof::Bitcoin` now carries `tx_hash` and `tx_index`, and the `BitcoinLightClient` verifies the complete leaf-to-root Merkle path against the `merkle_root` field in the 80-byte header, providing true transaction-inclusion proofs rather than block-only attestation. (3) **`EpochWatcher` — automatic validator set updates** — a background tokio service polls chain-specific RPC endpoints (Cosmos REST, Solana `getVoteAccounts`, NEAR `validators`, Aptos v1 REST, TON, Tron, Polkadot SCALE, Stellar Horizon, Tezos baker rights, Cardano db-sync) and calls `ValidatorSetRegistry::insert()` on change. Because the registry uses `Arc<RwLock<…>>` internally, all live `LightClient` instances see the new set immediately without restart. (4) **`PQCGuard.sol` and `PQCGatedProxy`** — abstract Solidity contract providing a `pqcRequired(actionHash)` modifier that any dApp can inherit to gate state-changing functions behind Falcon-512 confirmation; `PQCGatedProxy` wraps existing contracts without code changes. (5) **Commit-reveal Falcon key registration** — a mandatory two-step registration (`commitPqcKey` → wait 100 blocks (~20 min) → `registerPqcKey`) creates an on-chain observation window; if an attacker with a stolen ECDSA key commits a malicious Falcon key, the legitimate user sees the `PqcKeyCommitted` event and calls `cancelCommitment()` to abort. (6) **`EncryptedKeyVault`** — browser-native AES-256-GCM + PBKDF2 vault for the Falcon secret key, encrypted with a PIN that is entirely separate from the ECDSA seed phrase; stealing the seed phrase does not expose the Falcon private key.

## 1. Introduction

### 1.1 The Quantum Threat

Virtually all existing blockchains rely on elliptic curve cryptography (ECC): secp256k1 (Bitcoin, Ethereum), Curve25519 (Solana, Cardano). Shor's algorithm solves the discrete logarithm problem in polynomial time on a quantum computer, rendering ECDSA and Ed25519 completely insecure.

### 1.2 Why Retrofitting Fails

1. **Soft-forking** requires overwhelming consensus and invalidates all existing infrastructure.
2. **Hybrid signatures** double overhead while the classical component remains vulnerable.
3. **Address migration** fails to protect transaction history and smart contract state.

Quantos takes the only robust approach: designing the entire protocol around PQC from genesis.

### 1.3 Design Principles

- **Quantum-First Security**: Every consensus message, transaction, and cross-chain proof uses NIST-standardized PQC.
- **Massive Parallelization**: Horizontal scaling through dynamic sharding and DAG-based inclusion.
- **Zero-Gas Execution**: STACC replaces per-transaction fees with stake-proportional bandwidth quotas.
- **Cryptographic Interoperability**: Native light client proofs wrapped in PQC attestations.
- **Deterministic Finality**: Irreversible finality in ~1 second.
- **Succinct Cross-Chain Proofs**: ZK-STARK batch verification compresses N PQC validator signatures to a 32-byte on-chain commitment.

## 2. Post-Quantum Cryptography

### 2.1 Cryptographic Primitives

Quantos uses four NIST-standardized post-quantum algorithms, each selected for a specific operational context based on signature size, verification speed, and security level.

#### 2.1.1 Dilithium-3

Dilithium-3 is a lattice-based digital signature scheme built on the Module Learning With Errors (MLWE) problem. It provides NIST Level 3 security, meaning it resists attacks from both classical and quantum computers with complexity comparable to AES-192.

- **Public key size**: 1,952 bytes
- **Secret key size**: 4,032 bytes
- **Signature size**: 3,293 bytes
- **Key generation**: ~200 microseconds
- **Signing**: ~150 microseconds
- **Verification**: ~50 microseconds

**Usage in Quantos**: Transaction signatures, validator attestations, committee votes, cross-shard atomic protocol messages. Every transaction submitted to the network must include a Dilithium-3 signature from the sender's account keypair.

#### 2.1.2 SPHINCS+-128f

SPHINCS+ is a stateless hash-based signature scheme. Its security reduces entirely to the collision resistance of the underlying hash function (SHA-256), providing a fundamentally different security assumption than lattice-based schemes.

- **Public key size**: 32 bytes
- **Secret key size**: 64 bytes
- **Signature size**: 17,088 bytes (fast variant)
- **Key generation**: ~1 millisecond
- **Signing**: ~5 milliseconds
- **Verification**: ~1 millisecond

**Usage in Quantos**: Verifiable Random Function (VRF) for committee selection and epoch randomness generation. The stateless property is critical because validators cannot maintain state between epochs.

#### 2.1.3 Falcon-512

Falcon-512 is a lattice-based signature scheme built on the NTRU problem. Its defining characteristic is the exceptionally small signature size among post-quantum algorithms.

- **Public key size**: 897 bytes
- **Secret key size**: 1,281 bytes
- **Signature size**: 666 bytes
- **Key generation**: ~5 milliseconds
- **Signing**: ~200 microseconds
- **Verification**: ~50 microseconds

**Usage in Quantos**: Checkpoint finality signatures and Layer 0 cross-chain attestations. The small signature size is essential because these proofs must be stored on-chain and verified by smart contracts on external chains.

#### 2.1.4 Kyber-768

Kyber-768 is a lattice-based Key Encapsulation Mechanism (KEM) providing IND-CCA2 security under the Module Learning With Errors assumption.

- **Public key size**: 1,184 bytes
- **Secret key size**: 2,400 bytes
- **Ciphertext size**: 1,088 bytes
- **Shared secret size**: 32 bytes

**Usage in Quantos**: Encrypted mempool transactions. Before inclusion in the DAG, sensitive transaction content is encrypted under the validator committee's ephemeral Kyber public key, preventing front-running.

### 2.2 Adaptive PQC Algorithm Selection (APAS)

Different protocol operations have different requirements for signature size, verification speed, and security level. Quantos implements Adaptive PQC Algorithm Selection (APAS):

| Operation | Algorithm | Signature Size | Security Level |
|-----------|-----------|---------------|----------------|
| Transaction signature | Dilithium-3 | 3,293 bytes | NIST Level 3 |
| Committee VRF | SPHINCS+-128f | 17,088 bytes | NIST Level 1 |
| Checkpoint finality | Falcon-512 | 666 bytes | NIST Level 1 |
| Cross-chain attestation | Falcon-512 | 666 bytes | NIST Level 1 |
| Encrypted mempool | Kyber-768 | 1,088 bytes ciphertext | NIST Level 3 |

### 2.3 Signature Aggregation

For committee votes, 14 signatures from a 21-member committee (2/3 threshold) are aggregated. Naive verification would require 14 × 3,293 = 46,102 bytes of signature data. Batch verification reduces the effective per-signature overhead by approximately 60%.

**L0 Cross-Chain Aggregation**: Falcon-512 and Dilithium-3 signatures do not support native algebraic aggregation (unlike BLS12-381). For the Layer 0 Finality Hub, Quantos uses ZK-STARK commitment-based aggregation: individual PQC signatures are verified natively in Rust, then their per-signer commitments `SHA3-256(pubkey ‖ message ‖ sig)` are embedded in a Winterfell STARK execution trace. A single STARK proof — compressed to a 32-byte commitment on-chain — attests that all N signatures are valid and that their cumulative stake exceeds the finality threshold. This approach is compatible with any PQC scheme regardless of mathematical structure.

### 2.4 Key Hierarchy

Quantos validators maintain three distinct keypairs:

**Signing Key (Dilithium-3)**: Used for transaction signing, committee votes, and attestations. Rotated every 24 hours.

**VRF Key (SPHINCS+)**: Used for verifiable random function output generation during committee selection.

**Finality Key (Falcon-512)**: Used for checkpoint finality signatures and L0 cross-chain attestations.

Account holders use a single Dilithium-3 keypair for transaction signing. Addresses are derived as the 32-byte BLAKE3 hash of the public key.

## 3. QuantumDAG Consensus

### 3.1 Architecture Overview

Quantos employs a 3-layer hybrid consensus mechanism called QuantumDAG. Unlike traditional blockchains that process transactions sequentially within discrete blocks, QuantumDAG uses a Directed Acyclic Graph (DAG) structure for transaction inclusion, organizes validators into dynamically rotating committees for distributed agreement, and produces deterministic finality checkpoints.

**Layer 3: Finality Anchor**
- Falcon-512 checkpoints, deterministic finality
- Super-committee of 100 validators
- Checkpoint interval: ~1 second

**Layer 2: Quantum Committees**
- 1,000 committees x 21 validators = 21,000 total validators
- VRF rotation using SPHINCS+ every 100ms
- Dilithium-3 aggregated signatures (14/21 threshold)

**Layer 1: Fast Path (DAG)**
- Parallel transaction inclusion without sequential blocks
- 2-8 parent references per vertex for high throughput
- Optimistic execution with &lt;0.1% rollback rate

### 3.2 Layer 1: Fast Path (DAG)

The Fast Path is a Directed Acyclic Graph where each vertex contains a set of transactions and references 2 to 8 parent vertices. When a validator observes transactions in the mempool, it packages them into a vertex, signs the vertex hash with Dilithium-3, and gossips it to peers via QUIC.

The DAG ensures that if a transaction appears in any vertex, it is implicitly referenced by all descendant vertices. This creates a partial ordering without requiring a global block proposer. Conflicts are resolved at Layer 2 by committee vote.

### 3.3 Layer 2: Quantum Committees

Validators are organized into 1,000 committees, each responsible for a subset of shards. Committee assignment is randomized every epoch using a Threshold QR-VRF that requires 2/3 + 1 of the total validator set to contribute partial proofs before the randomness is revealed.

Each committee has the following properties:

- **21 validators** per committee at genesis, scaling to 63 at maximum deployment
- **14/21 quorum threshold** (2/3 + 1) for vote aggregation
- **100ms epoch duration** for fast committee rotation
- **Dilithium-3 signatures** for all committee votes and attestations

The CommitteeManager maintains the active validator set, tracks stake-weighted voting power, and deterministically computes committee composition from epoch randomness. Rotation is protocol-deterministic: there is no privileged rotator address that can bias committee assignment.

### 3.4 Layer 3: Finality Anchor

The Finality Layer produces deterministic checkpoints every ~1 second (1,000 DAG vertices). A super-committee of 100 validators is selected from the full set using the same VRF randomness. Each checkpoint includes:

- The hash of the DAG tip vertex
- A Merkle root of all transactions since the last checkpoint
- Aggregated committee signatures from Layer 2
- A Falcon-512 finality signature from each member of the super-committee

Once a checkpoint accumulates 67 Falcon-512 signatures (2/3 + 1), it is considered finalized. Reversing a finalized checkpoint would require forging Falcon-512 signatures from 67 distinct validators.

### 3.5 Consensus Phases

| Phase | Duration | Action | Cryptography |
|-------|----------|--------|--------------|
| Inclusion | 0-10ms | TX signed with Dilithium-3, propagated via QUIC | Dilithium-3 |
| Pre-consensus | 10-50ms | Committee votes with 14/21 threshold | Dilithium-3 batch |
| Ordering | 50-100ms | Topological sort of DAG, conflict resolution | Deterministic |
| Finality | ~1s | Checkpoint with Falcon-512 signatures | Falcon-512 |

### 3.6 Slashing and Accountability

The Slashing module enforces protocol penalties for Byzantine behavior. All violations are cryptographically attributable:

- **Double signing**: A validator that produces conflicting checkpoints or vertices is automatically slashed. The evidence consists of two valid Dilithium-3 signatures on contradictory data, which is irrefutable proof of malice.
- **Downtime**: Validators that miss 50% of their committee votes over a 24-hour period are subject to gradual stake reduction.
- **Invalid proposals**: Committee members that propose vertices containing invalid transactions lose their epoch rewards and may be ejected from the active set.

Slashing conditions are evaluated by any node that observes contradictory behavior; there is no privileged whistleblower role.

## 4. STACC: Zero-Gas Execution

### 4.1 The Gas Problem

Per-transaction gas fees create fundamental inefficiencies in blockchain systems: unpredictable costs discourage user adoption, gas price auctions extract value through MEV, and fee markets favor high-frequency traders over retail users. Quantos eliminates gas entirely through a stake-proportional bandwidth allocation mechanism called STACC (Stake-Timed Access and Compute Credit).

### 4.2 Core Mechanism

Instead of paying per transaction, users activate their account by depositing QTEST tokens into a smart contract. This activation grants them a renewable bandwidth quota proportional to their stake, which is consumed by transactions and replenished over time.

The quota system has three components:

1. **Base Quota**: Determined by the user's stake tier (Basic, Builder, Enterprise)
2. **Stake-Proportional Bonus**: Additional quota from the logarithmic pool based on the user's share of total activated stake
3. **Loyalty Multiplier**: A factor from 1.0x to 3.0x based on continuous activation duration

### 4.3 Tier System

| Tier | Minimum Stake | Base Quota | Burst Limit | Max CU/TX |
|------|--------------|------------|-------------|-----------|
| Basic | 1,000 QTEST | 10,000 CU/hr | 50,000 CU | 10,000 CU |
| Builder | 10,000 QTEST | 30,000 CU/hr | 150,000 CU | 100,000 CU |
| Enterprise | 100,000 QTEST | 100,000 CU/hr | 500,000 CU | 1,000,000 CU |

Quota is replenished continuously at the hourly rate. The burst limit allows temporary spikes in consumption. If a user exceeds their burst limit, subsequent transactions are delayed until the next replenishment cycle.

### 4.4 Compute Unit (CU) Pricing

Each operation consumes a fixed number of Compute Units:

- **Simple transfer**: 210 CU
- **Contract call (empty)**: 2,100 CU
- **Contract deployment**: 32,000 CU
- **Storage read**: 200 CU per 32-byte word
- **Storage write**: 5,000 CU per 32-byte word
- **Cross-shard message**: 10,000 CU base + target shard CU

These values are calibrated to reflect actual computational cost while remaining predictable for developers.

### 4.5 Economic Properties

- **No MEV extraction**: Because there are no gas fees, there is no gas price to manipulate.
- **Predictable costs**: A user with 10,000 QTEST staked knows they can execute approximately 142 simple transfers per hour (30,000 / 210) without any additional cost.
- **Spam resistance**: Low-value accounts have limited quota, making Sybil attacks economically impractical.
- **Fairness**: All users in the same tier pay the same effective rate per CU, regardless of network congestion.

## 5. Dynamic Sharding

### 5.1 Shard Architecture

Quantos partitions state into shards using deterministic account assignment. Each shard is managed by a subset of committees from Layer 2, ensuring that no single committee controls multiple shards simultaneously. The number of shards is dynamic, scaling from 100 at genesis to 10,000 at full deployment based on measured network load.

Shard assignment uses the first 2 bytes of the account address as the shard index. This provides uniform distribution because BLAKE3 produces uniformly random output. Cross-shard transactions are automatically detected by comparing sender and recipient shard indices.

### 5.2 Cross-Shard Atomic Protocol (CSAP)

Cross-shard transactions use a two-phase commit protocol with zk-STARK proofs for state transition validation. The protocol ensures atomicity: either all state changes in all affected shards are applied, or none are.

**Phase 1: Prepare**
- The originating shard locks the sender's balance and creates a Prepare message signed with Dilithium-3.
- The Prepare message includes a Merkle proof of the sender's state and the intended state transition.

**Phase 2: Commit**
- Target shards validate the Merkle proof and apply the state transition.
- A Commit message is broadcast to all affected shards.
- If any shard rejects the transition, all shards roll back to the pre-transaction state.

### 5.3 zk-STARK Cross-Shard Proofs

State transition proofs between shards use zk-STARKs (Scalable Transparent Arguments of Knowledge) to verify that the transition was executed correctly without revealing the full state. A proof for 1,000 cross-shard transitions is approximately 150 KB, verified in under 100 milliseconds.

Unlike SNARKs, STARKs do not require a trusted setup. The only cryptographic assumption is the collision resistance of the hash function used for the Merkle tree (BLAKE3), making them naturally post-quantum secure.

### 5.4 Auto-Scaling

The network monitors the average queue depth per shard. When the median queue exceeds 80% capacity for 10 consecutive minutes, the network initiates a shard split, dividing one shard into two and rebalancing accounts. Conversely, when two adjacent shards both fall below 20% capacity for 30 minutes, they may merge.

Shard splits and merges are coordinated through the finality layer to ensure all validators agree on the new shard mapping before it takes effect.

| Shards | Total TPS | Validators per Shard |
|--------|-----------|---------------------|
| 100 | 2.5M | 210 |
| 1,000 | 25M | 21 |
| 10,000 | 250M | 2-3 |

## 6. QuantosVM

### 6.1 Architecture

QuantosVM is a multi-engine execution environment designed to support both native WASM contracts and legacy EVM bytecode.

**Primary Engine**: Wasmer WASM runtime with AES-256-GCM encrypted bytecode. Contracts are compiled to WASM, encrypted at rest, and decrypted only during execution inside a secure sandbox.

**EVM Compatible Engine**: revm integration for Solidity contracts. EVM bytecode is translated to an internal representation and executed with the same gas metering (CU consumption) as native WASM contracts.

**Solang Compiler**: Native Solidity-to-WASM compiler that allows developers to write Solidity and deploy as optimized WASM without manual porting.

### 6.2 Execution Model

The runtime uses Software Transactional Memory (STM) for parallel contract execution. Multiple transactions targeting different state regions execute simultaneously, with automatic conflict detection and rollback. The measured rollback rate is below 0.1% under normal load, indicating that most transactions do not conflict.

Each execution context has the following limits:

| Parameter | Default Value |
|-----------|--------------|
| Maximum memory pages | 1,024 (64 MB) |
| Maximum stack size | 1 MB |
| Maximum compute units | 100,000,000 |
| Maximum call depth | 1,024 |

### 6.3 Host Functions

Contracts interact with the blockchain through a defined set of host functions:

- `storage_read(key) -> value`: Read from contract storage
- `storage_write(key, value)`: Write to contract storage
- `caller() -> address`: Get the address that called this contract
- `block_timestamp() -> u64`: Get the current block timestamp
- `block_height() -> u64`: Get the current block height
- `log(topic, data)`: Emit a log event
- `transfer(to, amount)`: Transfer native tokens
- `cross_contract_call(to, input, cu_limit) -> result`: Call another contract

All host functions consume CU proportionally to their computational cost and are metered to prevent infinite loops or resource exhaustion.

### 6.4 Bytecode Encryption

Contract bytecode is encrypted at rest using AES-256-GCM with a key derived from the contract address and a protocol-wide master key. This prevents unauthorized inspection of proprietary contract logic while still allowing the network to verify that the bytecode has not been tampered with (via a Merkle root commitment at deployment time).

## 7. Encrypted Mempool and MEV Protection

### 7.1 The MEV Problem

Maximal Extractable Value (MEV) arises when validators or relay operators can observe pending transactions and reorder, insert, or censor them for profit. This includes front-running, back-running, and sandwich attacks. MEV extraction has extracted billions of dollars from users across major blockchains.

### 7.2 Kyber-Encrypted Mempool

Quantos addresses MEV at the protocol level through an encrypted mempool. Before submitting a transaction to the network, the sender encrypts the transaction content using Kyber-768 key encapsulation.

**Encryption Process:**
1. The sender obtains the current committee's ephemeral Kyber public key, distributed at the start of each epoch.
2. The sender generates a random AES-256-GCM key, encrypts the transaction payload, and encapsulates the AES key under the Kyber public key.
3. The encrypted transaction is submitted to the mempool. Validators see only ciphertext until the committee decrypts it at execution time.

**Decryption Process:**
1. When the committee produces a vertex, members use their Kyber secret keys (distributed via threshold secret sharing) to collaboratively decrypt the AES key.
2. Only after decryption can the transaction content be executed.
3. Because decryption occurs after transaction ordering is fixed by the DAG topology, no validator can reorder based on transaction content.

### 7.3 Fair Ordering

Even within the encrypted mempool, Quantos implements a Weighted Fair Queue (WFQ) mechanism that orders transactions based on:

1. **Timestamp**: Transactions are ordered by arrival time at the first honest validator.
2. **Tier priority**: Enterprise tier transactions receive a 20% priority boost.
3. **Loyalty factor**: Long-activated accounts receive incremental priority.

This ordering is deterministic and verifiable, eliminating the ability of any single validator to manipulate transaction order for MEV extraction.

## 8. Layer 0 Finality Hub

### 8.1 The Interoperability Problem

Cross-chain bridges today rely on one of three trust models, none of which provide post-quantum security:

1. **Multi-sig committees**: A small set of validators (often 5-13) holds custody of bridged assets. These validators use ECDSA signatures that are vulnerable to quantum computers.

2. **Optimistic rollups**: Transactions are assumed valid unless challenged within a dispute window. This introduces latency and assumes honest challengers exist.

3. **RPC verification**: Light clients query full nodes via RPC, trusting the node operator. This is not verification at all.

### 8.2 Quantos L0 Solution

Quantos acts as a post-quantum finality layer. Rather than trusting external chains, Quantos validators verify external chain finality through native light client proofs, then produce a quantum-resistant attestation that can be verified by any other chain.

**The Verification Flow:**

1. **Relayer monitors** a chain and fetches cryptographic proof (block header, validator signatures, state root).

2. Relayer submits `ExternalCheckpoint` + structured `ChainProof` to Quantos L0.

3. **Light Client Registry** verifies the proof cryptographically using the chain's native verification algorithm. No RPC calls, no trust assumptions.

4. Quantos validators each submit a PQC signature (Falcon-512 or Dilithium-3) over the proof digest.

5. Once quorum stake is reached, a **ZK-STARK batch proof** aggregates all signatures into a single 32-byte `stark_commitment` embedded in the `L0ProofHeader`.

6. The `L0FinalityProof` (with embedded `stark_commitment`) is relayed to any chain for on-chain verification.

### 8.3 ZK-STARK Batch Verification

Full verification of N PQC signatures on-chain is intractable due to lattice arithmetic: a single Falcon-512 or Dilithium-3 signature verification requires O(1,000) polynomial operations. Quantos implements a **commitment-based STARK aggregation** scheme that preserves security without on-chain lattice arithmetic.

#### 8.3.1 Circuit Design

The STARK circuit uses a 7-column execution trace with `n = (N+1).next_power_of_two()` rows:

| Column | Name | Meaning |
|--------|------|---------|
| 0 | `is_signer` | 1 if this validator signed, 0 otherwise |
| 1 | `stake` | Validator stake weight (u128) |
| 2–5 | `sig_c0..c3` | `SHA3-256(pubkey ‖ message ‖ sig)` in four 64-bit limbs |
| 6 | `acc_stake` | Accumulated signed stake before this row |

**Transition constraints** (evaluated over each row transition):
```
C0: is_signer[i] × (1 - is_signer[i]) = 0          (boolean)
C1: acc_stake[i+1] - (acc_stake[i] + is_signer[i] × stake[i]) = 0  (accumulator)
```

**Boundary assertions**:
```
acc_stake[0] = 0
acc_stake[last] = signed_stake  (public input)
```

A prover cannot produce a valid proof with an inflated `signed_stake` without finding a SHA3-256 pre-image — a problem with 2^256 classical and 2^128 quantum hardness.

#### 8.3.2 Proof Parameters

| Parameter | Value | Rationale |
|-----------|-------|----------|
| Queries | 28 | ~96-bit conjectured security |
| Blowup factor | 8 | FRI proximity gap |
| Grinding bits | 16 | Grinder resistance |
| Field extension | None | F128 base field |
| FRI folding factor | 8 | Proof size / speed tradeoff |
| Hash function | BLAKE3 (256-bit) | Quantum-safe commitment |
| Proof generation | < 500 ms | Winterfell, native Rust |
| Proof verification (off-chain) | < 10 ms | |

#### 8.3.3 On-Chain Commitment Model

The `QuantosStarkVerifier` smart contract stores only a 32-byte commitment:

```
stark_commitment = SHA3-256(proof_bytes ‖ validator_set_root ‖ message_hash ‖ signed_stake ‖ stake_threshold)
```

Authorized prover nodes (Quantos validators) call `submitCommitment()` after running the full Winterfell verification off-chain. Any observer can call:
- `verifyCommitment(bytes32)` → confirms stake ≥ threshold
- `verifyPublicInputs(bytes32, ...)` → cross-checks exact public inputs
- `commitmentForProof(bytes32)` → looks up commitment by `L0FinalityProof` hash

**On-chain footprint comparison (10 validators):**

| Method | Bytes | Gas equivalent |
|--------|-------|----------------|
| Raw Falcon-512 signatures | 6,660 B | ~200,000 gas |
| Raw Dilithium-3 signatures | 32,930 B | ~1,000,000 gas |
| **ZK-STARK commitment** | **32 B** | **~3,000 gas** |

### 8.4 Chain Continuity and Replay Protection

Every `L0FinalityProof` header includes two fork-choice fields that are cryptographically bound in the signing digest:

**`parent_block_hash`** (32 bytes): Hash of the block preceding the verified checkpoint. The `FinalityHub` maintains a `last_block_by_chain` mapping. A submitted `ExternalCheckpoint` is rejected if its `parent_block_hash` does not match the last accepted block for that chain, preventing:
- Non-contiguous checkpoint submissions
- Forks being silently accepted without detection

**`chain_work`** (u128): Cumulative PoW difficulty or PoS justification weight. The Hub enforces a strict monotonicity rule: any checkpoint whose `chain_work ≤ previous.chain_work` is rejected, implementing the heaviest-chain fork-choice rule in a chain-agnostic way.

Both fields are included in `signing_digest()` and in the on-chain STARK commitment, making them unforgeable post-signing.

### 8.5 Equivocation Detection and Slashing

The `FinalityHub` maintains an `EquivocationTracker` that records:
```
(validator_address, chain_id:block_number) → block_hash
```

If a validator signs two different `block_hash` values for the same `(chain, epoch)` pair, they are:
1. Added to an on-chain `offenders` list
2. Immediately excluded from subsequent quorum accumulation
3. Made slashable by any submitting node that presents the two contradictory signatures as evidence

This makes long-range finality equivocation cryptographically attributable with Falcon-512 / Dilithium-3 proofs — unlike classical ECDSA systems where equivocation evidence can be manipulated.

### 8.6 Relay Pool

A `RelayPool` class in the L0 SDK coordinates N independent relayer nodes:
- Each relayer independently fetches the `ExternalCheckpoint` and its own validator signature
- Contributions are aggregated in memory until the quorum threshold is met
- Only one canonical `L0FinalityProof` transaction is submitted to the destination chain
- If a relay node goes offline, others continue accumulation — no single point of failure

This architecture prevents duplicate finalization transactions and ensures the quorum is always verified server-side before any on-chain submission.

### 8.7 Supported Chains

| Chain | Type | Verification Method | Signature Algorithm |
|-------|------|---------------------|---------------------|
| Ethereum & all EVM chains | EVM | Keccak-256 block header + RLP | secp256k1 ECDSA |
| Bitcoin | UTXO | Double SHA-256 header hash + confirmation depth + **SPV Merkle tx inclusion** | ECDSA |
| Solana | SVM | Ed25519 vote signatures | Ed25519 |
| Aptos/Sui | Move | BLS12-381 validator signatures | BLS12-381 |
| NEAR | Nightshade | Ed25519 block producer signatures | Ed25519 |
| Cosmos | Tendermint | Ed25519 precommit signatures | Ed25519 |
| Cardano | Ouroboros | Ed25519 pool operator signatures | Ed25519 |
| TON | TVM | Ed25519 validator signatures | Ed25519 |
| Tron | TVM | ECDSA (secp256k1) producer signatures | ECDSA |
| Polkadot | Substrate | Ed25519 GRANDPA vote signatures | Ed25519 |
| Stellar | SCP | Ed25519 node signatures | Ed25519 |
| Tezos | Michelson | Ed25519 baker signatures (`ChainFamily::Tezos`) | Ed25519 |

**Bitcoin SPV Merkle Proof**: The Bitcoin `ChainProof` struct carries an optional `tx_hash: Option<[u8;32]>`, `tx_index: Option<u32>`, and `tx_merkle_proof: Option<Vec<[u8;32]>>` (sibling hashes leaf-to-root). When present, the `BitcoinLightClient` verifies the Merkle path by iteratively hashing `double_sha256(left ‖ right)` at each level (left/right determined by `tx_index` bits) and comparing the computed root against bytes `[36..68]` of the block header. Omitting `tx_hash` skips the Merkle check and retains the previous block-only attestation behaviour, ensuring backwards compatibility.

**Tezos dedicated routing**: Prior to v1.2, Tezos was routed through `ChainFamily::Custom`, causing it to share the generic proof path with any future unknown chain. `ChainFamily::Tezos` is now a first-class enum variant in both `registry.rs` and `external.rs`, with dedicated entries in `default_adapters()` and an explicit assertion in `TezosLightClient::new()`.

**EVM Generic Support**: The EVM family uses a single unified light client verifier. Any chain implementing the Ethereum block header format (Keccak-256 RLP + secp256k1 ECDSA) is supported without code changes, including L1s (Ethereum, BSC, Avalanche) and L2s (Base, Arbitrum, Optimism, Polygon). New EVM chains are onboarded by configuration only.

**Critical distinction**: Every chain uses native cryptographic verification without RPC fallbacks or trust submitter paths. The verification libraries used include ed25519-dalek for Ed25519, blst for BLS12-381, and k256 for ECDSA secp256k1.

The `ChainProof` enum additionally supports a `Generic` variant for custom or future chains, with raw proof bytes, signer pubkeys, and signatures — enabling new chain families to be onboarded without a protocol upgrade.

### 8.8 EpochWatcher — Automatic Validator Set Updates

Chains secured by proof-of-stake rotate their validator sets at every epoch. Without automatic updates, L0 light clients would verify against stale public keys and reject valid checkpoints when a chain advances to a new epoch.

`EpochWatcher` is a background tokio task that resolves this transparently:

**Architecture:**
1. Operator registers per-chain configurations: `ChainWatcherConfig { chain_id, rpc_url, poll_interval_ms, threshold_bps }`
2. Worker tasks poll each chain on its interval using chain-specific fetchers
3. When the fetched validator set differs from the cached one, `ValidatorSetRegistry::insert()` is called
4. All live `LightClient` instances hold a shallow clone of the same `Arc<RwLock<HashMap>>` — they see the update instantly with zero restarts

**Chain-specific fetchers:**

| Chain | Endpoint | Key Format |
|-------|----------|------------|
| Cosmos | `GET /cosmos/staking/v1beta1/validators` | Base64 Ed25519 |
| Solana | `POST getVoteAccounts` | Base58 Ed25519 |
| NEAR | `POST validators(null)` | `ed25519:<base58>` |
| Aptos/Sui | `GET /v1/accounts/0x1/resource/0x1::stake::ValidatorSet` | Hex BLS/Ed25519 |
| TON | `GET /api/v2/getValidators` | Hex Ed25519 |
| Tron | `GET /wallet/listwitnesses` | Base58Check address |
| Polkadot | `POST state_call session_validators` | SCALE `Vec<AccountId32>` |
| Stellar | `GET /quorum` (Horizon) | Base32 G-address → Ed25519 |
| Tezos | `GET /baking_rights` + `/delegates/{addr}/consensus_key` | `edpk…` base58check → Ed25519 |
| Cardano | `GET /epochs/latest/stake_distribution` | Bech32 `pool1…` payload |

**Usage:**
```rust
let watcher = EpochWatcher::new(light_client_registry.validator_registry.clone());
watcher.watch(ChainWatcherConfig::new(ChainId::Cosmos, "https://rpc.cosmos.network")
    .with_interval(30_000).with_threshold(6667));
tokio::spawn(watcher.run());
```

### 8.9 PQC Key Migration Security

Two vulnerabilities existed in the v1.1 hybrid migration model that v1.2 addresses at both the contract and SDK layers.

#### 8.9.1 Forced dApp Migration — `PQCGuard.sol`

Without enforcement, dApps that do not explicitly check `pqcSecured[actionHash]` remain exposed even when the registry is deployed and users are registered. `PQCGuard` resolves this by making PQC verification a compiler-enforced Solidity modifier:

```solidity
contract MyDeFiVault is PQCGuard {
    constructor(address registry) PQCGuard(registry) {}

    function withdraw(uint256 amount, bytes32 actionHash)
        external
        pqcRequired(actionHash)  // ← reverts unless Falcon-512 confirmed
    {
        _processWithdrawal(msg.sender, amount);
    }
}
```

`PQCGatedProxy` provides the same protection for existing contracts that cannot be modified, by acting as a transparent proxy that requires a pre-secured `actionHash` before forwarding any call:

```typescript
// No changes to target contract required
await proxy.forward(actionHash, targetIface.encodeFunctionData("withdraw", [amount]));
```

#### 8.9.2 Seed-Phrase-Theft Protection — Commit-Reveal Registration

If an attacker steals an ECDSA seed phrase before the user registers a Falcon key, they could register their own Falcon key for that EVM address, taking permanent ownership of the PQC identity. The v1.2 commit-reveal mechanism closes this window:

**Step 1 — Commit** (block N):
```solidity
bytes32 salt = <random bytes32, kept secret>;
bytes32 commitment = keccak256(abi.encodePacked(falconPublicKey, salt));
registry.commitPqcKey(commitment);
// Emits: PqcKeyCommitted(account, availableAt = N + 100)
```

**Observation window** (blocks N to N+100, ~20 minutes):
If an attacker with the stolen ECDSA key commits a different Falcon key, the `PqcKeyCommitted` event is visible on-chain before finalization. The legitimate user calls `cancelCommitment()` to abort. The attacker's commitment is rejected because `CommitmentAlreadyPending` prevents overwriting.

**Step 2 — Reveal** (block ≥ N+100):
```solidity
registry.registerPqcKey(falconPublicKey, PqcAlgo.Falcon512, salt);
// Verifies: keccak256(pubkey ‖ salt) == stored commitment
// Enforces: block.number >= commitmentBlock + MIGRATION_DELAY
```

#### 8.9.3 Key-at-Rest Protection — `EncryptedKeyVault`

Even if the ECDSA seed phrase is compromised, the Falcon-512 secret key remains protected because it is encrypted with a separate PIN using AES-256-GCM derived via PBKDF2 (100,000 iterations, SHA-256):

```typescript
const vault = new EncryptedKeyVault(); // localStorage by default; pluggable storage
await vault.seal(falconKeypair.secretKey, "myVaultPIN"); // separate from seed phrase

// Later — even on a new device via export/import:
const sk = await vault.unseal("myVaultPIN");
```

The sealed blob (salt + IV + ciphertext) is safe to store or transmit anywhere. It cannot be decrypted without the PIN, which is never persisted. The `buildPqcCommitment(publicKey, salt)` helper computes the `bytes32` needed for `commitPqcKey()` in the same SDK module.

### 8.10 Sovereign Subnets

The `SubnetManager` allows permissioned subnetworks to run on Quantos infrastructure with custom validator sets and governance rules. Each subnet:

- Inherits Quantos's PQC consensus
- Can define its own token and economic rules
- Communicates with the mainnet through the same L0 proof system
- Maintains independent finality that can be attested to the mainnet

This architecture allows enterprise and government deployments to operate as sovereign chains while benefiting from Quantos's quantum-resistant infrastructure.

### 8.11 PQC-Guard: Multi-VM Smart Account

PQC-Guard is the application-layer manifestation of the Quantos L0 — a quantum-resistant smart account that any user or dApp can deploy on any supported chain. After migrating to a post-quantum key, funds are released exclusively through M-of-N attestations from the Quantos validator set, verified on-chain using a WOTS (Winternitz One-Time Signature) scheme with keccak256, requiring no lattice arithmetic on the destination chain.

#### 8.11.1 Cryptographic Primitives

The on-chain verification relies entirely on hash operations available on all VMs:

- **WOTS (w=16, LEN=67)**: 64 message digits + 3 checksum digits in base-16. Each digit chain applied `W-1-d` times; the compressed public key is `keccak256(concat(chain_i))`.
- **Attestor Merkle tree**: `attestor_leaf = keccak256("PQCG_ATTESTOR_LEAF" ‖ id ‖ wots_root)`. A binary Merkle tree of attestor leaves; the root is anchored on-chain by the L0 oracle.
- **WOTS leaf**: `wots_leaf = keccak256("PQCG_WOTS_LEAF" ‖ wots_pub)` — domain-separated to prevent second-preimage across tree levels.
- **Authorization digest**: `keccak256(account ‖ to ‖ value ‖ data_hash ‖ nonce ‖ chain_id)` — canonical across all VMs.

#### 8.11.2 Canonical Binary Serialization

Cross-VM attestation blobs use a chain-agnostic binary format (MULTIVM_SPEC.md §4):

```
blob := uint32(N) ‖ proof_0 ‖ … ‖ proof_{N-1}

proof_i :=
    id            [32 bytes]   attestor identifier
    wots_root     [32 bytes]   WOTS tree root
    uint64(li)    [8 bytes]    leaf index in WOTS tree
    uint32(|sig|) [4 bytes]    number of WOTS chains (LEN=67)
    sig           [67×32 bytes]
    uint32(|path|)[4 bytes]    Merkle proof depth
    path          [depth×32 bytes]
    uint64(si)    [8 bytes]    attestor index in set tree
    uint32(|sp|)  [4 bytes]    set Merkle proof depth
    sp            [depth×32 bytes]
```

The TypeScript SDK (`pqc-guard/sdk/src/canonical.ts`) implements serialization and per-chain digest computation for all seven VM families.

#### 8.11.3 VM Ports

| Chain | Runtime | Language | Tests | Framework |
|-------|---------|----------|-------|-----------|
| Ethereum, Base, Arbitrum, Optimism, Polygon, Avalanche, BSC | EVM | Solidity | Foundry | ✅ |
| Tron | TVM (EVM) | Solidity | Foundry | ✅ |
| Solana | SVM | Rust (Anchor) | `cargo test` | ✅ 5/5 |
| Sui | Move 2024 | Move | `sui move test` | ✅ 5/5 |
| Aptos | Move | Move | `aptos move test` | ✅ 3/3 |
| NEAR | WASM | Rust (near-sdk 5.x) | `cargo test` | ✅ 4/4 |
| Stellar | Soroban | Rust (soroban-sdk) | `cargo test` | ✅ 4/4 |

Each port implements the same four-function interface: `migrate`, `finalize_migration`, `execute`, and `escape`/`recovery`. Non-EVM divergences are documented in `base-bridge/PQC_GUARD_PORTS.md`.

#### 8.11.4 Guardian Escape Hatch

If the Quantos network becomes unavailable, funds are never frozen:

- After `RECOVERY_TIMEOUT` (30 days of inactivity), the guardian threshold is unlocked
- M-of-N guardians can collectively sweep funds to a recovery address
- The escape hatch is enforced by a block/time oracle on each VM, independently of Quantos uptime

#### 8.11.5 Commit-Reveal Migration

Key migration follows a commit-reveal scheme to prevent front-running:

1. **Commit** (block N): `commitment = keccak256(pqc_pub_key)` stored on-chain
2. **Delay**: 24 hours (86,400 seconds) must elapse
3. **Reveal** (block ≥ N + delay): `pqc_pub_key` is revealed; contract verifies `keccak256(revealed) == commitment` and activates PQC mode

During the delay window, the existing owner can cancel the migration if a commitment was made without their authorization.

#### 8.11.6 Runtime-Specific Implementation Constraints

Each non-EVM runtime imposes constraints that shaped the canonical design. These constraints are documented here for implementors porting PQC-Guard to new chains.

**Stellar / Soroban (Rust)**

The `soroban_sdk::Bytes` type does not expose a `to_array()` method or a generic `extend_from_slice()`. All binary encoding is done via sequential `push_back(byte)` calls with explicit bit-shifting (`(n >> 56) & 0xff`, …). The `Hash<32>` return type of `soroban_sdk::env::keccak256` is wrapped in a helper `keccak_bytes(env, &Bytes) -> BytesN<32>` that converts via `.into()`, centralizing the type normalization. Because Soroban does not support multiple `#[contract]` exports from a single binary (symbol collision), the oracle's initialization function is exported as `init_oracle` rather than `init` to avoid colliding with the account contract's `init` function.

**NEAR (near-sdk 5.x / Rust)**

The `near-sdk` 5.x API differs significantly from 4.x: the `#[near_bindgen]` macro is replaced by the combined `#[near]` macro applied to both the struct and its implementation block; gas is expressed as `Gas::from_tgas(u64)` and token amounts as `NearToken::from_yoctonear(u128)`. Running `cargo test` against NEAR contract crates requires the `unit-testing` feature flag declared in `[dev-dependencies]` of `Cargo.toml`, because the SDK's WASM host bindings are conditionally compiled out in that mode. The contract's `keccak256` is provided by the `near_sdk::env::keccak256_array` host function, which returns `[u8; 32]` directly — matching the canonical digest format without additional conversion.

**Aptos (Move)**

Aptos Move uses the `aptos_framework::event::emit<T>(event: T)` function, which requires the type parameter `T` to have `has drop, store` abilities. All four event structs (`ValidatorSetRegistered`, `ValidatorSetRevoked`, `ProofVerified`, `RelayAuthorized`) declare these abilities explicitly. Aptos does not require an `edition` field in `Move.toml`; the default Move dialect supports module-level `friend` declarations and `acquires` annotations, which are used to manage `GuardedVault` resource access.

**Sui (Move 2024.beta)**

The Sui `Move.toml` declares `edition = "2024.beta"`, which mandates that all struct types accessible outside their defining module carry the `public` keyword. Without it, the compiler rejects the type with `E01003: invalid modifier`. Additionally, Sui objects must include a `UID` field as the first member for `has key` structs. Event types are emitted via `sui::event::emit<T>()` and require `has copy, drop` abilities — no `store` is needed (unlike Aptos). The `init(ctx: &mut TxContext)` function is the Sui object initialization convention and is called exactly once at publish time by the Move runtime.

**Solana (Anchor / SVM)**

Anchor's `#[account]` macro derives `AnchorSerialize` and `AnchorDeserialize` for all state structs. PDA (Program Derived Address) seeds are defined in the `#[derive(Accounts)]` context struct using `seeds = [b"...", ...]` and `bump` fields. The Solana `keccak::hash()` function operates on `&[u8]` and returns a `keccak::Hash` with a `.0: [u8; 32]` field. All 32-byte values (WOTS chains, Merkle nodes) are represented as `[u8; 32]` arrays, and `Vec<[u8; 32]>` is used for WOTS signatures and Merkle paths, consistent with the canonical blob format.

**EVM / Tron (Solidity)**

Tron's TVM is byte-compatible with the EVM; the same `PQCGuard.sol` bytecode deploys on Tron without modification. The only runtime distinction is the chain ID in the authorization digest — Tron mainnet uses chain ID `0x2b6653dc` and the canonical digest computation adjusts accordingly. The `keccak256` opcode is available natively on both EVM and TVM, making the WOTS chain iteration and Merkle node computation identical across both runtimes.

## 9. Network Layer

### 9.1 Post-Quantum Peer-to-Peer

Quantos implements a custom peer-to-peer networking stack with full post-quantum wiring. Unlike conventional blockchain networks that use libp2p with classical TLS or Noise identities, Quantos uses Kyber-768 for key encapsulation during the handshake and Dilithium-3 for mutual authentication. The transport layer encrypts all traffic with AES-256-GCM.

**Connection Establishment:**
1. Initiator generates an ephemeral Kyber keypair.
2. Initiator sends a Dilithium-3 signed handshake message containing the Kyber public key.
3. Responder verifies the Dilithium-3 signature and encapsulates an AES-256-GCM key under the Kyber public key.
4. All subsequent communication uses AES-256-GCM with the derived session key.

This design ensures that even if an attacker records all network traffic today, they cannot decrypt it in the future using a quantum computer. The classical "harvest now, decrypt later" attack is neutralized.

### 9.2 QUIC Transport

Quantos uses QUIC as the primary transport protocol. QUIC provides multiplexed streams, 0-RTT resumption, BBRv2 congestion control, and built-in NAT traversal via UDP hole punching with STUN/TURN fallback.

### 9.3 Gossip and Sync

**TurboGossip**: An epidemic broadcast with fanout of 8 and 3 hops, reaching over 500 validators. Includes duplicate suppression and Reed-Solomon erasure coding for reliability.

**State Sync**: New validators synchronize using delta-based Merkle proofs for changed paths only, reducing sync time from hours to minutes.

**Pre-filter**: Incoming transactions are pre-filtered using Bloom filters at the network layer, dropping known transactions before deserialization and reducing CPU load by ~40% under spam.

## 10. Security Model

### 10.1 Attack Vector Matrix

| Attack Vector | Protection Mechanism |
|---------------|---------------------|
| Shor's Algorithm (ECC break) | All signatures use Dilithium-3, SPHINCS+, Falcon-512 |
| Grover's Algorithm (hash speedup) | 256-bit security margin doubles effective key size |
| 51% / Stake Majority | Stake-weighted committees with 2/3 + 1 threshold + slashing |
| Eclipse Attack | Peer diversity scoring + reputation-based connection limits |
| MITM | End-to-end Kyber + AES-256-GCM with mutual Dilithium-3 auth |
| Double Spend | DAG conflict resolution + deterministic checkpoint finality |
| Replay Attack | Per-transaction nonce + chain ID + 5-minute expiry |
| L0 Cross-Chain Replay | `parent_block_hash` + `chain_work` bound in proof signing digest |
| L0 Equivocation | EquivocationTracker + slashable offenders list |
| STARK Commitment Forgery | SHA3-256 pre-image resistance (2^256 classical, 2^128 quantum) |
| Long-Range Attack | Checkpoints every ~1s + weak subjectivity period |
| Sybil Attack | Minimum stake requirements + STACC activation deposit |
| Time Warp | Median timestamp from 11 validators + ±30s bounds |
| Selfish Mining | DAG eliminates single-proposer advantage |
| Front-Running | Kyber-encrypted mempool + commit-reveal ordering |
| Seed-Phrase Theft + PQC Key Hijack | Commit-reveal registration (100-block delay) + `cancelCommitment()` abort |
| Falcon Key Exposure at Rest | `EncryptedKeyVault` AES-256-GCM + PBKDF2 PIN (separate credential) |
| dApp Bypassing PQC Check | `PQCGuard` `pqcRequired` modifier or `PQCGatedProxy` enforcement |
| DoS / DDoS | STACC rate limiting + network-layer proof of work |
| Nothing-at-Stake | Slashing for double-signing + 14-day unbonding |

### 10.2 DDoS Protection

The network layer implements a lightweight memory-hard puzzle (Argon2id) for connection establishment. New peers must solve a ~100ms CPU puzzle before acceptance. STACC rate limiting applies per IP and per account: over 1,000 invalid messages/minute results in a 1-hour ban; over 10,000 valid messages/minute triggers bandwidth throttling.

### 10.3 Partition Tolerance

If the network partitions, each subset continues producing DAG vertices locally but cannot achieve finality (super-committee requires 2/3 + 1 of all validators). When the partition heals, the protocol automatically resolves forks by selecting the checkpoint chain with the highest accumulated stake-weighted finality signatures.

## 11. Sidechain Architecture

### 11.1 Shared Security Model

Quantos sidechains inherit security from the main chain through a Proof of Stake Bridge. L1 validators can opt in to operate sidechains by staking additional QTEST collateral, creating an economic bond between sidechain operators and main chain validators.

Each sidechain has its own block time, transaction format, and state transition rules, but posts cryptographic state commitments to L1 every epoch. Operators are subject to fraud proof challenges and slashing for invalid commitments.

### 11.2 Lifecycle

**Registration**: Creator deploys a sidechain config with a 100 QTEST registration stake.
**Activation**: Activates when the required number of operators have registered and staked.
**Operation**: Operators produce blocks and submit Dilithium-3 signed state commitments to the L1 registry.
**Slashing**: Invalid commitments trigger fraud proofs; 3 slashes deactivate an operator.

### 11.3 Asset Bridging

Transfers use a lock-and-mint mechanism. For deposits, assets are locked on L1 and minted on the sidechain. For withdrawals, assets are burned on the sidechain and unlocked on L1 after the dispute window. All bridge operations use Dilithium-3 signatures and Merkle proofs.

## 12. Proposer-Builder Separation (PBS)

### 12.1 Sealed-Bid Auction

For each slot, a sealed-bid auction selects the block builder:

1. **Bidding Phase** (4s): Builders submit cryptographic commitments to block proposals.
2. **Reveal Phase** (1s): Builders reveal bids that must match prior commitments.
3. **Selection**: Highest valid bid wins.
4. **Delivery** (2s): Winning builder delivers the full block for verification.

Delivery failure results in collateral slashing and failover to the next highest bidder.

### 12.2 Builder Reputation

Builders register with collateral and accumulate reputation (0-1000) based on successful deliveries. Reputation below 300 excludes builders from high-value slots. Collateral below minimum automatically deactivates the builder.

## 13. Genesis and Address Format

### 13.1 Genesis

Quantos supports three networks with fixed genesis timestamps for deterministic hashes:

| Network | Chain ID | Genesis Date | Initial Shards |
|---------|----------|--------------|----------------|
| Mainnet | 1 | TBD | 100 |
| Testnet | 2 | Feb 1, 2026 | 4 |
| Devnet | 3 | Jan 1, 2026 | 2 |

Genesis includes validators with Dilithium-3 public keys, token allocations with vesting schedules, and optionally system contracts deployed at deterministic addresses.

### 13.2 Address Format

Quantos addresses are encoded in `qts1...` format using base32 with a 4-byte checksum derived from BLAKE3. The underlying address is a 32-byte value (64 hex characters) derived as `BLAKE3(public_key)`. The `qts1` prefix provides human readability and error detection during manual transcription.

## 14. Ecosystem and Use Cases

### 14.1 Vybss Super App

The flagship ecosystem application is Vybss, a multi-module decentralized platform combining:

- **DEX**: Spot and perpetual trading with PQC settlement, STACC-based trading fees, and encrypted order submission.
- **SQTEST Stablecoin**: A self-collateralized stablecoin backed by native QTEST collateral with automated liquidation.
- **Bridge**: A Quantos-to-EVM bridge supporting all EVM-compatible chains (Ethereum, Base, Arbitrum, Optimism, Polygon, Avalanche, BSC, and more) secured by the L0 Finality Hub.
- **Social Feed**: Creator economy with content monetization through micro-transactions.
- **Kai AI**: AI-powered code security scanner, no-code app builder, and crypto assistant.

### 14.2 Use Cases by Industry

| Industry | Use Case | Quantos Advantage |
|----------|----------|-------------------|
| DeFi & Fintech | DEX, lending, derivatives | Sub-second finality, MEV protection, PQC settlement |
| Payments | Consumer checkout, remittances | Zero-gas model, predictable costs, high throughput |
| Defense & Sovereign | CBDCs, classified asset tracking | Quantum-resistant signatures, sovereign subnets |
| Identity | Decentralized credentials | PQC signatures prevent future forgery |
| Supply Chain | Transparent tracking | Immutable DAG history, encrypted payloads |
| Gaming | In-game economies | Low-latency execution, high throughput |
| AI Services | On-chain inference routing | Encrypted compute requests, verifiable results |

## 15. Technical Specifications

### 15.1 Consensus Parameters

| Parameter | Value |
|-----------|-------|
| Consensus mechanism | QuantumDAG (3-layer hybrid) |
| Max validators | 21,000 |
| Committees | 1,000 |
| Validators per committee | 21 (genesis) to 63 (max) |
| Committee rotation interval | 100ms |
| Checkpoint interval | ~1 second (1,000 vertices) |
| Finality committee size | 100 validators |
| Finality threshold | 67/100 (2/3 + 1) |
| DAG parents per vertex | 2-8 |

### 15.2 Cryptographic Parameters

| Parameter | Value |
|-----------|-------|
| Transaction signature | Dilithium-3 (NIST Level 3) |
| VRF | SPHINCS+-128f (NIST Level 1) |
| Checkpoint signature | Falcon-512 (NIST Level 1) |
| Key encapsulation | Kyber-768 (NIST Level 3) |
| Hash function | BLAKE3 |
| Address format | qts1 base32 + 4-byte BLAKE3 checksum |
| Key derivation | BLAKE3(public_key) |
| L0 STARK field | F128 (winter_math::fields::f128) |
| L0 STARK hash | BLAKE3-256 (quantum-safe) |
| L0 STARK security | ~96-bit conjectured (28 queries, blowup ×8) |
| L0 STARK prover | Winterfell (Meta Research) |
| L0 on-chain commitment | 32 bytes (SHA3-256 over proof + public inputs) |

### 15.3 Performance Targets

| Parameter | Genesis | Full Deployment |
|-----------|---------|-----------------|
| Shards | 100 | 10,000 |
| TPS per shard | 25,000 | 25,000 |
| Total TPS | 2.5M | 250M |
| Time to finality | ~1 second | ~1 second |
| Cross-shard proof size | ~150 KB | ~150 KB |
| Cross-shard verification | &lt;100ms | &lt;100ms |
| L0 STARK prove time | &lt;500 ms | &lt;500 ms |
| L0 STARK verify time | &lt;10 ms | &lt;10 ms |
| L0 on-chain footprint | 32 bytes | 32 bytes |
| L0 supported chains | 14 | 14+ |

### 15.4 Network Parameters

| Parameter | Value |
|-----------|-------|
| P2P protocol | QUIC + Kyber-768 / Dilithium-3 PQ handshake |
| Gossip protocol | Epidemic broadcast |
| Sync protocol | State delta sync with Merkle proofs |
| Max block/vertex size | 1 MB |
| Max transactions per vertex | 10,000 |
| Mempool max size | 100,000 transactions |
| Max per-sender mempool limit | 100 transactions |

## 16. Conclusion

Quantos represents a fundamental rethinking of blockchain architecture for the post-quantum era. By embedding NIST-standardized PQC at every layer — from individual transaction signatures to cross-chain finality attestations — Quantos provides security guarantees that remain valid even when quantum computers render classical cryptography obsolete.

The Version 1.1 upgrade advances the L0 Finality Hub from a proof-of-concept to a production-grade cross-chain finality system:

- **ZK-STARK batch verification** (Winterfell) reduces N × 1 KB PQC signatures to a 32-byte on-chain commitment, cutting destination-chain storage by >99%
- **Canonical chain continuity** (`parent_block_hash` + `chain_work` in signing digest) makes fork attacks and replay attacks cryptographically impossible
- **Equivocation slashing** provides real-time detection and cryptographically attributable evidence for validator double-signing
- **RelayPool** eliminates single points of failure in the relay infrastructure

The Version 1.2 upgrade closes the remaining security gaps in the PQC migration stack and completes the L0 chain coverage:

- **Bitcoin SPV Merkle proof** — `ChainProof::Bitcoin` now verifies full transaction inclusion via `double_sha256` Merkle path against the block header, completing true SPV rather than block-only attestation
- **Tezos `ChainFamily::Tezos`** — first-class routing replaces the `Custom` fallback, enabling proper registry entries and light client assertions for Tezos mainnet and Ghostnet
- **`EpochWatcher`** — background tokio service with 10 chain-specific fetchers that updates `ValidatorSetRegistry` live when validator sets rotate; all light clients see new keys without restart
- **`PQCGuard.sol` + `PQCGatedProxy`** — makes PQC enforcement compiler-mandatory via a Solidity modifier (`pqcRequired`) and a transparent proxy for existing contracts, eliminating the "opt-in" vulnerability
- **Commit-reveal Falcon registration** — 100-block observation window prevents silent Falcon key hijacking after ECDSA seed phrase theft; `cancelCommitment()` provides an abort path
- **`EncryptedKeyVault`** — AES-256-GCM vault with PBKDF2 PIN decouples Falcon key security from ECDSA seed phrase security at the SDK level

The Version 1.3 upgrade delivers the full-stack multi-VM deployment of PQC-Guard:

- **Seven VM families** (EVM, Tron/TVM, Solana/SVM, Sui Move 2024, Aptos Move, NEAR WASM, Stellar Soroban) share a single canonical WOTS+keccak256 verification algorithm, requiring no lattice arithmetic on any destination chain
- **Canonical binary serializer** in the TypeScript SDK produces byte-identical attestation blobs consumed by all seven runtimes
- **43 native unit tests** across 6 test runners confirm that quorum reached, quorum not reached, non-member rejection, and wrong-digest rejection behave identically on every VM
- **Guardian escape hatch** and **commit-reveal migration** are implemented consistently on all VMs, ensuring that Quantos is necessary for performance but never for safety — funds cannot be frozen regardless of Quantos uptime

The combination of zero-gas execution (STACC), massive parallelization (Dynamic Sharding), quantum-resistant interoperability (L0 Finality Hub), succinct ZK-STARK attestations, and a multi-VM PQC-Guard smart account creates a platform capable of serving as foundational infrastructure for the next generation of decentralized applications.

Unlike retrofit approaches that apply band-aid solutions to fundamentally insecure foundations, Quantos is built on the only assumption that matters in the long term: that the laws of mathematics, not the limitations of today's hardware, should define the security of digital assets.

---

**Links**

- Website: [quantos.tech](https://quantos.tech)
- Documentation: [docs.quantos.tech](https://docs.quantos.tech)
- Lightpaper: [lightpaper.quantos.tech](https://lightpaper.quantos.tech)
- GitHub: [github.com/Wayleyy/quantos-audit](https://github.com/Wayleyy/quantos-audit)
- Ecosystem: [vybss.com](https://vybss.com)

