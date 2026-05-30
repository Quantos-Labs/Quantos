---
id: overview
title: Quantos Overview
slug: /
---

# Quantos Overview

Quantos is a post-quantum Layer 1 DAG blockchain featuring zero-gas execution via **STACC** and a **Layer 0 finality hub** that anchors external chains with PQC proofs.

## Vision

Current blockchain infrastructure relies on **ECDSA** and **secp256k1**, cryptosystems that will be rendered insecure by Shor's algorithm on a sufficiently powerful quantum computer. Quantos is designed **quantum-first**: every consensus message, every transaction signature, and every cross-chain proof uses NIST-standardized post-quantum cryptography from day one.

Quantos does not merely add PQC as an afterthought. It re-architects consensus, execution, and interoperability around the constraints and capabilities of post-quantum algorithms.

## Architecture

### 3-Layer QuantumDAG Consensus

```
Layer 3: Finality Anchor
  Falcon-512 checkpoints, deterministic finality, ~1 second

Layer 2: Quantum Committees
  1,000 committees x 21 validators = 21,000 total
  VRF rotation (SPHINCS+) every 100ms
  Dilithium-3 aggregated signatures (14/21 threshold)

Layer 1: Fast Path (DAG)
  Parallel transaction inclusion, no sequential blocks
  2-8 parent references per vertex
  Optimistic execution with <0.1% rollback rate
```

### Post-Quantum Cryptography

| Algorithm | Usage | Signature Size |
|-----------|-------|----------------|
| Dilithium-3 | Transaction signatures | 3,293 bytes |
| SPHINCS+ | VRF committee selection | 17,088 bytes |
| Falcon-512 | Checkpoint finality | 666 bytes |

Adaptive PQC Algorithm Selection (APAS) dynamically selects the optimal algorithm per context.

### STACC: Zero-Gas Execution

**STACC** (Stake-Timed Access & Compute Credit) replaces per-transaction gas fees with a renewable, stake-proportional bandwidth quota.

**How it works:**
1. **Activation**: Users stake native tokens and activate their address (minimum stake required)
2. **Quota Allocation**: Compute Units (CU) are allocated via a dual token-bucket mechanism
3. **Fair Scheduling**: Weighted Fair Queueing (WFQ) orders transactions by stake, anciennete (loyalty), and priority boosts
4. **No Fees**: Transactions consume quota, not tokens. Quota refills continuously.

**Tier System:**

| Tier | Minimum Stake | Base Quota | Priority Boost |
|---|---|---|---|
| Basic | Minimum stake | 10,000 CU | — |
| Builder | Moderate stake | 30,000 CU | — |
| Enterprise | High stake | 100,000 CU | +20,000 weight |

Long-term participants receive a logarithmic quota multiplier (1.0x to 3.0x) that grows over ~6 months of continuous activation, rewarding network loyalty without capital requirements.

### Dynamic Sharding

- **100 to 10,000 shards** auto-scale based on load
- **Split threshold**: 150,000 TPS per shard
- **Cross-shard**: Two-phase commit with zk-STARK batched verification (~150 KB proof for 1,000 transitions)
- **Intra-shard throughput**: ~20,000 TPS

### QuantosVM

- **Engine**: Wasmer WASM with AES-256-GCM bytecode protection
- **EVM Compatible**: revm integration for Solidity contracts
- **Solang**: Native Solidity to WASM compiler
- **Host functions**: `qnt_storage_*`, `qnt_block_*`, `qnt_crypto_*`

### Layer 0 Finality Hub

Quantos acts as a **post-quantum finality layer** for external blockchains. It produces `L0FinalityProof` artifacts — cryptographically self-contained attestations signed with **Falcon-512** (PQC) that any chain can verify without trusting Quantos nodes.

**What it does in one sentence**

Ethereum, Bitcoin, Solana and others finalize with **classical signatures** (ECDSA, Ed25519) that Shor's algorithm will break. Quantos wraps their blocks with a **quantum-resistant attestation** that remains unforgeable even if the source chain's own cryptography collapses.

**Three concrete use cases**

| Use Case | Problem | Quantos L0 Solution |
|---|---|---|
| **Cross-chain bridges** | $500M locked on Ethereum; quantum attacker forges ECDSA finality to drain funds | Bridge waits for PQC `L0FinalityProof` before releasing funds — quantum attack impossible |
| **Institutional custody** | Long-term asset storage needs 20+ year security; classical signatures may be retroactively broken | PQC attestation provides cryptographic guarantee independent of source chain evolution |
| **Sovereign subnets** | Subnet wants Ethereum interoperability without building its own bridge | Subnet checkpoints are anchored to L0 hub; PQC proofs verified directly on Ethereum |

**How it works (5 steps)**

1. **Relayer** monitors a chain and fetches the cryptographic proof (block header, ledger entry, signatures)
2. Relayer submits `ExternalCheckpoint` + structured `ChainProof` to Quantos L0
3. **Light Client Registry** verifies the proof **cryptographically** — no RPC calls to source chains
4. Quantos validators produce `L0FinalityProof` signed with **Falcon-512**
5. Proof is relayed to any chain for on-chain verification

**Supported chains**

| Chain | Type | L0 Support Status |
|---|---|---|
| Ethereum | EVM | **Production** — full block header verification (Keccak-256) |
| Base | EVM | **Production** — full block header verification |
| Arbitrum | EVM | **Production** — full block header verification |
| Optimism | EVM | **Production** — full block header verification |
| Polygon | EVM | **Production** — full block header verification |
| Avalanche | EVM | **Production** — full block header verification |
| BNB Chain | EVM | **Production** — full block header verification |
| Bitcoin | UTXO | **Production** — block header hash (double SHA-256) + depth |
| Solana | SVM | **Production** — Ed25519 vote account signatures verified |
| Aptos | Move | **Production** — BLS12-381 validator signatures verified |
| Sui | Move | **Production** — BLS12-381 validator signatures verified |
| NEAR | Nightshade | **Production** — Ed25519 block producer signatures verified |
| Cosmos | Tendermint | **Production** — Ed25519 precommit signatures verified |
| Cardano | Ouroboros | **Production** — Ed25519 pool operator signatures verified |
| TON | TVM | **Production** — Ed25519 validator signatures verified |
| Tron | TVM | **Production** — ECDSA (secp256k1) producer signatures verified |
| Polkadot | Substrate | **Production** — Ed25519 GRANDPA vote signatures verified |
| Stellar | SCP | **Production** — Ed25519 node signatures verified |
| Tezos | Michelson | **Production** — Ed25519 baker signatures verified |

> **Production** = cryptographic verification is complete: proof structure + signatures verified.  
> **Planned** = light client framework ready, awaiting chain-specific proof format implementation.

**Sovereign Subnets with L0 anchoring**

Projects can deploy isolated subnets on Quantos with custom validators, STACC collateral leasing, shared economic security via double-staking, and cross-chain anchoring to the L0 hub — enabling PQC interoperability without building custom bridge infrastructure.

## Target Clients & Industries

Quantos serves a wide range of sectors requiring high-throughput, quantum-resistant infrastructure:

| Industry | Use Case |
|---|---|
| **DeFi & Fintech** | Fast settlement for DEXs, lending, derivatives, and retail finance |
| **Payments** | Sub-second finality for consumer checkout and enterprise rails |
| **Defense & Sovereign** | Cryptographic resilience and long-term signature security with PQC |
| **Identity** | Decentralized, privacy-preserving credentials and permissions |
| **Supply Chain** | Transparent, verifiable tracking of operations and assets |
| **Insurance** | Tamper-proof claims, policy workflows, and compliance audit trails |
| **Gaming** | Low-latency execution for in-game economies and NFT markets |
| **AI Services** | On-chain AI inference routing and verifiable model execution |

## Ecosystem: Vybss

The flagship super app combining:
- **DEX**: Spot and perpetual trading with PQC settlement
- **SQTEST Stablecoin**: Self-collateralized stablecoin with native token collateral, stability fees and liquidation
- **Bridge**: Quantos-Base cross-chain bridge with point rewards
- **Social Feed**: Creator economy with monetized content, subscriptions, and leaderboards
- **Kai AI**: AI-powered code security, app builder, and crypto assistant
- **Stories/Videos**: Short-form content with creator monetization

## Technical Specifications

| Parameter | Value |
|---|---|
| Consensus | QuantumDAG (3-layer hybrid) |
| Cryptography | Dilithium-3, Falcon-512, SPHINCS+, Kyber |
| Max validators | 21,000 |
| Shards | 100-10,000 (dynamic) |
| Checkpoint interval | ~1 second |
| VM | Wasmer WASM + EVM |
| Fee model | STACC (zero gas) |
| Address format | 32-byte hex (64 chars) |

---

**Links:** [quantos.tech](https://quantos.tech) · [GitHub](https://github.com/Wayleyy/quantos-audit)
