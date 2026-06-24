---
id: lightpaper
title: Quantos Lightpaper
slug: /
---

# Quantos Lightpaper

**Post-Quantum Layer 1 with Directional Cross-Chain Finality**

*June 2026*

---

## 1. In One Sentence

Quantos is a quantum-resistant Layer 1 blockchain that also acts as a **Layer 0** — it provides post-quantum attestations of its finalized state that Ethereum, Solana, Sui, Aptos, NEAR, and every major chain can verify on-chain.

---

## 2. The Problem

Quantum computers will break ECDSA, secp256k1, and Ed25519 — the cryptography behind Bitcoin, Ethereum, Solana, and virtually all blockchains. Most projects plan to retrofit PQC later. Quantos builds it **from genesis**.

---

## 3. Quantos Layer 1

The core network: validators stake QTS, run consensus, and finalize transactions using post-quantum signatures.

| Feature | Detail |
|---------|--------|
| Validators | Up to 21,000 |
| Finality | ~1 second |
| Sharding | 100 to 10,000 (auto-scaling) |
| Fees | Zero-gas (stake-proportional bandwidth) |
| Cryptography | ML-DSA-65, ML-KEM-768 (NIST level 3, FIPS 203/204 finalized) |

---

## 4. Quantos Layer 0

The L0 is Quantos' **finality hub**. It lets any blockchain verify that Quantos has confirmed something — without trusting a third party.

**How it works:**
1. Quantos cryptographically verifies a proof from an external chain (e.g. Ethereum block header)
2. Quantos validators sign that proof with post-quantum signatures
3. A **compressed proof** (32 bytes) is relayed to the target chain
4. Smart contracts on the target chain verify it **on-chain**

> **Directional by design:** Quantos exports *its own* finalized state to external chains in seconds, as post-quantum attestations they can verify on-chain. It does **not** add post-quantum resistance to those chains' native consensus — Ethereum stays on ECDSA. The reverse direction (external → Quantos) is bounded by the source chain's own finality. No chain can compress another chain's consensus.

**L0 Verifier — deployed contracts:**

| Chain | VM | PQC-Guard |
|-------|----|-----------|
| Ethereum, Base, Arbitrum, Optimism, Polygon, Avalanche, BSC | EVM (Solidity) | ✅ |
| Tron | TVM (EVM-compatible) | ✅ |
| Solana | SVM (Anchor/Rust) | ✅ |
| Sui | Move (2024) | ✅ |
| Aptos | Move | ✅ |
| NEAR | WASM (Rust) | ✅ |
| Stellar | Soroban (Rust) | ✅ |
| Cosmos | CosmWasm (Rust) | L0 verifier only |
| TON | FunC | L0 verifier only |
| Polkadot | ink! (Rust) | L0 verifier only |
| Cardano | Plutus | L0 verifier only |
| Bitcoin | Via Stacks (Clarity) | L0 verifier only |

> PQC-Guard is the full smart-account system (migrate, execute, recover). L0 verifier only means cross-chain proof anchoring is supported without the full smart-account layer.

---

## 5. PQC-Guard: User Security

PQC-Guard is the smart-account system that lets users:

- **Migrate** funds to a post-quantum key (24h commit-reveal delay)
- **Secure** assets behind M-of-N attestations from Quantos validators
- **Recover** funds via guardians if Quantos becomes unavailable (30-day timeout)

**Deployed on:** Ethereum, Solana, Sui, Aptos, NEAR, Stellar, Tron.

---

## 6. Why It's Different

| Classic Approach | Quantos |
|------------------|---------|
| Isolated L1 chain | L1 + L0 interconnected |
| Expensive PQC retrofit | Native PQC from genesis |
| Centralized bridges (multisig) | Cryptographic trustless verification |
| Each chain manages its own PQC | Quantos provides verifiable PQC attestations to everyone |

---

## 7. Ecosystem

- **Vybss** — Super-app with DEX, stablecoin, bridge, and AI
- **SDK** — JavaScript/TypeScript toolkit for dApp integration
- **Wallet Extension** — Post-quantum key management for users

---

## 8. Links

- Website: [quantos.tech](https://quantos.tech)
- Docs: [docs.quantos.tech](https://docs.quantos.tech)
- Code: [github.com/Wayleyy/quantos-audit](https://github.com/Wayleyy/quantos-audit)
- Ecosystem: [vybss.com](https://vybss.com)
