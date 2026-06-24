---
sidebar_position: 22
slug: /sidechains
---

# 21. Sidechains

## 21.1 Motivation

Dynamic sharding (Dynamic Sharding section) scales a single, homogeneous execution environment. Some applications, however, need a *different* environment entirely: a custom runtime, a private validator set, a domain-specific fee or governance policy, or isolation from the throughput of unrelated applications. Quantos serves these with **application-specific sidechains** (`quantos/src/sidechain/`) that inherit security from the L1 while running independently.

```
┌─────────────────────────────────────────────────────────────┐
│                        Quantos L1                            │
│  ┌────────────────── Sidechain Registry ──────────────────┐ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐              │ │
│  │  │ Chain A  │  │ Chain B  │  │ Chain C  │   ...        │ │
│  │  │ (DeFi)   │  │ (Gaming) │  │ (NFT)    │              │ │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘              │ │
│  │       └─────────────┼─────────────┘                    │ │
│  │               ┌─────▼──────┐                           │ │
│  │               │ Bridge Layer│  (asset locking)         │ │
│  │               └────────────┘                           │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## 21.2 Shared-Security Model

Sidechains use a **Proof-of-Stake bridge** model that anchors their security to the L1 validator set:

1. **Staked participation**: L1 validators opt in to securing a given sidechain by staking on its participation. They put L1-denominated stake at risk for honest sidechain operation.
2. **Periodic state commitments**: Each sidechain posts a state commitment to the L1 every epoch, creating an immutable, L1-anchored history of the sidechain's state roots.
3. **Fraud proofs**: Within a dispute window, any party may submit a fraud proof challenging an invalid sidechain state transition. A valid challenge reverts the disputed state.
4. **Slashing**: Operators proven to have committed an invalid or fraudulent state transition are slashed, with the same economic finality as L1 misbehaviour.

This gives sidechains the autonomy of an independent chain (custom runtime, independent throughput) while their finalised state remains accountable to, and defended by, L1 economic security.

## 21.3 Asset Bridging

Assets move between the L1 and a sidechain through a lock-and-mint bridge: tokens are locked on the source domain and a corresponding representation is credited on the destination domain, with the reverse on withdrawal. Because the sidechain's state roots are committed to L1 every epoch, bridge withdrawals can be validated against an L1-anchored commitment rather than trusting the sidechain operator's word. The bridge layer reuses the same post-quantum signature and proof machinery as the rest of the protocol.

## 21.4 Custom Runtimes

Each sidechain may define its own execution environment. A DeFi sidechain might run the full QuantosVM with the native token standards (Virtual Machine and Native Token Standards sections); a gaming sidechain might run a stripped-down, high-throughput runtime tuned for its specific transaction shapes. The L1 does not constrain the internal logic of a sidechain — it constrains only the commitment cadence and the fraud-proof / slashing discipline that keep the sidechain honest. This separation lets the ecosystem experiment with new runtimes without risking L1 consensus.
