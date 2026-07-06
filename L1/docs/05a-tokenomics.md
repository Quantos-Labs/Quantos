---
sidebar_position: 17
slug: /tokenomics
---

# 16. Tokenomics & QTS Economics

## 16.1 The QTS Token

**QTS** is the native asset of Quantos. It serves three roles, all structural rather than speculative:

1. **Security collateral** — QTS is staked by validators; the cost of attacking the chain is denominated in QTS at risk (the economic-security argument in the Security section).
2. **Bandwidth right** — under the zero-gas model, staked QTS entitles an account to a proportional compute-unit (CU) quota per slot. QTS is not spent per transaction; it is *held and staked* to earn throughput.
3. **Governance weight** — QTS-denominated stake weights participation in protocol governance.

This is a deliberate departure from fee-token designs: because Quantos charges no per-transaction gas (STACC section), QTS accrues value from the *right to transact and to secure the network*, not from fee burn alone.

## 16.2 Why Zero-Gas Changes the Economics

A pure zero-fee chain has a known failure mode: if validators earn nothing from usage, the only revenue is inflation, which dilutes holders indefinitely. Quantos avoids this trap with a **three-source revenue model** (`stacc/tokenomics.rs`) that progressively shifts validator income away from inflation:

| Source | Behaviour over time |
|--------|---------------------|
| **Targeted inflation** | Starts at 3–5% annually, declines toward a 1% floor as the staking rate approaches 67% |
| **State rent** | Grows with adoption (more stored state ⇒ more rent), progressively becoming the dominant source |
| **Slash redistribution** | Slashed stake is redistributed 80% to honest validators, 20% burned |

The inflation schedule is `inflation(t) = max(1%, 5% × (1 − staking_rate / 0.67))`: as more QTS is staked, new issuance falls, rewarding early security without permanent dilution.

## 16.3 State Rent as Sustainable Revenue

State rent (State Model and STACC sections) is the economic keystone. It prices *persistent storage* — the one resource a zero-gas chain must still meter — at `RENT_RATE_PER_SLOT_PER_BYTE = 1` CU per byte per slot, with a dust exemption (`storage_bytes ≤ 128`). Of collected rent, **20% is burned and 80% is redistributed to validators**. As on-chain state grows with adoption, rent revenue grows with it, allowing inflation to decline toward its floor.

## 16.4 Sustainability Metrics

The tokenomics engine publishes two metrics so the model's health is observable rather than asserted:

- **`rent_coverage`** — the fraction of validator revenue coming from rent rather than inflation.
- **`years_to_rent_parity`** — the estimated time until rent covers 50% of validator rewards.

At genesis, `rent_coverage` is near zero (revenue is almost entirely inflation). The model projects rent parity within **3–5 years** under conservative adoption curves, at which point the chain's security budget is funded primarily by usage rather than issuance.

## 16.5 Supply Dynamics

Net QTS supply change per epoch is `new_inflation − burned_rent − burned_slash`. As adoption rises, the burn terms grow while inflation shrinks, so the supply curve flattens and can become deflationary under high utilisation. Genesis allocation, validator-set parameters, and initial staking targets are defined in the genesis configuration (`quantos/src/genesis/`) and the network config (`quantos/config/`), which fix the starting validator set, chain id, and economic constants for a given network.
