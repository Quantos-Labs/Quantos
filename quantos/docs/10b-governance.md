---
sidebar_position: 27
slug: /governance
---

# 26. Governance

## 26.1 On-Chain Governance

Protocol evolution and treasury decisions are managed through on-chain governance, implemented as DAO contracts (`quantos/solidity-contracts/dao/`) running on QuantosVM. Governance weight is denominated in staked QTS, aligning decision power with economic exposure to the network's health.

## 26.2 Proposal Lifecycle

Governance follows a standard, auditable lifecycle:

1. **Proposal** — a staked participant submits a proposal (a parameter change, treasury disbursement, or upgrade authorisation).
2. **Voting** — QTS holders vote within a fixed window; voting power is stake-weighted, and validators may vote on behalf of delegated stake subject to delegation rules.
3. **Quorum & threshold** — a proposal passes only if it meets both a participation quorum and an approval threshold, preventing low-turnout capture.
4. **Timelock** — an approved proposal enters a timelock delay before execution, giving the network time to react (including exiting) if a malicious proposal somehow passes.
5. **Execution** — after the timelock, the change is enacted on-chain.

## 26.3 What Governance Controls

Governance is scoped to parameters and policies that are safe to vary, including economic constants (inflation bounds, rent rate, slashing percentages), sharding thresholds, committee sizing, treasury allocation, and the authorisation of protocol upgrades. Safety-critical invariants (the consensus safety properties, the post-quantum signature requirement) are not subject to casual parameter tuning; changing them requires a full upgrade path with the associated timelock and supermajority.

## 26.4 Treasury and Public Goods

A portion of protocol revenue can be directed to a treasury governed by the DAO, funding public goods — client diversity, audits, tooling, grants (`solidity-contracts/grants/`), and ecosystem development. This creates a sustainable, on-chain funding mechanism that does not depend on external sponsorship.

## 26.5 Quantum-Safe Governance

Because governance actions are themselves transactions, they inherit the chain's post-quantum security: proposals and votes are signed with ML-DSA-65 and ordered by the same consensus that secures ordinary transactions. Governance over a quantum-vulnerable chain would be a single point of failure; on Quantos the governance layer is as quantum-resistant as the base protocol.
