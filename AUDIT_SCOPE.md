# Audit Scope

## Priority 1 — Threshold ML-KEM (before consensus)

The following **must be audited first**, before consensus or execution-layer review:

| Component | Path | Risk |
|-----------|------|------|
| Threshold ML-KEM-768 decapsulation | `quantos/src/crypto/threshold_mlkem.rs` | Shamir over Z_q may not preserve ML-KEM correctness under noise |
| Coefficient-wise Shamir sharing | `quantos/src/crypto/shamir_zq.rs` | Research-grade; no cited academic construction |
| Lattice NIZK (Fiat-Shamir) | `quantos/src/crypto/lattice_nizk.rs` | Custom NIZK; high historical break rate |

These modules compile **only** with the Cargo feature `experimental-threshold-mlkem` and are **out of the mainnet critical path**. Mainnet uses accountable-leader front-running protection (`quantos/src/mempool/accountable_leader.rs`) until this audit completes.

## In Scope

- Quantos blockchain core implementation.
- Consensus and networking logic.
- Execution layer and deterministic WASM runtime.
- Post-quantum signature integration and related cryptographic assumptions.
- Accountable-leader mempool policy and front-running slashing evidence.
- Resource-based mainnet contract architecture and invariants.
- Wallet/key-management core if explicitly confirmed in the audit engagement.

## Conditional / Optional Scope

- Threshold ML-KEM encrypted mempool (only if `experimental-threshold-mlkem` is enabled for the engagement).
- Bridge components only if explicitly included in the CertiK engagement.
- Testnet Solidity prototypes only for context, not as production mainnet contract targets.

## Out of Scope

- Vybss frontend/backend and all consumer product code.
- Landing pages, bots, growth services, social apps, and unrelated Kai services.
- Local `.env` files, deployment secrets, logs, runtime state, and database dumps.
- Testnet Solidity contracts as final mainnet contracts.

## Smart Contract Scope Clarification

The current Solidity contracts are compatibility/testnet prototypes used to validate staking, liquid staking, restaking, insurance, DAO, and token flows on the testnet environment.

They are not intended to represent the final mainnet smart contract implementation.

Mainnet contracts will be implemented in Rust using Quantos' resource-based smart contract model. A separate audit phase should be planned once the final Rust mainnet contracts are complete.
