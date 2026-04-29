# Mainnet Resource-Based Contract Model

Quantos mainnet contracts are planned to use a Rust resource-based model rather than Solidity/EVM contracts.

## Design Goals

- Resources represent assets with strict ownership and movement semantics.
- Assets should not be duplicated, implicitly copied, or destroyed without explicit rules.
- Access control should be capability-based where possible.
- Contract state transitions should preserve explicit invariants.
- Execution should remain deterministic and auditable.

## Audit Focus

- Resource ownership and transfer invariants.
- Capability and authorization model.
- Contract upgrade boundaries.
- Error handling and rollback behavior.
- Interaction between native assets, staking, DeFi modules, and wallet authorization.

## Status

The final Rust mainnet contracts are not included in this snapshot. They should receive a separate smart contract audit once implemented.
