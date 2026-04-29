# Audit Scope

## In Scope

- Quantos blockchain core implementation.
- Consensus and networking logic.
- Execution layer and deterministic WASM runtime.
- Post-quantum signature integration and related cryptographic assumptions.
- Resource-based mainnet contract architecture and invariants.
- Wallet/key-management core if explicitly confirmed in the audit engagement.

## Conditional / Optional Scope

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
