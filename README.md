# Quantos Audit Repository

This repository is a dedicated private audit snapshot for Quantos.

It contains only the blockchain audit scope shared with CertiK:

- `quantos/` — Quantos blockchain core, runtime, consensus, node, SDK, tests, and testnet prototypes.
- `quantos-wallet-core/` — wallet/key-management core library, included in audit scope.
- `docs/` — audit scope, threat model, protocol overview, and mainnet contract model notes.

Out of scope:

- Vybss consumer app frontend/backend.
- Landing pages, bots, marketing services, and unrelated Kai/Vybss product code.
- Local environment files, logs, runtime state, and testnet data.

Important note: Solidity contracts currently present under `quantos/solidity-contracts/` are testnet prototypes used to validate product flows. They are not the final mainnet smart contracts. Mainnet contracts are expected to be implemented in Rust using Quantos' resource-based smart contract model.
