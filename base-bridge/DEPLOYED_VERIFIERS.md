# Quantos L0 Verifier — Deployed Addresses

## EVM Chains (Solidity — QuantosL0Verifier.sol)

| Chain | Network | Address | Deployer |
|-------|---------|---------|----------|
| Base | Sepolia | TBD | TBD |
| Ethereum | Sepolia | TBD | TBD |
| Arbitrum | Sepolia | TBD | TBD |
| Optimism | Sepolia | TBD | TBD |
| Polygon | Amoy | TBD | TBD |
| Avalanche | Fuji | TBD | TBD |
| BSC | Testnet | TBD | TBD |

## Non-EVM Chains

| Chain | Network | Program ID / Account | Status |
|-------|---------|---------------------|--------|
| Solana | Devnet | QNTSL0Vrf5erXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX | Ready to deploy |
| NEAR | Testnet | TBD | Ready to deploy |
| Aptos | Testnet | TBD | Ready to deploy |
| Sui | Testnet | TBD | Ready to deploy |
| Cosmos | Testnet | TBD | Ready to deploy |
| Stellar | Testnet | TBD | Ready to deploy |
| TON | Testnet | TBD | Ready to deploy |
| Tron | Shasta | TBD | Ready to deploy |
| Polkadot | Testnet | TBD | Ready to deploy |
| Cardano | Preview | TBD | Ready to deploy |
| Bitcoin/Stacks | Testnet | TBD | Ready to deploy |

## Deployment Commands

### EVM (Base Sepolia example)
```bash
cd base-bridge
npx hardhat run scripts/deploy-l0-verifier.js --network baseSepolia
npx hardhat run scripts/register-validator-set.js --network baseSepolia
```

### Solana
```bash
cd base-bridge/solana
anchor build
anchor deploy --provider.cluster devnet
```

### NEAR
```bash
cd base-bridge/near
cargo near build
near deploy <account-id> ./target/near/quantos_l0_verifier.wasm
```

### Aptos
```bash
cd base-bridge/aptos
aptos move compile
aptos move publish --profile testnet
```
