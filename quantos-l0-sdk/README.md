# Quantos L0 SDK

Post-Quantum Finality Proof client for all chains supported by the Quantos L0 hub.

## Install

```bash
npm install @quantos/l0-sdk
```

## Quick Start

```typescript
import { QuantosL0SDK, ChainFamily } from '@quantos/l0-sdk';

const sdk = new QuantosL0SDK({
  quantos: { rpcUrl: 'http://127.0.0.1:8555' },
  targets: [
    {
      chainId: 'base',
      family: ChainFamily.Evm,
      endpoint: 'https://base.llamarpc.com',
      verifierAddress: '0x...',
    },
    {
      chainId: 'solana',
      family: ChainFamily.Svm,
      endpoint: 'https://api.mainnet-beta.solana.com',
      verifierAddress: 'QNTSL0Vrf...',
    },
  ],
});

// 1. Fetch the latest L0 proof
const proof = await sdk.getLatestProof();

// 2. Verify off-chain (stake-weighted check)
const offChain = sdk.verifyOffChain(proof!, 2n, 3n); // 2/3 threshold
console.log('Off-chain valid:', offChain.valid);

// 3. Verify on-chain (Base EVM)
const onChain = await sdk.verifyOnChain('base', proof!, offChain.signedStake);
console.log('On-chain verified:', onChain.verified, 'tx:', onChain.txHash);
```

## Supported Chains

| Chain | Family | Adapter Class |
|---|---|---|
| Ethereum / Base / Monad / Arbitrum | EVM | `EvmAdapter` |
| Solana | SVM | `SolanaAdapter` |
| Sui | Move | `SuiAdapter` |
| Aptos | Move | `AptosAdapter` |
| NEAR Protocol | Near | `NearAdapter` |
| Cosmos Hub | Cosmos | `CosmosAdapter` |
| Polkadot / ink! | Wasm | `PolkadotAdapter` |
| Stellar / Soroban | Stellar | `StellarAdapter` |
| TON | Ton | `TonAdapter` |
| Cardano | Cardano | `CardanoAdapter` |
| Bitcoin (Stacks) | Stacks | `StacksAdapter` |

## Architecture

```
Quantos L1
   │
   ▼
FinalityHub ──▶ L0FinalityProof
   │
   ▼
RelayDispatcher ──▶ 12 chain adapters
   │
   ▼
Target chain verifier contract
   │
   ▼
App (bridge, DEX, DAO, oracle...)
```

## API Reference

### `QuantosNodeClient`

- `getFinalizedSlot()` → `Promise<number>`
- `getLatestProof()` → `Promise<L0FinalityProof | null>`
- `getProofByHash(hash)` → `Promise<L0FinalityProof | null>`
- `submitExternalCheckpoint(checkpoint, signature)` → `Promise<string>`

### `ExternalVerifier`

- `verify(proof, options)` → `{ valid, signedStake, totalStake, fraction, reason? }`
- `proofDigest(proof)` → canonical SHA-256 digest

### `QuantosL0SDK`

- `getLatestProof()` → fetch from Quantos node
- `verifyOffChain(proof, thresholdNum, thresholdDen)` → stake-weighted check
- `verifyOnChain(chainId, proof, signedStake)` → call target chain contract
- `isProofVerified(chainId, proofHash)` → read target chain state
- `isDepositRelayed(chainId, depositId)` → read target chain state

## License

Business Source License 1.1 (**BUSL-1.1**) — Quantos Labs SAS

See the [LICENSE](../LICENSE) file in the project root for the full license text.
