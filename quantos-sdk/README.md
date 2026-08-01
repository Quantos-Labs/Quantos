# @quantos/sdk

Post-Quantum L1 SDK for the Quantos blockchain.

## Install

```bash
npm install @quantos/sdk
```

## Quick Start

```typescript
import { Quantos, formatQts, qtsToBigInt } from '@quantos/sdk'

const q = new Quantos({
  rpcUrl: 'https://rpc.quantos.io',
  apiKey: 'qnt_xxx', // optional, for RPC providers
})

// Read state
const balance = await q.getBalance('QTS:0102…ff')
console.log(formatQts(balance)) // "1.5 QTS"

const account = await q.getAccount('QTS:0102…ff')
console.log(account.is_validator, account.is_contract)

// Submit a signed transaction
const txHash = await q.sendRawTransaction('QTS:deadbeef…')

// WebSocket subscriptions
const unsub = await q.subscriptions.subscribeNewHeads((head) => {
  console.log(`new slot ${head.slot}, finalized ${head.finalized_slot}`)
})

// Later
await unsub()
q.close()
```

## Key Concepts

- **PQC-native**: signatures are ML-DSA-65 (FIPS 204), not ECDSA.
- **32-byte addresses**: `QTS:` + 64 hex chars (not 20 bytes like EVM).
- **`QTS:` prefix**: all hex values returned by the RPC use `QTS:` (not `0x`).
- **Zero gas fees**: `estimateGas` always returns `qts:0`.

## API

See `docs/RPC_SPEC.md` for the full RPC specification.

### Client methods

All `qnt_*` RPC methods are exposed directly on the `Quantos` instance:

| Method | RPC |
|---|---|
| `getBalance(addr)` | `qnt_getBalance` |
| `getAccount(addr)` | `qnt_getAccount` |
| `sendRawTransaction(hex)` | `qnt_sendRawTransaction` |
| `getTransactionByHash(hash)` | `qnt_getTransactionByHash` |
| `getTransactionReceipt(hash)` | `qnt_getTransactionReceipt` |
| `callContract(req)` | `qnt_call` |
| `getValidators()` | `qnt_getValidators` |
| `getRecentTransactions(limit)` | `qnt_getRecentTransactions` |
| `getLatestL0Proof()` | `qnt_getLatestL0Proof` |
| … | (37 methods total) |

### Subscriptions

```typescript
q.subscriptions.subscribeNewHeads(cb)
q.subscriptions.subscribeNewPendingTransactions(cb)
q.subscriptions.subscribe(kind, cb) // generic
```

### Utilities

```typescript
stripPrefix('QTS:de0b…')     // 'de0b…'
withPrefix('de0b…')          // 'QTS:de0b…'
qtsToBigInt('QTS:de0b…')     // BigInt
bigIntToQts(10n ** 18n)      // 'QTS:de0b6b3a7640000'
formatQts('QTS:de0b6b3a7640000') // '1.0 QTS'
```

## License

BUSL-1.1 — Quantos Labs SAS
