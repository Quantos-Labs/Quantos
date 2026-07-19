# Quantos L0 Relayer

Universal relayer that submits external chain checkpoints to Quantos L0 for PQC finality certification.

## Features

- **Multi-chain support**: Ethereum, Base, Arbitrum, Optimism, Polygon, Avalanche, BSC, Solana, NEAR, Aptos, Sui, TON, Bitcoin, Stellar, Polkadot, Tron, Cosmos, Cardano
- **Automatic checkpoint submission**: Monitors source chains and submits finalized blocks to Quantos
- **PQC finality proofs**: Retrieves post-quantum cryptographic proofs from Quantos validators
- **Health monitoring**: Built-in health check endpoint for monitoring

## Setup

1. Install dependencies:
```bash
npm install
```

2. Configure environment:
```bash
cp .env.example .env
# Edit .env with your RPC URLs and settings
```

3. Build:
```bash
npm run build
```

4. Run:
```bash
npm start
```

## Configuration

### Environment Variables

- `QUANTOS_RPC_URL`: Quantos node RPC endpoint
- `SOURCE_CHAINS`: Comma-separated list of chains to monitor
- `POLL_INTERVAL`: Polling interval in seconds (default: 12)
- `MIN_CONFIRMATIONS`: Minimum confirmations before submitting (default: 6)
- `HEALTH_PORT`: Health check server port (default: 3200)

### Supported Chains

**EVM Chains:**
- ethereum, ethereum-sepolia
- base, base-sepolia
- arbitrum, arbitrum-sepolia
- optimism, optimism-sepolia
- polygon, polygon-amoy
- avalanche, avalanche-fuji
- bsc, bsc-testnet

**Non-EVM Chains (coming soon):**
- solana, solana-devnet
- near, near-testnet
- aptos, aptos-testnet
- sui, sui-testnet
- ton, ton-testnet
- bitcoin, bitcoin-testnet
- stellar, stellar-testnet
- polkadot, polkadot-testnet
- tron, tron-shasta
- cosmos, cosmos-testnet
- cardano, cardano-testnet

## Health Check

```bash
curl http://localhost:3200/health
```

Response:
```json
{
  "status": "ok",
  "timestamp": "2026-05-24T14:00:00.000Z",
  "chains": ["ethereum-sepolia", "base-sepolia"],
  "l0_metrics": {
    "proofs_produced": 1234,
    "proofs_failed": 5,
    "archived_proofs": 100
  }
}
```

## How It Works

1. **Monitor Source Chains**: Relayer polls configured chains for new finalized blocks
2. **Submit Checkpoints**: When a block has enough confirmations, submit it to Quantos via `qnt_submitExternalCheckpoint`
3. **Quantos Validation**: Quantos validators verify the checkpoint and sign with PQC signatures (Falcon-512/ML-DSA-65)
4. **Proof Generation**: Quantos L0 hub generates a PQC finality proof
5. **Proof Retrieval**: Relayer can fetch proofs via `qnt_getL0Proof` for relay back to source chain

## Architecture

```
Source Chain (e.g. Ethereum)
        │
        ▼
    [Relayer] ──────► Quantos L0 Hub
        │                    │
        │                    ▼
        │            PQC Validators Sign
        │                    │
        │                    ▼
        └────────◄── L0FinalityProof
                            │
                            ▼
                    Source Chain Verifier
                    (finalizeBlock)
```

## Development

```bash
npm run dev
```

## License

MIT
