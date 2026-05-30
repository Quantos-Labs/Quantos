# Bridge Relayer

Production off-chain relayer for the Quantos <-> Base bridge.

## Architecture

```
Quantos Node ─── [deposit QTEST to vault] ───> Supabase bridge_deposits
                                                        │
                                                        ▼
                                                Bridge Relayer (this service)
                                                        │
                                                        ▼
Base Sepolia ─── [mintFromQuantos on gateway] ──> wQTEST minted
```

## Flow (Quantos -> Base)

1. User deposits QTEST to vault via wallet-server
2. Frontend writes deposit record to Supabase `bridge_deposits` table
3. Relayer polls Supabase for `status = 'pending'` deposits
4. Relayer verifies the Quantos receipt on-chain (RPC)
5. Relayer calls `mintFromQuantos()` on `BaseBridgeGateway`
6. Relayer updates Supabase record with Base tx hash and `status = 'completed'`
7. Frontend reads updated status from Supabase

## Setup

```bash
# 1. Install dependencies
npm install

# 2. Configure environment
cp .env.example .env
# Fill in all values in .env

# 3. Run the Supabase migration
# Copy bridge_deposits_schema.sql into Supabase SQL Editor and run it

# 4. Deploy Base contracts (if not already deployed)
cd ../base-bridge
cp .env.example .env
# Fill in DEPLOYER_PRIVATE_KEY, OWNER_ADDRESS, RELAYER_ADDRESS, QUANTOS_CHAIN_ID
npm run deploy:base-sepolia
# Note the deployed addresses and set them in bridge-relayer/.env

# 5. Start the relayer
npm start
```

## API Endpoints (Health Server)

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Relayer status |
| `GET /stats` | Detailed stats (DB + Base) |
| `GET /deposits` | Recent deposits |
| `GET /deposit/:txHash` | Lookup by Quantos tx hash |
| `GET /balance/:address` | wQTEST balance check |

Default port: `3100`

## Environment Variables

See `.env.example` for all required variables.

## Production Deployment

```bash
# Build
npm run build

# Run compiled
npm run start:prod

# Or with process manager
pm2 start dist/index.js --name bridge-relayer
```
