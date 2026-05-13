# Solana NFT Marketplace - Deployment Guide

## Program Overview
- **Program Name**: solana_nft_marketplace
- **Program ID**: GXoEvrpfLCh4zM8VCygDJ3f9Cq6jDJJHC7ip959JY1av
- **Network**: Devnet
- **Framework**: Anchor 0.29.0

## Deployment Methods

### Method 1: Solana Playground (Recommended - No Local Setup Required)

1. **Go to Solana Playground**
   - Visit: https://beta.solpg.io/

2. **Create New Project**
   - Click "New Project"
   - Select "Anchor" framework
   - Name it "nft-marketplace"

3. **Copy Program Code**
   - Replace the content of `programs/nft-marketplace/src/lib.rs` with the code from:
     `/Users/wayle/Quantos_labs/quantos/solana-programs/nft-marketplace/programs/solana-nft-marketplace/src/lib.rs`

4. **Update Cargo.toml**
   - Replace `programs/nft-marketplace/Cargo.toml` with:
     ```toml
     [package]
     name = "solana-nft-marketplace"
     version = "0.1.0"
     edition = "2021"

     [lib]
     crate-type = ["cdylib", "lib"]
     name = "solana_nft_marketplace"

     [dependencies]
     anchor-lang = "0.29.0"
     anchor-spl = "0.29.0"
     solana-program = "1.17.0"

     [profile.release]
     overflow-checks = true
     ```

5. **Build the Program**
   - Click the "Build" button in the toolbar
   - Wait for compilation to complete (~2-3 minutes)
   - Check the console for any errors

6. **Deploy to Devnet**
   - Ensure you're connected to Devnet (check dropdown)
   - Click "Deploy"
   - Confirm the transaction in your wallet
   - Note the deployed program ID

7. **Update Frontend**
   - Copy the deployed program ID
   - Update `vybss/src/lib/nft-multichain.ts`:
     ```typescript
     solana: {
       nftContract: 'YOUR_DEPLOYED_PROGRAM_ID',
       marketplaceContract: 'YOUR_DEPLOYED_PROGRAM_ID',
       // ... rest of config
     }
     ```

### Method 2: Docker Build + CLI Deploy

1. **Start Docker Desktop**
   ```bash
   # On macOS, start Docker Desktop application
   # Or via command line:
   open -a Docker
   ```

2. **Wait for Docker to Start**
   ```bash
   # Check Docker is running
   docker ps
   ```

3. **Build Program with Docker**
   ```bash
   cd /Users/wayle/Quantos_labs/quantos/solana-programs/nft-marketplace
   
   docker run --rm -v "$(pwd)":/workspace -w /workspace \
     projectserum/build:v0.29.0 anchor build
   ```

4. **Generate Deployer Keypair** (if you don't have one)
   ```bash
   solana-keygen new --outfile ~/.config/solana/deployer-keypair.json
   ```

5. **Fund Deployer Wallet**
   ```bash
   # Get your public key
   solana-keygen pubkey ~/.config/solana/deployer-keypair.json
   
   # Request airdrop (2 SOL for deployment)
   solana airdrop 2 YOUR_PUBLIC_KEY --url devnet
   ```

6. **Deploy Program**
   ```bash
   solana program deploy \
     target/deploy/solana_nft_marketplace.so \
     --keypair ~/.config/solana/deployer-keypair.json \
     --url devnet
   ```

7. **Verify Deployment**
   ```bash
   solana program show GXoEvrpfLCh4zM8VCygDJ3f9Cq6jDJJHC7ip959JY1av --url devnet
   ```

### Method 3: GitHub Actions (CI/CD - Automated)

Create `.github/workflows/deploy-solana.yml`:

```yaml
name: Deploy Solana Program

on:
  push:
    branches: [main]
    paths:
      - 'quantos/solana-programs/nft-marketplace/**'
  workflow_dispatch:

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Solana
        run: |
          sh -c "$(curl -sSfL https://release.solana.com/v1.18.15/install)"
          echo "$HOME/.local/share/solana/install/active_release/bin" >> $GITHUB_PATH
      
      - name: Install Anchor
        run: |
          cargo install --git https://github.com/coral-xyz/anchor --tag v0.29.0 anchor-cli --locked --force
      
      - name: Build Program
        run: |
          cd quantos/solana-programs/nft-marketplace
          anchor build
      
      - name: Deploy to Devnet
        env:
          DEPLOYER_KEYPAIR: ${{ secrets.SOLANA_DEPLOYER_KEYPAIR }}
        run: |
          echo "$DEPLOYER_KEYPAIR" > deployer.json
          solana program deploy \
            quantos/solana-programs/nft-marketplace/target/deploy/solana_nft_marketplace.so \
            --keypair deployer.json \
            --url devnet
```

## Post-Deployment Steps

### 1. Update Frontend Configuration

Edit `vybss/src/lib/nft-multichain.ts`:
```typescript
export const CHAIN_CONFIGS: Record<Chain, ChainConfig> = {
  // ... other chains
  solana: {
    chainId: 0,
    name: 'Solana Devnet',
    nftContract: 'YOUR_DEPLOYED_PROGRAM_ID', // Update this
    marketplaceContract: 'YOUR_DEPLOYED_PROGRAM_ID', // Update this
    rpcUrl: 'https://api.devnet.solana.com',
    nativeCurrency: { name: 'SOL', symbol: 'SOL', decimals: 9 }
  }
};
```

### 2. Test the Deployment

```bash
# Test minting on frontend
npm run dev

# Navigate to: http://localhost:5173/nft/evm-solana/create
# Select "Solana" as blockchain
# Try minting an NFT
```

### 3. Create Test Collections

```bash
# Use the frontend to create a test collection
# Or use Solana CLI to interact with the program
```

## Troubleshooting

### Build Errors

**Error: `overflow-checks` not enabled**
- Solution: Add to Cargo.toml:
  ```toml
  [profile.release]
  overflow-checks = true
  ```

**Error: Program ID mismatch**
- Solution: Run `anchor keys sync` after building

### Deployment Errors

**Error: Insufficient SOL**
- Solution: Request more from faucet:
  ```bash
  solana airdrop 2 YOUR_WALLET --url devnet
  ```

**Error: Program account not large enough**
- Solution: Increase max program size in `Anchor.toml`:
  ```toml
  [programs.devnet]
  solana_nft_marketplace = "GXoEvrpfLCh4zM8VCygDJ3f9Cq6jDJJHC7ip959JY1av"
  
  [provider]
  cluster = "devnet"
  wallet = "~/.config/solana/id.json"
  
  [[programs.devnet.deploy]]
  max_len = 1000000  # Increase this
  ```

### Runtime Errors

**Error: Wallet not connected**
- Ensure Phantom/Solflare wallet is installed and connected
- Check wallet is set to Devnet

**Error: Transaction simulation failed**
- Check program logs: `solana logs --url devnet`
- Verify account structures match program expectations

## Program Architecture

### Instructions
1. **create_collection**: Create an NFT collection
2. **mint_nft**: Mint NFT (simplified - metadata via Metaplex client-side)
3. **list_nft**: List NFT for sale
4. **buy_nft**: Purchase listed NFT (enforces 1% fee + royalties)
5. **cancel_listing**: Cancel active listing

### Fee Structure
- **Marketplace Fee**: 1% (100 bps) → Treasury: `AobEygkdL7kcLETvmhgU7ejUkUpzER5KeEdrfDtzUHKE`
- **Royalties**: 2.5% default → NFT creator
- **Treasury Validation**: Buy transaction requires correct fee recipient

### Accounts
- **Collection**: Stores collection metadata
- **Listing**: Stores listing details (price, expiry, royalty info)
- **Escrow Authority**: PDA that holds NFTs during listing

## Security Notes

1. **Treasury Address**: Hardcoded in program for security
2. **Royalty Enforcement**: Buyer must provide correct royalty recipient
3. **Escrow PDA**: Prevents seller from withdrawing during listing
4. **Expiry**: Listings can have optional expiration timestamp

## Next Steps After Deployment

1. ✅ Update frontend config with program ID
2. ✅ Test minting on devnet
3. ✅ Test listing/buying flow
4. ✅ Verify fee distribution
5. ⏳ Audit smart contract before mainnet
6. ⏳ Deploy to mainnet
7. ⏳ Update frontend to mainnet config

## Resources

- Solana Playground: https://beta.solpg.io/
- Solana Devnet Faucet: https://faucet.solana.com/
- Anchor Docs: https://www.anchor-lang.com/
- Solana Program Library: https://spl.solana.com/
- Metaplex Docs: https://docs.metaplex.com/
