# NFT Multichain Deployment Guide

## Overview
This guide explains how to deploy the NFT marketplace contracts to multiple EVM testnets and Solana devnet.

## Smart Contracts

### EVM Contracts
- **MultichainNFT.sol**: ERC-721 NFT contract with creator royalties (EIP-2981)
- **MultichainNFTMarketplace.sol**: Marketplace contract with 1% platform fee and royalty enforcement

### Supported Networks
1. Base Sepolia (Testnet) / Base (Mainnet)
2. Arbitrum Sepolia (Testnet) / Arbitrum One (Mainnet)
3. BSC Testnet / BSC Mainnet
4. Polygon Amoy (Testnet) / Polygon (Mainnet)
5. HyperEVM Testnet (Hyperliquid)
6. Solana Devnet / Mainnet

## Fee Structure
- **Platform Fee**: 1% of sale price → Goes to treasury wallet
- **Royalties**: 2.5% default → Goes to NFT creator
- **Treasury Wallets**:
  - EVM: `0x44A9Eb810ffAFb611b4a00E6217A87ff3e762ba7`
  - Solana: `AobEygkdL7kcLETvmhgU7ejUkUpzER5KeEdrfDtzUHKE`

## EVM Deployment

### Prerequisites
```bash
cd quantos/solidity-contracts/nft-multichain
npm install
```

### Environment Setup
1. Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

2. Fill in your deployer wallet private key:
```
PRIVATE_KEY=your_private_key_here
```

3. Fund your deployer wallet with testnet tokens:
- **Base Sepolia**: https://www.coinbase.com/faucets/base-ethereum-goerli-faucet
- **Arbitrum Sepolia**: https://faucet.triangleplatform.com/arbitrum/sepolia
- **BSC Testnet**: https://testnet.bnbchain.org/faucet-smart
- **Polygon Amoy**: https://faucet.polygon.technology/

### Compile Contracts
```bash
npx hardhat compile
```

### Deploy to Testnets

Deploy to all testnets:
```bash
# Base Sepolia
npx hardhat run scripts/deploy.ts --network baseTestnet

# Arbitrum Sepolia
npx hardhat run scripts/deploy.ts --network arbitrumTestnet

# BSC Testnet
npx hardhat run scripts/deploy.ts --network bscTestnet

# Polygon Amoy
npx hardhat run scripts/deploy.ts --network polygonTestnet

# HyperEVM Testnet
npx hardhat run scripts/deploy.ts --network hyperevmTestnet
```

### Verify Contracts (Optional)
After deployment, verify on block explorers:
```bash
npx hardhat verify --network baseTestnet <NFT_ADDRESS> "Quantos NFT" "QNFT" "0x44A9Eb810ffAFb611b4a00E6217A87ff3e762ba7" 250

npx hardhat verify --network baseTestnet <MARKETPLACE_ADDRESS> "0x44A9Eb810ffAFb611b4a00E6217A87ff3e762ba7" 100
```

## Solana Deployment

### Prerequisites
1. Install Solana CLI and Anchor framework
2. Generate/configure deployer wallet

### Deployment Methods

#### Option 1: Local Build (Requires Solana/Anchor CLI)
```bash
cd quantos/solana-programs/nft-marketplace
anchor build
anchor deploy --provider.cluster devnet
```

#### Option 2: Solana Playground (Recommended for Quick Testing)
1. Go to https://beta.solpg.io/
2. Create new project
3. Copy code from `programs/solana-nft-marketplace/src/lib.rs`
4. Build and deploy via the web interface

#### Option 3: Docker (Reproducible Builds)
```bash
docker run --rm -v $(pwd):/workspace -w /workspace projectserum/build:v0.29.0 anchor build
solana program deploy target/deploy/solana_nft_marketplace.so --url devnet
```

### Update Program ID
After deployment, update:
1. `Anchor.toml` - Set the deployed program ID
2. Frontend `vybss/src/lib/nft-multichain.ts` - Update `SOLANA_PROGRAM_ID`

## Frontend Integration

### Update Contract Addresses
After deploying all contracts, update `vybss/src/lib/nft-multichain.ts`:

```typescript
const CHAIN_CONFIGS = {
  base: {
    nftContract: "0x...",  // Deployed MultichainNFT address
    marketplaceContract: "0x...",  // Deployed MultichainNFTMarketplace address
  },
  arbitrum: { /* ... */ },
  bsc: { /* ... */ },
  polygon: { /* ... */ },
  hyperevm: { /* ... */ },
  solana: {
    programId: "...",  // Deployed Solana program ID
  }
};
```

## Testing Deployment

### EVM Testing
```bash
# Interact via Hardhat console
npx hardhat console --network baseTestnet

# Test minting
const NFT = await ethers.getContractFactory("MultichainNFT");
const nft = await NFT.attach("DEPLOYED_ADDRESS");
await nft.mint(yourAddress, "ipfs://...", { value: ethers.parseEther("0.01") });
```

### Solana Testing
```bash
# Using Anchor
anchor test --provider.cluster devnet

# Using Solana CLI
solana program show <PROGRAM_ID> --url devnet
```

## Troubleshooting

### EVM Issues
- **Out of gas**: Increase gas limit in deployment script
- **Nonce too low**: Wait a few blocks or reset nonce
- **Verification fails**: Check constructor arguments match deployment

### Solana Issues
- **Build fails**: Check Anchor version matches (0.29.0)
- **Insufficient SOL**: Fund deployer with `solana airdrop 2 --url devnet`
- **Program ID mismatch**: Run `anchor keys sync` after generating keypair

## Production Deployment Checklist

Before mainnet deployment:
- [ ] Audit smart contracts
- [ ] Test all functions on testnet
- [ ] Verify treasury wallet addresses
- [ ] Configure multisig for contract ownership
- [ ] Set up monitoring and alerts
- [ ] Prepare upgrade strategy
- [ ] Document all deployed addresses
- [ ] Update frontend with mainnet addresses
- [ ] Test frontend with mainnet contracts

## Contract Addresses (To be filled after deployment)

### Testnet
- **Base Sepolia**: 
  - NFT: `TBD`
  - Marketplace: `TBD`
- **Arbitrum Sepolia**: 
  - NFT: `TBD`
  - Marketplace: `TBD`
- **BSC Testnet**: 
  - NFT: `TBD`
  - Marketplace: `TBD`
- **Polygon Amoy**: 
  - NFT: `TBD`
  - Marketplace: `TBD`
- **Solana Devnet**: 
  - Program ID: `GXoEvrpfLCh4zM8VCygDJ3f9Cq6jDJJHC7ip959JY1av`

### Mainnet
- **Base**: TBD
- **Arbitrum**: TBD
- **BSC**: TBD
- **Polygon**: TBD
- **HyperEVM**: TBD
- **Solana**: TBD
