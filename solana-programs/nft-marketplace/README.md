# Solana NFT Marketplace Program

Production-grade Solana program for NFT marketplace with Metaplex integration.

## Features

- ✅ Create NFT collections
- ✅ Mint NFTs with Metaplex Token Metadata
- ✅ Master Edition support (true NFTs with supply = 1)
- ✅ List NFTs for sale in escrow
- ✅ Buy/sell NFTs with royalty enforcement
- ✅ Cancel listings
- ✅ Configurable marketplace fees
- ✅ Collection-level royalties

## Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Solana CLI
sh -c "$(curl -sSfL https://release.solana.com/stable/install)"

# Install Anchor
cargo install --git https://github.com/coral-xyz/anchor avm --locked --force
avm install latest
avm use latest
```

## Project Structure

```
solana-programs/nft-marketplace/
├── Cargo.toml          # Rust dependencies
├── Anchor.toml         # Anchor configuration
├── lib.rs              # Main program code
└── README.md           # This file
```

## Build & Test

### 1. Build the program

```bash
cd /Users/wayle/Quantos_labs/quantos/solana-programs/nft-marketplace

# Build
anchor build

# Get program ID
solana address -k target/deploy/solana_nft_marketplace-keypair.json
```

### 2. Update Program ID

Copy the generated program ID and update in `lib.rs`:

```rust
declare_id!("YOUR_PROGRAM_ID_HERE");
```

Then rebuild:

```bash
anchor build
```

### 3. Run tests

```bash
anchor test
```

## Deployment

### Devnet Deployment

```bash
# Configure for devnet
solana config set --url devnet

# Airdrop SOL for deployment
solana airdrop 2

# Deploy program
anchor deploy

# Verify deployment
solana program show <PROGRAM_ID>
```

### Mainnet Deployment

```bash
# Configure for mainnet
solana config set --url mainnet-beta

# Ensure wallet has sufficient SOL for deployment (~5-10 SOL)
solana balance

# Deploy
anchor deploy --provider.cluster mainnet

# Verify
solana program show <PROGRAM_ID>
```

## Usage Examples

### Create Collection

```typescript
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SolanaNftMarketplace } from "../target/types/solana_nft_marketplace";

const program = anchor.workspace.SolanaNftMarketplace as Program<SolanaNftMarketplace>;

const collection = anchor.web3.Keypair.generate();

await program.methods
  .createCollection(
    "My NFT Collection",  // name
    "MNC",                // symbol
    "ipfs://...",         // uri
    500                   // royalty_bps (5%)
  )
  .accounts({
    collection: collection.publicKey,
    authority: wallet.publicKey,
    systemProgram: anchor.web3.SystemProgram.programId,
  })
  .signers([collection])
  .rpc();
```

### Mint NFT

```typescript
const nftMint = anchor.web3.Keypair.generate();
const tokenAccount = await getAssociatedTokenAddress(
  nftMint.publicKey,
  wallet.publicKey
);

// Derive Metaplex PDAs
const [metadata] = PublicKey.findProgramAddressSync(
  [
    Buffer.from("metadata"),
    METADATA_PROGRAM_ID.toBuffer(),
    nftMint.publicKey.toBuffer(),
  ],
  METADATA_PROGRAM_ID
);

const [masterEdition] = PublicKey.findProgramAddressSync(
  [
    Buffer.from("metadata"),
    METADATA_PROGRAM_ID.toBuffer(),
    nftMint.publicKey.toBuffer(),
    Buffer.from("edition"),
  ],
  METADATA_PROGRAM_ID
);

await program.methods
  .mintNft(
    "My NFT #1",          // name
    "MNC",                // symbol
    "ipfs://metadata"     // uri
  )
  .accounts({
    collection: collectionPubkey,
    nftMint: nftMint.publicKey,
    tokenAccount,
    metadata,
    masterEdition,
    minter: wallet.publicKey,
    rent: anchor.web3.SYSVAR_RENT_PUBKEY,
    systemProgram: anchor.web3.SystemProgram.programId,
    tokenProgram: TOKEN_PROGRAM_ID,
    associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
  })
  .signers([nftMint])
  .rpc();
```

### List NFT for Sale

```typescript
const listing = anchor.web3.Keypair.generate();
const escrowTokenAccount = await getAssociatedTokenAddress(
  nftMint.publicKey,
  escrowAuthority,  // PDA derived from seeds
  true
);

await program.methods
  .listNft(
    new anchor.BN(1_000_000_000), // price (1 SOL)
    new anchor.BN(0)               // expiry (0 = no expiration)
  )
  .accounts({
    listing: listing.publicKey,
    nftMint: nftMint.publicKey,
    sellerNftAccount: sellerTokenAccount,
    escrowNftAccount: escrowTokenAccount,
    seller: wallet.publicKey,
    tokenProgram: TOKEN_PROGRAM_ID,
    systemProgram: anchor.web3.SystemProgram.programId,
  })
  .signers([listing])
  .rpc();
```

### Buy NFT

```typescript
await program.methods
  .buyNft()
  .accounts({
    listing: listingPubkey,
    seller: sellerPubkey,
    buyer: wallet.publicKey,
    buyerNftAccount,
    escrowNftAccount,
    escrowAuthority,
    feeRecipient: marketplaceFeeRecipient,
    royaltyRecipient: collectionRoyaltyRecipient,
    tokenProgram: TOKEN_PROGRAM_ID,
  })
  .rpc();
```

## Program Accounts

### Collection
- `authority`: Collection creator/owner
- `name`: Collection name
- `symbol`: Collection symbol
- `uri`: Collection metadata URI
- `royalty_bps`: Royalty percentage in basis points (e.g., 500 = 5%)
- `total_minted`: Total NFTs minted from collection

### Listing
- `seller`: NFT seller address
- `nft_mint`: NFT mint address
- `price`: Listing price in lamports
- `expiry`: Expiration timestamp (0 = never expires)
- `royalty_bps`: Royalty to enforce on sale
- `is_active`: Listing status

## Security Considerations

1. **Royalty Enforcement**: Royalties are enforced on-chain during sales
2. **Escrow Security**: NFTs are held in PDAs during listing
3. **Reentrancy Protection**: State changes before external calls
4. **Authority Checks**: Strict signer/ownership verification
5. **Overflow Protection**: Using checked arithmetic

## Testing

Create test file `tests/nft-marketplace.ts`:

```typescript
import * as anchor from "@coral-xyz/anchor";
import { expect } from "chai";

describe("solana-nft-marketplace", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  it("Creates a collection", async () => {
    // Test implementation
  });

  it("Mints an NFT", async () => {
    // Test implementation
  });

  it("Lists NFT for sale", async () => {
    // Test implementation
  });

  it("Buys listed NFT", async () => {
    // Test implementation
  });

  it("Cancels listing", async () => {
    // Test implementation
  });
});
```

Run tests:
```bash
anchor test
```

## Monitoring

After deployment, monitor the program:

```bash
# Check program account
solana program show <PROGRAM_ID>

# View program logs
solana logs <PROGRAM_ID>

# Check program size
solana program dump <PROGRAM_ID> program.so
ls -lh program.so
```

## Upgrading

If you need to upgrade the program:

```bash
# Build new version
anchor build

# Upgrade (requires upgrade authority)
solana program deploy \
  --program-id <PROGRAM_ID> \
  --upgrade-authority <AUTHORITY_KEYPAIR> \
  target/deploy/solana_nft_marketplace.so
```

## Troubleshooting

### "Program failed to complete"
- Check account sizes are sufficient
- Verify all required accounts are provided
- Check signer requirements

### "Invalid account data"
- Ensure accounts are initialized in correct order
- Verify account discriminators match

### "Insufficient funds"
- Airdrop more SOL: `solana airdrop 2`
- Check transaction fees

## Resources

- [Anchor Documentation](https://www.anchor-lang.com/)
- [Metaplex Token Metadata](https://docs.metaplex.com/programs/token-metadata/)
- [Solana Cookbook](https://solanacookbook.com/)
- [Solana Program Library](https://spl.solana.com/)

## License

MIT

## Support

For issues or questions, please contact the development team.
