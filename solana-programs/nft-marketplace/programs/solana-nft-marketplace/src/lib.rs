/**
 * Solana NFT Marketplace Program (Anchor)
 * 
 * This is a basic Anchor program structure for the Solana NFT marketplace.
 * Supports: NFT minting, collection creation, listings, offers
 * 
 * To use:
 * 1. Install Anchor: https://www.anchor-lang.com/docs/installation
 * 2. Initialize Anchor project: anchor init solana-nft-marketplace
 * 3. Replace programs/solana-nft-marketplace/src/lib.rs with this structure
 * 4. Build: anchor build
 * 5. Test: anchor test
 * 6. Deploy: anchor deploy --provider.cluster devnet
 * 
 * Dependencies in Cargo.toml:
 * [dependencies]
 * anchor-lang = "0.29.0"
 * anchor-spl = "0.29.0"
 * mpl-token-metadata = "3.2.3"
 * 
 * Note: This is a Rust program structure placeholder.
 * Full implementation requires Rust/Anchor expertise.
 */

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke_signed;
use anchor_spl::token::{self, Token, TokenAccount, Mint, MintTo};
use anchor_spl::associated_token::AssociatedToken;
use std::str::FromStr;

declare_id!("GXoEvrpfLCh4zM8VCygDJ3f9Cq6jDJJHC7ip959JY1av");

const SOLANA_TREASURY_ADDRESS: &str = "AobEygkdL7kcLETvmhgU7ejUkUpzER5KeEdrfDtzUHKE";

fn solana_treasury() -> Pubkey {
    Pubkey::from_str(SOLANA_TREASURY_ADDRESS).expect("invalid Solana treasury address")
}

#[program]
pub mod solana_nft_marketplace {
    use super::*;

    /**
     * Create NFT Collection
     */
    pub fn create_collection(
        ctx: Context<CreateCollection>,
        name: String,
        symbol: String,
        uri: String,
        royalty_bps: u16,
    ) -> Result<()> {
        let collection = &mut ctx.accounts.collection;
        collection.authority = ctx.accounts.authority.key();
        collection.name = name;
        collection.symbol = symbol;
        collection.uri = uri;
        collection.royalty_bps = royalty_bps;
        collection.total_minted = 0;
        Ok(())
    }

    /**
     * Mint NFT from Collection
     * Simplified version - metadata creation handled client-side via Metaplex JS SDK
     */
    pub fn mint_nft(
        ctx: Context<MintNFT>,
        name: String,
        symbol: String,
        uri: String,
    ) -> Result<()> {
        // Mint 1 token to the NFT mint account
        token::mint_to(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                MintTo {
                    mint: ctx.accounts.nft_mint.to_account_info(),
                    to: ctx.accounts.token_account.to_account_info(),
                    authority: ctx.accounts.minter.to_account_info(),
                },
            ),
            1, // Mint exactly 1 NFT
        )?;

        // Update collection total minted
        let collection = &mut ctx.accounts.collection;
        collection.total_minted += 1;
        
        msg!("NFT minted: {} ({}) - Token ID: {}", name, collection.total_minted, ctx.accounts.nft_mint.key());
        msg!("Note: Metadata creation should be done client-side using @metaplex-foundation/js");
        Ok(())
    }

    /**
     * List NFT for Sale
     */
    pub fn list_nft(
        ctx: Context<ListNFT>,
        price: u64,
        expiry: i64,
    ) -> Result<()> {
        let listing = &mut ctx.accounts.listing;
        listing.seller = ctx.accounts.seller.key();
        listing.nft_mint = ctx.accounts.nft_mint.key();
        listing.price = price;
        listing.expiry = expiry;
        listing.royalty_bps = ctx.accounts.collection.royalty_bps;
        listing.royalty_recipient = ctx.accounts.collection.authority;
        listing.is_active = true;
        
        // Transfer NFT to escrow
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.seller_nft_account.to_account_info(),
                    to: ctx.accounts.escrow_nft_account.to_account_info(),
                    authority: ctx.accounts.seller.to_account_info(),
                },
            ),
            1,
        )?;
        
        msg!("NFT listed for {} lamports", price);
        Ok(())
    }

    /**
     * Buy Listed NFT
     */
    pub fn buy_nft(ctx: Context<BuyNFT>) -> Result<()> {
        let listing = &mut ctx.accounts.listing;
        require!(listing.is_active, ErrorCode::ListingNotActive);
        require_keys_eq!(ctx.accounts.fee_recipient.key(), solana_treasury(), ErrorCode::InvalidFeeRecipient);
        require_keys_eq!(ctx.accounts.royalty_recipient.key(), listing.royalty_recipient, ErrorCode::InvalidRoyaltyRecipient);
        
        let clock = Clock::get()?;
        if listing.expiry > 0 {
            require!(clock.unix_timestamp < listing.expiry, ErrorCode::ListingExpired);
        }
        
        let price = listing.price;
        let marketplace_fee = price * 100 / 10000; // 1% fee
        let royalty_fee = price * listing.royalty_bps as u64 / 10000;
        let seller_proceeds = price - marketplace_fee - royalty_fee;
        
        // Transfer SOL to seller
        **ctx.accounts.buyer.try_borrow_mut_lamports()? -= price;
        **ctx.accounts.seller.try_borrow_mut_lamports()? += seller_proceeds;
        **ctx.accounts.fee_recipient.try_borrow_mut_lamports()? += marketplace_fee;
        
        // Transfer royalty if applicable
        if royalty_fee > 0 {
            **ctx.accounts.royalty_recipient.try_borrow_mut_lamports()? += royalty_fee;
        }
        
        // Transfer NFT to buyer
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.escrow_nft_account.to_account_info(),
                    to: ctx.accounts.buyer_nft_account.to_account_info(),
                    authority: ctx.accounts.escrow_authority.to_account_info(),
                },
                &[&[b"escrow", &[ctx.bumps.escrow_authority]]],
            ),
            1,
        )?;
        
        listing.is_active = false;
        
        msg!("NFT sold for {} lamports", price);
        Ok(())
    }

    /**
     * Cancel Listing
     */
    pub fn cancel_listing(ctx: Context<CancelListing>) -> Result<()> {
        let listing = &mut ctx.accounts.listing;
        require!(listing.is_active, ErrorCode::ListingNotActive);
        
        // Return NFT to seller
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.escrow_nft_account.to_account_info(),
                    to: ctx.accounts.seller_nft_account.to_account_info(),
                    authority: ctx.accounts.escrow_authority.to_account_info(),
                },
                &[&[b"escrow", &[ctx.bumps.escrow_authority]]],
            ),
            1,
        )?;
        
        listing.is_active = false;
        
        msg!("Listing cancelled");
        Ok(())
    }
}

// ============================================================================
// ACCOUNT STRUCTURES
// ============================================================================

#[derive(Accounts)]
pub struct CreateCollection<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Collection::INIT_SPACE,
    )]
    pub collection: Account<'info, Collection>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct MintNFT<'info> {
    #[account(mut)]
    pub collection: Account<'info, Collection>,
    
    #[account(
        init,
        payer = minter,
        mint::decimals = 0,
        mint::authority = minter,
        mint::freeze_authority = minter,
    )]
    pub nft_mint: Account<'info, Mint>,
    
    #[account(
        init,
        payer = minter,
        associated_token::mint = nft_mint,
        associated_token::authority = minter,
    )]
    pub token_account: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub minter: Signer<'info>,
    
    pub rent: Sysvar<'info, Rent>,
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}

#[derive(Accounts)]
pub struct ListNFT<'info> {
    #[account(
        init,
        payer = seller,
        space = 8 + Listing::INIT_SPACE,
    )]
    pub listing: Account<'info, Listing>,

    pub collection: Account<'info, Collection>,
    
    pub nft_mint: Account<'info, Mint>,
    
    #[account(mut)]
    pub seller_nft_account: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub escrow_nft_account: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub seller: Signer<'info>,
    
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct BuyNFT<'info> {
    #[account(mut)]
    pub listing: Account<'info, Listing>,
    
    #[account(mut)]
    pub seller: SystemAccount<'info>,
    
    #[account(mut)]
    pub buyer: Signer<'info>,
    
    #[account(mut)]
    pub buyer_nft_account: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub escrow_nft_account: Account<'info, TokenAccount>,
    
    /// CHECK: Escrow authority PDA
    #[account(seeds = [b"escrow"], bump)]
    pub escrow_authority: UncheckedAccount<'info>,
    
    #[account(mut)]
    pub fee_recipient: SystemAccount<'info>,
    
    #[account(mut)]
    pub royalty_recipient: SystemAccount<'info>,
    
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct CancelListing<'info> {
    #[account(mut)]
    pub listing: Account<'info, Listing>,
    
    #[account(mut)]
    pub seller: Signer<'info>,
    
    #[account(mut)]
    pub seller_nft_account: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub escrow_nft_account: Account<'info, TokenAccount>,
    
    /// CHECK: Escrow authority PDA
    #[account(seeds = [b"escrow"], bump)]
    pub escrow_authority: UncheckedAccount<'info>,
    
    pub token_program: Program<'info, Token>,
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

#[account]
#[derive(InitSpace)]
pub struct Collection {
    pub authority: Pubkey,
    #[max_len(32)]
    pub name: String,
    #[max_len(10)]
    pub symbol: String,
    #[max_len(200)]
    pub uri: String,
    pub royalty_bps: u16,
    pub total_minted: u64,
}

#[account]
#[derive(InitSpace)]
pub struct Listing {
    pub seller: Pubkey,
    pub nft_mint: Pubkey,
    pub price: u64,
    pub expiry: i64,
    pub royalty_bps: u16,
    pub royalty_recipient: Pubkey,
    pub is_active: bool,
}

// ============================================================================
// ERROR CODES
// ============================================================================

#[error_code]
pub enum ErrorCode {
    #[msg("Listing is not active")]
    ListingNotActive,
    
    #[msg("Listing has expired")]
    ListingExpired,
    
    #[msg("Insufficient payment")]
    InsufficientPayment,
    
    #[msg("Unauthorized")]
    Unauthorized,

    #[msg("Invalid fee recipient")]
    InvalidFeeRecipient,

    #[msg("Invalid royalty recipient")]
    InvalidRoyaltyRecipient,
}
