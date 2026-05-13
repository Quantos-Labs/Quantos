use anchor_lang::prelude::*;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

declare_id!("11111111111111111111111111111111");

const MAX_OUTCOMES: usize = 8;
const TOTAL_FEE_BPS: u64 = 200;
const PROTOCOL_FEE_BPS: u64 = 50;
const LP_FEE_BPS: u64 = 150;
const BPS_DENOMINATOR: u64 = 10_000;
const ACC_PRECISION: u128 = 1_000_000_000_000_000_000;
const STATUS_TRADING: u8 = 0;
const STATUS_RESOLVED: u8 = 1;

#[program]
pub mod solana_prediction_market {
    use super::*;

    pub fn initialize_config(ctx: Context<InitializeConfig>, protocol_fee_recipient: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.authority = ctx.accounts.authority.key();
        config.protocol_fee_recipient = protocol_fee_recipient;
        config.next_market_index = 0;
        config.bump = ctx.bumps.config;
        Ok(())
    }

    pub fn create_market(
        ctx: Context<CreateMarket>,
        market_index: u64,
        num_outcomes: u8,
        trading_ends_at: i64,
        initial_liquidity: u64,
        resolver: Pubkey,
    ) -> Result<()> {
        require!(num_outcomes >= 2 && num_outcomes as usize <= MAX_OUTCOMES, PredictionError::InvalidOutcomeCount);
        require!(trading_ends_at > Clock::get()?.unix_timestamp, PredictionError::InvalidTimestamp);
        require!(initial_liquidity > 0, PredictionError::InvalidAmount);
        require!(resolver != Pubkey::default(), PredictionError::InvalidResolver);

        let protocol_fee_recipient = {
            let config = &mut ctx.accounts.config;
            require!(market_index == config.next_market_index, PredictionError::InvalidMarketIndex);
            config.next_market_index = config.next_market_index.checked_add(1).ok_or(PredictionError::MathOverflow)?;
            config.protocol_fee_recipient
        };

        let creator_key = ctx.accounts.creator.key();
        let collateral_mint_key = ctx.accounts.collateral_mint.key();
        let market_vault_key = ctx.accounts.market_vault.key();
        let lp_fee_vault_key = ctx.accounts.lp_fee_vault.key();
        let market_bump = ctx.bumps.market;
        let vault_authority_bump = ctx.bumps.vault_authority;
        let creator_lp_position_bump = ctx.bumps.creator_lp_position;

        transfer_tokens(
            ctx.accounts.into_creator_transfer_context(),
            initial_liquidity,
        )?;

        let market = &mut ctx.accounts.market;
        market.market_index = market_index;
        market.creator = creator_key;
        market.resolver = resolver;
        market.collateral_mint = collateral_mint_key;
        market.collateral_vault = market_vault_key;
        market.lp_fee_vault = lp_fee_vault_key;
        market.protocol_fee_recipient = protocol_fee_recipient;
        market.trading_ends_at = trading_ends_at;
        market.num_outcomes = num_outcomes;
        market.status = STATUS_TRADING;
        market.winning_outcome = 0;
        market.total_liquidity_shares = initial_liquidity;
        market.acc_lp_fee_per_share = 0;
        market.lp_fee_vault_balance = 0;
        market.backstop_collateral = initial_liquidity;
        market.locked_winning_collateral = 0;
        market.redeemable_liquidity = 0;
        market.bump = market_bump;
        market.vault_authority_bump = vault_authority_bump;
        market.pools = [0; MAX_OUTCOMES];
        market.total_outcome_shares = [0; MAX_OUTCOMES];
        allocate_across_pools(market, initial_liquidity)?;
        let market_key = market.key();

        let lp_position = &mut ctx.accounts.creator_lp_position;
        lp_position.market = market_key;
        lp_position.provider = creator_key;
        lp_position.liquidity_shares = initial_liquidity;
        lp_position.fee_debt = 0;
        lp_position.claimable_fees = 0;
        lp_position.bump = creator_lp_position_bump;

        Ok(())
    }

    pub fn add_liquidity(ctx: Context<AddLiquidity>, collateral_amount: u64) -> Result<()> {
        require!(collateral_amount > 0, PredictionError::InvalidAmount);
        let minted_shares = {
            let market = &ctx.accounts.market;
            require!(market.status == STATUS_TRADING, PredictionError::MarketNotTrading);
            require!(Clock::get()?.unix_timestamp < market.trading_ends_at, PredictionError::MarketClosed);
            sync_lp_position(market, &mut ctx.accounts.lp_position)?;

            if market.total_liquidity_shares == 0 || market.backstop_collateral == 0 {
                collateral_amount
            } else {
                ((collateral_amount as u128)
                    .checked_mul(market.total_liquidity_shares as u128)
                    .ok_or(PredictionError::MathOverflow)?
                    .checked_div(market.backstop_collateral as u128)
                    .ok_or(PredictionError::MathOverflow)?) as u64
            }
        };
        require!(minted_shares > 0, PredictionError::NoLiquidity);
        let provider_key = ctx.accounts.provider.key();
        let lp_position_bump = ctx.bumps.lp_position;

        transfer_tokens(ctx.accounts.into_provider_transfer_context(), collateral_amount)?;

        let market_key = ctx.accounts.market.key();
        let market = &mut ctx.accounts.market;
        market.total_liquidity_shares = market.total_liquidity_shares.checked_add(minted_shares).ok_or(PredictionError::MathOverflow)?;
        market.backstop_collateral = market.backstop_collateral.checked_add(collateral_amount).ok_or(PredictionError::MathOverflow)?;
        allocate_across_pools(market, collateral_amount)?;

        let lp_position = &mut ctx.accounts.lp_position;
        lp_position.market = market_key;
        lp_position.provider = provider_key;
        lp_position.liquidity_shares = lp_position.liquidity_shares.checked_add(minted_shares).ok_or(PredictionError::MathOverflow)?;
        lp_position.fee_debt = lp_fee_debt(market, lp_position.liquidity_shares)?;
        lp_position.bump = lp_position_bump;

        Ok(())
    }

    pub fn buy_shares(ctx: Context<BuyShares>, outcome_index: u8, collateral_amount: u64) -> Result<()> {
        require!(collateral_amount > 0, PredictionError::InvalidAmount);
        {
            let market = &ctx.accounts.market;
            require!(market.status == STATUS_TRADING, PredictionError::MarketNotTrading);
            require!(Clock::get()?.unix_timestamp < market.trading_ends_at, PredictionError::MarketClosed);
            require!((outcome_index as usize) < market.num_outcomes as usize, PredictionError::InvalidOutcome);
            require_keys_eq!(ctx.accounts.protocol_fee_recipient_token.owner, market.protocol_fee_recipient, PredictionError::InvalidProtocolRecipient);
            require_keys_eq!(ctx.accounts.protocol_fee_recipient_token.mint, market.collateral_mint, PredictionError::InvalidCollateralMint);
        }

        let protocol_fee = collateral_amount.checked_mul(PROTOCOL_FEE_BPS).ok_or(PredictionError::MathOverflow)?.checked_div(BPS_DENOMINATOR).ok_or(PredictionError::MathOverflow)?;
        let lp_fee = collateral_amount.checked_mul(LP_FEE_BPS).ok_or(PredictionError::MathOverflow)?.checked_div(BPS_DENOMINATOR).ok_or(PredictionError::MathOverflow)?;
        let net_collateral = collateral_amount.checked_sub(protocol_fee).ok_or(PredictionError::MathOverflow)?.checked_sub(lp_fee).ok_or(PredictionError::MathOverflow)?;
        let user_key = ctx.accounts.user.key();
        let outcome_position_bump = ctx.bumps.outcome_position;

        if net_collateral > 0 {
            transfer_tokens(ctx.accounts.into_user_to_market_context(), net_collateral)?;
        }
        if protocol_fee > 0 {
            transfer_tokens(ctx.accounts.into_user_to_protocol_context(), protocol_fee)?;
        }
        if lp_fee > 0 {
            transfer_tokens(ctx.accounts.into_user_to_lp_fee_context(), lp_fee)?;
        }

        let market = &mut ctx.accounts.market;
        if lp_fee > 0 {
            accrue_lp_fee(market, lp_fee)?;
        }
        let shares_out = calc_buy_shares(market, outcome_index as usize, net_collateral)?;
        require!(shares_out > 0, PredictionError::ZeroSharesOut);

        for i in 0..market.num_outcomes as usize {
            market.pools[i] = market.pools[i].checked_add(net_collateral).ok_or(PredictionError::MathOverflow)?;
        }
        market.pools[outcome_index as usize] = market.pools[outcome_index as usize].checked_sub(shares_out).ok_or(PredictionError::MathOverflow)?;
        market.backstop_collateral = market.backstop_collateral.checked_add(net_collateral).ok_or(PredictionError::MathOverflow)?;
        market.total_outcome_shares[outcome_index as usize] = market.total_outcome_shares[outcome_index as usize].checked_add(shares_out).ok_or(PredictionError::MathOverflow)?;

        let position = &mut ctx.accounts.outcome_position;
        if position.owner == Pubkey::default() {
            position.owner = user_key;
            position.market = market.key();
            position.bump = outcome_position_bump;
            position.shares = [0; MAX_OUTCOMES];
        }
        position.shares[outcome_index as usize] = position.shares[outcome_index as usize].checked_add(shares_out).ok_or(PredictionError::MathOverflow)?;

        Ok(())
    }

    pub fn sell_shares(ctx: Context<SellShares>, outcome_index: u8, shares_in: u64) -> Result<()> {
        require!(shares_in > 0, PredictionError::InvalidAmount);
        {
            let market = &ctx.accounts.market;
            require!(market.status == STATUS_TRADING, PredictionError::MarketNotTrading);
            require!(Clock::get()?.unix_timestamp < market.trading_ends_at, PredictionError::MarketClosed);
            require!((outcome_index as usize) < market.num_outcomes as usize, PredictionError::InvalidOutcome);
            require_keys_eq!(ctx.accounts.protocol_fee_recipient_token.owner, market.protocol_fee_recipient, PredictionError::InvalidProtocolRecipient);
            require_keys_eq!(ctx.accounts.protocol_fee_recipient_token.mint, market.collateral_mint, PredictionError::InvalidCollateralMint);
        }

        require!(ctx.accounts.outcome_position.shares[outcome_index as usize] >= shares_in, PredictionError::NotEnoughShares);

        let payout_gross = calc_sell_payout(&ctx.accounts.market, outcome_index as usize, shares_in)?;
        require!(payout_gross > 0, PredictionError::ZeroPayout);
        require!(ctx.accounts.market.backstop_collateral >= payout_gross, PredictionError::InsufficientBackstop);

        let protocol_fee = payout_gross.checked_mul(PROTOCOL_FEE_BPS).ok_or(PredictionError::MathOverflow)?.checked_div(BPS_DENOMINATOR).ok_or(PredictionError::MathOverflow)?;
        let lp_fee = payout_gross.checked_mul(LP_FEE_BPS).ok_or(PredictionError::MathOverflow)?.checked_div(BPS_DENOMINATOR).ok_or(PredictionError::MathOverflow)?;
        let seller_payout = payout_gross.checked_sub(protocol_fee).ok_or(PredictionError::MathOverflow)?.checked_sub(lp_fee).ok_or(PredictionError::MathOverflow)?;

        {
            let market = &mut ctx.accounts.market;
            market.pools[outcome_index as usize] = market.pools[outcome_index as usize].checked_add(shares_in).ok_or(PredictionError::MathOverflow)?;
            let per_pool_reduction = payout_gross.checked_div(market.num_outcomes as u64).ok_or(PredictionError::MathOverflow)?;
            for i in 0..market.num_outcomes as usize {
                market.pools[i] = market.pools[i].checked_sub(per_pool_reduction).ok_or(PredictionError::MathOverflow)?;
            }

            let position = &mut ctx.accounts.outcome_position;
            position.shares[outcome_index as usize] = position.shares[outcome_index as usize].checked_sub(shares_in).ok_or(PredictionError::MathOverflow)?;
            market.total_outcome_shares[outcome_index as usize] = market.total_outcome_shares[outcome_index as usize].checked_sub(shares_in).ok_or(PredictionError::MathOverflow)?;
            market.backstop_collateral = market.backstop_collateral.checked_sub(payout_gross).ok_or(PredictionError::MathOverflow)?;
            if lp_fee > 0 {
                accrue_lp_fee(market, lp_fee)?;
            }
        }

        let market = &ctx.accounts.market;

        if seller_payout > 0 {
            transfer_tokens_signed(ctx.accounts.into_market_to_user_context(), seller_payout, market)?;
        }
        if protocol_fee > 0 {
            transfer_tokens_signed(ctx.accounts.into_market_to_protocol_context(), protocol_fee, market)?;
        }
        if lp_fee > 0 {
            transfer_tokens_signed(ctx.accounts.into_market_to_lp_fee_context(), lp_fee, market)?;
        }

        Ok(())
    }

    pub fn resolve_market(ctx: Context<ResolveMarket>, winning_outcome: u8) -> Result<()> {
        let resolver_key = ctx.accounts.resolver.key();
        let authority_key = ctx.accounts.config.authority;
        let market = &mut ctx.accounts.market;
        require!(market.status == STATUS_TRADING, PredictionError::MarketNotTrading);
        require!(Clock::get()?.unix_timestamp >= market.trading_ends_at, PredictionError::MarketStillTrading);
        require!((winning_outcome as usize) < market.num_outcomes as usize, PredictionError::InvalidOutcome);
        require!(resolver_key == market.resolver || resolver_key == authority_key, PredictionError::NotResolver);

        let locked_winning = market.total_outcome_shares[winning_outcome as usize];
        require!(market.backstop_collateral >= locked_winning, PredictionError::InsufficientBackstop);

        market.status = STATUS_RESOLVED;
        market.winning_outcome = winning_outcome;
        market.locked_winning_collateral = locked_winning;
        market.redeemable_liquidity = market.backstop_collateral.checked_sub(locked_winning).ok_or(PredictionError::MathOverflow)?;

        Ok(())
    }

    pub fn claim_winnings(ctx: Context<ClaimWinnings>) -> Result<()> {
        let payout = {
            let market = &mut ctx.accounts.market;
            require!(market.status == STATUS_RESOLVED, PredictionError::MarketNotResolved);

            let winning_outcome = market.winning_outcome as usize;
            let payout = ctx.accounts.outcome_position.shares[winning_outcome];
            require!(payout > 0, PredictionError::NoWinnings);

            ctx.accounts.outcome_position.shares[winning_outcome] = 0;
            market.locked_winning_collateral = market.locked_winning_collateral.checked_sub(payout).ok_or(PredictionError::MathOverflow)?;
            market.backstop_collateral = market.backstop_collateral.checked_sub(payout).ok_or(PredictionError::MathOverflow)?;
            payout
        };

        let market = &ctx.accounts.market;
        transfer_tokens_signed(ctx.accounts.into_market_to_user_context(), payout, market)?;
        Ok(())
    }

    pub fn claim_lp_fees(ctx: Context<ClaimLpFees>) -> Result<()> {
        let claimable = {
            let market = &mut ctx.accounts.market;
            sync_lp_position(market, &mut ctx.accounts.lp_position)?;

            let claimable = ctx.accounts.lp_position.claimable_fees;
            require!(claimable > 0, PredictionError::NoClaimableFees);
            require!(market.lp_fee_vault_balance >= claimable, PredictionError::InsufficientLpVault);

            ctx.accounts.lp_position.claimable_fees = 0;
            ctx.accounts.lp_position.fee_debt = lp_fee_debt(market, ctx.accounts.lp_position.liquidity_shares)?;
            market.lp_fee_vault_balance = market.lp_fee_vault_balance.checked_sub(claimable).ok_or(PredictionError::MathOverflow)?;
            claimable
        };

        let market = &ctx.accounts.market;
        transfer_tokens_signed(ctx.accounts.into_lp_fee_to_provider_context(), claimable, market)?;
        Ok(())
    }

    pub fn redeem_liquidity(ctx: Context<RedeemLiquidity>, liquidity_shares_to_burn: u64) -> Result<()> {
        require!(liquidity_shares_to_burn > 0, PredictionError::InvalidAmount);
        let collateral_out = {
            let market = &mut ctx.accounts.market;
            require!(market.status == STATUS_RESOLVED, PredictionError::MarketNotResolved);

            sync_lp_position(market, &mut ctx.accounts.lp_position)?;
            require!(ctx.accounts.lp_position.liquidity_shares >= liquidity_shares_to_burn, PredictionError::NoLiquidity);

            let collateral_out = ((market.redeemable_liquidity as u128)
                .checked_mul(liquidity_shares_to_burn as u128)
                .ok_or(PredictionError::MathOverflow)?
                .checked_div(market.total_liquidity_shares as u128)
                .ok_or(PredictionError::MathOverflow)?) as u64;
            require!(collateral_out > 0, PredictionError::NoLiquidity);

            ctx.accounts.lp_position.liquidity_shares = ctx.accounts.lp_position.liquidity_shares.checked_sub(liquidity_shares_to_burn).ok_or(PredictionError::MathOverflow)?;
            ctx.accounts.lp_position.fee_debt = lp_fee_debt(market, ctx.accounts.lp_position.liquidity_shares)?;
            market.total_liquidity_shares = market.total_liquidity_shares.checked_sub(liquidity_shares_to_burn).ok_or(PredictionError::MathOverflow)?;
            market.redeemable_liquidity = market.redeemable_liquidity.checked_sub(collateral_out).ok_or(PredictionError::MathOverflow)?;
            market.backstop_collateral = market.backstop_collateral.checked_sub(collateral_out).ok_or(PredictionError::MathOverflow)?;
            collateral_out
        };

        let market = &ctx.accounts.market;
        transfer_tokens_signed(ctx.accounts.into_market_to_provider_context(), collateral_out, market)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    #[account(
        init,
        payer = authority,
        seeds = [b"config"],
        bump,
        space = Config::LEN,
    )]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(market_index: u64)]
pub struct CreateMarket<'info> {
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(
        init,
        payer = creator,
        seeds = [b"market".as_ref(), market_index.to_le_bytes().as_ref()],
        bump,
        space = Market::LEN,
    )]
    pub market: Account<'info, Market>,
    #[account(
        init,
        payer = creator,
        associated_token::mint = collateral_mint,
        associated_token::authority = vault_authority,
    )]
    pub market_vault: Account<'info, TokenAccount>,
    #[account(
        init,
        payer = creator,
        associated_token::mint = collateral_mint,
        associated_token::authority = vault_authority,
    )]
    pub lp_fee_vault: Account<'info, TokenAccount>,
    #[account(
        init,
        payer = creator,
        seeds = [b"lp", market.key().as_ref(), creator.key().as_ref()],
        bump,
        space = LpPosition::LEN,
    )]
    pub creator_lp_position: Account<'info, LpPosition>,
    #[account(mut)]
    pub creator: Signer<'info>,
    #[account(
        mut,
        constraint = creator_collateral.owner == creator.key(),
        constraint = creator_collateral.mint == collateral_mint.key(),
    )]
    pub creator_collateral: Account<'info, TokenAccount>,
    pub collateral_mint: Account<'info, Mint>,
    #[account(seeds = [b"vault-authority", market.key().as_ref()], bump)]
    /// CHECK: PDA used only as vault authority
    pub vault_authority: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

impl<'info> CreateMarket<'info> {
    fn into_creator_transfer_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        CpiContext::new(
            self.token_program.to_account_info(),
            Transfer {
                from: self.creator_collateral.to_account_info(),
                to: self.market_vault.to_account_info(),
                authority: self.creator.to_account_info(),
            },
        )
    }
}

#[derive(Accounts)]
pub struct AddLiquidity<'info> {
    #[account(mut)]
    pub market: Account<'info, Market>,
    #[account(
        init_if_needed,
        payer = provider,
        seeds = [b"lp", market.key().as_ref(), provider.key().as_ref()],
        bump,
        space = LpPosition::LEN,
    )]
    pub lp_position: Account<'info, LpPosition>,
    #[account(mut)]
    pub provider: Signer<'info>,
    #[account(
        mut,
        constraint = provider_collateral.owner == provider.key(),
        constraint = provider_collateral.mint == market.collateral_mint,
    )]
    pub provider_collateral: Account<'info, TokenAccount>,
    #[account(mut, address = market.collateral_vault)]
    pub market_vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

impl<'info> AddLiquidity<'info> {
    fn into_provider_transfer_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        CpiContext::new(
            self.token_program.to_account_info(),
            Transfer {
                from: self.provider_collateral.to_account_info(),
                to: self.market_vault.to_account_info(),
                authority: self.provider.to_account_info(),
            },
        )
    }
}

#[derive(Accounts)]
pub struct BuyShares<'info> {
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub market: Account<'info, Market>,
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(
        init_if_needed,
        payer = user,
        seeds = [b"position", market.key().as_ref(), user.key().as_ref()],
        bump,
        space = OutcomePosition::LEN,
    )]
    pub outcome_position: Account<'info, OutcomePosition>,
    #[account(
        mut,
        constraint = user_collateral.owner == user.key(),
        constraint = user_collateral.mint == market.collateral_mint,
    )]
    pub user_collateral: Account<'info, TokenAccount>,
    #[account(mut, address = market.collateral_vault)]
    pub market_vault: Account<'info, TokenAccount>,
    #[account(mut, address = market.lp_fee_vault)]
    pub lp_fee_vault: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = protocol_fee_recipient_token.owner == config.protocol_fee_recipient,
        constraint = protocol_fee_recipient_token.mint == market.collateral_mint,
    )]
    pub protocol_fee_recipient_token: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

impl<'info> BuyShares<'info> {
    fn into_user_to_market_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        CpiContext::new(
            self.token_program.to_account_info(),
            Transfer {
                from: self.user_collateral.to_account_info(),
                to: self.market_vault.to_account_info(),
                authority: self.user.to_account_info(),
            },
        )
    }

    fn into_user_to_protocol_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        CpiContext::new(
            self.token_program.to_account_info(),
            Transfer {
                from: self.user_collateral.to_account_info(),
                to: self.protocol_fee_recipient_token.to_account_info(),
                authority: self.user.to_account_info(),
            },
        )
    }

    fn into_user_to_lp_fee_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        CpiContext::new(
            self.token_program.to_account_info(),
            Transfer {
                from: self.user_collateral.to_account_info(),
                to: self.lp_fee_vault.to_account_info(),
                authority: self.user.to_account_info(),
            },
        )
    }
}

#[derive(Accounts)]
pub struct SellShares<'info> {
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub market: Account<'info, Market>,
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut, seeds = [b"position", market.key().as_ref(), user.key().as_ref()], bump = outcome_position.bump)]
    pub outcome_position: Account<'info, OutcomePosition>,
    #[account(mut, address = market.collateral_vault)]
    pub market_vault: Account<'info, TokenAccount>,
    #[account(mut, address = market.lp_fee_vault)]
    pub lp_fee_vault: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = user_collateral.owner == user.key(),
        constraint = user_collateral.mint == market.collateral_mint,
    )]
    pub user_collateral: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = protocol_fee_recipient_token.owner == config.protocol_fee_recipient,
        constraint = protocol_fee_recipient_token.mint == market.collateral_mint,
    )]
    pub protocol_fee_recipient_token: Account<'info, TokenAccount>,
    #[account(seeds = [b"vault-authority", market.key().as_ref()], bump = market.vault_authority_bump)]
    /// CHECK: PDA used only as vault authority
    pub vault_authority: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
}

impl<'info> SellShares<'info> {
    fn into_market_to_user_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        CpiContext::new(
            self.token_program.to_account_info(),
            Transfer {
                from: self.market_vault.to_account_info(),
                to: self.user_collateral.to_account_info(),
                authority: self.vault_authority.to_account_info(),
            },
        )
    }

    fn into_market_to_protocol_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        CpiContext::new(
            self.token_program.to_account_info(),
            Transfer {
                from: self.market_vault.to_account_info(),
                to: self.protocol_fee_recipient_token.to_account_info(),
                authority: self.vault_authority.to_account_info(),
            },
        )
    }

    fn into_market_to_lp_fee_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        CpiContext::new(
            self.token_program.to_account_info(),
            Transfer {
                from: self.market_vault.to_account_info(),
                to: self.lp_fee_vault.to_account_info(),
                authority: self.vault_authority.to_account_info(),
            },
        )
    }
}

#[derive(Accounts)]
pub struct ResolveMarket<'info> {
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub market: Account<'info, Market>,
    pub resolver: Signer<'info>,
}

#[derive(Accounts)]
pub struct ClaimWinnings<'info> {
    #[account(mut)]
    pub market: Account<'info, Market>,
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut, seeds = [b"position", market.key().as_ref(), user.key().as_ref()], bump = outcome_position.bump)]
    pub outcome_position: Account<'info, OutcomePosition>,
    #[account(mut, address = market.collateral_vault)]
    pub market_vault: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = user_collateral.owner == user.key(),
        constraint = user_collateral.mint == market.collateral_mint,
    )]
    pub user_collateral: Account<'info, TokenAccount>,
    #[account(seeds = [b"vault-authority", market.key().as_ref()], bump = market.vault_authority_bump)]
    /// CHECK: PDA used only as vault authority
    pub vault_authority: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
}

impl<'info> ClaimWinnings<'info> {
    fn into_market_to_user_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        CpiContext::new(
            self.token_program.to_account_info(),
            Transfer {
                from: self.market_vault.to_account_info(),
                to: self.user_collateral.to_account_info(),
                authority: self.vault_authority.to_account_info(),
            },
        )
    }
}

#[derive(Accounts)]
pub struct ClaimLpFees<'info> {
    #[account(mut)]
    pub market: Account<'info, Market>,
    #[account(mut)]
    pub provider: Signer<'info>,
    #[account(mut, seeds = [b"lp", market.key().as_ref(), provider.key().as_ref()], bump = lp_position.bump)]
    pub lp_position: Account<'info, LpPosition>,
    #[account(mut, address = market.lp_fee_vault)]
    pub lp_fee_vault: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = provider_collateral.owner == provider.key(),
        constraint = provider_collateral.mint == market.collateral_mint,
    )]
    pub provider_collateral: Account<'info, TokenAccount>,
    #[account(seeds = [b"vault-authority", market.key().as_ref()], bump = market.vault_authority_bump)]
    /// CHECK: PDA used only as vault authority
    pub vault_authority: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
}

impl<'info> ClaimLpFees<'info> {
    fn into_lp_fee_to_provider_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        CpiContext::new(
            self.token_program.to_account_info(),
            Transfer {
                from: self.lp_fee_vault.to_account_info(),
                to: self.provider_collateral.to_account_info(),
                authority: self.vault_authority.to_account_info(),
            },
        )
    }
}

#[derive(Accounts)]
pub struct RedeemLiquidity<'info> {
    #[account(mut)]
    pub market: Account<'info, Market>,
    #[account(mut)]
    pub provider: Signer<'info>,
    #[account(mut, seeds = [b"lp", market.key().as_ref(), provider.key().as_ref()], bump = lp_position.bump)]
    pub lp_position: Account<'info, LpPosition>,
    #[account(mut, address = market.collateral_vault)]
    pub market_vault: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = provider_collateral.owner == provider.key(),
        constraint = provider_collateral.mint == market.collateral_mint,
    )]
    pub provider_collateral: Account<'info, TokenAccount>,
    #[account(seeds = [b"vault-authority", market.key().as_ref()], bump = market.vault_authority_bump)]
    /// CHECK: PDA used only as vault authority
    pub vault_authority: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
}

impl<'info> RedeemLiquidity<'info> {
    fn into_market_to_provider_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        CpiContext::new(
            self.token_program.to_account_info(),
            Transfer {
                from: self.market_vault.to_account_info(),
                to: self.provider_collateral.to_account_info(),
                authority: self.vault_authority.to_account_info(),
            },
        )
    }
}

#[account]
pub struct Config {
    pub authority: Pubkey,
    pub protocol_fee_recipient: Pubkey,
    pub next_market_index: u64,
    pub bump: u8,
}

impl Config {
    pub const LEN: usize = 8 + 32 + 32 + 8 + 1;
}

#[account]
pub struct Market {
    pub market_index: u64,
    pub creator: Pubkey,
    pub resolver: Pubkey,
    pub collateral_mint: Pubkey,
    pub collateral_vault: Pubkey,
    pub lp_fee_vault: Pubkey,
    pub protocol_fee_recipient: Pubkey,
    pub trading_ends_at: i64,
    pub num_outcomes: u8,
    pub status: u8,
    pub winning_outcome: u8,
    pub bump: u8,
    pub vault_authority_bump: u8,
    pub total_liquidity_shares: u64,
    pub acc_lp_fee_per_share: u128,
    pub lp_fee_vault_balance: u64,
    pub backstop_collateral: u64,
    pub locked_winning_collateral: u64,
    pub redeemable_liquidity: u64,
    pub pools: [u64; MAX_OUTCOMES],
    pub total_outcome_shares: [u64; MAX_OUTCOMES],
}

impl Market {
    pub const LEN: usize = 8 + 8 + (32 * 6) + 8 + 5 + 8 + 16 + (8 * 5) + (8 * MAX_OUTCOMES * 2);
}

#[account]
pub struct LpPosition {
    pub market: Pubkey,
    pub provider: Pubkey,
    pub liquidity_shares: u64,
    pub fee_debt: u128,
    pub claimable_fees: u64,
    pub bump: u8,
}

impl LpPosition {
    pub const LEN: usize = 8 + 32 + 32 + 8 + 16 + 8 + 1;
}

#[account]
pub struct OutcomePosition {
    pub market: Pubkey,
    pub owner: Pubkey,
    pub shares: [u64; MAX_OUTCOMES],
    pub bump: u8,
}

impl OutcomePosition {
    pub const LEN: usize = 8 + 32 + 32 + (8 * MAX_OUTCOMES) + 1;
}

fn transfer_tokens<'info>(ctx: CpiContext<'_, '_, '_, 'info, Transfer<'info>>, amount: u64) -> Result<()> {
    token::transfer(ctx, amount)
}

fn transfer_tokens_signed<'info>(ctx: CpiContext<'_, '_, '_, 'info, Transfer<'info>>, amount: u64, market: &Account<'info, Market>) -> Result<()> {
    let market_key = market.key();
    let signer_seeds: &[&[u8]] = &[
        b"vault-authority",
        market_key.as_ref(),
        &[market.vault_authority_bump],
    ];
    token::transfer(ctx.with_signer(&[signer_seeds]), amount)
}

fn allocate_across_pools(market: &mut Account<Market>, collateral_amount: u64) -> Result<()> {
    let per_outcome = collateral_amount.checked_div(market.num_outcomes as u64).ok_or(PredictionError::MathOverflow)?;
    let remainder = collateral_amount.checked_sub(per_outcome.checked_mul(market.num_outcomes as u64).ok_or(PredictionError::MathOverflow)?).ok_or(PredictionError::MathOverflow)?;

    for i in 0..market.num_outcomes as usize {
        market.pools[i] = market.pools[i].checked_add(per_outcome).ok_or(PredictionError::MathOverflow)?;
    }
    if remainder > 0 {
        market.pools[0] = market.pools[0].checked_add(remainder).ok_or(PredictionError::MathOverflow)?;
    }
    Ok(())
}

fn calc_buy_shares(market: &Account<Market>, outcome_index: usize, amount: u64) -> Result<u64> {
    let mut ratio = market.pools[outcome_index] as u128;
    for i in 0..market.num_outcomes as usize {
        if i == outcome_index {
            continue;
        }
        let numerator = ratio.checked_mul(market.pools[i] as u128).ok_or(PredictionError::MathOverflow)?;
        let denominator = (market.pools[i] as u128).checked_add(amount as u128).ok_or(PredictionError::MathOverflow)?;
        ratio = numerator.checked_div(denominator).ok_or(PredictionError::MathOverflow)?;
    }
    let result = ((market.pools[outcome_index] as u128).checked_add(amount as u128).ok_or(PredictionError::MathOverflow)?)
        .checked_sub(ratio)
        .ok_or(PredictionError::MathOverflow)?;
    Ok(result as u64)
}

fn calc_sell_payout(market: &Account<Market>, outcome_index: usize, shares_in: u64) -> Result<u64> {
    let scale = 1_000_000_000_000_000_000u128;
    let mut reciprocal_sum = 0u128;
    for i in 0..market.num_outcomes as usize {
        require!(market.pools[i] > 0, PredictionError::ZeroPool);
        reciprocal_sum = reciprocal_sum.checked_add(scale.checked_div(market.pools[i] as u128).ok_or(PredictionError::MathOverflow)?).ok_or(PredictionError::MathOverflow)?;
    }
    require!(reciprocal_sum > 0, PredictionError::ZeroPayout);
    let my_reciprocal = scale.checked_div(market.pools[outcome_index] as u128).ok_or(PredictionError::MathOverflow)?;
    let price_e18 = my_reciprocal.checked_mul(scale).ok_or(PredictionError::MathOverflow)?.checked_div(reciprocal_sum).ok_or(PredictionError::MathOverflow)?;
    let payout = (shares_in as u128).checked_mul(price_e18).ok_or(PredictionError::MathOverflow)?.checked_div(scale).ok_or(PredictionError::MathOverflow)?;
    Ok(payout as u64)
}

fn accrue_lp_fee(market: &mut Account<Market>, lp_fee: u64) -> Result<()> {
    market.lp_fee_vault_balance = market.lp_fee_vault_balance.checked_add(lp_fee).ok_or(PredictionError::MathOverflow)?;
    if market.total_liquidity_shares > 0 {
        market.acc_lp_fee_per_share = market.acc_lp_fee_per_share
            .checked_add((lp_fee as u128).checked_mul(ACC_PRECISION).ok_or(PredictionError::MathOverflow)?
            .checked_div(market.total_liquidity_shares as u128).ok_or(PredictionError::MathOverflow)?)
            .ok_or(PredictionError::MathOverflow)?;
    }
    Ok(())
}

fn sync_lp_position(market: &Account<Market>, lp_position: &mut Account<LpPosition>) -> Result<()> {
    if lp_position.provider == Pubkey::default() {
        return Ok(());
    }
    let accrued = lp_fee_debt(market, lp_position.liquidity_shares)?;
    if accrued > lp_position.fee_debt {
        let delta = accrued.checked_sub(lp_position.fee_debt).ok_or(PredictionError::MathOverflow)?;
        lp_position.claimable_fees = lp_position.claimable_fees.checked_add(delta as u64).ok_or(PredictionError::MathOverflow)?;
    }
    lp_position.fee_debt = accrued;
    Ok(())
}

fn lp_fee_debt(market: &Account<Market>, liquidity_shares: u64) -> Result<u128> {
    (liquidity_shares as u128)
        .checked_mul(market.acc_lp_fee_per_share)
        .ok_or_else(|| error!(PredictionError::MathOverflow))
        .map(|value| value / ACC_PRECISION)
}

#[error_code]
pub enum PredictionError {
    #[msg("Invalid outcome count")]
    InvalidOutcomeCount,
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Invalid timestamp")]
    InvalidTimestamp,
    #[msg("Invalid resolver")]
    InvalidResolver,
    #[msg("Invalid market index")]
    InvalidMarketIndex,
    #[msg("Market is not trading")]
    MarketNotTrading,
    #[msg("Market is already closed")]
    MarketClosed,
    #[msg("Market is still trading")]
    MarketStillTrading,
    #[msg("Market is not resolved")]
    MarketNotResolved,
    #[msg("Invalid outcome")]
    InvalidOutcome,
    #[msg("Not enough shares")]
    NotEnoughShares,
    #[msg("Zero shares out")]
    ZeroSharesOut,
    #[msg("Zero payout")]
    ZeroPayout,
    #[msg("Backstop collateral is insufficient")]
    InsufficientBackstop,
    #[msg("Not resolver")]
    NotResolver,
    #[msg("No winnings to claim")]
    NoWinnings,
    #[msg("No LP fees to claim")]
    NoClaimableFees,
    #[msg("No liquidity available")]
    NoLiquidity,
    #[msg("Math overflow")]
    MathOverflow,
    #[msg("Protocol recipient token account is invalid")]
    InvalidProtocolRecipient,
    #[msg("Collateral mint is invalid")]
    InvalidCollateralMint,
    #[msg("LP fee vault is insufficient")]
    InsufficientLpVault,
    #[msg("Zero pool")]
    ZeroPool,
}
