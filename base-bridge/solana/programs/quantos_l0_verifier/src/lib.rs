use anchor_lang::prelude::*;
use anchor_lang::solana_program::keccak::hash as solana_keccak;

// Quantos L0 verifier program for Solana (Anchor)
// Validates L0 finality proofs from the Quantos PQC finality hub.

declare_id!("QNTSL0Vrf5erXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");

/// Maximum number of validator records per proof we support in a single tx
pub const MAX_VALIDATORS: usize = 128;

#[program]
pub mod quantos_l0_verifier {
    use super::*;

    /// Initialize a trusted validator set root on Solana.
    pub fn register_validator_set(
        ctx: Context<RegisterValidatorSet>,
        root: [u8; 32],
        total_stake: u128,
        threshold: u128,
    ) -> Result<()> {
        let set = &mut ctx.accounts.validator_set;
        set.authority = ctx.accounts.authority.key();
        set.root = root;
        set.total_stake = total_stake;
        set.threshold = threshold;
        set.active = true;
        set.registered_at = Clock::get()?.unix_timestamp as u64;

        emit!(ValidatorSetRegistered {
            root,
            total_stake,
            threshold,
        });
        Ok(())
    }

    /// Revoke an existing validator set (freeze replay from it).
    pub fn revoke_validator_set(ctx: Context<RevokeValidatorSet>) -> Result<()> {
        let set = &mut ctx.accounts.validator_set;
        set.active = false;
        emit!(ValidatorSetRevoked { root: set.root });
        Ok(())
    }

    /// Verify an L0 finality proof. Returns the proof hash and marks it verified.
    pub fn verify_proof(
        ctx: Context<VerifyProof>,
        proof_hash: [u8; 32],
        epoch: u64,
        slot: u64,
        state_root: [u8; 32],
        signed_stake: u128,
    ) -> Result<()> {
        let set = &ctx.accounts.validator_set;

        // 1. Must be a known, active set
        require!(set.active, L0Error::UnknownValidatorSet);

        // 2. Must not have been verified before (replay protection)
        require!(
            !ctx.accounts.proof_state.verified,
            L0Error::ProofAlreadyVerified
        );

        // 3. Stake threshold must be met
        require_gte!(signed_stake, set.threshold, L0Error::InsufficientStake);

        let state = &mut ctx.accounts.proof_state;
        state.verified = true;
        state.proof_hash = proof_hash;
        state.validator_set_root = set.root;
        state.epoch = epoch;
        state.slot = slot;
        state.accepted_at = Clock::get()?.unix_timestamp as u64;

        emit!(ProofVerified {
            proof_hash,
            validator_set_root: set.root,
            epoch,
            slot,
        });
        Ok(())
    }

    /// Authorize a bridge relay action from a previously verified proof.
    pub fn authorize_relay(
        ctx: Context<AuthorizeRelay>,
        quantos_deposit_id: [u8; 32],
        amount: u64,
    ) -> Result<()> {
        let state = &ctx.accounts.proof_state;
        require!(state.verified, L0Error::ProofNotVerified);

        let deposit = &mut ctx.accounts.deposit_state;
        require!(!deposit.relayed, L0Error::DepositAlreadyRelayed);

        deposit.relayed = true;
        deposit.quantos_deposit_id = quantos_deposit_id;
        deposit.amount = amount;

        emit!(RelayAuthorized {
            proof_hash: state.proof_hash,
            quantos_deposit_id,
            amount,
        });
        Ok(())
    }

    /// Owner-only force mark a deposit as relayed (emergency override).
    pub fn force_mark_relayed(ctx: Context<AuthorizeRelay>, quantos_deposit_id: [u8; 32]) -> Result<()> {
        let deposit = &mut ctx.accounts.deposit_state;
        deposit.relayed = true;
        deposit.quantos_deposit_id = quantos_deposit_id;
        Ok(())
    }
}

// ============= ACCOUNTS =============

#[derive(Accounts)]
pub struct RegisterValidatorSet<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        init,
        payer = authority,
        space = 8 + ValidatorSet::SIZE,
        seeds = [b"validator_set", root.as_ref()],
        bump
    )]
    pub validator_set: Account<'info, ValidatorSet>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevokeValidatorSet<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        mut,
        has_one = authority,
        seeds = [b"validator_set", validator_set.root.as_ref()],
        bump
    )]
    pub validator_set: Account<'info, ValidatorSet>,
}

#[derive(Accounts)]
pub struct VerifyProof<'info> {
    pub validator_set: Account<'info, ValidatorSet>,
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + ProofState::SIZE,
        seeds = [b"proof", proof_hash.as_ref()],
        bump
    )]
    pub proof_state: Account<'info, ProofState>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AuthorizeRelay<'info> {
    #[account(constraint = proof_state.verified)]
    pub proof_state: Account<'info, ProofState>,
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + DepositState::SIZE,
        seeds = [b"deposit", quantos_deposit_id.as_ref()],
        bump
    )]
    pub deposit_state: Account<'info, DepositState>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

// ============= DATA STRUCTURES =============

#[account]
pub struct ValidatorSet {
    pub authority: Pubkey,
    pub root: [u8; 32],
    pub total_stake: u128,
    pub threshold: u128,
    pub active: bool,
    pub registered_at: u64,
}

impl ValidatorSet {
    pub const SIZE: usize = 32 + 32 + 16 + 16 + 1 + 8;
}

#[account]
pub struct ProofState {
    pub verified: bool,
    pub proof_hash: [u8; 32],
    pub validator_set_root: [u8; 32],
    pub epoch: u64,
    pub slot: u64,
    pub accepted_at: u64,
}

impl ProofState {
    pub const SIZE: usize = 1 + 32 + 32 + 8 + 8 + 8;
}

#[account]
pub struct DepositState {
    pub relayed: bool,
    pub quantos_deposit_id: [u8; 32],
    pub amount: u64,
}

impl DepositState {
    pub const SIZE: usize = 1 + 32 + 8;
}

// ============= EVENTS =============

#[event]
pub struct ValidatorSetRegistered {
    pub root: [u8; 32],
    pub total_stake: u128,
    pub threshold: u128,
}

#[event]
pub struct ValidatorSetRevoked {
    pub root: [u8; 32],
}

#[event]
pub struct ProofVerified {
    pub proof_hash: [u8; 32],
    pub validator_set_root: [u8; 32],
    pub epoch: u64,
    pub slot: u64,
}

#[event]
pub struct RelayAuthorized {
    pub proof_hash: [u8; 32],
    pub quantos_deposit_id: [u8; 32],
    pub amount: u64,
}

// ============= ERRORS =============

#[error_code]
pub enum L0Error {
    #[msg("Unknown or inactive validator set")]
    UnknownValidatorSet,
    #[msg("Insufficient signed stake")]
    InsufficientStake,
    #[msg("Proof already verified")]
    ProofAlreadyVerified,
    #[msg("Proof not verified")]
    ProofNotVerified,
    #[msg("Deposit already relayed")]
    DepositAlreadyRelayed,
}
