//! PQC-Guard — quantum-resistant guarded vault for Solana (Anchor).
//!
//! Reference port aligned with MULTIVM_SPEC.md. A `GuardedVault` PDA holds SOL
//! and, after migrating to a post-quantum key, releases funds only via an
//! M-of-N attestation from the Quantos-finalized attestor set (the QTS anchor),
//! checked on-chain with pure keccak256 (`solana_program::keccak`).
//!
//! L0 anchoring: `update_attestor_set` reads the L0 verifier's `ProofState` PDA
//! (owned by the L0 program) and requires its `verified` flag, binding the
//! attestor-set root to a Quantos finality proof.
//!
//! TESTNET ONLY. // AUDIT REQUIRED.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::keccak::hash as keccak_hash;
use anchor_lang::system_program;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

/// Canonical PQCG chain id for Solana (spec §6).
const CHAIN_ID: u64 = 0x534f000000000001;
/// 24h commit-reveal delay (seconds).
const COMMIT_DELAY_S: i64 = 86_400;
/// 30d inactivity before the guardian escape hatch unlocks (seconds).
const RECOVERY_TIMEOUT_S: i64 = 2_592_000;
const MAX_GUARDIANS: usize = 10;

#[program]
pub mod quantos_pqc_guard {
    use super::*;

    // ── oracle ──

    pub fn init_oracle(ctx: Context<InitOracle>, l0_program: Pubkey) -> Result<()> {
        let o = &mut ctx.accounts.oracle;
        o.admin = ctx.accounts.admin.key();
        o.l0_program = l0_program;
        o.attestor_set_root = [0u8; 32];
        o.epoch = 0;
        o.threshold = 0;
        Ok(())
    }

    /// Publish a Quantos-finalized attestor set, gated by a VERIFIED L0 proof.
    /// `proof_state` must be the L0 verifier's PDA for `proof_hash` and report
    /// `verified == true`.
    pub fn update_attestor_set(
        ctx: Context<UpdateAttestorSet>,
        root: [u8; 32],
        epoch: u64,
        threshold: u32,
        proof_hash: [u8; 32],
    ) -> Result<()> {
        let o = &mut ctx.accounts.oracle;
        require_keys_eq!(ctx.accounts.admin.key(), o.admin, PqcError::NotOwner);
        require!(epoch > o.epoch || o.epoch == 0, PqcError::StaleEpoch);

        // Bind the proof PDA to the L0 program + proof_hash and read `verified`.
        let proof = &ctx.accounts.proof_state;
        let (expected, _bump) =
            Pubkey::find_program_address(&[b"proof", proof_hash.as_ref()], &o.l0_program);
        require_keys_eq!(proof.key(), expected, PqcError::BadProofAccount);
        require_keys_eq!(*proof.owner, o.l0_program, PqcError::BadProofAccount);
        let data = proof.try_borrow_data()?;
        // Anchor layout: [8-byte discriminator][verified: bool ...]
        require!(data.len() >= 9 && data[8] == 1, PqcError::ProofNotVerified);

        o.attestor_set_root = root;
        o.epoch = epoch;
        o.threshold = threshold;
        Ok(())
    }

    // ── vault lifecycle ──

    pub fn init_vault(ctx: Context<InitVault>, oracle: Pubkey) -> Result<()> {
        let v = &mut ctx.accounts.vault;
        v.owner = ctx.accounts.owner.key();
        v.oracle = oracle;
        v.migrated = false;
        v.pqc_commitment = [0u8; 32];
        v.pending_commitment = None;
        v.pending_time = 0;
        v.nonce = 0;
        v.guardians = Vec::new();
        v.guardian_threshold = 0;
        v.last_activity = Clock::get()?.unix_timestamp;
        v.sweep_active = false;
        v.sweep_to = None;
        v.sweep_approvals = Vec::new();
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let cpi = system_program::Transfer {
            from: ctx.accounts.payer.to_account_info(),
            to: ctx.accounts.vault.to_account_info(),
        };
        system_program::transfer(
            CpiContext::new(ctx.accounts.system_program.to_account_info(), cpi),
            amount,
        )?;
        ctx.accounts.vault.last_activity = Clock::get()?.unix_timestamp;
        Ok(())
    }

    pub fn migrate(
        ctx: Context<OwnerOnly>,
        commitment: [u8; 32],
        guardians: Vec<Pubkey>,
        guardian_threshold: u32,
    ) -> Result<()> {
        let v = &mut ctx.accounts.vault;
        require_keys_eq!(ctx.accounts.owner.key(), v.owner, PqcError::NotOwner);
        require!(!v.migrated, PqcError::AlreadyMigrated);
        require!(guardians.len() <= MAX_GUARDIANS, PqcError::TooManyGuardians);
        v.pending_commitment = Some(commitment);
        v.pending_time = Clock::get()?.unix_timestamp;
        v.guardians = guardians;
        v.guardian_threshold = guardian_threshold;
        Ok(())
    }

    pub fn finalize(ctx: Context<OwnerOnly>, pqc_pub_key: Vec<u8>) -> Result<()> {
        let v = &mut ctx.accounts.vault;
        require_keys_eq!(ctx.accounts.owner.key(), v.owner, PqcError::NotOwner);
        let pending = v.pending_commitment.ok_or(PqcError::NoPending)?;
        let now = Clock::get()?.unix_timestamp;
        require!(now >= v.pending_time + COMMIT_DELAY_S, PqcError::DelayNotElapsed);
        require!(keccak_hash(&pqc_pub_key).0 == pending, PqcError::BadReveal);
        v.pqc_commitment = pending;
        v.migrated = true;
        v.pending_commitment = None;
        v.last_activity = now;
        Ok(())
    }

    pub fn cancel(ctx: Context<OwnerOnly>) -> Result<()> {
        let v = &mut ctx.accounts.vault;
        require_keys_eq!(ctx.accounts.owner.key(), v.owner, PqcError::NotOwner);
        v.pending_commitment = None;
        Ok(())
    }

    // ── execute (guarded SOL release) ──

    pub fn execute(
        ctx: Context<Execute>,
        to: Pubkey,
        value: u64,
        data: Vec<u8>,
        attestation: Vec<u8>,
    ) -> Result<()> {
        require_keys_eq!(ctx.accounts.recipient.key(), to, PqcError::BadRecipient);
        let v = &ctx.accounts.vault;
        let o = &ctx.accounts.oracle;
        require!(v.migrated, PqcError::NotMigrated);
        require_keys_eq!(v.oracle, o.key(), PqcError::BadOracle);

        let digest = compute_digest(&v.pqc_commitment, &to, value, &data, v.nonce);
        require!(
            verify_authorization(&attestation, &digest, &o.attestor_set_root, o.threshold),
            PqcError::Unauthorized
        );

        // Debit program-owned vault PDA, credit recipient.
        **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? -= value;
        **ctx.accounts.recipient.to_account_info().try_borrow_mut_lamports()? += value;

        let v = &mut ctx.accounts.vault;
        v.nonce += 1;
        v.last_activity = Clock::get()?.unix_timestamp;
        Ok(())
    }

    // ── escape hatch ──

    pub fn propose_recovery(ctx: Context<GuardianAction>, to: Pubkey) -> Result<()> {
        let g = ctx.accounts.guardian.key();
        let v = &mut ctx.accounts.vault;
        require!(v.guardians.contains(&g), PqcError::NotGuardian);
        let now = Clock::get()?.unix_timestamp;
        require!(now > v.last_activity + RECOVERY_TIMEOUT_S, PqcError::TimeoutNotReached);
        v.sweep_active = true;
        v.sweep_to = Some(to);
        v.sweep_approvals = vec![g];
        Ok(())
    }

    pub fn approve_recovery(ctx: Context<GuardianAction>) -> Result<()> {
        let g = ctx.accounts.guardian.key();
        let v = &mut ctx.accounts.vault;
        require!(v.guardians.contains(&g), PqcError::NotGuardian);
        require!(v.sweep_active, PqcError::NoRecovery);
        if !v.sweep_approvals.contains(&g) {
            require!(v.sweep_approvals.len() < MAX_GUARDIANS, PqcError::TooManyGuardians);
            v.sweep_approvals.push(g);
        }
        Ok(())
    }

    pub fn execute_recovery(ctx: Context<ExecuteRecovery>) -> Result<()> {
        let v = &ctx.accounts.vault;
        require!(v.sweep_active, PqcError::NoRecovery);
        require!(
            v.sweep_approvals.len() as u32 >= v.guardian_threshold,
            PqcError::NoQuorum
        );
        let to = v.sweep_to.ok_or(PqcError::NoRecovery)?;
        require_keys_eq!(ctx.accounts.recipient.key(), to, PqcError::BadRecipient);

        // Sweep all lamports above the rent-exempt minimum.
        let rent = Rent::get()?.minimum_balance(ctx.accounts.vault.to_account_info().data_len());
        let bal = ctx.accounts.vault.to_account_info().lamports();
        let movable = bal.saturating_sub(rent);
        **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? -= movable;
        **ctx.accounts.recipient.to_account_info().try_borrow_mut_lamports()? += movable;

        ctx.accounts.vault.sweep_active = false;
        Ok(())
    }
}

// ─────────────────────────── digest + verify (spec §3/§5) ──────────────────

fn keccak(data: &[u8]) -> [u8; 32] {
    keccak_hash(data).0
}

fn u256_be_u64(n: u64) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[24..].copy_from_slice(&n.to_be_bytes());
    o
}

/// Authorization digest (spec §3), Solana field normalization:
/// `to` is the native 32-byte pubkey.
fn compute_digest(account: &[u8; 32], to: &Pubkey, value: u64, data: &[u8], nonce: u64) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 * 6);
    buf.extend_from_slice(account);
    buf.extend_from_slice(&to.to_bytes());
    buf.extend_from_slice(&u256_be_u64(value));
    buf.extend_from_slice(&keccak(data));
    buf.extend_from_slice(&u256_be_u64(nonce));
    buf.extend_from_slice(&u256_be_u64(CHAIN_ID));
    keccak(&buf)
}

// crypto (WOTS + Merkle, spec §2)

const W: u32 = 16;
const LEN: usize = 67;

fn digits(digest: &[u8; 32]) -> [u8; 67] {
    let mut d = [0u8; 67];
    let mut csum: u32 = 0;
    for i in 0..32 {
        let hi = digest[i] >> 4;
        let lo = digest[i] & 0x0f;
        d[2 * i] = hi;
        d[2 * i + 1] = lo;
        csum += W - 1 - (hi as u32);
        csum += W - 1 - (lo as u32);
    }
    d[64] = ((csum >> 8) & 0x0f) as u8;
    d[65] = ((csum >> 4) & 0x0f) as u8;
    d[66] = (csum & 0x0f) as u8;
    d
}

fn pub_key_from_sig(digest: &[u8; 32], sig: &[[u8; 32]]) -> [u8; 32] {
    let d = digits(digest);
    let mut concat = Vec::with_capacity(LEN * 32);
    for i in 0..LEN {
        let mut x = sig[i];
        let mut j = d[i] as u32;
        while j < W - 1 {
            x = keccak(&x);
            j += 1;
        }
        concat.extend_from_slice(&x);
    }
    keccak(&concat)
}

fn wots_leaf(wots_pub: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(14 + 32);
    buf.extend_from_slice(b"PQCG_WOTS_LEAF");
    buf.extend_from_slice(wots_pub);
    keccak(&buf)
}

fn attestor_leaf(id: &[u8; 32], wots_root: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(18 + 64);
    buf.extend_from_slice(b"PQCG_ATTESTOR_LEAF");
    buf.extend_from_slice(id);
    buf.extend_from_slice(wots_root);
    keccak(&buf)
}

fn node(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    keccak(&buf)
}

fn root_from_leaf(leaf: [u8; 32], index: u64, path: &[[u8; 32]]) -> [u8; 32] {
    let mut h = leaf;
    let mut idx = index;
    for sib in path {
        if idx & 1 == 0 {
            h = node(&h, sib);
        } else {
            h = node(sib, &h);
        }
        idx >>= 1;
    }
    h
}

fn read_u32(b: &[u8], off: &mut usize) -> u32 {
    let mut v = 0u32;
    for i in 0..4 {
        v = (v << 8) | (b[*off + i] as u32);
    }
    *off += 4;
    v
}

fn read_u64(b: &[u8], off: &mut usize) -> u64 {
    let mut v = 0u64;
    for i in 0..8 {
        v = (v << 8) | (b[*off + i] as u64);
    }
    *off += 8;
    v
}

fn read_word(b: &[u8], off: &mut usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    w.copy_from_slice(&b[*off..*off + 32]);
    *off += 32;
    w
}

fn read_words(b: &[u8], off: &mut usize, count: u32) -> Vec<[u8; 32]> {
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        out.push(read_word(b, off));
    }
    out
}

fn verify_authorization(blob: &[u8], digest: &[u8; 32], set_root: &[u8; 32], threshold: u32) -> bool {
    let mut off = 0usize;
    let count = read_u32(blob, &mut off);
    let mut seen: Vec<[u8; 32]> = Vec::new();
    let mut valid: u32 = 0;
    for _ in 0..count {
        let attestor_id = read_word(blob, &mut off);
        let wots_root = read_word(blob, &mut off);
        let leaf_index = read_u64(blob, &mut off);
        let sig_len = read_u32(blob, &mut off);
        let sig = read_words(blob, &mut off, sig_len);
        let path_len = read_u32(blob, &mut off);
        let path = read_words(blob, &mut off, path_len);
        let set_index = read_u64(blob, &mut off);
        let sp_len = read_u32(blob, &mut off);
        let set_proof = read_words(blob, &mut off, sp_len);

        if seen.contains(&attestor_id) {
            continue;
        }
        let pubk = pub_key_from_sig(digest, &sig);
        let troot = root_from_leaf(wots_leaf(&pubk), leaf_index, &path);
        if troot != wots_root {
            continue;
        }
        let aleaf = attestor_leaf(&attestor_id, &wots_root);
        let sroot = root_from_leaf(aleaf, set_index, &set_proof);
        if &sroot != set_root {
            continue;
        }
        seen.push(attestor_id);
        valid += 1;
        if valid >= threshold {
            return true;
        }
    }
    valid >= threshold
}

// ─────────────────────────── accounts ──────────────────────────────────────

#[account]
pub struct AttestorOracle {
    pub admin: Pubkey,
    pub l0_program: Pubkey,
    pub attestor_set_root: [u8; 32],
    pub epoch: u64,
    pub threshold: u32,
}
impl AttestorOracle {
    pub const SIZE: usize = 32 + 32 + 32 + 8 + 4;
}

#[account]
pub struct GuardedVault {
    pub owner: Pubkey,
    pub oracle: Pubkey,
    pub migrated: bool,
    pub pqc_commitment: [u8; 32],
    pub pending_commitment: Option<[u8; 32]>,
    pub pending_time: i64,
    pub nonce: u64,
    pub guardians: Vec<Pubkey>,
    pub guardian_threshold: u32,
    pub last_activity: i64,
    pub sweep_active: bool,
    pub sweep_to: Option<Pubkey>,
    pub sweep_approvals: Vec<Pubkey>,
}
impl GuardedVault {
    // Generous fixed allocation (MAX_GUARDIANS each for guardians + approvals).
    pub const SIZE: usize = 32 + 32 + 1 + 32 + (1 + 32) + 8 + 8
        + (4 + MAX_GUARDIANS * 32) + 4 + 8 + 1 + (1 + 32) + (4 + MAX_GUARDIANS * 32);
}

#[derive(Accounts)]
pub struct InitOracle<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(init, payer = admin, space = 8 + AttestorOracle::SIZE, seeds = [b"oracle"], bump)]
    pub oracle: Account<'info, AttestorOracle>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateAttestorSet<'info> {
    #[account(mut, seeds = [b"oracle"], bump)]
    pub oracle: Account<'info, AttestorOracle>,
    pub admin: Signer<'info>,
    /// CHECK: validated as the L0 program's ProofState PDA in the handler.
    pub proof_state: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct InitVault<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(init, payer = owner, space = 8 + GuardedVault::SIZE, seeds = [b"vault", owner.key().as_ref()], bump)]
    pub vault: Account<'info, GuardedVault>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, seeds = [b"vault", vault.owner.as_ref()], bump)]
    pub vault: Account<'info, GuardedVault>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct OwnerOnly<'info> {
    pub owner: Signer<'info>,
    #[account(mut, seeds = [b"vault", vault.owner.as_ref()], bump)]
    pub vault: Account<'info, GuardedVault>,
}

#[derive(Accounts)]
pub struct Execute<'info> {
    #[account(mut, seeds = [b"vault", vault.owner.as_ref()], bump)]
    pub vault: Account<'info, GuardedVault>,
    #[account(seeds = [b"oracle"], bump)]
    pub oracle: Account<'info, AttestorOracle>,
    /// CHECK: must equal the `to` argument; only receives lamports.
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct GuardianAction<'info> {
    pub guardian: Signer<'info>,
    #[account(mut, seeds = [b"vault", vault.owner.as_ref()], bump)]
    pub vault: Account<'info, GuardedVault>,
}

#[derive(Accounts)]
pub struct ExecuteRecovery<'info> {
    #[account(mut, seeds = [b"vault", vault.owner.as_ref()], bump)]
    pub vault: Account<'info, GuardedVault>,
    /// CHECK: must equal the stored sweep target; only receives lamports.
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
}

// ─────────────────────────── errors ────────────────────────────────────────

#[error_code]
pub enum PqcError {
    #[msg("not owner")]
    NotOwner,
    #[msg("stale epoch")]
    StaleEpoch,
    #[msg("bad proof account")]
    BadProofAccount,
    #[msg("L0 proof not verified")]
    ProofNotVerified,
    #[msg("already migrated")]
    AlreadyMigrated,
    #[msg("not migrated")]
    NotMigrated,
    #[msg("no pending migration")]
    NoPending,
    #[msg("commit delay not elapsed")]
    DelayNotElapsed,
    #[msg("bad commitment reveal")]
    BadReveal,
    #[msg("unauthorized")]
    Unauthorized,
    #[msg("bad oracle")]
    BadOracle,
    #[msg("bad recipient")]
    BadRecipient,
    #[msg("not guardian")]
    NotGuardian,
    #[msg("recovery timeout not reached")]
    TimeoutNotReached,
    #[msg("no recovery in flight")]
    NoRecovery,
    #[msg("guardian quorum not reached")]
    NoQuorum,
    #[msg("too many guardians")]
    TooManyGuardians,
}

// ─────────────────────────── tests ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // WOTS test signer (mirrors the spec; on-chain only verifies).
    fn sk(seed: &[u8; 32], leaf: u64, chain: u64) -> [u8; 32] {
        let mut b = Vec::new();
        b.extend_from_slice(b"PQCG_WOTS_SK");
        b.extend_from_slice(seed);
        b.extend_from_slice(&u256_be_u64(leaf));
        b.extend_from_slice(&u256_be_u64(chain));
        keccak(&b)
    }

    fn sign(seed: &[u8; 32], leaf: u64, digest: &[u8; 32]) -> Vec<[u8; 32]> {
        let d = digits(digest);
        (0..LEN)
            .map(|i| {
                let mut x = sk(seed, leaf, i as u64);
                for _ in 0..d[i] {
                    x = keccak(&x);
                }
                x
            })
            .collect()
    }

    /// Height-0 WOTS root = wots_leaf(recomputed pub).
    fn wots_root0(seed: &[u8; 32], leaf: u64, digest: &[u8; 32]) -> [u8; 32] {
        wots_leaf(&pub_key_from_sig(digest, &sign(seed, leaf, digest)))
    }

    fn enc_u32(v: &mut Vec<u8>, n: u32) {
        v.extend_from_slice(&n.to_be_bytes());
    }
    fn enc_u64(v: &mut Vec<u8>, n: u64) {
        v.extend_from_slice(&n.to_be_bytes());
    }
    fn enc_words(v: &mut Vec<u8>, ws: &[[u8; 32]]) {
        enc_u32(v, ws.len() as u32);
        for w in ws {
            v.extend_from_slice(w);
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn enc_proof(
        v: &mut Vec<u8>,
        id: &[u8; 32],
        root: &[u8; 32],
        leaf_index: u64,
        sig: &[[u8; 32]],
        path: &[[u8; 32]],
        set_index: u64,
        set_proof: &[[u8; 32]],
    ) {
        v.extend_from_slice(id);
        v.extend_from_slice(root);
        enc_u64(v, leaf_index);
        enc_words(v, sig);
        enc_words(v, path);
        enc_u64(v, set_index);
        enc_words(v, set_proof);
    }

    struct Fixture {
        digest: [u8; 32],
        set_root: [u8; 32],
        id0: [u8; 32],
        id1: [u8; 32],
        root0: [u8; 32],
        root1: [u8; 32],
        leaf0: [u8; 32],
        leaf1: [u8; 32],
        sig0: Vec<[u8; 32]>,
        sig1: Vec<[u8; 32]>,
    }

    fn fixture() -> Fixture {
        let digest = keccak(b"authorize this");
        let seed0 = [1u8; 32];
        let seed1 = [2u8; 32];
        let id0 = [0x11u8; 32];
        let id1 = [0x22u8; 32];
        let root0 = wots_root0(&seed0, 0, &digest);
        let root1 = wots_root0(&seed1, 0, &digest);
        let leaf0 = attestor_leaf(&id0, &root0);
        let leaf1 = attestor_leaf(&id1, &root1);
        let set_root = node(&leaf0, &leaf1);
        Fixture {
            digest,
            set_root,
            id0,
            id1,
            root0,
            root1,
            leaf0,
            leaf1,
            sig0: sign(&seed0, 0, &digest),
            sig1: sign(&seed1, 0, &digest),
        }
    }

    #[test]
    fn quorum_reached() {
        let f = fixture();
        let mut blob = Vec::new();
        enc_u32(&mut blob, 2);
        enc_proof(&mut blob, &f.id0, &f.root0, 0, &f.sig0, &[], 0, &[f.leaf1]);
        enc_proof(&mut blob, &f.id1, &f.root1, 0, &f.sig1, &[], 1, &[f.leaf0]);
        assert!(verify_authorization(&blob, &f.digest, &f.set_root, 2));
    }

    #[test]
    fn quorum_not_reached() {
        let f = fixture();
        let mut blob = Vec::new();
        enc_u32(&mut blob, 1);
        enc_proof(&mut blob, &f.id0, &f.root0, 0, &f.sig0, &[], 0, &[f.leaf1]);
        assert!(!verify_authorization(&blob, &f.digest, &f.set_root, 2));
    }

    #[test]
    fn non_member_rejected() {
        let f = fixture();
        let fake_id = [0xDEu8; 32];
        let mut blob = Vec::new();
        enc_u32(&mut blob, 2);
        enc_proof(&mut blob, &f.id0, &f.root0, 0, &f.sig0, &[], 0, &[f.leaf1]);
        // root1's signature but a forged id ⇒ attestor leaf not in the set tree.
        enc_proof(&mut blob, &fake_id, &f.root1, 0, &f.sig1, &[], 1, &[f.leaf0]);
        assert!(!verify_authorization(&blob, &f.digest, &f.set_root, 2));
    }

    #[test]
    fn wrong_digest_rejected() {
        let f = fixture();
        let other = keccak(b"different message");
        let mut blob = Vec::new();
        enc_u32(&mut blob, 2);
        enc_proof(&mut blob, &f.id0, &f.root0, 0, &f.sig0, &[], 0, &[f.leaf1]);
        enc_proof(&mut blob, &f.id1, &f.root1, 0, &f.sig1, &[], 1, &[f.leaf0]);
        // Signatures are over `digest`, not `other` ⇒ recomputed roots mismatch.
        assert!(!verify_authorization(&blob, &other, &f.set_root, 2));
    }
}
