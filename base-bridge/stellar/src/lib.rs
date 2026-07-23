// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

#![no_std]
use soroban_sdk::{contract, contracterror, contractimpl, contracttype, symbol_short, Address, Env, Symbol, Vec, Map};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum L0Error {
    UnknownSet = 1,
    InsufficientStake = 2,
    ProofAlreadyVerified = 3,
    ProofNotVerified = 4,
    DepositAlreadyRelayed = 5,
    NotAdmin = 6,
    ChallengeWindowActive = 7,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorSet {
    pub root: [u8; 32],
    pub total_stake: u128,
    pub threshold: u128,
    pub active: bool,
    pub registered_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofState {
    pub verified: bool,
    pub validator_set_root: [u8; 32],
    pub epoch: u64,
    pub slot: u64,
    pub accepted_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositState {
    pub relayed: bool,
    pub quantos_deposit_id: [u8; 32],
    pub amount: u64,
}

#[contracttype]
pub enum DataKey {
    Admin,
    ChallengeWindow,
    ValidatorSet([u8; 32]),
    Proof([u8; 32]),
    Deposit([u8; 32]),
}

#[contract]
pub struct QuantosL0Verifier;

#[contractimpl]
impl QuantosL0Verifier {
    pub fn init(env: Env, admin: Address, challenge_window: Option<u64>) {
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        let window = challenge_window.unwrap_or(300);
        env.storage().instance().set(&DataKey::ChallengeWindow, &window);
    }

    pub fn register_validator_set(env: Env, root: [u8; 32], total_stake: u128, threshold: u128) {
        Self::admin(&env).require_auth();
        let set = ValidatorSet {
            root,
            total_stake,
            threshold,
            active: true,
            registered_at: env.ledger().timestamp(),
        };
        env.storage().persistent().set(&DataKey::ValidatorSet(root), &set);
        env.events().publish((symbol_short!("VSetReg"),), (root, total_stake, threshold));
    }

    pub fn revoke_validator_set(env: Env, root: [u8; 32]) {
        Self::admin(&env).require_auth();
        let mut set: ValidatorSet = env.storage().persistent().get(&DataKey::ValidatorSet(root)).unwrap_or_else(|| panic!("unknown set"));
        set.active = false;
        env.storage().persistent().set(&DataKey::ValidatorSet(root), &set);
        env.events().publish((symbol_short!("VSetRev"),), root);
    }

    pub fn verify_proof(env: Env, proof_hash: [u8; 32], validator_set_root: [u8; 32], epoch: u64, slot: u64, _state_root: [u8; 32], signed_stake: u128) {
        let set: ValidatorSet = env.storage().persistent().get(&DataKey::ValidatorSet(validator_set_root)).unwrap_or_else(|| panic!("unknown set"));
        assert!(set.active, "unknown set");
        if env.storage().persistent().has(&DataKey::Proof(proof_hash)) {
            panic!("already verified");
        }
        assert!(signed_stake >= set.threshold, "insufficient stake");
        let state = ProofState {
            verified: true,
            validator_set_root,
            epoch,
            slot,
            accepted_at: env.ledger().timestamp(),
        };
        env.storage().persistent().set(&DataKey::Proof(proof_hash), &state);
        env.events().publish((symbol_short!("ProofVer"),), (proof_hash, validator_set_root, epoch, slot));
    }

    pub fn authorize_relay(env: Env, proof_hash: [u8; 32], quantos_deposit_id: [u8; 32], amount: u64) {
        let state: ProofState = env.storage().persistent().get(&DataKey::Proof(proof_hash)).unwrap_or_else(|| panic!("not verified"));
        assert!(state.verified, "not verified");
        if env.storage().persistent().has(&DataKey::Deposit(quantos_deposit_id)) {
            panic!("already relayed");
        }
        let window: u64 = env.storage().instance().get(&DataKey::ChallengeWindow).unwrap_or(300);
        assert!(env.ledger().timestamp() >= state.accepted_at + window, "challenge window active");
        let deposit = DepositState { relayed: true, quantos_deposit_id, amount };
        env.storage().persistent().set(&DataKey::Deposit(quantos_deposit_id), &deposit);
        env.events().publish((symbol_short!("RelayAuth"),), (proof_hash, quantos_deposit_id, amount));
    }

    pub fn force_mark_relayed(env: Env, quantos_deposit_id: [u8; 32], amount: u64) {
        Self::admin(&env).require_auth();
        let deposit = DepositState { relayed: true, quantos_deposit_id, amount };
        env.storage().persistent().set(&DataKey::Deposit(quantos_deposit_id), &deposit);
    }

    pub fn is_proof_verified(env: Env, proof_hash: [u8; 32]) -> bool {
        match env.storage().persistent().get::<DataKey, ProofState>(&DataKey::Proof(proof_hash)) {
            Some(state) => state.verified,
            None => false,
        }
    }

    pub fn is_deposit_relayed(env: Env, deposit_id: [u8; 32]) -> bool {
        match env.storage().persistent().get::<DataKey, DepositState>(&DataKey::Deposit(deposit_id)) {
            Some(d) => d.relayed,
            None => false,
        }
    }

    fn admin(env: &Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }
}
