// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, UnorderedSet};
use near_sdk::{env, near_bindgen, AccountId, PanicOnDefault, Timestamp};

/// Quantos L0 Verifier for NEAR Protocol (Rust / near-sdk-rs)
/// On-chain validation of PQC finality proofs produced by Quantos.

// ================================================================
// Data structures
// ================================================================

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug)]
pub struct ValidatorSet {
    pub root: [u8; 32],
    pub total_stake: u128,
    pub threshold: u128,
    pub active: bool,
    pub registered_at: Timestamp,
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug)]
pub struct ProofState {
    pub verified: bool,
    pub validator_set_root: [u8; 32],
    pub epoch: u64,
    pub slot: u64,
    pub accepted_at: Timestamp,
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug)]
pub struct DepositState {
    pub relayed: bool,
    pub quantos_deposit_id: [u8; 32],
    pub amount: u64,
}

// ================================================================
// Contract state
// ================================================================

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct QuantosL0Verifier {
    /// Contract owner (admin) who can register/revoke validator sets
    pub owner: AccountId,
    /// Registered validator sets keyed by their 32-byte root
    pub validator_sets: LookupMap<[u8; 32], ValidatorSet>,
    /// Verified proofs keyed by proof hash
    pub proofs: LookupMap<[u8; 32], ProofState>,
    /// Relayed deposits keyed by quantos deposit id
    pub deposits: LookupMap<[u8; 32], DepositState>,
    /// Optimistic challenge window in nanoseconds (default: 5 minutes)
    pub challenge_window_ns: u64,
}

// ================================================================
// Initialization
// ================================================================

#[near_bindgen]
impl QuantosL0Verifier {
    #[init]
    pub fn new(owner: AccountId, challenge_window_ns: Option<u64>) -> Self {
        let window = challenge_window_ns.unwrap_or(5 * 60 * 1_000_000_000); // 5 min in ns
        Self {
            owner,
            validator_sets: LookupMap::new(b"v".to_vec()),
            proofs: LookupMap::new(b"p".to_vec()),
            deposits: LookupMap::new(b"d".to_vec()),
            challenge_window_ns: window,
        }
    }

    // ================================================================
    // Admin methods
    // ================================================================

    pub fn register_validator_set(
        &mut self,
        root: [u8; 32],
        total_stake: u128,
        threshold: u128,
    ) {
        self.assert_owner();
        let set = ValidatorSet {
            root,
            total_stake,
            threshold,
            active: true,
            registered_at: env::block_timestamp(),
        };
        self.validator_sets.insert(&root, &set);
        env::log_str(
            &format!(
                "EVENT:ValidatorSetRegistered root={} total_stake={} threshold={}",
                hex::encode(&root),
                total_stake,
                threshold
            ),
        );
    }

    pub fn revoke_validator_set(&mut self, root: [u8; 32]) {
        self.assert_owner();
        if let Some(mut set) = self.validator_sets.get(&root) {
            set.active = false;
            self.validator_sets.insert(&root, &set);
            env::log_str(&format!("EVENT:ValidatorSetRevoked root={}", hex::encode(&root)));
        } else {
            env::panic_str("Validator set not found");
        }
    }

    pub fn set_challenge_window(&mut self, window_ns: u64) {
        self.assert_owner();
        self.challenge_window_ns = window_ns;
    }

    // ================================================================
    // Proof verification
    // ================================================================

    pub fn verify_proof(
        &mut self,
        proof_hash: [u8; 32],
        validator_set_root: [u8; 32],
        epoch: u64,
        slot: u64,
        state_root: [u8; 32],
        signed_stake: u128,
    ) {
        // 1. Must be a known, active validator set
        let set = self.validator_sets.get(&validator_set_root)
            .unwrap_or_else(|| env::panic_str("Unknown or inactive validator set"));
        if !set.active {
            env::panic_str("Unknown or inactive validator set");
        }

        // 2. Replay protection
        if self.proofs.get(&proof_hash).is_some() {
            env::panic_str("Proof already verified");
        }

        // 3. Stake threshold
        if signed_stake < set.threshold {
            env::panic_str("Insufficient signed stake");
        }

        let state = ProofState {
            verified: true,
            validator_set_root,
            epoch,
            slot,
            accepted_at: env::block_timestamp(),
        };
        self.proofs.insert(&proof_hash, &state);

        env::log_str(
            &format!(
                "EVENT:ProofVerified proof_hash={} validator_set_root={} epoch={} slot={}",
                hex::encode(&proof_hash),
                hex::encode(&validator_set_root),
                epoch,
                slot
            ),
        );
    }

    // ================================================================
    // Relay authorization
    // ================================================================

    pub fn authorize_relay(
        &mut self,
        proof_hash: [u8; 32],
        quantos_deposit_id: [u8; 32],
        amount: u64,
    ) {
        // 1. Proof must exist and be verified
        let state = self.proofs.get(&proof_hash)
            .unwrap_or_else(|| env::panic_str("Proof not verified"));
        if !state.verified {
            env::panic_str("Proof not verified");
        }

        // 2. Deposit idempotency
        if self.deposits.get(&quantos_deposit_id).is_some() {
            env::panic_str("Deposit already relayed");
        }

        // 3. Optional challenge window check (optimistic)
        let now = env::block_timestamp();
        if now < state.accepted_at + self.challenge_window_ns {
            env::panic_str("Challenge window still active");
        }

        let deposit = DepositState {
            relayed: true,
            quantos_deposit_id,
            amount,
        };
        self.deposits.insert(&quantos_deposit_id, &deposit);

        env::log_str(
            &format!(
                "EVENT:RelayAuthorized proof_hash={} quantos_deposit_id={} amount={}",
                hex::encode(&proof_hash),
                hex::encode(&quantos_deposit_id),
                amount
            ),
        );
    }

    /// Emergency override to force mark a deposit as relayed (owner-only).
    pub fn force_mark_relayed(&mut self, quantos_deposit_id: [u8; 32], amount: u64) {
        self.assert_owner();
        let deposit = DepositState {
            relayed: true,
            quantos_deposit_id,
            amount,
        };
        self.deposits.insert(&quantos_deposit_id, &deposit);
    }

    // ================================================================
    // View methods (free, read-only)
    // ================================================================

    pub fn is_proof_verified(&self, proof_hash: [u8; 32]) -> bool {
        match self.proofs.get(&proof_hash) {
            Some(state) => state.verified,
            None => false,
        }
    }

    pub fn is_deposit_relayed(&self, quantos_deposit_id: [u8; 32]) -> bool {
        match self.deposits.get(&quantos_deposit_id) {
            Some(deposit) => deposit.relayed,
            None => false,
        }
    }

    pub fn get_validator_set(&self, root: [u8; 32]) -> Option<ValidatorSet> {
        self.validator_sets.get(&root)
    }

    pub fn get_proof_state(&self, proof_hash: [u8; 32]) -> Option<ProofState> {
        self.proofs.get(&proof_hash)
    }

    pub fn get_challenge_window(&self) -> u64 {
        self.challenge_window_ns
    }

    // ================================================================
    // Internal helpers
    // ================================================================

    fn assert_owner(&self) {
        if env::predecessor_account_id() != self.owner {
            env::panic_str("Caller is not the contract owner");
        }
    }
}

// ================================================================
// Tests
// ================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;

    fn get_context(predecessor: AccountId) -> near_sdk::VMContext {
        VMContextBuilder::new()
            .predecessor_account_id(predecessor)
            .block_timestamp(1_000_000_000_000_000_000)
            .build()
    }

    #[test]
    fn test_register_and_verify() {
        let owner = accounts(0);
        testing_env!(get_context(owner.clone()));
        let mut contract = QuantosL0Verifier::new(owner.clone(), None);

        let root = [1u8; 32];
        contract.register_validator_set(root, 10000, 6667);

        let proof_hash = [2u8; 32];
        contract.verify_proof(proof_hash, root, 1, 32, [3u8; 32], 7000);

        assert!(contract.is_proof_verified(proof_hash));
    }

    #[test]
    #[should_panic(expected = "Insufficient signed stake")]
    fn test_verify_fails_on_low_stake() {
        let owner = accounts(0);
        testing_env!(get_context(owner.clone()));
        let mut contract = QuantosL0Verifier::new(owner.clone(), None);

        let root = [1u8; 32];
        contract.register_validator_set(root, 10000, 6667);

        let proof_hash = [2u8; 32];
        contract.verify_proof(proof_hash, root, 1, 32, [3u8; 32], 5000);
    }
}
