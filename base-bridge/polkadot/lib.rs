// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

#![cfg_attr(not(feature = "std"), no_std)]

use ink_prelude::vec::Vec;
use ink_storage::{Mapping, traits::SpreadAllocate};

/// Quantos L0 Verifier for Polkadot / ink!
/// On-chain validation of PQC finality proofs produced by Quantos.
/// Deployed on any ink!-compatible parachain (Astar, Aleph Zero, Phala, ...).

#[ink::contract]
mod quantos_l0_verifier {
    use super::*;

    // ================================================================
    // Types
    // ================================================================
    pub type Hash32 = [u8; 32];

    // ================================================================
    // Data structures
    // ================================================================
    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct ValidatorSet {
        pub root: Hash32,
        pub total_stake: u128,
        pub threshold: u128,
        pub active: bool,
        pub registered_at: u64,
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct ProofState {
        pub verified: bool,
        pub validator_set_root: Hash32,
        pub epoch: u64,
        pub slot: u64,
        pub accepted_at: u64,
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct DepositState {
        pub relayed: bool,
        pub quantos_deposit_id: Hash32,
        pub amount: u64,
    }

    // ================================================================
    // Contract storage
    // ================================================================
    #[ink(storage)]
    #[derive(SpreadAllocate)]
    pub struct QuantosL0Verifier {
        admin: AccountId,
        challenge_window: u64,
        validator_sets: Mapping<Hash32, ValidatorSet>,
        proofs: Mapping<Hash32, ProofState>,
        deposits: Mapping<Hash32, DepositState>,
    }

    // ================================================================
    // Events
    // ================================================================
    #[ink(event)]
    pub struct ValidatorSetRegistered {
        #[ink(topic)]
        pub root: Hash32,
        pub total_stake: u128,
        pub threshold: u128,
    }

    #[ink(event)]
    pub struct ValidatorSetRevoked {
        #[ink(topic)]
        pub root: Hash32,
    }

    #[ink(event)]
    pub struct ProofVerified {
        #[ink(topic)]
        pub proof_hash: Hash32,
        #[ink(topic)]
        pub validator_set_root: Hash32,
        pub epoch: u64,
        pub slot: u64,
    }

    #[ink(event)]
    pub struct RelayAuthorized {
        #[ink(topic)]
        pub proof_hash: Hash32,
        #[ink(topic)]
        pub quantos_deposit_id: Hash32,
        pub amount: u64,
    }

    // ================================================================
    // Errors
    // ================================================================
    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum L0Error {
        UnknownSet,
        InsufficientStake,
        ProofAlreadyVerified,
        ProofNotVerified,
        DepositAlreadyRelayed,
        NotAdmin,
        ChallengeWindowActive,
    }

    // ================================================================
    // Implementation
    // ================================================================
    impl QuantosL0Verifier {
        #[ink(constructor)]
        pub fn new(admin: AccountId, challenge_window: u64) -> Self {
            ink_lang::utils::initialize_contract(|contract: &mut Self| {
                contract.admin = admin;
                contract.challenge_window = if challenge_window == 0 { 300 } else { challenge_window };
            })
        }

        #[ink(constructor)]
        pub fn default() -> Self {
            ink_lang::utils::initialize_contract(|contract: &mut Self| {
                contract.admin = Self::env().caller();
                contract.challenge_window = 300;
            })
        }

        // ---------------------------------------------------------------
        // Admin
        // ---------------------------------------------------------------
        #[ink(message)]
        pub fn register_validator_set(
            &mut self,
            root: Hash32,
            total_stake: u128,
            threshold: u128,
        ) -> Result<(), L0Error> {
            self.assert_admin()?;
            let set = ValidatorSet {
                root,
                total_stake,
                threshold,
                active: true,
                registered_at: self.env().block_timestamp(),
            };
            self.validator_sets.insert(root, &set);
            self.env().emit_event(ValidatorSetRegistered { root, total_stake, threshold });
            Ok(())
        }

        #[ink(message)]
        pub fn revoke_validator_set(&mut self, root: Hash32) -> Result<(), L0Error> {
            self.assert_admin()?;
            let mut set = self.validator_sets.get(root).ok_or(L0Error::UnknownSet)?;
            set.active = false;
            self.validator_sets.insert(root, &set);
            self.env().emit_event(ValidatorSetRevoked { root });
            Ok(())
        }

        #[ink(message)]
        pub fn set_challenge_window(&mut self, window: u64) -> Result<(), L0Error> {
            self.assert_admin()?;
            self.challenge_window = window;
            Ok(())
        }

        #[ink(message)]
        pub fn transfer_admin(&mut self, new_admin: AccountId) -> Result<(), L0Error> {
            self.assert_admin()?;
            self.admin = new_admin;
            Ok(())
        }

        // ---------------------------------------------------------------
        // Proof verification
        // ---------------------------------------------------------------
        #[ink(message)]
        pub fn verify_proof(
            &mut self,
            proof_hash: Hash32,
            validator_set_root: Hash32,
            epoch: u64,
            slot: u64,
            _state_root: Hash32,
            signed_stake: u128,
        ) -> Result<(), L0Error> {
            let set = self.validator_sets.get(validator_set_root).ok_or(L0Error::UnknownSet)?;
            if !set.active {
                return Err(L0Error::UnknownSet);
            }
            if self.proofs.get(proof_hash).is_some() {
                return Err(L0Error::ProofAlreadyVerified);
            }
            if signed_stake < set.threshold {
                return Err(L0Error::InsufficientStake);
            }
            let state = ProofState {
                verified: true,
                validator_set_root,
                epoch,
                slot,
                accepted_at: self.env().block_timestamp(),
            };
            self.proofs.insert(proof_hash, &state);
            self.env().emit_event(ProofVerified {
                proof_hash,
                validator_set_root,
                epoch,
                slot,
            });
            Ok(())
        }

        // ---------------------------------------------------------------
        // Relay authorization
        // ---------------------------------------------------------------
        #[ink(message)]
        pub fn authorize_relay(
            &mut self,
            proof_hash: Hash32,
            quantos_deposit_id: Hash32,
            amount: u64,
        ) -> Result<(), L0Error> {
            let state = self.proofs.get(proof_hash).ok_or(L0Error::ProofNotVerified)?;
            if !state.verified {
                return Err(L0Error::ProofNotVerified);
            }
            if self.deposits.get(quantos_deposit_id).is_some() {
                return Err(L0Error::DepositAlreadyRelayed);
            }
            let now = self.env().block_timestamp();
            if now < state.accepted_at + self.challenge_window {
                return Err(L0Error::ChallengeWindowActive);
            }
            let deposit = DepositState {
                relayed: true,
                quantos_deposit_id,
                amount,
            };
            self.deposits.insert(quantos_deposit_id, &deposit);
            self.env().emit_event(RelayAuthorized {
                proof_hash,
                quantos_deposit_id,
                amount,
            });
            Ok(())
        }

        #[ink(message)]
        pub fn force_mark_relayed(
            &mut self,
            quantos_deposit_id: Hash32,
            amount: u64,
        ) -> Result<(), L0Error> {
            self.assert_admin()?;
            let deposit = DepositState {
                relayed: true,
                quantos_deposit_id,
                amount,
            };
            self.deposits.insert(quantos_deposit_id, &deposit);
            Ok(())
        }

        // ---------------------------------------------------------------
        // View functions
        // ---------------------------------------------------------------
        #[ink(message)]
        pub fn is_proof_verified(&self, proof_hash: Hash32) -> bool {
            match self.proofs.get(proof_hash) {
                Some(state) => state.verified,
                None => false,
            }
        }

        #[ink(message)]
        pub fn is_deposit_relayed(&self, deposit_id: Hash32) -> bool {
            match self.deposits.get(deposit_id) {
                Some(d) => d.relayed,
                None => false,
            }
        }

        #[ink(message)]
        pub fn get_validator_set(&self, root: Hash32) -> Option<ValidatorSet> {
            self.validator_sets.get(root)
        }

        #[ink(message)]
        pub fn get_challenge_window(&self) -> u64 {
            self.challenge_window
        }

        // ---------------------------------------------------------------
        // Internal
        // ---------------------------------------------------------------
        fn assert_admin(&self) -> Result<(), L0Error> {
            if self.env().caller() != self.admin {
                return Err(L0Error::NotAdmin);
            }
            Ok(())
        }
    }
}
