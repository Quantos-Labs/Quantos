//! # Confidential Contract State
//!
//! Lets a smart contract keep selected storage slots **confidential**: the slot
//! values (a contract's private variables) are encrypted under a contract
//! viewing key and exposed on-chain only as commitments. The public
//! `storage_root` still binds the full slot set, so state integrity and state
//! rent accounting are unaffected — observers simply cannot read the values.
//!
//! Confidentiality is provided here (commitment + ML-KEM/AES viewing key).
//! *Correctness* of a confidential state transition (i.e. that the new
//! committed slots are the honest result of executing the contract) is proven
//! by the VM's zk-STARK execution proof. As documented in the module root, the
//! in-circuit binding of the private witness reuses the same Keccak-AIR track
//! that is pending audit; until then this layer provides confidentiality with
//! commitment-bound integrity, not full zero-knowledge execution.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::types::{hash_data, Hash};

use super::{aead_open, aead_seal, merkle_root, PrivacyError, DOMAIN_CONF_STATE};

/// A single confidential storage slot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfidentialSlot {
    /// Storage key (slot address within the contract).
    pub key: Hash,
    /// Commitment `H(DOMAIN ‖ key ‖ value ‖ blinding)` — public, hides `value`.
    pub value_commitment: Hash,
    /// AES-256-GCM ciphertext of the slot value (openable with the viewing key).
    pub encrypted_value: Vec<u8>,
}

/// Confidential storage for one contract.
///
/// Slots are kept in a `BTreeMap` keyed by slot address so that the
/// `storage_root` is deterministic regardless of insertion order.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConfidentialContractState {
    slots: BTreeMap<Hash, ConfidentialSlot>,
}

/// Commits to a slot value: `H(DOMAIN_CONF_STATE ‖ key ‖ value_le ‖ blinding)`.
pub fn commit_slot(key: &Hash, value: u64, blinding: &Hash) -> Hash {
    let mut data = Vec::with_capacity(DOMAIN_CONF_STATE.len() + 32 + 8 + 32);
    data.extend_from_slice(DOMAIN_CONF_STATE);
    data.extend_from_slice(key);
    data.extend_from_slice(&value.to_le_bytes());
    data.extend_from_slice(blinding);
    hash_data(&data)
}

impl ConfidentialContractState {
    /// Creates an empty confidential storage map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Writes a confidential slot. `viewing_key` is the AES-256 key derived from
    /// the contract's ML-KEM viewing keypair; only key holders can later read
    /// the value, but anyone can verify the commitment is well-formed.
    pub fn set_slot(
        &mut self,
        viewing_key: &[u8; 32],
        key: Hash,
        value: u64,
        blinding: Hash,
    ) -> Result<(), PrivacyError> {
        let value_commitment = commit_slot(&key, value, &blinding);

        let mut plaintext = Vec::with_capacity(8 + 32);
        plaintext.extend_from_slice(&value.to_le_bytes());
        plaintext.extend_from_slice(&blinding);
        let encrypted_value = aead_seal(viewing_key, &plaintext)?;

        self.slots.insert(
            key,
            ConfidentialSlot {
                key,
                value_commitment,
                encrypted_value,
            },
        );
        Ok(())
    }

    /// Reads and decrypts a confidential slot, verifying the commitment opens
    /// to the recovered value.
    pub fn get_slot(
        &self,
        viewing_key: &[u8; 32],
        key: &Hash,
    ) -> Result<Option<u64>, PrivacyError> {
        let slot = match self.slots.get(key) {
            Some(s) => s,
            None => return Ok(None),
        };
        let plaintext = aead_open(viewing_key, &slot.encrypted_value)?;
        if plaintext.len() != 40 {
            return Err(PrivacyError::DecryptionFailed);
        }
        let mut value_bytes = [0u8; 8];
        value_bytes.copy_from_slice(&plaintext[..8]);
        let value = u64::from_le_bytes(value_bytes);
        let mut blinding = [0u8; 32];
        blinding.copy_from_slice(&plaintext[8..40]);

        if commit_slot(key, value, &blinding) != slot.value_commitment {
            return Err(PrivacyError::InvalidCommitment);
        }
        Ok(Some(value))
    }

    /// The public storage root binding all confidential slot commitments.
    /// Leaves are `H(key ‖ value_commitment)` over the sorted slot set.
    pub fn storage_root(&self) -> Hash {
        let leaves: Vec<Hash> = self
            .slots
            .values()
            .map(|s| {
                let mut buf = Vec::with_capacity(64);
                buf.extend_from_slice(&s.key);
                buf.extend_from_slice(&s.value_commitment);
                hash_data(&buf)
            })
            .collect();
        merkle_root(&leaves)
    }

    /// Number of confidential slots.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether the contract has no confidential slots.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Public digest a STARK execution proof binds, witnessing a transition
    /// from `prev_root` to `self.storage_root()`.
    pub fn transition_digest(&self, prev_root: &Hash) -> Hash {
        let mut data = Vec::with_capacity(DOMAIN_CONF_STATE.len() + 64);
        data.extend_from_slice(DOMAIN_CONF_STATE);
        data.extend_from_slice(prev_root);
        data.extend_from_slice(&self.storage_root());
        hash_data(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_set_get_roundtrip() {
        let mut state = ConfidentialContractState::new();
        let vk = [11u8; 32];
        let key = [1u8; 32];
        state.set_slot(&vk, key, 999, [2u8; 32]).unwrap();
        assert_eq!(state.get_slot(&vk, &key).unwrap(), Some(999));
        assert_eq!(state.len(), 1);
        assert_ne!(state.storage_root(), [0u8; 32]);
    }

    #[test]
    fn missing_slot_returns_none() {
        let state = ConfidentialContractState::new();
        assert_eq!(state.get_slot(&[0u8; 32], &[9u8; 32]).unwrap(), None);
    }

    #[test]
    fn wrong_viewing_key_fails() {
        let mut state = ConfidentialContractState::new();
        state.set_slot(&[1u8; 32], [1u8; 32], 5, [3u8; 32]).unwrap();
        assert!(state.get_slot(&[9u8; 32], &[1u8; 32]).is_err());
    }

    #[test]
    fn root_changes_with_state() {
        let mut state = ConfidentialContractState::new();
        let r0 = state.storage_root();
        state.set_slot(&[1u8; 32], [1u8; 32], 1, [0u8; 32]).unwrap();
        let r1 = state.storage_root();
        assert_ne!(r0, r1);
        assert_ne!(state.transition_digest(&r0), [0u8; 32]);
    }
}
