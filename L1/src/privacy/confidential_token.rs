//! # Confidential QN Token Registry
//!
//! Hides **who holds a given native (QN) token and how much**. A transparent
//! QN4 token keeps a public `address → balance` map ([`crate::standards::QN4Token`]);
//! a confidential registry instead keeps a per-token [`ShieldedPool`] of value
//! notes. The *total supply* stays public (auditable issuance), but individual
//! holder balances and transfers are shielded exactly like the base-asset
//! shielded pool.
//!
//! This composes with [`super::stealth`] so that recipients of a confidential
//! token transfer are addressed via one-time stealth addresses, breaking the
//! holder graph as well as the balances.

use serde::{Deserialize, Serialize};

use crate::types::Hash;
use crate::zk::{Commitment, Nullifier, PrivateTransferInputs, StarkProof, StarkProver};

use super::shielded_pool::{ShieldedPool, ShieldedTransfer};
use super::PrivacyError;

/// A shielded holder registry for a single QN token.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfidentialTokenRegistry {
    /// Identifier of the token this registry shields (e.g. hash of the token
    /// contract address / metadata).
    pub token_id: Hash,
    /// Publicly auditable total supply (sum of all minted, minus burned).
    pub public_total_supply: u64,
    /// Per-token shielded note pool (commitments + nullifiers).
    pool: ShieldedPool,
}

impl ConfidentialTokenRegistry {
    /// Creates a new, empty confidential registry for `token_id`.
    pub fn new(token_id: Hash, tree_depth: u8) -> Self {
        Self {
            token_id,
            public_total_supply: 0,
            pool: ShieldedPool::new(tree_depth),
        }
    }

    /// Public note-set root (binds confidential transfers for this token).
    pub fn root(&self) -> Hash {
        self.pool.root()
    }

    /// Read-only access to the underlying pool.
    pub fn pool(&self) -> &ShieldedPool {
        &self.pool
    }

    /// Confidentially mints `value` into a new note commitment, increasing the
    /// public total supply. The minted note commitment is the holder's shielded
    /// balance; the holder identity stays private.
    pub fn shielded_mint(
        &mut self,
        commitment: &Commitment,
        value: u64,
    ) -> Result<u64, PrivacyError> {
        let new_supply = self
            .public_total_supply
            .checked_add(value)
            .ok_or(PrivacyError::BalanceViolation)?;
        let index = self.pool.insert_commitment(commitment)?;
        self.public_total_supply = new_supply;
        Ok(index)
    }

    /// Confidentially burns a note (by nullifier), decreasing the public total
    /// supply by the publicly-declared `value` that the accompanying STARK
    /// proof binds to the burned commitment.
    pub fn shielded_burn(
        &mut self,
        nullifier: &Nullifier,
        value: u64,
    ) -> Result<(), PrivacyError> {
        let new_supply = self
            .public_total_supply
            .checked_sub(value)
            .ok_or(PrivacyError::BalanceViolation)?;
        self.pool.mark_spent(nullifier)?;
        self.public_total_supply = new_supply;
        Ok(())
    }

    /// Confidential token transfer: total supply is unchanged, only ownership
    /// of value moves between shielded notes. Proven and applied through the
    /// shared [`ShieldedTransfer`] machinery.
    #[allow(clippy::too_many_arguments)]
    pub fn shielded_transfer(
        &mut self,
        prover: &StarkProver,
        inputs: &PrivateTransferInputs,
        input_values: &[u64],
        input_blindings: &[Hash],
        output_values: &[u64],
        output_blindings: &[Hash],
        fee_value: u64,
        fee_blinding: Hash,
        note_merkle_proofs: &[Vec<Hash>],
    ) -> Result<StarkProof, PrivacyError> {
        ShieldedTransfer::prove_and_apply(
            prover,
            &mut self.pool,
            inputs,
            input_values,
            input_blindings,
            output_values,
            output_blindings,
            fee_value,
            fee_blinding,
            note_merkle_proofs,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_increases_supply_and_notes() {
        let mut reg = ConfidentialTokenRegistry::new([1u8; 32], 16);
        let c = Commitment::new(1_000, [2u8; 32]);
        reg.shielded_mint(&c, 1_000).unwrap();
        assert_eq!(reg.public_total_supply, 1_000);
        assert_eq!(reg.pool().num_notes(), 1);
        assert_ne!(reg.root(), [0u8; 32]);
    }

    #[test]
    fn burn_decreases_supply() {
        let mut reg = ConfidentialTokenRegistry::new([1u8; 32], 16);
        let c = Commitment::new(500, [2u8; 32]);
        reg.shielded_mint(&c, 500).unwrap();
        let n = Nullifier::new(&[3u8; 32], &[4u8; 32]);
        reg.shielded_burn(&n, 200).unwrap();
        assert_eq!(reg.public_total_supply, 300);
    }

    #[test]
    fn burn_more_than_supply_fails() {
        let mut reg = ConfidentialTokenRegistry::new([1u8; 32], 16);
        let n = Nullifier::new(&[3u8; 32], &[4u8; 32]);
        assert!(matches!(
            reg.shielded_burn(&n, 1),
            Err(PrivacyError::BalanceViolation)
        ));
    }
}
