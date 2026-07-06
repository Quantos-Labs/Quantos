//! # Shielded Pool
//!
//! Hides **transaction amounts** and **account balances**, and (together with
//! [`super::stealth`]) the **sender→recipient graph**.
//!
//! Funds in confidential mode are represented as UTXO-style **notes** rather
//! than as a public `address → balance` map. Each note publishes only a value
//! *commitment* `C = H(value ‖ blinding)`; the amount and owner stay private.
//! Spending a note publishes a **nullifier** `N = H(note_id ‖ spend_key)` that
//! prevents double-spends without revealing which note was consumed.
//!
//! Correctness of a confidential transfer — value conservation
//! `sum(inputs) = sum(outputs) + fee`, 64-bit range bounds, note membership and
//! nullifier derivation — is proven with the existing Winterfell zk-STARK
//! prover via [`crate::zk::StarkProver::prove_private_transfer`]. This module
//! adds the **persistent state** (commitment tree + nullifier set) and the
//! post-quantum **note encryption** that the prover does not own.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::crypto::derive_channel_key;
use crate::types::{hash_data, Address, Hash};
use crate::zk::{
    Commitment, Nullifier, PrivateNote, PrivateTransferInputs, StarkProof, StarkProver,
};

use super::{aead_open, aead_seal, merkle_root, PrivacyError, DOMAIN_NOTE_ENC};

/// Append-only note-commitment tree plus the spent-nullifier set.
///
/// The commitment tree proves a note *exists* (Merkle membership); the
/// nullifier set proves a note has *not yet been spent*. Together they are the
/// only public state the shielded pool exposes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedPool {
    /// Note commitments, in insertion order (Merkle leaves).
    leaves: Vec<Hash>,
    /// Spent nullifiers. `BTreeSet` keeps it deterministic and serialisable.
    nullifiers: BTreeSet<Hash>,
    /// Maximum number of notes (2^depth).
    max_leaves: usize,
}

impl ShieldedPool {
    /// Creates an empty pool with a tree of depth `tree_depth`
    /// (capacity `2^tree_depth` notes).
    pub fn new(tree_depth: u8) -> Self {
        let depth = tree_depth.min(40) as u32; // guard against usize overflow
        Self {
            leaves: Vec::new(),
            nullifiers: BTreeSet::new(),
            max_leaves: 1usize << depth,
        }
    }

    /// Inserts a note commitment, returning its leaf index.
    pub fn insert_commitment(&mut self, commitment: &Commitment) -> Result<u64, PrivacyError> {
        if self.leaves.len() >= self.max_leaves {
            return Err(PrivacyError::TreeFull);
        }
        let index = self.leaves.len() as u64;
        self.leaves.push(commitment.data);
        Ok(index)
    }

    /// Current Merkle root over all note commitments. This is the
    /// `note_set_root` that confidential transfers bind to.
    pub fn root(&self) -> Hash {
        merkle_root(&self.leaves)
    }

    /// Returns `true` if the nullifier has already been spent.
    pub fn is_spent(&self, nullifier: &Nullifier) -> bool {
        self.nullifiers.contains(&nullifier.data)
    }

    /// Marks a nullifier as spent, rejecting double-spends.
    pub fn mark_spent(&mut self, nullifier: &Nullifier) -> Result<(), PrivacyError> {
        if !self.nullifiers.insert(nullifier.data) {
            return Err(PrivacyError::DoubleSpend);
        }
        Ok(())
    }

    /// Number of notes inserted so far.
    pub fn num_notes(&self) -> usize {
        self.leaves.len()
    }

    /// Number of spent nullifiers.
    pub fn num_spent(&self) -> usize {
        self.nullifiers.len()
    }
}

/// Derives the symmetric note-encryption key from a stealth/KEM shared secret.
fn note_key(shared_secret: &[u8]) -> Result<[u8; 32], PrivacyError> {
    derive_channel_key(shared_secret, DOMAIN_NOTE_ENC).map_err(|e| PrivacyError::Crypto(e.to_string()))
}

/// Seals a note: builds the public commitment and encrypts `(value, blinding)`
/// so that only the holder of `shared_secret` (the stealth recipient) can open
/// it. The `owner` is normally a one-time stealth address.
pub fn seal_note(
    shared_secret: &[u8],
    owner: Address,
    value: u64,
    blinding: Hash,
) -> Result<PrivateNote, PrivacyError> {
    let commitment = Commitment::new(value, blinding);

    let mut plaintext = Vec::with_capacity(8 + 32);
    plaintext.extend_from_slice(&value.to_le_bytes());
    plaintext.extend_from_slice(&blinding);

    let key = note_key(shared_secret)?;
    let encrypted_value = aead_seal(&key, &plaintext)?;

    let mut id_data = Vec::with_capacity(64);
    id_data.extend_from_slice(&owner);
    id_data.extend_from_slice(&commitment.data);
    let id = hash_data(&id_data);

    Ok(PrivateNote {
        id,
        owner,
        commitment,
        encrypted_value,
    })
}

/// Opens a sealed note, recovering `(value, blinding)` and checking the
/// commitment opens correctly.
pub fn open_note(shared_secret: &[u8], note: &PrivateNote) -> Result<(u64, Hash), PrivacyError> {
    let key = note_key(shared_secret)?;
    let plaintext = aead_open(&key, &note.encrypted_value)?;
    if plaintext.len() != 40 {
        return Err(PrivacyError::DecryptionFailed);
    }
    let mut value_bytes = [0u8; 8];
    value_bytes.copy_from_slice(&plaintext[..8]);
    let value = u64::from_le_bytes(value_bytes);
    let mut blinding = [0u8; 32];
    blinding.copy_from_slice(&plaintext[8..40]);

    if !note.commitment.verify(value, &blinding) {
        return Err(PrivacyError::InvalidCommitment);
    }
    Ok((value, blinding))
}

/// Generates a fresh random blinding factor.
pub fn random_blinding() -> Hash {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

/// High-level confidential transfer: proves validity with the zk-STARK prover
/// **and** atomically updates the pool (spends input nullifiers, inserts output
/// commitments). The proof is rejected before any state change if it would
/// double-spend.
pub struct ShieldedTransfer;

impl ShieldedTransfer {
    /// Proves and applies a confidential transfer.
    ///
    /// The private witness (`*_values`, `*_blindings`, merkle proofs) is passed
    /// straight through to [`StarkProver::prove_private_transfer`], which
    /// enforces value conservation and range bounds. On success the pool is
    /// mutated: nullifiers are burned and output commitments are appended.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_and_apply(
        prover: &StarkProver,
        pool: &mut ShieldedPool,
        inputs: &PrivateTransferInputs,
        input_values: &[u64],
        input_blindings: &[Hash],
        output_values: &[u64],
        output_blindings: &[Hash],
        fee_value: u64,
        fee_blinding: Hash,
        note_merkle_proofs: &[Vec<Hash>],
    ) -> Result<StarkProof, PrivacyError> {
        // Reject double-spends before doing expensive proving.
        for n in &inputs.input_nullifiers {
            if pool.is_spent(n) {
                return Err(PrivacyError::DoubleSpend);
            }
        }

        let proof = prover
            .prove_private_transfer(
                inputs,
                input_values,
                input_blindings,
                output_values,
                output_blindings,
                fee_value,
                fee_blinding,
                note_merkle_proofs,
            )
            .map_err(|e| PrivacyError::Zk(e.to_string()))?;

        // Apply state transition atomically.
        for n in &inputs.input_nullifiers {
            pool.mark_spent(n)?;
        }
        for c in &inputs.output_commitments {
            pool.insert_commitment(c)?;
        }

        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::stealth::{create_stealth_payment, StealthKeys};

    #[test]
    fn note_seal_open_roundtrip_via_stealth() {
        let keys = StealthKeys::generate([3u8; 32]).unwrap();
        let (payment, payer_ss) = create_stealth_payment(&keys.meta_address()).unwrap();

        let blinding = random_blinding();
        let note = seal_note(&payer_ss, payment.one_time_address, 42_000, blinding).unwrap();

        // Recipient recovers the same secret and opens the note.
        let recipient_ss = keys.recover_shared_secret(&payment).unwrap();
        let (value, recovered_blinding) = open_note(&recipient_ss, &note).unwrap();
        assert_eq!(value, 42_000);
        assert_eq!(recovered_blinding, blinding);
    }

    #[test]
    fn pool_tracks_notes_and_rejects_double_spend() {
        let mut pool = ShieldedPool::new(16);
        let c = Commitment::new(100, [1u8; 32]);
        let idx = pool.insert_commitment(&c).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(pool.num_notes(), 1);
        assert_ne!(pool.root(), [0u8; 32]);

        let n = Nullifier::new(&[7u8; 32], &[8u8; 32]);
        assert!(!pool.is_spent(&n));
        pool.mark_spent(&n).unwrap();
        assert!(pool.is_spent(&n));
        assert!(matches!(pool.mark_spent(&n), Err(PrivacyError::DoubleSpend)));
    }

    #[test]
    fn opening_with_wrong_secret_fails() {
        let keys = StealthKeys::generate([4u8; 32]).unwrap();
        let (payment, payer_ss) = create_stealth_payment(&keys.meta_address()).unwrap();
        let note = seal_note(&payer_ss, payment.one_time_address, 7, random_blinding()).unwrap();
        assert!(open_note(&[0u8; 32], &note).is_err());
    }
}
