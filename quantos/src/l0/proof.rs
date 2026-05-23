//! Wire format of an L0 finality proof.
//!
//! An [`L0FinalityProof`] is the *single* artifact that flows out of
//! Quantos when the L0 hub is enabled. It is intentionally minimal,
//! versioned and self-contained:
//!
//! * `header` captures the slot / epoch identity and the canonical hash
//!   over the proof body.
//! * `validators` lists the public keys *referenced* by the signatures
//!   that follow, alongside their stake weight at the time of signing.
//! * `signatures` is a list of post-quantum signatures (Falcon-512 by
//!   default, Dilithium-3 as a fallback for nodes that do not run
//!   Falcon).
//!
//! All structures derive [`Serialize`] / [`Deserialize`] so that the
//! proof can be encoded with bincode, JSON, MessagePack, or any other
//! serde format depending on what the target chain prefers.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::types::Hash;

/// Wire version emitted by the current implementation. Bumped any time
/// a non-backwards-compatible change to the layout is introduced.
pub const L0_PROOF_VERSION: u16 = 1;

/// Algorithm tag for a [`ProofSignature`]. The values are stable across
/// versions so that older verifiers can still parse newer proofs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PqcSignatureAlgo {
    /// Falcon-512 — preferred for compact L0 proofs.
    Falcon512 = 1,
    /// Dilithium-3 — fallback when Falcon is unavailable.
    Dilithium3 = 2,
}

/// Header of an L0 proof. Captures the identity of the attested
/// checkpoint and the binding hash over the body.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct L0ProofHeader {
    /// Wire version, must equal [`L0_PROOF_VERSION`] on emission.
    pub version: u16,
    /// Epoch the attested checkpoint belongs to.
    pub epoch: u64,
    /// Slot the attested checkpoint belongs to.
    pub slot: u64,
    /// Hash of the previous L0 proof (chaining for replay-protection).
    pub previous_proof_hash: Hash,
    /// State root committed by the L1 DAG at this checkpoint.
    pub state_root: Hash,
    /// Root of the L1 DAG at this checkpoint.
    pub dag_root: Hash,
    /// Hash of the validator set snapshot used to sign this proof.
    pub validator_set_root: Hash,
    /// Total stake covered by the validator set snapshot.
    pub total_stake: u128,
    /// Stake threshold required for finality.
    pub stake_threshold: u128,
    /// Timestamp (ms) the proof was emitted.
    pub emitted_at_ms: u64,
}

/// Description of a single validator that signed the proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorRecord {
    /// 32-byte validator address.
    pub address: [u8; 32],
    /// Validator public key (Falcon-512 or Dilithium-3 depending on
    /// the matching signature entry).
    pub public_key: Vec<u8>,
    /// Stake weight at the time of signing.
    pub stake: u128,
}

/// A single PQC signature attached to the proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofSignature {
    /// Index into [`L0FinalityProof::validators`].
    pub validator_index: u32,
    /// Signature algorithm.
    pub algo: PqcSignatureAlgo,
    /// Raw signature bytes.
    pub signature: Vec<u8>,
}

/// Compact, self-contained L0 finality proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct L0FinalityProof {
    /// Header carrying the binding metadata.
    pub header: L0ProofHeader,
    /// Validator set referenced by `signatures`.
    pub validators: Vec<ValidatorRecord>,
    /// PQC signatures over [`L0FinalityProof::signing_digest`].
    pub signatures: Vec<ProofSignature>,
}

impl L0FinalityProof {
    /// Returns the canonical digest that signers commit to. The digest
    /// covers the header and the validator list, but explicitly *not*
    /// the signatures themselves (to avoid circular hashing).
    pub fn signing_digest(&self) -> Hash {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.header.version.to_be_bytes());
        hasher.update(&self.header.epoch.to_be_bytes());
        hasher.update(&self.header.slot.to_be_bytes());
        hasher.update(self.header.previous_proof_hash);
        hasher.update(self.header.state_root);
        hasher.update(self.header.dag_root);
        hasher.update(self.header.validator_set_root);
        hasher.update(self.header.total_stake.to_be_bytes());
        hasher.update(self.header.stake_threshold.to_be_bytes());
        hasher.update(self.header.emitted_at_ms.to_be_bytes());

        for v in &self.validators {
            hasher.update(v.address);
            hasher.update((v.public_key.len() as u32).to_be_bytes());
            hasher.update(&v.public_key);
            hasher.update(v.stake.to_be_bytes());
        }

        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    /// Full proof hash, including signatures. Used to chain proofs
    /// together and to address them in the archive.
    pub fn proof_hash(&self) -> Hash {
        let mut hasher = Sha3_256::new();
        hasher.update(self.signing_digest());
        for sig in &self.signatures {
            hasher.update(sig.validator_index.to_be_bytes());
            hasher.update([sig.algo as u8]);
            hasher.update((sig.signature.len() as u32).to_be_bytes());
            hasher.update(&sig.signature);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    /// Returns the total stake covered by the signatures actually present.
    pub fn signed_stake(&self) -> u128 {
        self.signatures
            .iter()
            .filter_map(|s| self.validators.get(s.validator_index as usize))
            .fold(0u128, |acc, v| acc.saturating_add(v.stake))
    }

    /// Returns true if the proof's signature aggregate reaches the
    /// stake threshold recorded in the header.
    pub fn meets_threshold(&self) -> bool {
        self.signed_stake() >= self.header.stake_threshold
    }
}
