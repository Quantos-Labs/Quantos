//! Quantos L0 finality hub.
//!
//! Consumes finalized [`Checkpoint`]s from the L1 consensus path and
//! turns them into [`L0FinalityProof`]s that can be relayed to any
//! supported target chain.

use std::collections::VecDeque;
use std::sync::Arc;

use parking_lot::RwLock;
use sha3::{Digest, Sha3_256};

use crate::crypto::{verify_dilithium_batch, verify_falcon};
use crate::l0::config::L0Config;
use crate::l0::error::{L0Error, L0Result};
use crate::l0::proof::{
    L0FinalityProof, L0ProofHeader, L0_PROOF_VERSION, PqcSignatureAlgo, ProofSignature,
    ValidatorRecord,
};
use crate::types::{Checkpoint, Hash};

/// Snapshot of the validator set used to sign a given proof.
#[derive(Clone, Debug)]
pub struct ValidatorSetSnapshot {
    /// Hash that uniquely identifies the snapshot (committed in the proof).
    pub root: Hash,
    /// Validators eligible to sign at this height.
    pub validators: Vec<ValidatorRecord>,
}

impl ValidatorSetSnapshot {
    /// Returns the total stake covered by the snapshot.
    pub fn total_stake(&self) -> u128 {
        self.validators
            .iter()
            .fold(0u128, |acc, v| acc.saturating_add(v.stake))
    }

    /// Convenience: looks up a validator by address.
    pub fn position_of(&self, address: &[u8; 32]) -> Option<usize> {
        self.validators.iter().position(|v| v.address == *address)
    }

    /// Computes the canonical root of a snapshot from a list of
    /// validator records. Intended to be used at construction time.
    pub fn compute_root(records: &[ValidatorRecord]) -> Hash {
        let mut hasher = Sha3_256::new();
        for v in records {
            hasher.update(v.address);
            hasher.update((v.public_key.len() as u32).to_be_bytes());
            hasher.update(&v.public_key);
            hasher.update(v.stake.to_be_bytes());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }
}

/// Metrics produced by the hub. Cheap to clone, safe to expose to
/// monitoring endpoints.
#[derive(Clone, Debug, Default)]
pub struct HubMetrics {
    /// Number of proofs produced since boot.
    pub proofs_produced: u64,
    /// Number of proofs that failed self-verification.
    pub proofs_failed: u64,
    /// Number of proofs cached in the in-memory archive.
    pub archived_proofs: u64,
}

/// Signature contribution that a validator hands to the hub.
#[derive(Clone, Debug)]
pub struct SignatureContribution {
    /// Validator address.
    pub validator: [u8; 32],
    /// Algorithm used for the signature.
    pub algo: PqcSignatureAlgo,
    /// Raw signature bytes.
    pub signature: Vec<u8>,
}

/// L0 finality hub.
pub struct FinalityHub {
    config: Arc<RwLock<L0Config>>,
    metrics: Arc<RwLock<HubMetrics>>,
    last_proof_hash: Arc<RwLock<Hash>>,
    archive: Arc<RwLock<VecDeque<L0FinalityProof>>>,
}

impl FinalityHub {
    /// Creates a new hub with the provided configuration.
    pub fn new(config: L0Config) -> L0Result<Self> {
        config.validate().map_err(L0Error::Config)?;
        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            metrics: Arc::new(RwLock::new(HubMetrics::default())),
            last_proof_hash: Arc::new(RwLock::new([0u8; 32])),
            archive: Arc::new(RwLock::new(VecDeque::new())),
        })
    }

    /// Returns whether the hub is active.
    pub fn is_enabled(&self) -> bool {
        self.config.read().enabled
    }

    /// Updates the live configuration. Used by admin endpoints.
    pub fn update_config(&self, config: L0Config) -> L0Result<()> {
        config.validate().map_err(L0Error::Config)?;
        *self.config.write() = config;
        Ok(())
    }

    /// Returns a snapshot of the current metrics.
    pub fn metrics(&self) -> HubMetrics {
        self.metrics.read().clone()
    }

    /// Builds a finality proof from a finalized checkpoint and the
    /// active validator set snapshot. The hub does *not* solicit
    /// signatures itself — those are provided by the existing finality
    /// committee through `contributions`.
    pub fn build_proof(
        &self,
        checkpoint: &Checkpoint,
        snapshot: &ValidatorSetSnapshot,
        contributions: &[SignatureContribution],
    ) -> L0Result<L0FinalityProof> {
        if !self.is_enabled() {
            return Err(L0Error::Config("L0 hub is disabled".into()));
        }
        if checkpoint.slot == 0 && checkpoint.epoch == 0 {
            return Err(L0Error::InvalidCheckpoint(
                "genesis checkpoint cannot be promoted".into(),
            ));
        }
        if snapshot.validators.is_empty() {
            return Err(L0Error::UnknownValidatorSet(
                "snapshot has no validators".into(),
            ));
        }

        let cfg = self.config.read().clone();
        let total_stake = snapshot.total_stake();
        let required = cfg.required_stake(total_stake);

        let validator_set_root = snapshot.root;
        let previous_proof_hash = *self.last_proof_hash.read();

        let header = L0ProofHeader {
            version: L0_PROOF_VERSION,
            epoch: checkpoint.epoch,
            slot: checkpoint.slot,
            previous_proof_hash,
            state_root: checkpoint.state_root,
            dag_root: checkpoint.dag_root,
            validator_set_root,
            total_stake,
            stake_threshold: required,
            emitted_at_ms: chrono::Utc::now().timestamp_millis() as u64,
        };

        // Build a draft proof so we can compute the signing digest the
        // contributors must have signed.
        let mut proof = L0FinalityProof {
            header,
            validators: snapshot.validators.clone(),
            signatures: Vec::with_capacity(contributions.len()),
        };
        let digest = proof.signing_digest();

        // Verify and attach each contribution. We do a stake tally on
        // the fly to short-circuit as soon as the threshold is met.
        let mut signed_stake: u128 = 0;
        for contribution in contributions {
            let Some(index) = snapshot.position_of(&contribution.validator) else {
                continue;
            };
            let validator = &snapshot.validators[index];

            let ok = match contribution.algo {
                PqcSignatureAlgo::Falcon512 => verify_falcon(
                    &validator.public_key,
                    &digest,
                    &contribution.signature,
                )
                .unwrap_or(false),
                PqcSignatureAlgo::Dilithium3 => verify_dilithium_batch(
                    validator.public_key.clone(),
                    digest.to_vec(),
                    contribution.signature.clone(),
                ),
            };

            if !ok {
                continue;
            }

            // Refuse duplicates.
            if proof
                .signatures
                .iter()
                .any(|s| s.validator_index as usize == index)
            {
                continue;
            }

            proof.signatures.push(ProofSignature {
                validator_index: index as u32,
                algo: contribution.algo,
                signature: contribution.signature.clone(),
            });
            signed_stake = signed_stake.saturating_add(validator.stake);
        }

        if signed_stake < required {
            self.metrics.write().proofs_failed = self
                .metrics
                .read()
                .proofs_failed
                .saturating_add(1);
            return Err(L0Error::InsufficientStake {
                signed: signed_stake,
                required,
            });
        }

        let proof_hash = proof.proof_hash();
        *self.last_proof_hash.write() = proof_hash;

        if cfg.archive_proofs {
            let mut archive = self.archive.write();
            if archive.len() >= cfg.archive_capacity {
                archive.pop_front();
            }
            archive.push_back(proof.clone());
            self.metrics.write().archived_proofs = archive.len() as u64;
        }

        self.metrics.write().proofs_produced = self
            .metrics
            .read()
            .proofs_produced
            .saturating_add(1);

        Ok(proof)
    }

    /// Returns the most recently produced proof, if any.
    pub fn latest(&self) -> Option<L0FinalityProof> {
        self.archive.read().back().cloned()
    }

    /// Looks up a proof by its hash in the in-memory archive.
    pub fn lookup(&self, hash: &Hash) -> Option<L0FinalityProof> {
        self.archive
            .read()
            .iter()
            .rev()
            .find(|p| &p.proof_hash() == hash)
            .cloned()
    }
}
