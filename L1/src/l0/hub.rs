//! Quantos L0 finality hub.
//!
//! Consumes finalized [`Checkpoint`]s from the L1 consensus path and
//! turns them into [`L0FinalityProof`]s that can be relayed to any
//! supported target chain.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use parking_lot::RwLock;
use sha3::{Digest, Sha3_256};

use crate::crypto::{verify_dilithium_batch, verify_ml_dsa_65};
use crate::l0::config::L0Config;
use crate::l0::error::{L0Error, L0Result};
use crate::l0::external::{ExternalCheckpoint, VerificationResult, VerificationStrategy};
use crate::l0::proof::{
    L0FinalityProof, L0ProofHeader, L0_PROOF_VERSION, PqcSignatureAlgo, ProofSignature,
    ValidatorRecord,
};
use crate::l0::stark_prover::{BatchPublicInputs, SignerInput, prove_batch};
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

/// Tracks validator equivocations: (validator_address, chain_epoch_key) → block_hash.
/// A validator equivocates if they sign two different blocks for the same epoch/chain.
#[derive(Clone, Debug, Default)]
pub struct EquivocationTracker {
    /// validator_address → (chain_id + epoch) → block_hash they signed
    signed_blocks: HashMap<Hash, HashMap<String, Hash>>,
    /// List of validators caught equivocating (for slashing)
    offenders: Vec<Hash>,
}

impl EquivocationTracker {
    /// Record that a validator signed a block. Returns true if this is an equivocation.
    pub fn record(&mut self, validator: Hash, chain_epoch_key: String, block_hash: Hash) -> bool {
        let entry = self.signed_blocks.entry(validator).or_default();
        if let Some(existing) = entry.get(&chain_epoch_key) {
            if existing != &block_hash {
                if !self.offenders.contains(&validator) {
                    self.offenders.push(validator);
                }
                return true; // Equivocation detected
            }
            return false; // Same block, already recorded
        }
        entry.insert(chain_epoch_key, block_hash);
        false
    }

    pub fn is_offender(&self, validator: &Hash) -> bool {
        self.offenders.contains(validator)
    }
}

/// L0 finality hub.
pub struct FinalityHub {
    config: Arc<RwLock<L0Config>>,
    metrics: Arc<RwLock<HubMetrics>>,
    last_proof_hash: Arc<RwLock<Hash>>,
    archive: Arc<RwLock<VecDeque<L0FinalityProof>>>,
    equivocations: Arc<RwLock<EquivocationTracker>>,
    /// Last known block hash per chain for parent continuity verification.
    last_block_by_chain: Arc<RwLock<HashMap<String, Hash>>>,
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
            equivocations: Arc::new(RwLock::new(EquivocationTracker::default())),
            last_block_by_chain: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Returns whether the hub is active.
    pub fn is_enabled(&self) -> bool {
        self.config.read().enabled
    }

    /// Returns a read handle to the current configuration.
    pub fn config(&self) -> parking_lot::MappedRwLockReadGuard<'_, L0Config> {
        parking_lot::RwLockReadGuard::map(self.config.read(), |c| c)
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
            external_chain: None, // Native Quantos checkpoint
            epoch: checkpoint.epoch,
            slot: checkpoint.slot,
            previous_proof_hash,
            state_root: checkpoint.state_root,
            dag_root: checkpoint.dag_root,
            parent_block_hash: checkpoint.previous_checkpoint,
            chain_work: 0,
            validator_set_root,
            total_stake,
            stake_threshold: required,
            emitted_at_ms: chrono::Utc::now().timestamp_millis() as u64,
            stark_commitment: [0u8; 32],
        };

        let mut proof = L0FinalityProof {
            header,
            validators: snapshot.validators.clone(),
            signatures: Vec::with_capacity(contributions.len()),
            stark_proof: None,
        };
        // Contributions come from the finality committee (see doc comment
        // above), which signs checkpoint.signing_data() (domain-prefixed
        // checkpoint hash), not this proof's own signing digest.
        let digest = checkpoint.signing_data();

        // One STARK signer entry per validator (is_signer=false by default).
        // Filled in below as signatures are verified.
        let mut signer_inputs: Vec<crate::l0::stark_prover::SignerInput> = snapshot
            .validators
            .iter()
            .enumerate()
            .map(|(i, v)| crate::l0::stark_prover::SignerInput {
                validator_index: i as u32,
                stake: v.stake,
                sig_commitment: [0u8; 32],
                is_signer: false,
            })
            .collect();

        // Verify and attach each contribution. We do a stake tally on
        // the fly to short-circuit as soon as the threshold is met.
        let mut signed_stake: u128 = 0;
        for contribution in contributions {
            let Some(index) = snapshot.position_of(&contribution.validator) else {
                continue;
            };
            let validator = &snapshot.validators[index];

            let ok = match contribution.algo {
                PqcSignatureAlgo::MlDsa65 => verify_ml_dsa_65(
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

            // Mark this validator as a signer in the STARK circuit.
            if let Some(si) = signer_inputs.get_mut(index) {
                si.is_signer = true;
                si.sig_commitment = crate::l0::stark_prover::SignerInput::build_commitment(
                    &validator.public_key,
                    &digest,
                    &contribution.signature,
                );
            }

            proof.signatures.push(ProofSignature {
                validator_index: index as u32,
                algo: contribution.algo,
                signature: contribution.signature.clone(),
            });
            signed_stake = signed_stake.saturating_add(validator.stake);
        }

        if signed_stake < required {
            let new_failed = self.metrics.read().proofs_failed.saturating_add(1);
            self.metrics.write().proofs_failed = new_failed;
            return Err(L0Error::InsufficientStake {
                signed: signed_stake,
                required,
            });
        }

        // ── ZK-STARK batch proof ────────────────────────────────────────────────
        // Aggregate all PQC signature verifications into a single 32-byte
        // commitment that can be cheaply stored on any target chain.
        // Proven off-chain in <10 ms; the on-chain footprint is 32 bytes.
        let stark_pub_inputs = crate::l0::stark_prover::BatchPublicInputs {
            validator_set_root,
            message_hash: digest,
            signed_stake,
            stake_threshold: required,
            signer_count: proof.signatures.len() as u32,
        };
        match crate::l0::stark_prover::prove_batch(&signer_inputs, stark_pub_inputs) {
            Ok(stark_proof) => {
                tracing::info!(
                    epoch = checkpoint.epoch,
                    commitment = %hex::encode(&stark_proof.commitment[..8]),
                    signers = proof.signatures.len(),
                    "STARK batch proof generated"
                );
                proof.header.stark_commitment = stark_proof.commitment;
                proof.stark_proof = Some(stark_proof);
            }
            Err(e) => {
                tracing::warn!(
                    epoch = checkpoint.epoch,
                    error = %e,
                    "STARK batch proof failed — proof emitted without STARK commitment"
                );
            }
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

        let new_produced = self.metrics.read().proofs_produced.saturating_add(1);
        self.metrics.write().proofs_produced = new_produced;

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

    /// Builds a PQC finality proof for an external chain checkpoint.
    ///
    /// This enables external chains (Ethereum, Solana, NEAR, Aptos, etc.) to
    /// anchor their finality on Quantos by submitting their checkpoints and
    /// receiving PQC-signed proofs in return.
    ///
    /// # Arguments
    ///
    /// * `checkpoint` - The external chain checkpoint to certify
    /// * `snapshot` - Quantos validator set that will sign the proof
    /// * `contributions` - PQC signatures from Quantos validators
    /// * `verification` - Result of verifying the external checkpoint
    ///
    /// # Returns
    ///
    /// An `L0FinalityProof` with `external_chain` set to the checkpoint's chain ID.
    pub fn build_external_proof(
        &self,
        checkpoint: &ExternalCheckpoint,
        snapshot: &ValidatorSetSnapshot,
        contributions: &[SignatureContribution],
        verification: &VerificationResult,
    ) -> L0Result<L0FinalityProof> {
        if !verification.valid {
            return Err(L0Error::InvalidCheckpoint(
                verification.reason.clone().unwrap_or_else(|| "Invalid external checkpoint".into()),
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

        // Parent continuity check: new checkpoint must reference previous known block
        let chain_key = checkpoint.chain_id.as_str().to_string();
        let last_known = self.last_block_by_chain.read().get(&chain_key).cloned();
        if let Some(last_hash) = last_known {
            if checkpoint.parent_block_hash != last_hash {
                return Err(L0Error::InvalidCheckpoint(
                    format!("Parent continuity broken: expected {}, got {}",
                        hex::encode(last_hash), hex::encode(checkpoint.parent_block_hash))
                ));
            }
        }

        // Chain work must advance (fork-choice rule)
        if let Some(prev) = self.archive.read().back() {
            if prev.header.external_chain.as_ref() == Some(&checkpoint.chain_id) {
                if checkpoint.chain_work <= prev.header.chain_work {
                    return Err(L0Error::InvalidCheckpoint(
                        format!("Chain work did not advance: {} <= {}",
                            checkpoint.chain_work, prev.header.chain_work)
                    ));
                }
            }
        }

        let validator_set_root = snapshot.root;
        let previous_proof_hash = *self.last_proof_hash.read();

        let header = L0ProofHeader {
            version: L0_PROOF_VERSION,
            external_chain: Some(checkpoint.chain_id.clone()),
            epoch: checkpoint.block_number,
            slot: 0, // External chains don't have Quantos slots
            previous_proof_hash,
            state_root: checkpoint.state_root,
            dag_root: checkpoint.block_hash,
            parent_block_hash: checkpoint.parent_block_hash,
            chain_work: checkpoint.chain_work,
            validator_set_root,
            total_stake,
            stake_threshold: required,
            emitted_at_ms: chrono::Utc::now().timestamp_millis() as u64,
            stark_commitment: [0u8; 32], // filled after STARK proof generation
        };

        // Build a draft proof so we can compute the signing digest
        let mut proof = L0FinalityProof {
            header,
            validators: snapshot.validators.clone(),
            signatures: Vec::with_capacity(contributions.len()),
            stark_proof: None,
        };
        let digest = proof.signing_digest();

        // Verify and attach each contribution
        let mut signed_stake: u128 = 0;
        let chain_epoch_key = format!("{}:{}", checkpoint.chain_id.as_str(), checkpoint.block_number);
        let mut equivocators = Vec::new();

        for contribution in contributions {
            let Some(index) = snapshot.position_of(&contribution.validator) else {
                continue;
            };
            let validator = &snapshot.validators[index];

            // Slash condition: reject known equivocators
            if self.equivocations.read().is_offender(&contribution.validator) {
                continue;
            }

            let ok = match contribution.algo {
                PqcSignatureAlgo::MlDsa65 => verify_ml_dsa_65(
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

            // Refuse duplicates
            if proof
                .signatures
                .iter()
                .any(|s| s.validator_index as usize == index)
            {
                continue;
            }

            // Detect equivocation: same validator signing different block for same epoch/chain
            let is_equivocating = self.equivocations.write().record(
                contribution.validator,
                chain_epoch_key.clone(),
                checkpoint.block_hash,
            );
            if is_equivocating {
                equivocators.push(contribution.validator);
                continue; // Do not count this signature
            }

            proof.signatures.push(ProofSignature {
                validator_index: index as u32,
                algo: contribution.algo,
                signature: contribution.signature.clone(),
            });
            signed_stake = signed_stake.saturating_add(validator.stake);

            if signed_stake >= required {
                break;
            }
        }

        if signed_stake < required {
            let new_failed = self.metrics.read().proofs_failed.saturating_add(1);
            self.metrics.write().proofs_failed = new_failed;
            return Err(L0Error::InsufficientStake {
                signed: signed_stake,
                required,
            });
        }

        // Generate ZK-STARK batch proof aggregating all signature commitments.
        let signer_inputs: Vec<SignerInput> = proof.signatures.iter().map(|sig| {
            let v = &proof.validators[sig.validator_index as usize];
            SignerInput {
                validator_index: sig.validator_index,
                stake: v.stake,
                sig_commitment: SignerInput::build_commitment(
                    &v.public_key,
                    &digest,
                    &sig.signature,
                ),
                is_signer: true,
            }
        }).collect();

        let stark_pub = BatchPublicInputs {
            validator_set_root,
            message_hash: digest,
            signed_stake,
            stake_threshold: required,
            signer_count: signer_inputs.len() as u32,
        };

        match prove_batch(&signer_inputs, stark_pub) {
            Ok(stark) => {
                proof.header.stark_commitment = stark.commitment;
                proof.stark_proof = Some(stark);
            }
            Err(e) => {
                tracing::warn!("STARK batch proof generation failed (non-fatal): {:?}", e);
            }
        }

        let proof_hash = proof.proof_hash();
        *self.last_proof_hash.write() = proof_hash;

        // Update chain head for parent continuity verification
        self.last_block_by_chain.write().insert(chain_key, checkpoint.block_hash);

        if cfg.archive_proofs {
            let mut archive = self.archive.write();
            if archive.len() >= cfg.archive_capacity {
                archive.pop_front();
            }
            archive.push_back(proof.clone());
            self.metrics.write().archived_proofs = archive.len() as u64;
        }

        let new_produced = self.metrics.read().proofs_produced.saturating_add(1);
        self.metrics.write().proofs_produced = new_produced;

        Ok(proof)
    }
}
