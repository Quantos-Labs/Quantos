//! # Quantos Slashing Mechanism
//!
//! Penalties for malicious or negligent validator behavior.
//!
//! ## Slashable Offenses
//!
//! | Offense | Penalty | Evidence |
//! |---------|---------|----------|
//! | Double Signing | 5% stake | Two conflicting signed messages |
//! | Surround Vote | 5% stake | Vote that surrounds another |
//! | Downtime | 0.1% per epoch | Missing blocks/votes |
//! | Invalid Block | 10% stake | Block failing validation |
//! | Equivocation | 5% stake | Conflicting committee votes |
//! | Front-Running | 2% stake | Leader block order ≠ canonical fair order |
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Slashing Pipeline                         │
//! ├─────────────────────────────────────────────────────────────┤
//! │  1. Evidence Submission -> SlashingPool                     │
//! │  2. Evidence Verification -> validate proofs                │
//! │  3. Slashing Calculation -> compute penalty                 │
//! │  4. Execution -> deduct stake, jail validator               │
//! │  5. Distribution -> reward reporter, burn remainder         │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

use crate::types::{Address, Hash, Slot};
use crate::crypto::{
    verify_dilithium, with_domain,
    DOMAIN_SLASH_DOUBLE_SIGN, DOMAIN_SLASH_EQUIVOC, DOMAIN_SLASH_INVALID_BLOCK,
    DOMAIN_SLASH_FRONT_RUN,
};

/// Slashing errors.
#[derive(Debug, Error)]
pub enum SlashingError {
    #[error("Invalid evidence: {0}")]
    InvalidEvidence(String),
    
    #[error("Evidence already processed: {0:?}")]
    DuplicateEvidence([u8; 32]),
    
    #[error("Validator not found: {0}")]
    ValidatorNotFound(String),
    
    #[error("Evidence expired: submitted at slot {0}, current slot {1}")]
    EvidenceExpired(Slot, Slot),
    
    #[error("Insufficient stake: required {0}, available {1}")]
    InsufficientStake(u64, u64),
    
    #[error("Validator already jailed")]
    AlreadyJailed,
    
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    
    #[error("Self-slashing not allowed")]
    SelfSlashing,
}

pub type SlashingResult<T> = Result<T, SlashingError>;

/// Minimum stake required for validator registration
const MIN_VALIDATOR_STAKE: u64 = 10_000;
/// Maximum stake allowed (prevents overflow in downstream calculations)
const MAX_VALIDATOR_STAKE: u64 = 1_000_000_000_000;

/// Slashing configuration.
#[derive(Clone, Debug)]
pub struct SlashingConfig {
    /// Double signing penalty (basis points, 100 = 1%)
    pub double_sign_penalty_bps: u64,
    /// Surround vote penalty (basis points)
    pub surround_vote_penalty_bps: u64,
    /// Downtime penalty per epoch (basis points)
    pub downtime_penalty_bps: u64,
    /// Invalid block penalty (basis points)
    pub invalid_block_penalty_bps: u64,
    /// Equivocation penalty (basis points)
    pub equivocation_penalty_bps: u64,
    /// Proven front-running penalty (basis points)
    pub front_running_penalty_bps: u64,
    /// Maximum evidence age in slots
    pub max_evidence_age: u64,
    /// Jail duration in slots
    pub jail_duration: u64,
    /// Minimum stake after slashing
    pub min_stake_after_slash: u64,
    /// Reporter reward percentage (of slashed amount)
    pub reporter_reward_bps: u64,
    /// Burn percentage (of slashed amount after reporter reward)
    pub burn_percentage_bps: u64,
    /// Maximum downtime epochs before slashing
    pub max_downtime_epochs: u64,
    /// Enable progressive slashing (harsher for repeat offenders)
    pub progressive_slashing: bool,
    /// Progressive multiplier per offense
    pub progressive_multiplier: f64,
}

impl Default for SlashingConfig {
    fn default() -> Self {
        Self {
            double_sign_penalty_bps: 500,      // 5%
            surround_vote_penalty_bps: 500,    // 5%
            downtime_penalty_bps: 10,          // 0.1%
            invalid_block_penalty_bps: 1000,   // 10%
            equivocation_penalty_bps: 500,     // 5%
            front_running_penalty_bps: 200,    // 2%
            max_evidence_age: 10000,           // ~10000 slots
            jail_duration: 50000,              // ~50000 slots
            min_stake_after_slash: 1000,       // Minimum stake to remain validator
            reporter_reward_bps: 1000,         // 10% to reporter
            burn_percentage_bps: 5000,         // 50% burned
            max_downtime_epochs: 3,            // 3 epochs of downtime
            progressive_slashing: true,
            progressive_multiplier: 1.5,
        }
    }
}

/// Type of slashable offense.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum OffenseType {
    /// Signing two different blocks at the same height
    DoubleSigning,
    /// Vote that surrounds another vote (Casper FFG violation)
    SurroundVote,
    /// Extended downtime / missing duties
    Downtime,
    /// Proposing an invalid block
    InvalidBlock,
    /// Conflicting votes in same committee round
    Equivocation,
    /// Leader proposed transaction order deviating from canonical fair order
    FrontRunning,
    /// Custom offense type
    Custom(String),
}

impl OffenseType {
    /// Gets the base penalty for this offense type.
    pub fn base_penalty_bps(&self, config: &SlashingConfig) -> u64 {
        match self {
            OffenseType::DoubleSigning => config.double_sign_penalty_bps,
            OffenseType::SurroundVote => config.surround_vote_penalty_bps,
            OffenseType::Downtime => config.downtime_penalty_bps,
            OffenseType::InvalidBlock => config.invalid_block_penalty_bps,
            OffenseType::Equivocation => config.equivocation_penalty_bps,
            OffenseType::FrontRunning => config.front_running_penalty_bps,
            OffenseType::Custom(_) => 100, // 1% default for custom
        }
    }

    /// Whether this offense results in jailing.
    pub fn results_in_jail(&self) -> bool {
        matches!(
            self,
            OffenseType::DoubleSigning
                | OffenseType::SurroundVote
                | OffenseType::InvalidBlock
                | OffenseType::Equivocation
                | OffenseType::FrontRunning
        )
    }
}

/// Evidence of a slashable offense.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingEvidence {
    /// Unique evidence ID
    pub id: Hash,
    /// Type of offense
    pub offense_type: OffenseType,
    /// Offending validator
    pub validator: [u8; 32],
    /// Slot when offense occurred
    pub offense_slot: Slot,
    /// Slot when evidence was submitted
    pub submission_slot: Slot,
    /// Reporter address
    pub reporter: Address,
    /// Evidence data (varies by offense type)
    pub evidence_data: EvidenceData,
    /// Evidence hash for verification
    pub evidence_hash: Hash,
}

/// Specific evidence data for each offense type.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EvidenceData {
    /// Double signing evidence: two conflicting signed messages
    DoubleSigning {
        message1: SignedMessage,
        message2: SignedMessage,
    },
    /// Surround vote evidence
    SurroundVote {
        vote1: SignedVote,
        vote2: SignedVote,
    },
    /// Downtime evidence
    Downtime {
        start_slot: Slot,
        end_slot: Slot,
        missed_duties: Vec<MissedDuty>,
    },
    /// Invalid block evidence
    InvalidBlock {
        block_hash: Hash,
        block_slot: Slot,
        validation_error: String,
        /// Signature by the accused validator over the invalid block binding.
        proposer_signature: Vec<u8>,
    },
    /// Equivocation evidence
    Equivocation {
        vote1: SignedVote,
        vote2: SignedVote,
        committee_round: u64,
    },
    /// Proven front-running: leader order ≠ canonical fair order
    FrontRunning {
        block: u64,
        ordering_beacon: Hash,
        canonical_order: Vec<Hash>,
        proposed_order: Vec<Hash>,
        leader_signature: Vec<u8>,
    },
}

/// A signed message (for double signing evidence).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedMessage {
    /// Message content hash
    pub message_hash: Hash,
    /// Slot
    pub slot: Slot,
    /// Signature
    pub signature: Vec<u8>,
    /// Block hash (if block proposal)
    pub block_hash: Option<Hash>,
}

/// A signed vote (for surround/equivocation evidence).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedVote {
    /// Source epoch/slot
    pub source: Slot,
    /// Target epoch/slot
    pub target: Slot,
    /// Vote hash
    pub vote_hash: Hash,
    /// Signature
    pub signature: Vec<u8>,
}

/// A missed duty record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MissedDuty {
    /// Slot of missed duty
    pub slot: Slot,
    /// Type of duty
    pub duty_type: DutyType,
}

/// Type of validator duty.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DutyType {
    /// Block proposal
    BlockProposal,
    /// Committee attestation
    Attestation,
    /// Sync committee participation
    SyncCommittee,
}

/// Slashing record for a validator.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingRecord {
    /// Evidence that triggered slashing
    pub evidence_id: Hash,
    /// Offense type
    pub offense_type: OffenseType,
    /// Amount slashed
    pub amount_slashed: u64,
    /// Slot when slashed
    pub slashed_at: Slot,
    /// Reporter who submitted evidence
    pub reporter: Address,
    /// Reporter reward
    pub reporter_reward: u64,
    /// Amount burned
    pub amount_burned: u64,
    /// Whether validator was jailed
    pub jailed: bool,
}

/// Validator jail status.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JailStatus {
    /// Slot when jailed
    pub jailed_at: Slot,
    /// Slot when jail ends
    pub jail_ends_at: Slot,
    /// Reason for jailing
    pub reason: OffenseType,
    /// Number of times jailed
    pub jail_count: u32,
}

/// Slashing execution result.
#[derive(Clone, Debug)]
pub struct SlashingExecution {
    /// Validator slashed
    pub validator: [u8; 32],
    /// Total amount slashed
    pub total_slashed: u64,
    /// Amount sent to reporter
    pub reporter_reward: u64,
    /// Amount burned
    pub amount_burned: u64,
    /// Amount redistributed to other validators
    pub amount_redistributed: u64,
    /// Whether validator was jailed
    pub jailed: bool,
    /// New validator stake after slashing
    pub new_stake: u64,
}

/// Slashing metrics.
#[derive(Clone, Debug, Default)]
pub struct SlashingMetrics {
    /// Total evidence submitted
    pub evidence_submitted: u64,
    /// Total evidence validated
    pub evidence_validated: u64,
    /// Total evidence rejected
    pub evidence_rejected: u64,
    /// Total slashing events
    pub total_slashings: u64,
    /// Total amount slashed
    pub total_amount_slashed: u64,
    /// Total amount burned
    pub total_amount_burned: u64,
    /// Total reporter rewards
    pub total_reporter_rewards: u64,
    /// Validators currently jailed
    pub validators_jailed: u64,
    /// Slashings by type
    pub slashings_by_type: HashMap<String, u64>,
}

/// Validator registration info including public key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator address (32 bytes)
    pub address: [u8; 32],
    /// Dilithium public key for signature verification
    pub public_key: Vec<u8>,
    /// Current stake amount
    pub stake: u64,
    /// Registration slot
    pub registered_at: Slot,
}

/// Manages slashing logic and evidence.
pub struct SlashingManager {
    config: SlashingConfig,
    /// Pending evidence pool
    evidence_pool: Arc<DashMap<Hash, SlashingEvidence>>,
    /// Processed evidence (to prevent duplicates)
    processed_evidence: Arc<DashMap<Hash, Slot>>,
    /// Slashing history per validator
    slashing_history: Arc<DashMap<[u8; 32], Vec<SlashingRecord>>>,
    /// Jail status per validator
    jail_status: Arc<DashMap<[u8; 32], JailStatus>>,
    /// Validator stakes (would normally come from staking module)
    validator_stakes: Arc<DashMap<[u8; 32], u64>>,
    /// Validator public keys for signature verification
    validator_pubkeys: Arc<DashMap<[u8; 32], Vec<u8>>>,
    /// Downtime tracking
    downtime_tracker: Arc<DashMap<[u8; 32], Vec<MissedDuty>>>,
    /// Current slot
    current_slot: Arc<RwLock<Slot>>,
    /// Metrics
    metrics: Arc<RwLock<SlashingMetrics>>,
}

impl SlashingManager {
    /// Creates a new slashing manager.
    pub fn new(config: SlashingConfig) -> Self {
        Self {
            config,
            evidence_pool: Arc::new(DashMap::new()),
            processed_evidence: Arc::new(DashMap::new()),
            slashing_history: Arc::new(DashMap::new()),
            jail_status: Arc::new(DashMap::new()),
            validator_stakes: Arc::new(DashMap::new()),
            validator_pubkeys: Arc::new(DashMap::new()),
            downtime_tracker: Arc::new(DashMap::new()),
            current_slot: Arc::new(RwLock::new(0)),
            metrics: Arc::new(RwLock::new(SlashingMetrics::default())),
        }
    }

    /// Sets the current slot.
    pub fn set_current_slot(&self, slot: Slot) {
        *self.current_slot.write() = slot;
    }

    /// Registers a validator with stake and public key.
    /// Validates stake is within acceptable bounds.
    pub fn register_validator(&self, validator: [u8; 32], stake: u64) -> SlashingResult<()> {
        if stake < MIN_VALIDATOR_STAKE {
            return Err(SlashingError::InsufficientStake(MIN_VALIDATOR_STAKE, stake));
        }
        if stake > MAX_VALIDATOR_STAKE {
            return Err(SlashingError::InvalidEvidence(
                format!("Stake {} exceeds maximum {}", stake, MAX_VALIDATOR_STAKE)
            ));
        }
        self.validator_stakes.insert(validator, stake);
        Ok(())
    }
    
    /// Registers a validator with full info including public key.
    /// Validates stake is within acceptable bounds.
    pub fn register_validator_with_pubkey(&self, validator: [u8; 32], stake: u64, public_key: Vec<u8>) -> SlashingResult<()> {
        if stake < MIN_VALIDATOR_STAKE {
            return Err(SlashingError::InsufficientStake(MIN_VALIDATOR_STAKE, stake));
        }
        if stake > MAX_VALIDATOR_STAKE {
            return Err(SlashingError::InvalidEvidence(
                format!("Stake {} exceeds maximum {}", stake, MAX_VALIDATOR_STAKE)
            ));
        }
        self.validator_stakes.insert(validator, stake);
        self.validator_pubkeys.insert(validator, public_key);
        Ok(())
    }
    
    /// Gets the public key for a validator.
    pub fn get_validator_pubkey(&self, validator: &[u8; 32]) -> Option<Vec<u8>> {
        self.validator_pubkeys.get(validator).map(|v| v.clone())
    }

    /// Submits evidence of a slashable offense.
    pub fn submit_evidence(&self, evidence: SlashingEvidence) -> SlashingResult<Hash> {
        let current_slot = *self.current_slot.read();
        
        // Check if evidence already processed
        if self.processed_evidence.contains_key(&evidence.id) {
            return Err(SlashingError::DuplicateEvidence(evidence.id));
        }

        // Prevent future slot evidence
        if evidence.offense_slot > current_slot {
            return Err(SlashingError::InvalidEvidence(
                format!("Evidence from future slot: offense_slot={}, current_slot={}", 
                    evidence.offense_slot, current_slot)
            ));
        }

        // Check evidence age (not too old)
        if current_slot > evidence.offense_slot + self.config.max_evidence_age {
            return Err(SlashingError::EvidenceExpired(
                evidence.offense_slot,
                current_slot,
            ));
        }

        // Validate evidence
        self.validate_evidence(&evidence)?;

        let evidence_id = evidence.id;
        self.evidence_pool.insert(evidence_id, evidence);
        self.metrics.write().evidence_submitted += 1;

        info!(
            "Evidence submitted: {:?}, validator: {}",
            evidence_id,
            hex::encode(&evidence_id[..8])
        );

        Ok(evidence_id)
    }

    /// Validates evidence.
    fn validate_evidence(&self, evidence: &SlashingEvidence) -> SlashingResult<()> {
        // Check validator exists
        if !self.validator_stakes.contains_key(&evidence.validator) {
            return Err(SlashingError::ValidatorNotFound(
                hex::encode(&evidence.validator[..8]),
            ));
        }

        // Validate based on evidence type
        match &evidence.evidence_data {
            EvidenceData::DoubleSigning { message1, message2 } => {
                self.validate_double_signing(evidence, message1, message2)?;
            }
            EvidenceData::SurroundVote { vote1, vote2 } => {
                self.validate_surround_vote(evidence, vote1, vote2)?;
            }
            EvidenceData::Downtime { missed_duties, .. } => {
                self.validate_downtime(evidence, missed_duties)?;
            }
            EvidenceData::InvalidBlock { block_hash, proposer_signature, .. } => {
                self.validate_invalid_block(evidence, block_hash, proposer_signature)?;
            }
            EvidenceData::Equivocation { vote1, vote2, .. } => {
                self.validate_equivocation(evidence, vote1, vote2)?;
            }
            EvidenceData::FrontRunning {
                block,
                ordering_beacon,
                canonical_order,
                proposed_order,
                leader_signature,
            } => {
                self.validate_front_running(
                    evidence,
                    *block,
                    ordering_beacon,
                    canonical_order,
                    proposed_order,
                    leader_signature,
                )?;
            }
        }

        self.metrics.write().evidence_validated += 1;
        Ok(())
    }

    /// Validates double signing evidence.
    fn validate_double_signing(
        &self,
        evidence: &SlashingEvidence,
        msg1: &SignedMessage,
        msg2: &SignedMessage,
    ) -> SlashingResult<()> {
        // Messages must be for the same slot
        if msg1.slot != msg2.slot {
            return Err(SlashingError::InvalidEvidence(
                "Messages not from same slot".into(),
            ));
        }

        // Messages must be different
        if msg1.message_hash == msg2.message_hash {
            return Err(SlashingError::InvalidEvidence(
                "Messages are identical".into(),
            ));
        }

        // Fetch validator's public key from registry
        let validator_pubkey = self.get_validator_pubkey(&evidence.validator)
            .ok_or_else(|| SlashingError::InvalidEvidence(
                format!("Validator public key not registered: {}", hex::encode(&evidence.validator[..8]))
            ))?;
        
        // Verify both message signatures. The signing payload is domain-separated
        // with DOMAIN_SLASH_DOUBLE_SIGN so that an evidence submitter cannot reuse
        // signatures produced in other contexts (e.g. committee votes).
        let payload1 = with_domain(DOMAIN_SLASH_DOUBLE_SIGN, &msg1.message_hash);
        let valid1 = verify_dilithium(
            &validator_pubkey,
            &payload1,
            &msg1.signature,
        ).map_err(|e| SlashingError::InvalidEvidence(
            format!("Failed to verify signature 1: {}", e)
        ))?;
        
        if !valid1 {
            return Err(SlashingError::SignatureVerificationFailed);
        }
        
        let payload2 = with_domain(DOMAIN_SLASH_DOUBLE_SIGN, &msg2.message_hash);
        let valid2 = verify_dilithium(
            &validator_pubkey,
            &payload2,
            &msg2.signature,
        ).map_err(|e| SlashingError::InvalidEvidence(
            format!("Failed to verify signature 2: {}", e)
        ))?;
        
        if !valid2 {
            return Err(SlashingError::SignatureVerificationFailed);
        }

        Ok(())
    }

    /// Validates surround vote evidence.
    fn validate_surround_vote(
        &self,
        evidence: &SlashingEvidence,
        vote1: &SignedVote,
        vote2: &SignedVote,
    ) -> SlashingResult<()> {
        // Check if vote1 surrounds vote2 OR vote2 surrounds vote1
        let vote1_surrounds_vote2 = vote1.source < vote2.source && vote1.target > vote2.target;
        let vote2_surrounds_vote1 = vote2.source < vote1.source && vote2.target > vote1.target;

        if !vote1_surrounds_vote2 && !vote2_surrounds_vote1 {
            return Err(SlashingError::InvalidEvidence(
                "Votes do not constitute a surround".into(),
            ));
        }

        // Fetch validator's public key from registry
        let validator_pubkey = self.get_validator_pubkey(&evidence.validator)
            .ok_or_else(|| SlashingError::InvalidEvidence(
                format!("Validator public key not registered: {}", hex::encode(&evidence.validator[..8]))
            ))?;
        
        // Apply DOMAIN_SLASH_EQUIVOC so surround-vote evidence cannot be confused
        // with signatures from other protocol messages.
        let payload1 = with_domain(DOMAIN_SLASH_EQUIVOC, &vote1.vote_hash);
        let valid1 = verify_dilithium(
            &validator_pubkey,
            &payload1,
            &vote1.signature,
        ).map_err(|e| SlashingError::InvalidEvidence(
            format!("Failed to verify vote signature 1: {}", e)
        ))?;
        
        if !valid1 {
            return Err(SlashingError::SignatureVerificationFailed);
        }
        
        let payload2 = with_domain(DOMAIN_SLASH_EQUIVOC, &vote2.vote_hash);
        let valid2 = verify_dilithium(
            &validator_pubkey,
            &payload2,
            &vote2.signature,
        ).map_err(|e| SlashingError::InvalidEvidence(
            format!("Failed to verify vote signature 2: {}", e)
        ))?;
        
        if !valid2 {
            return Err(SlashingError::SignatureVerificationFailed);
        }

        Ok(())
    }

    /// Validates downtime evidence.
    fn validate_downtime(
        &self,
        _evidence: &SlashingEvidence,
        missed_duties: &[MissedDuty],
    ) -> SlashingResult<()> {
        // Need enough missed duties to trigger slashing
        if missed_duties.is_empty() {
            return Err(SlashingError::InvalidEvidence(
                "No missed duties provided".into(),
            ));
        }

        let current_slot = *self.current_slot.read();
        let validator = &_evidence.validator;
        
        // Verify each missed duty against committee assignments
        let mut verified_missed_duties = 0u64;
        
        for duty in missed_duties {
            // Check duty is not in future
            if duty.slot > current_slot {
                return Err(SlashingError::InvalidEvidence(
                    format!("Missed duty in future slot: {}", duty.slot)
                ));
            }
            
            // Check duty is not too old
            if current_slot - duty.slot > self.config.max_evidence_age {
                return Err(SlashingError::InvalidEvidence(
                    format!("Missed duty too old: slot {}", duty.slot)
                ));
            }
            
            // Verify validator was actually assigned this duty
            // Uses deterministic duty assignment based on slot and validator set
            let duty_epoch = duty.slot / 32; // Assuming 32 slots per epoch
            let was_assigned = self.verify_duty_assignment(validator, duty.slot, duty_epoch, &duty.duty_type);
            
            if was_assigned {
                verified_missed_duties += 1;
            }
        }
        
        // Require minimum threshold of verified missed duties
        let minimum_missed = 10u64;
        if verified_missed_duties < minimum_missed {
            return Err(SlashingError::InvalidEvidence(
                format!(
                    "Not enough verified missed duties: {} (minimum {}, submitted {})", 
                    verified_missed_duties, minimum_missed, missed_duties.len()
                )
            ));
        }

        Ok(())
    }
    
    /// Verifies that a validator was assigned a specific duty at a slot.
    /// Uses deterministic assignment based on slot, epoch, and validator stake.
    fn verify_duty_assignment(
        &self,
        validator: &[u8; 32],
        slot: Slot,
        epoch: u64,
        duty_type: &DutyType,
    ) -> bool {
        // Get validator stake - must be registered
        let stake = match self.validator_stakes.get(validator) {
            Some(s) => *s,
            None => return false,
        };
        
        // Minimum stake required for duty assignment
        if stake < self.config.min_stake_after_slash {
            return false;
        }
        
        // Compute deterministic duty assignment seed
        let mut seed_data = Vec::with_capacity(48);
        seed_data.extend_from_slice(&epoch.to_le_bytes());
        seed_data.extend_from_slice(&slot.to_le_bytes());
        seed_data.extend_from_slice(validator);
        let assignment_seed = crate::types::hash_data(&seed_data);
        
        // Determine if validator was assigned based on duty type
        match duty_type {
            DutyType::BlockProposal => {
                // Block proposer: one per slot, selected by seed mod total_validators
                // Use first 8 bytes of seed as selection index
                let selection_idx = u64::from_le_bytes(assignment_seed[0..8].try_into().unwrap());
                let total_validators = self.validator_stakes.len() as u64;
                if total_validators == 0 {
                    return false;
                }
                
                // Check if this validator's index matches
                let validator_idx = self.get_validator_index(validator);
                selection_idx % total_validators == validator_idx as u64
            }
            DutyType::Attestation => {
                // Attestation: validators assigned to committees based on epoch
                // Each validator attests once per epoch
                let committee_idx = u64::from_le_bytes(assignment_seed[8..16].try_into().unwrap()) % 32;
                let slot_in_epoch = slot % 32;
                committee_idx == slot_in_epoch
            }
            DutyType::SyncCommittee => {
                // Sync committee: subset of validators for 256 epochs
                // Selection based on stake-weighted randomness
                let sync_period = epoch / 256;
                let mut sync_seed = Vec::with_capacity(40);
                sync_seed.extend_from_slice(&sync_period.to_le_bytes());
                sync_seed.extend_from_slice(validator);
                let sync_hash = crate::types::hash_data(&sync_seed);
                
                // Top 512 validators by deterministic score are in sync committee
                let score = u64::from_le_bytes(sync_hash[0..8].try_into().unwrap());
                let threshold = u64::MAX / 512; // Approximately 1/512 chance
                score < threshold * (stake / 1000).min(10) // Stake-weighted
            }
        }
    }
    
    /// Gets the index of a validator in the stake map (deterministic ordering)
    fn get_validator_index(&self, validator: &[u8; 32]) -> usize {
        let mut validators: Vec<[u8; 32]> = self.validator_stakes
            .iter()
            .map(|entry| *entry.key())
            .collect();
        validators.sort();
        validators.iter().position(|v| v == validator).unwrap_or(0)
    }

    /// Validates invalid block evidence.
    /// 
    /// Verifies that:
    /// 1. Block hash is valid and non-empty
    /// 2. Validator was the assigned proposer for that slot
    /// 3. Validation error is properly documented
    /// 4. Block slot is within valid range
    fn validate_invalid_block(
        &self,
        evidence: &SlashingEvidence,
        block_hash: &Hash,
        proposer_signature: &[u8],
    ) -> SlashingResult<()> {
        // 1. Block hash must be non-empty
        if block_hash == &[0u8; 32] {
            return Err(SlashingError::InvalidEvidence(
                "Invalid block hash: empty".into()
            ));
        }
        
        if let EvidenceData::InvalidBlock { validation_error, block_slot, .. } = &evidence.evidence_data {
            // 2. Validation error must be documented
            if validation_error.is_empty() {
                return Err(SlashingError::InvalidEvidence(
                    "No validation error provided".into()
                ));
            }
            
            // 3. Block slot must be reasonable
            let current_slot = *self.current_slot.read();
            if *block_slot > current_slot {
                return Err(SlashingError::InvalidEvidence(
                    format!("Block in future slot: {}", block_slot)
                ));
            }
            
            if current_slot - block_slot > self.config.max_evidence_age {
                return Err(SlashingError::InvalidEvidence(
                    format!("Block too old: slot {}", block_slot)
                ));
            }
            
            // 4. Verify validator was the assigned block proposer for this slot
            let epoch = *block_slot / 32;
            let was_proposer = self.verify_duty_assignment(
                &evidence.validator,
                *block_slot,
                epoch,
                &DutyType::BlockProposal,
            );
            
            if !was_proposer {
                return Err(SlashingError::InvalidEvidence(
                    format!(
                        "Validator was not assigned as block proposer for slot {}",
                        block_slot
                    )
                ));
            }
            
            // 5. Verify block hash is cryptographically bound to the proposer
            // The evidence must include a signature from the accused validator over the block hash.
            // Without this, an attacker can fabricate evidence with any block hash.
            let validator_pubkey = self.get_validator_pubkey(&evidence.validator)
                .ok_or_else(|| SlashingError::InvalidEvidence(
                    format!("Validator public key not registered for invalid block evidence: {}",
                        hex::encode(&evidence.validator[..8]))
                ))?;
            
            let block_binding = Self::invalid_block_signing_data(
                &evidence.validator,
                *block_slot,
                block_hash,
            );

            let valid = verify_dilithium(
                &validator_pubkey,
                &block_binding,
                proposer_signature,
            ).map_err(|e| SlashingError::InvalidEvidence(
                format!("Failed to verify invalid block proposer signature: {}", e)
            ))?;

            if !valid {
                return Err(SlashingError::SignatureVerificationFailed);
            }
        }

        Ok(())
    }

    fn invalid_block_signing_data(
        validator: &[u8; 32],
        block_slot: Slot,
        block_hash: &Hash,
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(32 + 8 + 32);
        msg.extend_from_slice(validator);
        msg.extend_from_slice(&block_slot.to_le_bytes());
        msg.extend_from_slice(block_hash);
        with_domain(DOMAIN_SLASH_INVALID_BLOCK, &msg)
    }

    /// Validates proven front-running evidence (accountable leader order violation).
    fn validate_front_running(
        &self,
        evidence: &SlashingEvidence,
        block: u64,
        ordering_beacon: &Hash,
        canonical_order: &[Hash],
        proposed_order: &[Hash],
        leader_signature: &[u8],
    ) -> SlashingResult<()> {
        if canonical_order.is_empty() {
            return Err(SlashingError::InvalidEvidence(
                "empty canonical order".into(),
            ));
        }
        if proposed_order.is_empty() {
            return Err(SlashingError::InvalidEvidence(
                "empty proposed order".into(),
            ));
        }
        if canonical_order == proposed_order {
            return Err(SlashingError::InvalidEvidence(
                "orders match; not front-running".into(),
            ));
        }

        if !self.verify_duty_assignment(
            &evidence.validator,
            block,
            block / 32,
            &DutyType::BlockProposal,
        ) {
            return Err(SlashingError::InvalidEvidence(
                format!("validator was not block proposer for slot {}", block),
            ));
        }

        let validator_pubkey = self.get_validator_pubkey(&evidence.validator).ok_or_else(|| {
            SlashingError::InvalidEvidence(format!(
                "validator public key not registered: {}",
                hex::encode(&evidence.validator[..8])
            ))
        })?;

        let signing_payload =
            Self::front_run_order_signing_payload(block, ordering_beacon, proposed_order);

        let valid = verify_dilithium(&validator_pubkey, &signing_payload, leader_signature)
            .map_err(|e| {
                SlashingError::InvalidEvidence(format!(
                    "failed to verify leader order signature: {}",
                    e
                ))
            })?;

        if !valid {
            return Err(SlashingError::SignatureVerificationFailed);
        }

        Ok(())
    }

    fn front_run_order_signing_payload(block: u64, beacon: &Hash, tx_order: &[Hash]) -> Vec<u8> {
        let mut raw = Vec::with_capacity(8 + 32 + tx_order.len() * 32);
        raw.extend_from_slice(&block.to_le_bytes());
        raw.extend_from_slice(beacon);
        for h in tx_order {
            raw.extend_from_slice(h);
        }
        with_domain(DOMAIN_SLASH_FRONT_RUN, &raw)
    }

    /// Validates equivocation evidence.
    fn validate_equivocation(
        &self,
        evidence: &SlashingEvidence,
        vote1: &SignedVote,
        vote2: &SignedVote,
    ) -> SlashingResult<()> {
        // Votes must be for the same target but different content
        if vote1.target != vote2.target {
            return Err(SlashingError::InvalidEvidence(
                "Votes not for same target".into(),
            ));
        }

        if vote1.vote_hash == vote2.vote_hash {
            return Err(SlashingError::InvalidEvidence(
                "Votes are identical".into(),
            ));
        }

        let validator_pubkey = self.get_validator_pubkey(&evidence.validator)
            .ok_or_else(|| SlashingError::InvalidEvidence(
                format!("Validator public key not registered: {}", hex::encode(&evidence.validator[..8]))
            ))?;
        
        // Apply DOMAIN_SLASH_EQUIVOC consistently with the surround-vote path.
        let payload1 = with_domain(DOMAIN_SLASH_EQUIVOC, &vote1.vote_hash);
        let valid1 = verify_dilithium(
            &validator_pubkey,
            &payload1,
            &vote1.signature,
        ).map_err(|e| SlashingError::InvalidEvidence(
            format!("Failed to verify equivocation vote signature 1: {}", e)
        ))?;
        
        if !valid1 {
            return Err(SlashingError::SignatureVerificationFailed);
        }
        
        let payload2 = with_domain(DOMAIN_SLASH_EQUIVOC, &vote2.vote_hash);
        let valid2 = verify_dilithium(
            &validator_pubkey,
            &payload2,
            &vote2.signature,
        ).map_err(|e| SlashingError::InvalidEvidence(
            format!("Failed to verify equivocation vote signature 2: {}", e)
        ))?;
        
        if !valid2 {
            return Err(SlashingError::SignatureVerificationFailed);
        }

        Ok(())
    }

    /// Processes pending evidence and executes slashing.
    pub fn process_evidence(&self) -> Vec<SlashingExecution> {
        let mut executions = Vec::new();
        let evidence_ids: Vec<_> = self.evidence_pool.iter().map(|e| *e.key()).collect();

        for evidence_id in evidence_ids {
            if let Some((_, evidence)) = self.evidence_pool.remove(&evidence_id) {
                match self.execute_slashing(&evidence) {
                    Ok(execution) => {
                        executions.push(execution);
                        self.processed_evidence
                            .insert(evidence_id, *self.current_slot.read());
                    }
                    Err(e) => {
                        warn!("Failed to execute slashing: {}", e);
                        self.metrics.write().evidence_rejected += 1;
                    }
                }
            }
        }

        executions
    }

    /// Executes slashing for validated evidence.
    fn execute_slashing(&self, evidence: &SlashingEvidence) -> SlashingResult<SlashingExecution> {
        let validator = evidence.validator;
        
        // Check if already jailed
        if let Some(jail) = self.jail_status.get(&validator) {
            if jail.jail_ends_at > *self.current_slot.read() {
                return Err(SlashingError::AlreadyJailed);
            }
        }

        // Get current stake
        let current_stake = self.validator_stakes
            .get(&validator)
            .map(|s| *s)
            .ok_or_else(|| SlashingError::ValidatorNotFound(hex::encode(&validator[..8])))?;

        // Calculate penalty
        let base_penalty_bps = evidence.offense_type.base_penalty_bps(&self.config);
        let mut penalty_bps = base_penalty_bps;

        // Apply progressive slashing if enabled
        if self.config.progressive_slashing {
            let offense_count = self.slashing_history
                .get(&validator)
                .map(|h| h.len())
                .unwrap_or(0);
            
            if offense_count > 0 {
                penalty_bps = (penalty_bps as f64 
                    * self.config.progressive_multiplier.powi(offense_count as i32)) as u64;
            }
        }

        // Cap penalty at 100%
        penalty_bps = penalty_bps.min(10000);

        // Calculate amounts
        let slash_amount = (current_stake * penalty_bps) / 10000;
        let reporter_reward = (slash_amount * self.config.reporter_reward_bps) / 10000;
        let remaining = slash_amount - reporter_reward;
        let burn_amount = (remaining * self.config.burn_percentage_bps) / 10000;
        let redistribute_amount = remaining - burn_amount;

        // Update validator stake
        let new_stake = current_stake.saturating_sub(slash_amount);
        self.validator_stakes.insert(validator, new_stake);

        // Jail if required
        let jailed = evidence.offense_type.results_in_jail();
        if jailed {
            let current_slot = *self.current_slot.read();
            let jail_count = self.jail_status
                .get(&validator)
                .map(|j| j.jail_count + 1)
                .unwrap_or(1);

            self.jail_status.insert(validator, JailStatus {
                jailed_at: current_slot,
                jail_ends_at: current_slot + self.config.jail_duration,
                reason: evidence.offense_type.clone(),
                jail_count,
            });

            self.metrics.write().validators_jailed += 1;
        }

        // Record slashing
        let record = SlashingRecord {
            evidence_id: evidence.id,
            offense_type: evidence.offense_type.clone(),
            amount_slashed: slash_amount,
            slashed_at: *self.current_slot.read(),
            reporter: evidence.reporter,
            reporter_reward,
            amount_burned: burn_amount,
            jailed,
        };

        self.slashing_history
            .entry(validator)
            .or_insert_with(Vec::new)
            .push(record);

        // Update metrics
        {
            let mut metrics = self.metrics.write();
            metrics.total_slashings += 1;
            metrics.total_amount_slashed += slash_amount;
            metrics.total_amount_burned += burn_amount;
            metrics.total_reporter_rewards += reporter_reward;
            
            let offense_key = format!("{:?}", evidence.offense_type);
            *metrics.slashings_by_type.entry(offense_key).or_insert(0) += 1;
        }

        info!(
            "Slashing executed: validator={}, amount={}, jailed={}",
            hex::encode(&validator[..8]),
            slash_amount,
            jailed
        );

        Ok(SlashingExecution {
            validator,
            total_slashed: slash_amount,
            reporter_reward,
            amount_burned: burn_amount,
            amount_redistributed: redistribute_amount,
            jailed,
            new_stake,
        })
    }

    /// Records a missed duty for downtime tracking.
    pub fn record_missed_duty(&self, validator: [u8; 32], duty: MissedDuty) {
        self.downtime_tracker
            .entry(validator)
            .or_insert_with(Vec::new)
            .push(duty);
    }

    /// Checks downtime and creates evidence if threshold exceeded.
    pub fn check_downtime(&self, validator: [u8; 32]) -> Option<SlashingEvidence> {
        let missed_duties = self.downtime_tracker.get(&validator)?;
        
        // Trigger slashing when missed duties exceed the downtime threshold
        if missed_duties.len() < 100 {
            return None;
        }

        let current_slot = *self.current_slot.read();
        let start_slot = missed_duties.first().map(|d| d.slot).unwrap_or(0);
        let end_slot = missed_duties.last().map(|d| d.slot).unwrap_or(current_slot);

        let evidence_data = EvidenceData::Downtime {
            start_slot,
            end_slot,
            missed_duties: missed_duties.clone(),
        };

        let mut evidence_bytes = Vec::new();
        evidence_bytes.extend_from_slice(&validator);
        evidence_bytes.extend_from_slice(&start_slot.to_le_bytes());
        evidence_bytes.extend_from_slice(&end_slot.to_le_bytes());
        let evidence_hash = crate::types::hash_data(&evidence_bytes);

        Some(SlashingEvidence {
            id: evidence_hash,
            offense_type: OffenseType::Downtime,
            validator,
            offense_slot: end_slot,
            submission_slot: current_slot,
            reporter: Address::default(),
            evidence_data,
            evidence_hash,
        })
    }

    /// Checks if a validator is jailed.
    pub fn is_jailed(&self, validator: &[u8; 32]) -> bool {
        if let Some(jail) = self.jail_status.get(validator) {
            jail.jail_ends_at > *self.current_slot.read()
        } else {
            false
        }
    }

    /// Gets jail status for a validator.
    pub fn get_jail_status(&self, validator: &[u8; 32]) -> Option<JailStatus> {
        self.jail_status.get(validator).map(|j| j.clone())
    }

    /// Gets slashing history for a validator.
    pub fn get_slashing_history(&self, validator: &[u8; 32]) -> Vec<SlashingRecord> {
        self.slashing_history
            .get(validator)
            .map(|h| h.clone())
            .unwrap_or_default()
    }

    /// Unjails a validator (after jail period).
    pub fn unjail(&self, validator: [u8; 32]) -> SlashingResult<()> {
        let current_slot = *self.current_slot.read();
        
        if let Some(jail) = self.jail_status.get(&validator) {
            if jail.jail_ends_at > current_slot {
                return Err(SlashingError::AlreadyJailed);
            }
        }

        self.jail_status.remove(&validator);
        let new_jailed = self.metrics.read().validators_jailed.saturating_sub(1);
        self.metrics.write().validators_jailed = new_jailed;

        info!("Validator unjailed: {}", hex::encode(&validator[..8]));
        Ok(())
    }

    /// Gets current metrics.
    pub fn get_metrics(&self) -> SlashingMetrics {
        self.metrics.read().clone()
    }

    /// Gets the number of pending evidence items.
    pub fn pending_evidence_count(&self) -> usize {
        self.evidence_pool.len()
    }

    /// Clears old processed evidence records.
    pub fn prune_processed_evidence(&self, before_slot: Slot) {
        self.processed_evidence.retain(|_, &mut slot| slot >= before_slot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::DilithiumKeypair;

    fn create_test_manager() -> SlashingManager {
        let config = SlashingConfig::default();
        let manager = SlashingManager::new(config);
        manager.set_current_slot(1000);
        manager
    }

    #[test]
    fn test_slashing_config_default() {
        let config = SlashingConfig::default();
        assert_eq!(config.double_sign_penalty_bps, 500);
        assert_eq!(config.reporter_reward_bps, 1000);
    }

    #[test]
    fn test_register_validator() {
        let manager = create_test_manager();
        let validator = [1u8; 32];
        manager.register_validator(validator, 1000000).unwrap();
        
        assert!(manager.validator_stakes.contains_key(&validator));
    }

    #[test]
    fn test_offense_type_penalty() {
        let config = SlashingConfig::default();
        
        assert_eq!(OffenseType::DoubleSigning.base_penalty_bps(&config), 500);
        assert_eq!(OffenseType::InvalidBlock.base_penalty_bps(&config), 1000);
        assert!(OffenseType::DoubleSigning.results_in_jail());
        assert!(!OffenseType::Downtime.results_in_jail());
    }

    #[test]
    fn test_jail_check() {
        let manager = create_test_manager();
        let validator = [1u8; 32];
        
        manager.jail_status.insert(validator, JailStatus {
            jailed_at: 500,
            jail_ends_at: 2000,
            reason: OffenseType::DoubleSigning,
            jail_count: 1,
        });

        assert!(manager.is_jailed(&validator));
        
        manager.set_current_slot(2001);
        assert!(!manager.is_jailed(&validator));
    }

    #[test]
    fn test_submit_evidence_duplicate() {
        let manager = create_test_manager();
        let keypair = DilithiumKeypair::generate().unwrap();
        let validator = keypair.address();
        let message1_hash = [1u8; 32];
        let message2_hash = [3u8; 32];
        let signature1 = keypair.sign(&message1_hash).unwrap();
        let signature2 = keypair.sign(&message2_hash).unwrap();
        manager
            .register_validator_with_pubkey(validator, 1000000, keypair.public_key)
            .unwrap();

        let evidence = SlashingEvidence {
            id: [42u8; 32],
            offense_type: OffenseType::DoubleSigning,
            validator,
            offense_slot: 900,
            submission_slot: 1000,
            reporter: Address::default(),
            evidence_data: EvidenceData::DoubleSigning {
                message1: SignedMessage {
                    message_hash: message1_hash,
                    slot: 900,
                    signature: signature1,
                    block_hash: Some([2u8; 32]),
                },
                message2: SignedMessage {
                    message_hash: message2_hash,
                    slot: 900,
                    signature: signature2,
                    block_hash: Some([4u8; 32]),
                },
            },
            evidence_hash: [42u8; 32],
        };

        // First submission should succeed
        let result = manager.submit_evidence(evidence.clone());
        assert!(result.is_ok());

        // Process evidence
        manager.process_evidence();

        // Second submission should fail
        let result = manager.submit_evidence(evidence);
        assert!(matches!(result, Err(SlashingError::DuplicateEvidence(_))));
    }

    #[test]
    fn test_progressive_slashing() {
        let config = SlashingConfig {
            progressive_slashing: true,
            progressive_multiplier: 2.0,
            double_sign_penalty_bps: 500,
            ..Default::default()
        };
        let manager = SlashingManager::new(config);
        manager.set_current_slot(1000);

        let validator = [1u8; 32];
        manager.register_validator(validator, 1000000).unwrap();

        // Seed test slashing history for verification
        manager.slashing_history.insert(validator, vec![
            SlashingRecord {
                evidence_id: [0u8; 32],
                offense_type: OffenseType::DoubleSigning,
                amount_slashed: 50000,
                slashed_at: 500,
                reporter: Address::default(),
                reporter_reward: 5000,
                amount_burned: 22500,
                jailed: true,
            },
        ]);

        // Verify history exists
        let history = manager.get_slashing_history(&validator);
        assert_eq!(history.len(), 1);
    }
}
