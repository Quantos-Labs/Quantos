//! # Quantos Light Client
//!
//! Lightweight client implementation for resource-constrained devices.
//!
//! ## Features
//!
//! - **Header Sync**: Download and verify block headers only
//! - **Merkle Proofs**: Verify account/storage state with proofs
//! - **Transaction Proofs**: Verify transaction inclusion
//! - **Committee Tracking**: Follow validator committee changes
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Light Client                              │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Header Chain: [H0] <- [H1] <- [H2] <- ... <- [Hn]          │
//! │                                                              │
//! │  Finality Checkpoints: [C0] -------- [C1] -------- [C2]     │
//! │                                                              │
//! │  Committee Tracking: validators[], stake_weights[]          │
//! ├─────────────────────────────────────────────────────────────┤
//! │  State Queries:                                              │
//! │    - get_balance(addr) -> (balance, merkle_proof)           │
//! │    - get_storage(addr, key) -> (value, merkle_proof)        │
//! │    - verify_tx(tx_hash) -> (receipt, inclusion_proof)       │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, warn};

use crate::types::{Address, Amount, Hash, ShardId, Slot};
use crate::crypto::verify_falcon;

/// Maximum headers in a single batch
const MAX_BATCH_HEADERS: usize = 1000;
/// Maximum proof nodes
const MAX_PROOF_NODES: usize = 64;
/// Maximum committees stored
const MAX_COMMITTEES: usize = 100;
/// Max timestamp drift (seconds)
const MAX_TIMESTAMP_DRIFT: u64 = 300;
/// Maximum validators per committee to prevent memory exhaustion
const MAX_VALIDATORS_PER_COMMITTEE: usize = 1_000;
/// Maximum checkpoints stored (separate from header limit)
const MAX_CHECKPOINTS: usize = 500;
/// Minimum expected account proof value size (nonce + balance + code_hash + storage_root)
const MIN_ACCOUNT_PROOF_VALUE_SIZE: usize = 8 + 16 + 32 + 32;

/// Light client errors.
#[derive(Debug, Error)]
pub enum LightClientError {
    #[error("Header not found: slot {0}")]
    HeaderNotFound(Slot),
    
    #[error("Invalid proof: {0}")]
    InvalidProof(String),
    
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Not synced: behind by {0} slots")]
    NotSynced(u64),
    
    #[error("Committee unknown for slot {0}")]
    CommitteeUnknown(Slot),
    
    #[error("Insufficient signatures: got {0}, need {1}")]
    InsufficientSignatures(usize, usize),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Invalid header: {0}")]
    InvalidHeader(String),
}

pub type LightClientResult<T> = Result<T, LightClientError>;

/// Light client configuration.
#[derive(Clone, Debug)]
pub struct LightClientConfig {
    /// Maximum headers to store
    pub max_headers: usize,
    /// Finality checkpoint interval
    pub checkpoint_interval: u64,
    /// Minimum committee signatures for finality
    pub min_finality_signatures: usize,
    /// Maximum header age before requiring resync
    pub max_header_age_slots: u64,
    /// Enable header pruning
    pub prune_old_headers: bool,
    /// Trust period for weak subjectivity
    pub trust_period_slots: u64,
}

impl Default for LightClientConfig {
    fn default() -> Self {
        Self {
            max_headers: 10000,
            checkpoint_interval: 100,
            min_finality_signatures: 67, // 2/3 + 1
            max_header_age_slots: 1000,
            prune_old_headers: true,
            trust_period_slots: 50000,
        }
    }
}

/// Lightweight block header for light clients.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LightHeader {
    /// Slot number
    pub slot: Slot,
    /// Parent header hash
    pub parent_hash: Hash,
    /// State root (for verifying state proofs)
    pub state_root: Hash,
    /// Transactions root
    pub transactions_root: Hash,
    /// Receipts root
    pub receipts_root: Hash,
    /// Validator who proposed this block
    pub proposer: [u8; 32],
    /// Timestamp
    pub timestamp: u64,
    /// Shard ID (for sharded chains)
    pub shard_id: Option<ShardId>,
    /// Hash of this header
    pub hash: Hash,
}

impl LightHeader {
    /// Computes the header hash.
    pub fn compute_hash(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&self.slot.to_le_bytes());
        data.extend_from_slice(&self.parent_hash);
        data.extend_from_slice(&self.state_root);
        data.extend_from_slice(&self.transactions_root);
        data.extend_from_slice(&self.receipts_root);
        data.extend_from_slice(&self.proposer);
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        crate::types::hash_data(&data)
    }

    /// Verifies the header hash.
    pub fn verify_hash(&self) -> bool {
        self.hash == self.compute_hash()
    }
}

/// Finality checkpoint with committee attestations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalityCheckpoint {
    /// Slot of the checkpoint
    pub slot: Slot,
    /// Header hash at this checkpoint
    pub header_hash: Hash,
    /// State root at checkpoint
    pub state_root: Hash,
    /// Signatures from committee members
    pub signatures: Vec<CommitteeSignature>,
    /// Total stake that signed
    pub signed_stake: u64,
    /// Total committee stake
    pub total_stake: u64,
}

impl FinalityCheckpoint {
    /// Checks if checkpoint has sufficient signatures.
    pub fn is_finalized(&self, threshold: f64) -> bool {
        if self.total_stake == 0 {
            return false;
        }
        (self.signed_stake as f64 / self.total_stake as f64) >= threshold
    }
}

/// Signature from a committee member.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitteeSignature {
    /// Validator public key
    pub validator: [u8; 32],
    /// Signature
    pub signature: Vec<u8>,
    /// Validator's stake
    pub stake: u64,
}

/// Validator committee information.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Committee {
    /// Epoch/slot range start
    pub start_slot: Slot,
    /// Epoch/slot range end
    pub end_slot: Slot,
    /// Validator public keys
    pub validators: Vec<[u8; 32]>,
    /// Stake weights
    pub stakes: Vec<u64>,
    /// Total stake
    pub total_stake: u64,
}

impl Committee {
    /// Checks if a validator is in the committee.
    pub fn contains(&self, validator: &[u8; 32]) -> bool {
        self.validators.contains(validator)
    }

    /// Gets a validator's stake.
    pub fn get_stake(&self, validator: &[u8; 32]) -> Option<u64> {
        self.validators
            .iter()
            .position(|v| v == validator)
            .map(|i| self.stakes[i])
    }
}

/// Merkle proof for state verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Key being proven
    pub key: Vec<u8>,
    /// Value at key (None if key doesn't exist)
    pub value: Option<Vec<u8>>,
    /// Proof nodes (siblings on path to root)
    pub proof_nodes: Vec<ProofNode>,
    /// Root hash this proof is against
    pub root: Hash,
}

/// Single node in a merkle proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofNode {
    /// Hash of sibling node
    pub hash: Hash,
    /// Position (left or right)
    pub position: ProofPosition,
}

/// Position of proof node.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofPosition {
    Left,
    Right,
}

impl MerkleProof {
    /// Verifies the merkle proof against a root.
    pub fn verify(&self, expected_root: &Hash) -> bool {
        if self.root != *expected_root {
            return false;
        }
        
        // CRITICAL: Limit proof nodes to prevent DoS
        if self.proof_nodes.len() > MAX_PROOF_NODES {
            return false;
        }

        // Compute leaf hash
        let mut current_hash = match &self.value {
            Some(value) => {
                let mut leaf_data = Vec::new();
                leaf_data.extend_from_slice(&self.key);
                leaf_data.extend_from_slice(value);
                crate::types::hash_data(&leaf_data)
            }
            None => {
                // Empty/non-existence proof
                crate::types::hash_data(&self.key)
            }
        };

        // Walk up the tree
        for node in &self.proof_nodes {
            let mut combined = Vec::with_capacity(64);
            match node.position {
                ProofPosition::Left => {
                    combined.extend_from_slice(&node.hash);
                    combined.extend_from_slice(&current_hash);
                }
                ProofPosition::Right => {
                    combined.extend_from_slice(&current_hash);
                    combined.extend_from_slice(&node.hash);
                }
            }
            current_hash = crate::types::hash_data(&combined);
        }

        current_hash == *expected_root
    }
}

/// Proof of transaction inclusion.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionProof {
    /// Transaction hash
    pub tx_hash: Hash,
    /// Block slot containing the transaction
    pub slot: Slot,
    /// Index in the block
    pub index: u32,
    /// Merkle proof to transactions root
    pub merkle_proof: MerkleProof,
    /// Transaction receipt (optional)
    pub receipt: Option<TransactionReceipt>,
    /// Receipt proof (if receipt included)
    pub receipt_proof: Option<MerkleProof>,
}

/// Lightweight transaction receipt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionReceipt {
    /// Transaction hash
    pub tx_hash: Hash,
    /// Success status
    pub success: bool,
    /// Gas used
    pub gas_used: u64,
    /// Logs/events
    pub logs: Vec<LogEntry>,
}

/// Log entry from transaction execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogEntry {
    /// Contract address
    pub address: Address,
    /// Topics
    pub topics: Vec<Hash>,
    /// Data
    pub data: Vec<u8>,
}

/// Account state proof response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountProof {
    /// Account address
    pub address: Address,
    /// Account balance
    pub balance: Amount,
    /// Account nonce
    pub nonce: u64,
    /// Code hash (for contracts)
    pub code_hash: Option<Hash>,
    /// Storage root (for contracts)
    pub storage_root: Option<Hash>,
    /// Merkle proof
    pub proof: MerkleProof,
    /// Slot this proof is valid for
    pub slot: Slot,
}

/// Storage proof response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageProof {
    /// Contract address
    pub address: Address,
    /// Storage key
    pub key: Hash,
    /// Storage value
    pub value: [u8; 32],
    /// Account proof (to verify storage root)
    pub account_proof: MerkleProof,
    /// Storage proof (to verify value)
    pub storage_proof: MerkleProof,
    /// Slot this proof is valid for
    pub slot: Slot,
}

/// Light client state.
pub struct LightClient {
    config: LightClientConfig,
    /// Synced headers by slot
    headers: Arc<RwLock<BTreeMap<Slot, LightHeader>>>,
    /// Finality checkpoints
    checkpoints: Arc<RwLock<VecDeque<FinalityCheckpoint>>>,
    /// Known committees by start slot
    committees: Arc<RwLock<BTreeMap<Slot, Committee>>>,
    /// Latest finalized slot
    finalized_slot: Arc<RwLock<Slot>>,
    /// Latest synced slot
    synced_slot: Arc<RwLock<Slot>>,
    /// Trusted root (for bootstrapping)
    trusted_root: Arc<RwLock<Option<(Slot, Hash)>>>,
}

impl LightClient {
    /// Creates a new light client.
    pub fn new(config: LightClientConfig) -> Self {
        Self {
            config,
            headers: Arc::new(RwLock::new(BTreeMap::new())),
            checkpoints: Arc::new(RwLock::new(VecDeque::new())),
            committees: Arc::new(RwLock::new(BTreeMap::new())),
            finalized_slot: Arc::new(RwLock::new(0)),
            synced_slot: Arc::new(RwLock::new(0)),
            trusted_root: Arc::new(RwLock::new(None)),
        }
    }

    /// Bootstraps the light client with a trusted checkpoint.
    pub fn bootstrap(
        &self,
        checkpoint: FinalityCheckpoint,
        committee: Committee,
    ) -> LightClientResult<()> {
        info!("Bootstrapping light client at slot {}", checkpoint.slot);

        // Validate committee size to prevent memory exhaustion
        if committee.validators.len() > MAX_VALIDATORS_PER_COMMITTEE {
            return Err(LightClientError::VerificationFailed(
                format!("Committee too large: {} > {}", committee.validators.len(), MAX_VALIDATORS_PER_COMMITTEE)
            ));
        }

        // CRITICAL: Verify checkpoint cryptographically
        // Prepare message
        let mut message = Vec::new();
        message.extend_from_slice(&checkpoint.slot.to_le_bytes());
        message.extend_from_slice(&checkpoint.header_hash);
        message.extend_from_slice(&checkpoint.state_root);
        
        // Verify signatures from committee
        // SECURITY: Treat verification errors as invalid signatures (not skipped)
        let mut verified_stake = 0u64;
        let mut invalid_count = 0usize;
        for sig in &checkpoint.signatures {
            if let Some(stake) = committee.get_stake(&sig.validator) {
                match verify_falcon(&sig.validator, &message, &sig.signature) {
                    Ok(true) => {
                        verified_stake = verified_stake.checked_add(stake)
                            .ok_or_else(|| LightClientError::VerificationFailed(
                                "Stake overflow in bootstrap".into()
                            ))?;
                    }
                    Ok(false) => {
                        warn!("Invalid signature from validator in bootstrap");
                        invalid_count += 1;
                    }
                    Err(e) => {
                        // Treat errors as invalid — do NOT silently skip
                        warn!("Signature verification error in bootstrap: {:?}", e);
                        invalid_count += 1;
                    }
                }
            }
        }
        
        if invalid_count > 0 {
            warn!("{} invalid/error signatures detected during bootstrap", invalid_count);
        }
        
        // Require 2/3+ stake with valid signatures
        if (verified_stake as f64 / committee.total_stake as f64) < 2.0 / 3.0 {
            return Err(LightClientError::InsufficientSignatures(
                checkpoint.signatures.len(),
                self.config.min_finality_signatures,
            ));
        }
        
        // Validate committee slot range
        if checkpoint.slot < committee.start_slot || checkpoint.slot > committee.end_slot {
            return Err(LightClientError::VerificationFailed(
                "Checkpoint slot outside committee range".into()
            ));
        }

        // Atomic state update: acquire all write locks together to prevent
        // concurrent reads from seeing partially-updated state
        {
            let mut trusted_root = self.trusted_root.write();
            let mut finalized_slot = self.finalized_slot.write();
            let mut synced_slot = self.synced_slot.write();
            *trusted_root = Some((checkpoint.slot, checkpoint.header_hash));
            *finalized_slot = checkpoint.slot;
            *synced_slot = checkpoint.slot;
        }

        // Store committee
        self.committees.write().insert(committee.start_slot, committee);

        // Store checkpoint
        self.checkpoints.write().push_back(checkpoint);

        info!("Light client bootstrapped successfully");
        Ok(())
    }

    /// Processes a new header.
    pub fn process_header(&self, header: LightHeader) -> LightClientResult<()> {
        // Verify header hash
        if !header.verify_hash() {
            return Err(LightClientError::InvalidHeader("Hash mismatch".into()));
        }
        
        // CRITICAL: Validate timestamp to prevent time manipulation
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Reject headers with timestamps too far in future
        if header.timestamp > current_time + MAX_TIMESTAMP_DRIFT {
            return Err(LightClientError::InvalidHeader(
                format!("Timestamp too far in future: {} > {}", header.timestamp, current_time)
            ));
        }
        
        // Reject headers with unreasonably old timestamps (more than 1 year old)
        if current_time > header.timestamp + 365 * 24 * 3600 {
            return Err(LightClientError::InvalidHeader(
                "Timestamp too old".into()
            ));
        }

        let synced_slot = *self.synced_slot.read();

        // Enforce sequential processing: reject headers that would create gaps
        if header.slot > 0 && synced_slot > 0 {
            // Only allow the next sequential slot or a slot we already have a parent for
            if header.slot > synced_slot + 1 {
                return Err(LightClientError::InvalidHeader(
                    format!("Non-sequential header: slot {} but synced to {}", header.slot, synced_slot)
                ));
            }
            
            let headers = self.headers.read();
            // Verify parent hash if parent exists
            if let Some(parent) = headers.get(&(header.slot - 1)) {
                if parent.hash != header.parent_hash {
                    return Err(LightClientError::InvalidHeader(
                        "Parent hash mismatch".into(),
                    ));
                }
            } else if header.slot != synced_slot + 1 {
                // Parent must exist for non-sequential headers
                return Err(LightClientError::HeaderNotFound(header.slot - 1));
            }
        }

        // Store header
        self.headers.write().insert(header.slot, header.clone());
        
        // Update synced slot
        if header.slot > synced_slot {
            *self.synced_slot.write() = header.slot;
        }

        // Prune old headers if needed
        if self.config.prune_old_headers {
            self.prune_headers();
        }

        debug!("Processed header at slot {}", header.slot);
        Ok(())
    }

    /// Processes a batch of headers.
    pub fn process_headers(&self, headers: Vec<LightHeader>) -> LightClientResult<()> {
        // CRITICAL: Limit batch size to prevent DoS
        if headers.len() > MAX_BATCH_HEADERS {
            return Err(LightClientError::VerificationFailed(
                format!("Batch too large: {} > {}", headers.len(), MAX_BATCH_HEADERS)
            ));
        }
        
        for header in headers {
            self.process_header(header)?;
        }
        Ok(())
    }

    /// Processes a finality checkpoint.
    pub fn process_checkpoint(
        &self,
        checkpoint: FinalityCheckpoint,
    ) -> LightClientResult<()> {
        // Verify checkpoint signatures against known committee
        let committee = self.get_committee_for_slot(checkpoint.slot)?;
        
        // Prepare message to verify (checkpoint data)
        let mut message = Vec::new();
        message.extend_from_slice(&checkpoint.slot.to_le_bytes());
        message.extend_from_slice(&checkpoint.header_hash);
        message.extend_from_slice(&checkpoint.state_root);
        
        // SECURITY: Treat verification errors as invalid signatures (not skipped)
        let mut signed_stake = 0u64;
        let mut invalid_count = 0usize;
        for sig in &checkpoint.signatures {
            if let Some(stake) = committee.get_stake(&sig.validator) {
                // CRITICAL: Verify actual Falcon signature
                match verify_falcon(&sig.validator, &message, &sig.signature) {
                    Ok(true) => {
                        // Use checked arithmetic to prevent overflow
                        signed_stake = signed_stake.checked_add(stake)
                            .ok_or_else(|| LightClientError::VerificationFailed(
                                "Stake overflow".into()
                            ))?;
                    }
                    Ok(false) => {
                        warn!("Invalid signature from validator {:?}", sig.validator);
                        invalid_count += 1;
                    }
                    Err(e) => {
                        // Treat errors as invalid — do NOT silently skip
                        warn!("Signature verification error (counted as invalid): {:?}", e);
                        invalid_count += 1;
                    }
                }
            }
        }
        
        if invalid_count > 0 {
            warn!("{} invalid/error signatures in checkpoint at slot {}", invalid_count, checkpoint.slot);
        }

        if (signed_stake as f64 / committee.total_stake as f64) < 2.0 / 3.0 {
            return Err(LightClientError::InsufficientSignatures(
                checkpoint.signatures.len(),
                self.config.min_finality_signatures,
            ));
        }

        // Update finalized slot
        let current_finalized = *self.finalized_slot.read();
        if checkpoint.slot > current_finalized {
            *self.finalized_slot.write() = checkpoint.slot;
        }

        // Store checkpoint
        let mut checkpoints = self.checkpoints.write();
        checkpoints.push_back(checkpoint.clone());

        // Prune old checkpoints using dedicated checkpoint limit (not header limit)
        while checkpoints.len() > MAX_CHECKPOINTS {
            checkpoints.pop_front();
        }

        info!("Processed finality checkpoint at slot {}", checkpoint.slot);
        Ok(())
    }

    /// Updates committee information.
    /// 
    /// CRITICAL: Requires cryptographic proof that the transition follows consensus rules.
    /// The new committee must be attested by 2/3+ stake of the current committee to prevent
    /// an attacker from installing a malicious committee.
    pub fn update_committee(
        &self,
        committee: Committee,
        transition_signatures: &[CommitteeSignature],
    ) -> LightClientResult<()> {
        info!(
            "Updating committee for slots {}-{}",
            committee.start_slot, committee.end_slot
        );
        
        // CRITICAL: Validate committee before accepting
        // Check slot range is valid
        if committee.start_slot >= committee.end_slot {
            return Err(LightClientError::VerificationFailed(
                "Invalid committee slot range".into()
            ));
        }
        
        // Cap validator count to prevent memory exhaustion
        if committee.validators.len() > MAX_VALIDATORS_PER_COMMITTEE {
            return Err(LightClientError::VerificationFailed(
                format!("Committee too large: {} > {}", committee.validators.len(), MAX_VALIDATORS_PER_COMMITTEE)
            ));
        }
        
        // Validators and stakes must match in length
        if committee.validators.len() != committee.stakes.len() {
            return Err(LightClientError::VerificationFailed(
                "Validators/stakes length mismatch".into()
            ));
        }
        
        // Check committee is not too far in the future
        let synced_slot = *self.synced_slot.read();
        if committee.start_slot > synced_slot + self.config.trust_period_slots {
            return Err(LightClientError::VerificationFailed(
                "Committee too far in future".into()
            ));
        }
        
        // CRITICAL: Verify transition is attested by the current committee
        // The new committee must be signed by 2/3+ stake of an existing trusted committee
        let current_committee = self.get_committee_for_slot(committee.start_slot.saturating_sub(1))
            .map_err(|_| LightClientError::VerificationFailed(
                "No current committee to validate transition against".into()
            ))?;
        
        // Build the transition message: hash of the new committee data
        let mut transition_msg = Vec::new();
        transition_msg.extend_from_slice(b"committee-transition:");
        transition_msg.extend_from_slice(&committee.start_slot.to_le_bytes());
        transition_msg.extend_from_slice(&committee.end_slot.to_le_bytes());
        for v in &committee.validators {
            transition_msg.extend_from_slice(v);
        }
        for s in &committee.stakes {
            transition_msg.extend_from_slice(&s.to_le_bytes());
        }
        
        let mut attested_stake = 0u64;
        for sig in transition_signatures {
            if let Some(stake) = current_committee.get_stake(&sig.validator) {
                match verify_falcon(&sig.validator, &transition_msg, &sig.signature) {
                    Ok(true) => {
                        attested_stake = attested_stake.checked_add(stake)
                            .ok_or_else(|| LightClientError::VerificationFailed(
                                "Stake overflow in committee transition".into()
                            ))?;
                    }
                    Ok(false) => {
                        warn!("Invalid transition signature from validator");
                    }
                    Err(e) => {
                        warn!("Transition signature error (counted as invalid): {:?}", e);
                    }
                }
            }
        }
        
        // Require 2/3+ of current committee stake to attest
        if current_committee.total_stake == 0 || 
           (attested_stake as f64 / current_committee.total_stake as f64) < 2.0 / 3.0 {
            return Err(LightClientError::VerificationFailed(
                format!(
                    "Insufficient attestation for committee transition: {}/{} stake",
                    attested_stake, current_committee.total_stake
                )
            ));
        }
        
        // Check for overlapping committees
        let committees = self.committees.read();
        for (_, existing) in committees.iter() {
            if committee.start_slot <= existing.end_slot && committee.end_slot >= existing.start_slot {
                return Err(LightClientError::VerificationFailed(
                    "Overlapping committee ranges".into()
                ));
            }
        }
        drop(committees);
        
        // Enforce maximum committees limit
        let mut committees = self.committees.write();
        if committees.len() >= MAX_COMMITTEES {
            // Remove oldest committee
            if let Some(&oldest_slot) = committees.keys().next() {
                committees.remove(&oldest_slot);
            }
        }
        
        committees.insert(committee.start_slot, committee);
        Ok(())
    }

    /// Gets the committee for a given slot.
    fn get_committee_for_slot(&self, slot: Slot) -> LightClientResult<Committee> {
        let committees = self.committees.read();
        
        // Find committee whose range includes this slot
        for (_, committee) in committees.iter().rev() {
            if slot >= committee.start_slot && slot <= committee.end_slot {
                return Ok(committee.clone());
            }
        }
        
        Err(LightClientError::CommitteeUnknown(slot))
    }

    /// Verifies an account proof.
    pub fn verify_account_proof(&self, proof: &AccountProof) -> LightClientResult<bool> {
        // Get header for the proof's slot
        let header = self.get_header(proof.slot)?;

        // Verify merkle proof against state root
        if !proof.proof.verify(&header.state_root) {
            return Err(LightClientError::InvalidProof(
                "Account proof verification failed".into(),
            ));
        }

        Ok(true)
    }

    /// Verifies a storage proof.
    pub fn verify_storage_proof(&self, proof: &StorageProof) -> LightClientResult<bool> {
        // Get header for the proof's slot
        let header = self.get_header(proof.slot)?;

        // Verify account proof first
        if !proof.account_proof.verify(&header.state_root) {
            return Err(LightClientError::InvalidProof(
                "Account proof verification failed".into(),
            ));
        }

        // Extract storage root from account proof value
        // CRITICAL: Validate the full account data structure before extraction
        let storage_root = proof.account_proof.value.as_ref()
            .and_then(|v| {
                // Account proof value must contain: nonce(8) + balance(16) + code_hash(32) + storage_root(32) = 88 bytes min
                if v.len() < MIN_ACCOUNT_PROOF_VALUE_SIZE {
                    return None;
                }
                let mut root = [0u8; 32];
                root.copy_from_slice(&v[v.len() - 32..]);
                Some(root)
            })
            .ok_or_else(|| LightClientError::InvalidProof(
                format!("Invalid account proof value: expected >= {} bytes", MIN_ACCOUNT_PROOF_VALUE_SIZE)
            ))?;

        // Verify storage proof against storage root
        if !proof.storage_proof.verify(&storage_root) {
            return Err(LightClientError::InvalidProof(
                "Storage proof verification failed".into(),
            ));
        }

        Ok(true)
    }

    /// Verifies a transaction inclusion proof.
    pub fn verify_transaction_proof(
        &self,
        proof: &TransactionProof,
    ) -> LightClientResult<bool> {
        // Get header
        let header = self.get_header(proof.slot)?;

        // Verify transaction inclusion
        if !proof.merkle_proof.verify(&header.transactions_root) {
            return Err(LightClientError::InvalidProof(
                "Transaction proof verification failed".into(),
            ));
        }

        // Verify receipt if present
        if let (Some(receipt_proof), Some(_receipt)) = (&proof.receipt_proof, &proof.receipt) {
            if !receipt_proof.verify(&header.receipts_root) {
                return Err(LightClientError::InvalidProof(
                    "Receipt proof verification failed".into(),
                ));
            }
        }

        Ok(true)
    }

    /// Gets a header by slot.
    pub fn get_header(&self, slot: Slot) -> LightClientResult<LightHeader> {
        self.headers
            .read()
            .get(&slot)
            .cloned()
            .ok_or(LightClientError::HeaderNotFound(slot))
    }

    /// Gets the latest synced slot.
    pub fn get_synced_slot(&self) -> Slot {
        *self.synced_slot.read()
    }

    /// Gets the latest finalized slot.
    pub fn get_finalized_slot(&self) -> Slot {
        *self.finalized_slot.read()
    }

    /// Checks if the client is synced.
    pub fn is_synced(&self, current_network_slot: Slot) -> bool {
        let synced = *self.synced_slot.read();
        current_network_slot.saturating_sub(synced) <= self.config.max_header_age_slots
    }

    /// Gets the state root for a slot.
    pub fn get_state_root(&self, slot: Slot) -> LightClientResult<Hash> {
        self.get_header(slot).map(|h| h.state_root)
    }

    /// Prunes old headers.
    fn prune_headers(&self) {
        let mut headers = self.headers.write();
        let finalized = *self.finalized_slot.read();

        while headers.len() > self.config.max_headers {
            if let Some((&oldest_slot, _)) = headers.iter().next() {
                if oldest_slot < finalized {
                    headers.remove(&oldest_slot);
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    /// Gets sync status.
    pub fn get_sync_status(&self) -> LightClientSyncStatus {
        LightClientSyncStatus {
            synced_slot: *self.synced_slot.read(),
            finalized_slot: *self.finalized_slot.read(),
            headers_stored: self.headers.read().len(),
            checkpoints_stored: self.checkpoints.read().len(),
            committees_known: self.committees.read().len(),
        }
    }
}

/// Light client sync status.
#[derive(Clone, Debug)]
pub struct LightClientSyncStatus {
    pub synced_slot: Slot,
    pub finalized_slot: Slot,
    pub headers_stored: usize,
    pub checkpoints_stored: usize,
    pub committees_known: usize,
}

/// Light client proof request types.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProofRequest {
    /// Request account balance proof
    AccountBalance { address: Address, slot: Option<Slot> },
    /// Request storage proof
    Storage { address: Address, key: Hash, slot: Option<Slot> },
    /// Request transaction inclusion proof
    Transaction { tx_hash: Hash },
    /// Request receipt proof
    Receipt { tx_hash: Hash },
}

/// Light client proof response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProofResponse {
    AccountBalance(AccountProof),
    Storage(StorageProof),
    Transaction(TransactionProof),
    Error(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_light_client_creation() {
        let config = LightClientConfig::default();
        let client = LightClient::new(config);
        assert_eq!(client.get_synced_slot(), 0);
        assert_eq!(client.get_finalized_slot(), 0);
    }

    #[test]
    fn test_merkle_proof_verification() {
        let proof = MerkleProof {
            key: b"test_key".to_vec(),
            value: Some(b"test_value".to_vec()),
            proof_nodes: vec![],
            root: [0u8; 32],
        };

        // Empty proof should verify against computed leaf hash
        let leaf_hash = {
            let mut data = Vec::new();
            data.extend_from_slice(b"test_key");
            data.extend_from_slice(b"test_value");
            crate::types::hash_data(&data)
        };

        let proof_with_correct_root = MerkleProof {
            root: leaf_hash,
            ..proof
        };

        assert!(proof_with_correct_root.verify(&leaf_hash));
    }

    #[test]
    fn test_header_hash_verification() {
        let header = LightHeader {
            slot: 100,
            parent_hash: [0u8; 32],
            state_root: [1u8; 32],
            transactions_root: [2u8; 32],
            receipts_root: [3u8; 32],
            proposer: [4u8; 32],
            timestamp: 12345,
            shard_id: None,
            hash: [0u8; 32], // Will be computed
        };

        let computed_hash = header.compute_hash();
        let header_with_hash = LightHeader {
            hash: computed_hash,
            ..header
        };

        assert!(header_with_hash.verify_hash());
    }

    #[test]
    fn test_checkpoint_finality() {
        let checkpoint = FinalityCheckpoint {
            slot: 100,
            header_hash: [0u8; 32],
            state_root: [1u8; 32],
            signatures: vec![],
            signed_stake: 70,
            total_stake: 100,
        };

        assert!(checkpoint.is_finalized(0.67));
        assert!(!checkpoint.is_finalized(0.75));
    }
}
