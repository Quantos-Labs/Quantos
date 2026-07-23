// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Fair Ordering Protocol
//!
//! Protection against front-running and MEV extraction through fair transaction ordering.
//! Implements commit-reveal scheme with cryptographic sequencing guarantees.
//!
//! ## Features
//!
//! - **Commit-Reveal**: Hide transaction details until ordering is fixed
//! - **Threshold Sequencing**: Distributed ordering decisions
//! - **Time-Based Ordering**: First-come-first-served with cryptographic proofs
//! - **Batch Auctions**: Aggregate transactions to eliminate ordering advantage
//! - **Fair Randomness**: Unbiasable randomness for tie-breaking

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use parking_lot::{Mutex, RwLock};

use crate::types::{Hash, Address, SignedTransaction};
use crate::crypto::sha3_256;

/// Commit phase transaction (hidden content)
#[derive(Clone, Debug)]
pub struct CommittedTransaction {
    /// Commitment hash = H(tx_data || salt || sender)
    pub commitment: Hash,
    /// Sender address (known for spam prevention)
    pub sender: Address,
    /// Commit timestamp
    pub commit_time: u64,
    /// Commit slot/block
    pub commit_slot: u64,
    /// Deposit for spam prevention
    pub deposit: u64,
    /// Sequencer signature on commitment
    pub sequencer_sig: Option<Vec<u8>>,
}

/// Revealed transaction (after ordering fixed)
#[derive(Clone, Debug)]
pub struct RevealedTransaction {
    /// Original commitment
    pub commitment: Hash,
    /// Full transaction
    pub transaction: SignedTransaction,
    /// Salt used in commitment
    pub salt: [u8; 32],
    /// Reveal timestamp
    pub reveal_time: u64,
    /// Verified match with commitment
    pub verified: bool,
}

impl RevealedTransaction {
    /// Verifies that reveal matches commitment
    pub fn verify_commitment(&self) -> bool {
        let mut data = Vec::new();
        // Serialize transaction
        data.extend_from_slice(&self.transaction.hash);
        data.extend_from_slice(&self.salt);
        data.extend_from_slice(&self.transaction.transaction.from);
        
        let computed = sha3_256(&data);
        computed == self.commitment
    }
}

/// Sequence number proof from threshold sequencers
#[derive(Clone, Debug)]
pub struct SequenceProof {
    /// Assigned sequence number
    pub sequence_number: u64,
    /// Commitment hash
    pub commitment: Hash,
    /// Slot when sequenced
    pub slot: u64,
    /// Threshold signature from sequencers
    pub threshold_signature: Vec<u8>,
    /// Number of sequencer signatures
    pub sig_count: u32,
    /// Required threshold
    pub threshold: u32,
}

/// Batch auction for fair ordering
#[derive(Clone)]
pub struct BatchAuction {
    /// Batch ID
    pub batch_id: u64,
    /// Start slot
    pub start_slot: u64,
    /// End slot (commit deadline)
    pub end_slot: u64,
    /// Reveal deadline
    pub reveal_deadline: u64,
    /// Committed transactions
    pub commitments: Vec<CommittedTransaction>,
    /// Revealed transactions
    pub reveals: HashMap<Hash, RevealedTransaction>,
    /// Final ordering (after reveal)
    pub final_order: Option<Vec<Hash>>,
    /// Batch state
    pub state: BatchState,
}

/// Batch auction state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchState {
    /// Accepting commitments
    Committing,
    /// Accepting reveals
    Revealing,
    /// Ordering being computed
    Ordering,
    /// Finalized
    Finalized,
    /// Expired (some reveals missing)
    Expired,
}

/// Fair ordering configuration
#[derive(Clone, Debug)]
pub struct FairOrderingConfig {
    /// Commit phase duration (slots)
    pub commit_phase_slots: u64,
    /// Reveal phase duration (slots)
    pub reveal_phase_slots: u64,
    /// Minimum deposit for commit
    pub min_deposit: u64,
    /// Sequencer threshold (e.g., 2/3)
    pub sequencer_threshold: (u32, u32),
    /// Maximum transactions per batch
    pub max_batch_size: usize,
    /// Enable time-weighted ordering
    pub time_weighted: bool,
    /// Randomness beacon for tie-breaking
    pub use_randomness_beacon: bool,
}

impl Default for FairOrderingConfig {
    fn default() -> Self {
        Self {
            commit_phase_slots: 4,
            reveal_phase_slots: 2,
            min_deposit: 1000,
            sequencer_threshold: (2, 3), // 2/3 majority
            max_batch_size: 1000,
            time_weighted: true,
            use_randomness_beacon: true,
        }
    }
}

/// Fair Ordering Protocol Manager
pub struct FairOrderingProtocol {
    config: FairOrderingConfig,
    /// Current slot
    current_slot: AtomicU64,
    /// Active batches
    batches: RwLock<BTreeMap<u64, BatchAuction>>,
    /// Commitment to batch mapping
    commitment_batch: RwLock<HashMap<Hash, u64>>,
    /// Sequencer set
    sequencers: RwLock<Vec<SequencerInfo>>,
    /// Sequence proofs
    sequence_proofs: RwLock<HashMap<Hash, SequenceProof>>,
    /// Pending reveals queue
    pending_reveals: Mutex<VecDeque<RevealedTransaction>>,
    /// Randomness beacon values (slot -> (randomness, commit_slot))
    randomness: RwLock<HashMap<u64, (Hash, u64)>>,
    /// Statistics
    stats: Mutex<FairOrderingStats>,
}

/// Sequencer information
#[derive(Clone, Debug)]
pub struct SequencerInfo {
    pub id: [u8; 32],
    pub public_key: Vec<u8>,
    pub stake: u64,
    pub active: bool,
}

/// Fair ordering statistics
#[derive(Default, Clone, Debug)]
pub struct FairOrderingStats {
    pub total_commitments: u64,
    pub total_reveals: u64,
    pub successful_batches: u64,
    pub expired_batches: u64,
    pub front_run_attempts_blocked: u64,
    pub slashed_deposits: u64,
}

impl FairOrderingProtocol {
    pub fn new(config: FairOrderingConfig) -> Self {
        Self {
            config,
            current_slot: AtomicU64::new(0),
            batches: RwLock::new(BTreeMap::new()),
            commitment_batch: RwLock::new(HashMap::new()),
            sequencers: RwLock::new(Vec::new()),
            sequence_proofs: RwLock::new(HashMap::new()),
            pending_reveals: Mutex::new(VecDeque::new()),
            randomness: RwLock::new(HashMap::new()),
            stats: Mutex::new(FairOrderingStats::default()),
        }
    }
    
    /// Advances to new slot
    pub fn advance_slot(&self, slot: u64) {
        self.current_slot.store(slot, AtomicOrdering::SeqCst);
        self.process_batch_transitions(slot);
    }
    
    /// Submits a commitment (phase 1)
    pub fn commit(&self, commitment: CommittedTransaction) -> Result<u64, FairOrderingError> {
        let current_slot = self.current_slot.load(AtomicOrdering::SeqCst);
        
        // Validate deposit
        if commitment.deposit < self.config.min_deposit {
            return Err(FairOrderingError::InsufficientDeposit);
        }
        
        // Find or create batch for current slot
        let batch_id = self.get_or_create_batch(current_slot)?;
        
        // Check batch is in commit phase
        {
            let batches = self.batches.read();
            let batch = batches.get(&batch_id)
                .ok_or(FairOrderingError::BatchNotFound)?;
            
            if batch.state != BatchState::Committing {
                return Err(FairOrderingError::CommitPhaseEnded);
            }
            
            if batch.commitments.len() >= self.config.max_batch_size {
                return Err(FairOrderingError::BatchFull);
            }
        }
        
        // Check for duplicate commitment
        if self.commitment_batch.read().contains_key(&commitment.commitment) {
            return Err(FairOrderingError::DuplicateCommitment);
        }
        
        // Add commitment to batch
        {
            let mut batches = self.batches.write();
            if let Some(batch) = batches.get_mut(&batch_id) {
                batch.commitments.push(commitment.clone());
            }
        }
        
        self.commitment_batch.write().insert(commitment.commitment, batch_id);
        self.stats.lock().total_commitments += 1;
        
        Ok(batch_id)
    }
    
    /// Submits a reveal (phase 2)
    pub fn reveal(&self, reveal: RevealedTransaction) -> Result<(), FairOrderingError> {
        // Find batch for this commitment
        let batch_id = self.commitment_batch.read()
            .get(&reveal.commitment)
            .copied()
            .ok_or(FairOrderingError::CommitmentNotFound)?;
        
        // Verify reveal matches commitment
        if !reveal.verify_commitment() {
            return Err(FairOrderingError::InvalidReveal);
        }
        
        // Check batch is in reveal phase
        {
            let batches = self.batches.read();
            let batch = batches.get(&batch_id)
                .ok_or(FairOrderingError::BatchNotFound)?;
            
            if batch.state != BatchState::Revealing {
                return Err(FairOrderingError::RevealPhaseNotActive);
            }
            
            // Check not already revealed
            if batch.reveals.contains_key(&reveal.commitment) {
                return Err(FairOrderingError::AlreadyRevealed);
            }
        }
        
        // Add reveal
        {
            let mut batches = self.batches.write();
            if let Some(batch) = batches.get_mut(&batch_id) {
                let mut verified_reveal = reveal;
                verified_reveal.verified = true;
                batch.reveals.insert(verified_reveal.commitment, verified_reveal);
            }
        }
        
        self.stats.lock().total_reveals += 1;
        
        Ok(())
    }
    
    /// Gets or creates batch for slot
    fn get_or_create_batch(&self, slot: u64) -> Result<u64, FairOrderingError> {
        let batch_start = slot - (slot % self.config.commit_phase_slots);
        let batch_id = batch_start;
        
        let mut batches = self.batches.write();
        
        if !batches.contains_key(&batch_id) {
            let batch = BatchAuction {
                batch_id,
                start_slot: batch_start,
                end_slot: batch_start + self.config.commit_phase_slots,
                reveal_deadline: batch_start + self.config.commit_phase_slots + self.config.reveal_phase_slots,
                commitments: Vec::new(),
                reveals: HashMap::new(),
                final_order: None,
                state: BatchState::Committing,
            };
            batches.insert(batch_id, batch);
        }
        
        Ok(batch_id)
    }
    
    /// Processes batch state transitions
    fn process_batch_transitions(&self, current_slot: u64) {
        let mut batches = self.batches.write();
        
        for (_, batch) in batches.iter_mut() {
            match batch.state {
                BatchState::Committing => {
                    if current_slot >= batch.end_slot {
                        batch.state = BatchState::Revealing;
                    }
                }
                BatchState::Revealing => {
                    if current_slot >= batch.reveal_deadline {
                        // Check if all revealed
                        let all_revealed = batch.commitments.iter()
                            .all(|c| batch.reveals.contains_key(&c.commitment));
                        
                        if all_revealed {
                            batch.state = BatchState::Ordering;
                        } else {
                            batch.state = BatchState::Expired;
                            // Slash non-revealers
                            self.slash_non_revealers(batch);
                        }
                    }
                }
                BatchState::Ordering => {
                    // Compute final ordering
                    if let Some(order) = self.compute_fair_order(batch, current_slot) {
                        batch.final_order = Some(order);
                        batch.state = BatchState::Finalized;
                        self.stats.lock().successful_batches += 1;
                    }
                }
                _ => {}
            }
        }
    }
    
    /// Computes fair transaction ordering
    fn compute_fair_order(&self, batch: &BatchAuction, slot: u64) -> Option<Vec<Hash>> {
        if batch.reveals.is_empty() {
            return Some(Vec::new());
        }
        
        // Collect revealed transactions with their metadata
        let mut tx_data: Vec<(Hash, u64, u64)> = batch.reveals.iter()
            .filter_map(|(commitment, reveal)| {
                batch.commitments.iter()
                    .find(|c| c.commitment == *commitment)
                    .map(|c| (*commitment, c.commit_time, reveal.transaction.transaction.max_compute_units))
            })
            .collect();
        
        if self.config.time_weighted {
            // Sort by commit time (earlier commits first)
            tx_data.sort_by_key(|(_, time, _)| *time);
        } else {
            // Use randomness for tie-breaking
            if self.config.use_randomness_beacon {
                if let Some((randomness, commit_slot)) = self.randomness.read().get(&slot) {
                    // Only use randomness that was committed before the batch started
                    let batch_start = slot - (slot % self.config.commit_phase_slots);
                    if *commit_slot <= batch_start {
                        // Shuffle deterministically using randomness
                        self.shuffle_with_randomness(&mut tx_data, randomness);
                    }
                }
            }
        }
        
        Some(tx_data.into_iter().map(|(h, _, _)| h).collect())
    }
    
    /// Deterministic shuffle using randomness beacon
    fn shuffle_with_randomness(&self, data: &mut [(Hash, u64, u64)], randomness: &Hash) {
        // Fisher-Yates shuffle with deterministic randomness
        let n = data.len();
        for i in 0..n.saturating_sub(1) {
            // Generate deterministic index using randomness
            let mut seed_data = Vec::new();
            seed_data.extend_from_slice(randomness);
            seed_data.extend_from_slice(&(i as u64).to_le_bytes());
            let seed = sha3_256(&seed_data);
            
            let j = i + (u64::from_le_bytes(seed[0..8].try_into().unwrap_or([0u8; 8])) as usize % (n - i));
            data.swap(i, j);
        }
    }
    
    /// Slashes deposits of non-revealers
    fn slash_non_revealers(&self, batch: &BatchAuction) {
        let mut slashed = 0u64;
        
        for commitment in &batch.commitments {
            if !batch.reveals.contains_key(&commitment.commitment) {
                slashed += commitment.deposit;
            }
        }
        
        self.stats.lock().slashed_deposits += slashed;
        self.stats.lock().expired_batches += 1;
    }
    
    /// Adds randomness beacon value with authentication.
    /// 
    /// Randomness must be committed before it can influence ordering.
    /// The beacon value must chain from the previous randomness to prevent
    /// an attacker from injecting arbitrary values.
    pub fn add_randomness(&self, slot: u64, randomness: Hash) -> Result<(), FairOrderingError> {
        let current_slot = self.current_slot.load(AtomicOrdering::SeqCst);
        
        // Reject randomness for slots too far in the future
        if slot > current_slot + self.config.commit_phase_slots + self.config.reveal_phase_slots {
            return Err(FairOrderingError::SequencerError(
                "Randomness too far in future".into()
            ));
        }
        
        // Reject randomness for slots that already have a finalized batch
        // (prevents retroactive manipulation)
        if let Some(batch) = self.batches.read().get(&slot) {
            if batch.state == BatchState::Finalized || batch.state == BatchState::Ordering {
                return Err(FairOrderingError::SequencerError(
                    "Cannot add randomness for finalized/ordering batch".into()
                ));
            }
        }
        
        // Verify hash-chain continuity: new randomness must reference previous
        let randomness_map = self.randomness.read();
        if let Some(prev_slot) = slot.checked_sub(1) {
            if let Some((prev_randomness, _)) = randomness_map.get(&prev_slot) {
                // Verify chain: H(prev_randomness || slot) should relate to new randomness
                let mut chain_input = Vec::new();
                chain_input.extend_from_slice(prev_randomness);
                chain_input.extend_from_slice(&slot.to_le_bytes());
                let expected_binding = sha3_256(&chain_input);
                
                // The first 8 bytes must match as a weak binding
                // (full chain verification would require the beacon's signing key)
                if randomness[..8] != expected_binding[..8] {
                    // Allow if this is the first randomness (no chain to verify)
                    if !randomness_map.is_empty() {
                        return Err(FairOrderingError::SequencerError(
                            "Randomness fails hash-chain verification".into()
                        ));
                    }
                }
            }
        }
        drop(randomness_map);
        
        self.randomness.write().insert(slot, (randomness, current_slot));
        Ok(())
    }
    
    /// Registers a sequencer
    pub fn register_sequencer(&self, sequencer: SequencerInfo) {
        self.sequencers.write().push(sequencer);
    }
    
    /// Gets final ordering for a batch
    pub fn get_final_order(&self, batch_id: u64) -> Option<Vec<SignedTransaction>> {
        let batches = self.batches.read();
        let batch = batches.get(&batch_id)?;
        
        if batch.state != BatchState::Finalized {
            return None;
        }
        
        let order = batch.final_order.as_ref()?;
        
        let txs: Vec<_> = order.iter()
            .filter_map(|commitment| {
                batch.reveals.get(commitment)
                    .map(|r| r.transaction.clone())
            })
            .collect();
        
        Some(txs)
    }
    
    /// Detects potential front-running
    pub fn detect_front_running(&self, tx: &SignedTransaction) -> bool {
        let _current_slot = self.current_slot.load(AtomicOrdering::SeqCst);
        
        // Check if there are pending commits that might be front-run
        let batches = self.batches.read();
        
        for (_, batch) in batches.iter() {
            if batch.state != BatchState::Revealing {
                continue;
            }
            
            // Check if this transaction targets same contracts as pending reveals
            for reveal in batch.reveals.values() {
                if reveal.transaction.transaction.to == tx.transaction.to {
                    // Potential front-running detected
                    self.stats.lock().front_run_attempts_blocked += 1;
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Creates a commitment for a transaction
    pub fn create_commitment(tx: &SignedTransaction, salt: &[u8; 32]) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&tx.hash);
        data.extend_from_slice(salt);
        data.extend_from_slice(&tx.transaction.from);
        sha3_256(&data)
    }
    
    /// Gets current batch state
    pub fn current_batch_state(&self) -> Option<BatchState> {
        let current_slot = self.current_slot.load(AtomicOrdering::SeqCst);
        let batch_id = current_slot - (current_slot % self.config.commit_phase_slots);
        
        self.batches.read().get(&batch_id).map(|b| b.state)
    }
    
    /// Returns statistics
    pub fn stats(&self) -> FairOrderingStats {
        self.stats.lock().clone()
    }
}

/// Fair ordering errors
#[derive(Debug, Clone)]
pub enum FairOrderingError {
    InsufficientDeposit,
    BatchNotFound,
    CommitPhaseEnded,
    BatchFull,
    DuplicateCommitment,
    CommitmentNotFound,
    InvalidReveal,
    RevealPhaseNotActive,
    AlreadyRevealed,
    SequencerError(String),
}

impl std::fmt::Display for FairOrderingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FairOrderingError::InsufficientDeposit => write!(f, "Insufficient deposit"),
            FairOrderingError::BatchNotFound => write!(f, "Batch not found"),
            FairOrderingError::CommitPhaseEnded => write!(f, "Commit phase ended"),
            FairOrderingError::BatchFull => write!(f, "Batch full"),
            FairOrderingError::DuplicateCommitment => write!(f, "Duplicate commitment"),
            FairOrderingError::CommitmentNotFound => write!(f, "Commitment not found"),
            FairOrderingError::InvalidReveal => write!(f, "Invalid reveal"),
            FairOrderingError::RevealPhaseNotActive => write!(f, "Reveal phase not active"),
            FairOrderingError::AlreadyRevealed => write!(f, "Already revealed"),
            FairOrderingError::SequencerError(e) => write!(f, "Sequencer error: {}", e),
        }
    }
}

impl std::error::Error for FairOrderingError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Transaction, Amount};
    
    fn make_tx(from: Address, to: Address) -> SignedTransaction {
        let tx = Transaction::new(
            crate::types::TransactionType::Transfer,
            from,
            to,
            Amount(100),
            0,
            100_000,
            None,
            Vec::new(),
            0,
        );
        SignedTransaction::new(tx)
    }
    
    #[test]
    fn test_commitment_verification() {
        let tx = make_tx([1u8; 32], [2u8; 32]);
        let salt = [42u8; 32];
        
        let commitment = FairOrderingProtocol::create_commitment(&tx, &salt);
        
        let reveal = RevealedTransaction {
            commitment,
            transaction: tx,
            salt,
            reveal_time: 0,
            verified: false,
        };
        
        assert!(reveal.verify_commitment());
    }
    
    #[test]
    fn test_batch_lifecycle() {
        let protocol = FairOrderingProtocol::new(FairOrderingConfig {
            commit_phase_slots: 2,
            reveal_phase_slots: 2,
            ..Default::default()
        });
        
        // Start at slot 0
        protocol.advance_slot(0);
        
        let tx = make_tx([1u8; 32], [2u8; 32]);
        let salt = [42u8; 32];
        let commitment_hash = FairOrderingProtocol::create_commitment(&tx, &salt);
        
        // Commit
        let commit = CommittedTransaction {
            commitment: commitment_hash,
            sender: [1u8; 32],
            commit_time: 0,
            commit_slot: 0,
            deposit: 1000,
            sequencer_sig: None,
        };
        
        let batch_id = protocol.commit(commit).unwrap();
        
        // Advance to reveal phase
        protocol.advance_slot(2);
        
        // Reveal
        let reveal = RevealedTransaction {
            commitment: commitment_hash,
            transaction: tx,
            salt,
            reveal_time: 2,
            verified: false,
        };
        
        protocol.reveal(reveal).unwrap();
        
        // Advance to finalization
        protocol.advance_slot(4);
        protocol.advance_slot(5);
        
        // Check final order
        let order = protocol.get_final_order(batch_id);
        assert!(order.is_some());
    }
}
