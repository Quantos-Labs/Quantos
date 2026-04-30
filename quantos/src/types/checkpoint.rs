use serde::{Deserialize, Serialize};
use crate::types::{Address, Hash, hash_data};
use crate::crypto::{verify_falcon, with_domain, DOMAIN_CHECKPOINT};

/// HIGH (z5): Maximum validators per checkpoint to prevent DoS
const MAX_CHECKPOINT_VALIDATORS: usize = 1000;
/// CRITICAL (z3): Maximum signatures in a finality proof
const MAX_FINALITY_SIGNATURES: usize = 1000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Checkpoint {
    pub epoch: u64,
    pub slot: u64,
    pub state_root: Hash,
    pub dag_root: Hash,
    pub vertex_count: u64,
    pub transaction_count: u64,
    pub validators: Vec<Address>,
    pub signature: Vec<u8>,
    pub timestamp: u64,
    pub previous_checkpoint: Hash,
}

impl Checkpoint {
    pub fn new(
        epoch: u64,
        slot: u64,
        state_root: Hash,
        dag_root: Hash,
        vertex_count: u64,
        transaction_count: u64,
        previous_checkpoint: Hash,
    ) -> Self {
        Self {
            epoch,
            slot,
            state_root,
            dag_root,
            vertex_count,
            transaction_count,
            validators: Vec::new(),
            signature: Vec::new(),
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            previous_checkpoint,
        }
    }
    
    /// HIGH (z5): Add validator with bounds checking
    pub fn add_validator(&mut self, address: Address) -> Result<(), String> {
        if self.validators.len() >= MAX_CHECKPOINT_VALIDATORS {
            return Err(format!("Checkpoint validator limit reached: {}", MAX_CHECKPOINT_VALIDATORS));
        }
        if self.validators.contains(&address) {
            return Err("Validator already in checkpoint".to_string());
        }
        self.validators.push(address);
        Ok(())
    }

    pub fn hash(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&self.epoch.to_le_bytes());
        data.extend_from_slice(&self.slot.to_le_bytes());
        data.extend_from_slice(&self.state_root);
        data.extend_from_slice(&self.dag_root);
        data.extend_from_slice(&self.vertex_count.to_le_bytes());
        data.extend_from_slice(&self.transaction_count.to_le_bytes());
        data.extend_from_slice(&self.previous_checkpoint);
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        hash_data(&data)
    }

    pub fn signing_data(&self) -> Vec<u8> {
        with_domain(DOMAIN_CHECKPOINT, &self.hash())
    }

    pub fn genesis() -> Self {
        Self {
            epoch: 0,
            slot: 0,
            state_root: [0u8; 32],
            dag_root: [0u8; 32],
            vertex_count: 0,
            transaction_count: 0,
            validators: Vec::new(),
            signature: Vec::new(),
            timestamp: 0,
            previous_checkpoint: [0u8; 32],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalityProof {
    pub checkpoint: Checkpoint,
    pub super_committee_signatures: Vec<ValidatorSignature>,
    pub total_stake_signed: u128,
    pub stake_threshold: u128,
}

impl FinalityProof {
    pub fn new(checkpoint: Checkpoint, stake_threshold: u128) -> Self {
        Self {
            checkpoint,
            super_committee_signatures: Vec::new(),
            total_stake_signed: 0,
            stake_threshold,
        }
    }

    /// CRITICAL (z3): Validates signature before adding to finality proof
    pub fn add_signature(&mut self, sig: ValidatorSignature, stake: u128, validator_pubkey: &[u8]) -> Result<(), String> {
        // Bounds check
        if self.super_committee_signatures.len() >= MAX_FINALITY_SIGNATURES {
            return Err(format!("Finality proof signature limit reached: {}", MAX_FINALITY_SIGNATURES));
        }
        
        // Check for duplicate validator
        if self.super_committee_signatures.iter().any(|s| s.validator == sig.validator) {
            return Err("Duplicate validator signature".to_string());
        }
        
        // CRITICAL (z3): Verify the finality signature cryptographically.
        let checkpoint_hash = self.checkpoint.hash();
        match verify_falcon(validator_pubkey, &checkpoint_hash, &sig.signature) {
            Ok(true) => {},
            Ok(false) => return Err("Invalid finality signature: verification failed".to_string()),
            Err(e) => return Err(format!("Signature verification error: {:?}", e)),
        }
        
        self.super_committee_signatures.push(sig);
        self.total_stake_signed = self.total_stake_signed.saturating_add(stake);
        Ok(())
    }

    pub fn is_finalized(&self) -> bool {
        self.total_stake_signed >= self.stake_threshold
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSignature {
    pub validator: Address,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

impl ValidatorSignature {
    pub fn new(validator: Address, signature: Vec<u8>) -> Self {
        Self {
            validator,
            signature,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochInfo {
    pub epoch: u64,
    pub start_slot: u64,
    pub end_slot: u64,
    pub validator_set_hash: Hash,
    pub total_stake: u128,
    pub committees: Vec<CommitteeInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitteeInfo {
    pub committee_id: u16,
    pub shard_id: u16,
    pub validators: Vec<Address>,
    pub total_stake: u128,
}

impl CommitteeInfo {
    pub fn quorum_threshold(&self) -> u128 {
        (self.total_stake * 2) / 3 + 1
    }
}
