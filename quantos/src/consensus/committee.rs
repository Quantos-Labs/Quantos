use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::consensus::{ConsensusError, ConsensusResult};
use crate::crypto::{VRFProof, CommitteeRandomnessGenerator, PartialVRFProof};
use crate::types::{
    Address, CommitteeVote, Hash, 
    ShardId, Validator, ValidatorSet,
};
use crate::storage::Storage;

pub struct CommitteeManager {
    storage: Storage,
    current_epoch: Arc<RwLock<u64>>,
    committees: Arc<DashMap<(u64, u16), Committee>>,
    validator_set: Arc<RwLock<ValidatorSet>>,
    num_committees: u16,
    validators_per_committee: usize,
    /// Authorized addresses that can trigger committee rotation
    authorized_rotators: Arc<RwLock<HashSet<Address>>>,
    /// PRODUCTION: Threshold QR-VRF for committee rotation randomness
    threshold_vrf: Arc<RwLock<Option<CommitteeRandomnessGenerator>>>,
    /// Collected partial VRF proofs for current epoch
    partial_proofs: Arc<DashMap<u64, Vec<PartialVRFProof>>>,
    /// CRITICAL (z1): Authorization token for privileged operations
    auth_token: Arc<Mutex<[u8; 32]>>,
}

#[derive(Clone)]
pub struct Committee {
    pub id: u16,
    pub epoch: u64,
    pub shard_id: ShardId,
    pub members: Vec<CommitteeMember>,
    pub total_stake: u128,
}

#[derive(Clone)]
pub struct CommitteeMember {
    pub address: Address,
    pub stake: u128,
    pub vrf_proof: Option<VRFProof>,
    pub active: bool,
}

impl Committee {
    /// Calculates the quorum threshold (2/3 + 1 of total stake).
    /// Uses checked arithmetic to prevent overflow.
    pub fn quorum_threshold(&self) -> Result<u128, ConsensusError> {
        let doubled = self.total_stake.checked_mul(2)
            .ok_or_else(|| ConsensusError::ArithmeticOverflow(
                "Quorum calculation overflow: total_stake too large".to_string()
            ))?;
        
        let threshold = doubled / 3;
        
        threshold.checked_add(1)
            .ok_or_else(|| ConsensusError::ArithmeticOverflow(
                "Quorum threshold overflow".to_string()
            ))
    }

    pub fn has_member(&self, address: &Address) -> bool {
        self.members.iter().any(|m| &m.address == address)
    }

    pub fn get_member(&self, address: &Address) -> Option<&CommitteeMember> {
        self.members.iter().find(|m| &m.address == address)
    }

    pub fn member_count(&self) -> usize {
        self.members.len()
    }
}

impl CommitteeManager {
    pub fn new(
        storage: Storage,
        num_committees: u16,
        validators_per_committee: usize,
    ) -> Self {
        // CRITICAL (z1): Generate auth token with cryptographically secure RNG
        let mut token = [0u8; 32];
        OsRng.fill_bytes(&mut token);
        
        Self {
            storage,
            current_epoch: Arc::new(RwLock::new(0)),
            committees: Arc::new(DashMap::new()),
            validator_set: Arc::new(RwLock::new(ValidatorSet::new())),
            num_committees,
            validators_per_committee,
            authorized_rotators: Arc::new(RwLock::new(HashSet::new())),
            threshold_vrf: Arc::new(RwLock::new(None)),
            partial_proofs: Arc::new(DashMap::new()),
            auth_token: Arc::new(Mutex::new(token)),
        }
    }
    
    /// PRODUCTION: Initializes Threshold QR-VRF with validator public keys
    pub fn initialize_threshold_vrf(&self, validator_pubkeys: Vec<Vec<u8>>) -> Result<(), String> {
        let threshold = (validator_pubkeys.len() * 2 / 3) + 1; // 2/3 + 1
        
        let generator = CommitteeRandomnessGenerator::new(threshold, validator_pubkeys)
            .map_err(|e| format!("Failed to initialize threshold VRF: {}", e))?;
        
        *self.threshold_vrf.write() = Some(generator);
        
        tracing::info!(
            "✅ Threshold QR-VRF initialized: {}/{} threshold",
            threshold,
            threshold * 3 / 2
        );
        
        Ok(())
    }
    
    /// PRODUCTION: Submits partial VRF proof from validator
    pub fn submit_partial_proof(&self, epoch: u64, proof: PartialVRFProof) -> Result<(), String> {
        let mut proofs = self.partial_proofs.entry(epoch).or_insert_with(Vec::new);
        
        // Check for duplicate
        if proofs.iter().any(|p| p.participant_index == proof.participant_index) {
            return Err("Duplicate proof from participant".to_string());
        }
        
        proofs.push(proof);
        
        tracing::debug!(
            "Partial VRF proof collected for epoch {}: {}/threshold",
            epoch,
            proofs.len()
        );
        
        Ok(())
    }
    
    /// PRODUCTION: Generates committee rotation randomness using threshold VRF
    fn generate_rotation_randomness(&self, epoch: u64) -> Result<[u8; 32], String> {
        let mut vrf = self.threshold_vrf.write();
        let generator = vrf.as_mut()
            .ok_or_else(|| "Threshold VRF not initialized".to_string())?;
        
        // Get collected partial proofs
        let proofs = self.partial_proofs.get(&epoch)
            .ok_or_else(|| format!("No proofs collected for epoch {}", epoch))?;
        
        let randomness = generator.generate_epoch_randomness(epoch, proofs.clone())
            .map_err(|e| format!("Failed to generate randomness: {}", e))?;
        
        Ok(randomness)
    }

    /// Adds an authorized address that can trigger committee rotation.
    pub fn add_authorized_rotator(&self, address: Address) {
        self.authorized_rotators.write().insert(address);
    }

    /// Removes an authorized rotator.
    pub fn remove_authorized_rotator(&self, address: &Address) {
        self.authorized_rotators.write().remove(address);
    }

    /// Checks if an address is authorized to rotate committees.
    pub fn is_authorized_rotator(&self, address: &Address) -> bool {
        self.authorized_rotators.read().contains(address)
    }

    /// Rotates committees for a new epoch.
    /// 
    /// CRITICAL: Requires caller authorization to prevent manipulation.
    pub fn rotate_committees(
        &self,
        epoch: u64,
        slot: u64,
        randomness: &Hash,
        caller: &Address,
    ) -> ConsensusResult<()> {
        // Access control: only authorized addresses can rotate committees
        if !self.is_authorized_rotator(caller) {
            return Err(ConsensusError::Unauthorized(
                format!("Address {:?} not authorized to rotate committees", caller)
            ));
        }
        let validator_set = self.validator_set.read();
        let active_validators = validator_set.active_validators();
        
        if active_validators.is_empty() {
            return Ok(());
        }

        for committee_id in 0..self.num_committees {
            let seed = self.compute_committee_seed(epoch, slot, committee_id, randomness);
            let members = self.select_committee_members(&active_validators, &seed, committee_id)?;
            
            let total_stake: u128 = members.iter().map(|m| m.stake).sum();
            
            let committee = Committee {
                id: committee_id,
                epoch,
                shard_id: committee_id,
                members,
                total_stake,
            };

            self.committees.insert((epoch, committee_id), committee);
        }

        *self.current_epoch.write() = epoch;

        Ok(())
    }

    fn compute_committee_seed(&self, epoch: u64, slot: u64, committee_id: u16, randomness: &Hash) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&epoch.to_le_bytes());
        data.extend_from_slice(&slot.to_le_bytes());
        data.extend_from_slice(&committee_id.to_le_bytes());
        data.extend_from_slice(randomness);
        crate::types::hash_data(&data)
    }

    fn select_committee_members(
        &self,
        validators: &[&Validator],
        seed: &Hash,
        _committee_id: u16,
    ) -> ConsensusResult<Vec<CommitteeMember>> {
        let total_stake: u128 = validators.iter().map(|v| v.stake.0).sum();
        if total_stake == 0 {
            return Ok(Vec::new());
        }

        let mut members = Vec::new();
        let mut used_indices = std::collections::HashSet::new();

        for i in 0..self.validators_per_committee {
            let mut selection_seed = {
                let mut data = seed.to_vec();
                data.extend_from_slice(&(i as u64).to_le_bytes());
                crate::types::hash_data(&data)
            };

            // Use rejection sampling to avoid modulo bias
            let selection_value = loop {
                let bytes: [u8; 16] = selection_seed[0..16].try_into()
                    .map_err(|_| ConsensusError::InvalidData("Invalid seed length".to_string()))?;
                let value = u128::from_le_bytes(bytes);
                
                // Rejection sampling: only accept if value is in unbiased range
                let max_unbiased = (u128::MAX / total_stake) * total_stake;
                if value < max_unbiased {
                    break value % total_stake;
                }
                
                // Re-hash for next attempt
                let mut rehash_data = selection_seed.to_vec();
                rehash_data.push(i as u8);
                selection_seed = crate::types::hash_data(&rehash_data);
            };

            let mut cumulative = 0u128;
            for (idx, validator) in validators.iter().enumerate() {
                cumulative += validator.stake.0;
                if selection_value < cumulative && !used_indices.contains(&idx) {
                    used_indices.insert(idx);
                    members.push(CommitteeMember {
                        address: validator.address,
                        stake: validator.stake.0,
                        vrf_proof: None,
                        active: true,
                    });
                    break;
                }
            }

            if members.len() >= self.validators_per_committee {
                break;
            }
        }

        Ok(members)
    }

    pub fn get_committee(&self, epoch: u64, committee_id: u16) -> Option<Committee> {
        self.committees.get(&(epoch, committee_id)).map(|c| c.clone())
    }

    pub fn get_committee_for_shard(&self, epoch: u64, shard_id: ShardId) -> Option<Committee> {
        let committee_id = shard_id % self.num_committees;
        self.get_committee(epoch, committee_id)
    }

    pub fn is_committee_member(&self, epoch: u64, committee_id: u16, address: &Address) -> bool {
        self.get_committee(epoch, committee_id)
            .map(|c| c.has_member(address))
            .unwrap_or(false)
    }

    pub fn verify_committee_vote(
        &self,
        vote: &CommitteeVote,
        epoch: u64,
        committee_id: u16,
    ) -> ConsensusResult<bool> {
        let committee = self.get_committee(epoch, committee_id)
            .ok_or(ConsensusError::NotCommitteeMember)?;

        if !committee.has_member(&vote.validator) {
            return Err(ConsensusError::NotCommitteeMember);
        }

        Ok(true)
    }

    /// CRITICAL (z1): Validates auth_token before adding validator
    pub fn add_validator(&self, validator: Validator, auth_token: &[u8; 32]) -> Result<(), String> {
        // Validate stake bounds before adding
        if validator.stake.0 == 0 {
            return Err("Validator stake must be non-zero".to_string());
        }
        if validator.stake.0 > u128::MAX / 2 {
            return Err(format!("Validator stake {} exceeds safe maximum", validator.stake.0));
        }
        let expected = self.auth_token.lock();
        self.validator_set.write().add_validator(validator, auth_token, &*expected)
    }
    
    /// CRITICAL (z1): Returns the stored auth token for callers that need it
    pub fn get_auth_token(&self) -> [u8; 32] {
        *self.auth_token.lock()
    }

    pub fn remove_validator(&self, address: &Address) {
        let mut set = self.validator_set.write();
        set.validators.retain(|v| &v.address != address);
    }

    pub fn get_validator_set(&self) -> ValidatorSet {
        self.validator_set.read().clone()
    }

    /// Returns the number of registered validators (used for single-node detection).
    pub fn total_validators(&self) -> usize {
        self.validator_set.read().validators.len()
    }

    pub fn current_epoch(&self) -> u64 {
        *self.current_epoch.read()
    }

    pub fn select_super_committee(&self, _epoch: u64, randomness: &Hash) -> ConsensusResult<Vec<Address>> {
        let validator_set = self.validator_set.read();
        let active = validator_set.active_validators();
        
        let total_stake: u128 = active.iter().map(|v| v.stake.0).sum();
        if total_stake == 0 {
            return Ok(Vec::new());
        }
        let mut selected = Vec::new();
        let super_committee_size = 100;

        for i in 0..super_committee_size {
            let seed = {
                let mut data = randomness.to_vec();
                data.extend_from_slice(b"super");
                data.extend_from_slice(&(i as u64).to_le_bytes());
                crate::types::hash_data(&data)
            };

            // Use rejection sampling to avoid modulo bias
            let mut current_seed = seed.clone();
            let selection_value = loop {
                let bytes: [u8; 16] = current_seed[0..16].try_into()
                    .map_err(|_| ConsensusError::InvalidData("Invalid seed length".to_string()))?;
                let value = u128::from_le_bytes(bytes);
                
                // Rejection sampling: only accept if value is in unbiased range
                let max_unbiased = (u128::MAX / total_stake) * total_stake;
                if value < max_unbiased {
                    break value % total_stake;
                }
                
                // Re-hash for next attempt
                let mut rehash_data = current_seed.to_vec();
                rehash_data.extend_from_slice(&(i as u64).to_le_bytes());
                current_seed = crate::types::hash_data(&rehash_data);
            };

            let mut cumulative = 0u128;
            for validator in &active {
                cumulative += validator.stake.0;
                if selection_value < cumulative {
                    if !selected.contains(&validator.address) {
                        selected.push(validator.address);
                    }
                    break;
                }
            }
        }

        Ok(selected)
    }
}

pub struct VRFCommitteeSelection {
    pub epoch: u64,
    pub slot: u64,
    pub validator_proofs: HashMap<Address, VRFProof>,
}

impl VRFCommitteeSelection {
    pub fn new(epoch: u64, slot: u64) -> Self {
        Self {
            epoch,
            slot,
            validator_proofs: HashMap::new(),
        }
    }

    pub fn add_proof(&mut self, address: Address, proof: VRFProof) {
        self.validator_proofs.insert(address, proof);
    }

    pub fn is_selected(&self, address: &Address, threshold: u64) -> bool {
        self.validator_proofs
            .get(address)
            .map(|p| p.is_selected(threshold))
            .unwrap_or(false)
    }
}
