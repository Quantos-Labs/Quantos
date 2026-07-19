use std::collections::HashMap;
use std::sync::Arc;
use dashmap::DashMap;
use parking_lot::RwLock;

use crate::consensus::{ConsensusError, ConsensusResult};
use crate::crypto::VRFProof;
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
        Self {
            storage,
            current_epoch: Arc::new(RwLock::new(0)),
            committees: Arc::new(DashMap::new()),
            validator_set: Arc::new(RwLock::new(ValidatorSet::new())),
            num_committees,
            validators_per_committee,
        }
    }
    
    /// Rotates committees for a new epoch.
    ///
    /// Rotation is protocol-deterministic. There is intentionally no privileged
    /// rotator address because any mutable caller-controlled rotation authority
    /// can bias committee assignment.
    pub fn rotate_committees(
        &self,
        epoch: u64,
        slot: u64,
        randomness: &Hash,
    ) -> ConsensusResult<()> {
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

    pub fn num_committees(&self) -> u16 {
        self.num_committees
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

        let validator_set = self.validator_set.read();
        let validator = validator_set.get_validator(&vote.validator)
            .ok_or_else(|| ConsensusError::InvalidValidator(
                format!("Validator {:?} not found", vote.validator)
            ))?;

        if !validator.active || validator.jailed {
            return Ok(false);
        }

        let valid = verify_ml_dsa_65(
            &validator.public_key,
            &vote.signing_data(),
            &vote.signature,
        ).map_err(|e| ConsensusError::CryptoError(e.to_string()))?;

        Ok(valid)
    }

    pub fn add_validator(&self, validator: Validator) -> Result<(), String> {
        // Validate stake bounds before adding
        if validator.stake.0 == 0 {
            return Err("Validator stake must be non-zero".to_string());
        }
        if validator.stake.0 > u128::MAX / 2 {
            return Err(format!("Validator stake {} exceeds safe maximum", validator.stake.0));
        }
        self.validator_set.write().add_validator(validator)
    }

    pub fn remove_validator(&self, address: &Address) {
        let mut set = self.validator_set.write();
        set.validators.retain(|v| &v.address != address);
    }

    pub fn update_validator_vrf(&self, address: &Address, vrf_public_key: Vec<u8>) {
        let mut set = self.validator_set.write();
        if let Some(v) = set.get_validator_mut(address) {
            v.vrf_public_key = vrf_public_key;
        }
    }

    pub fn update_validator_finality_key(&self, address: &Address, finality_public_key: Vec<u8>) {
        let mut set = self.validator_set.write();
        if let Some(v) = set.get_validator_mut(address) {
            v.finality_public_key = finality_public_key;
        }
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
