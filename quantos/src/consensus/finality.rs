use std::sync::Arc;
use dashmap::DashMap;
use parking_lot::RwLock;

use crate::consensus::{ConsensusError, ConsensusResult, CommitteeManager};
use crate::crypto::{verify_falcon, FalconKeypair, merkle_root};
use crate::dag::DAGGraph;
use crate::storage::Storage;
use crate::types::{
    Address, Checkpoint, FinalityProof, Hash, 
    ValidatorSignature,
};

pub struct FinalityLayer {
    storage: Storage,
    dag: Arc<DAGGraph>,
    committee_manager: Arc<CommitteeManager>,
    pending_checkpoints: Arc<DashMap<Hash, PendingCheckpoint>>,
    finalized_checkpoints: Arc<RwLock<Vec<Checkpoint>>>,
    checkpoint_interval: u64,
    last_checkpoint_slot: Arc<RwLock<u64>>,
    /// Number of shards in the system
    num_shards: u16,
}

struct PendingCheckpoint {
    checkpoint: Checkpoint,
    signatures: Vec<ValidatorSignature>,
    total_stake_signed: u128,
}

impl FinalityLayer {
    pub fn new(
        storage: Storage,
        dag: Arc<DAGGraph>,
        committee_manager: Arc<CommitteeManager>,
        checkpoint_interval: u64,
        num_shards: u16,
    ) -> Self {
        Self {
            storage,
            dag,
            committee_manager,
            pending_checkpoints: Arc::new(DashMap::new()),
            finalized_checkpoints: Arc::new(RwLock::new(Vec::new())),
            checkpoint_interval,
            last_checkpoint_slot: Arc::new(RwLock::new(0)),
            num_shards,
        }
    }

    pub async fn maybe_create_checkpoint(&self, current_slot: u64) -> ConsensusResult<Option<Checkpoint>> {
        let last_slot = *self.last_checkpoint_slot.read();
        
        if current_slot - last_slot < self.checkpoint_interval {
            return Ok(None);
        }

        let checkpoint = self.create_checkpoint(current_slot).await?;
        *self.last_checkpoint_slot.write() = current_slot;

        Ok(Some(checkpoint))
    }

    async fn create_checkpoint(&self, slot: u64) -> ConsensusResult<Checkpoint> {
        let epoch = slot / 32;
        
        let previous = self.finalized_checkpoints.read().last()
            .map(|c| c.hash())
            .unwrap_or([0u8; 32]);

        let dag_tips = self.collect_dag_state();
        let dag_root = merkle_root(&dag_tips);

        let state_root = self.storage.get_state_root(slot)
            .map_err(|e| ConsensusError::StorageError(e.to_string()))?
            .unwrap_or([0u8; 32]);

        let vertex_count = self.dag.vertex_count() as u64;
        let transaction_count = self.count_transactions_since_last_checkpoint();

        let checkpoint = Checkpoint::new(
            epoch,
            slot,
            state_root,
            dag_root,
            vertex_count,
            transaction_count,
            previous,
        );

        let checkpoint_hash = checkpoint.hash();
        self.pending_checkpoints.insert(checkpoint_hash, PendingCheckpoint {
            checkpoint: checkpoint.clone(),
            signatures: Vec::new(),
            total_stake_signed: 0,
        });

        Ok(checkpoint)
    }

    /// Collects DAG state from all active shards.
    /// Uses dynamic shard count instead of hardcoded limit.
    fn collect_dag_state(&self) -> Vec<Hash> {
        let mut tips = Vec::new();
        for shard_id in 0..self.num_shards {
            tips.extend(self.dag.get_tips(shard_id));
        }
        tips
    }

    fn count_transactions_since_last_checkpoint(&self) -> u64 {
        0
    }

    /// Signs a checkpoint.
    /// 
    /// CRITICAL: Verifies that the provided key actually belongs to the validator.
    pub async fn sign_checkpoint(
        &self,
        checkpoint_hash: &Hash,
        validator: Address,
        falcon_key: &FalconKeypair,
    ) -> ConsensusResult<ValidatorSignature> {
        let pending = self.pending_checkpoints.get(checkpoint_hash)
            .ok_or(ConsensusError::CheckpointVerificationFailed)?;

        // Verify key ownership: check that the public key matches the validator
        let validator_set = self.committee_manager.get_validator_set();
        let validator_info = validator_set.get_validator(&validator)
            .ok_or_else(|| ConsensusError::InvalidValidator(
                format!("Validator {:?} not found", validator)
            ))?;

        // Verify the public key matches
        if validator_info.public_key != falcon_key.public_key {
            return Err(ConsensusError::Unauthorized(
                format!("Public key mismatch for validator {:?}", validator)
            ));
        }

        let signature = falcon_key.sign(&pending.checkpoint.signing_data())
            .map_err(|e| ConsensusError::CryptoError(e.to_string()))?;

        Ok(ValidatorSignature::new(validator, signature))
    }

    pub async fn receive_checkpoint_signature(
        &self,
        checkpoint_hash: &Hash,
        signature: ValidatorSignature,
        validator_stake: u128,
    ) -> ConsensusResult<bool> {
        let mut finalized = false;

        if let Some(mut pending) = self.pending_checkpoints.get_mut(checkpoint_hash) {
            // Verify the signature against the validator's registered public key
            // This prevents key confusion attacks where signatures don't match registered keys
            let validator_set = self.committee_manager.get_validator_set();
            let validator_info = validator_set.get_validator(&signature.validator)
                .ok_or_else(|| ConsensusError::InvalidValidator(
                    format!("Validator {:?} not found for checkpoint signature", signature.validator)
                ))?;
            
            let checkpoint_data = pending.checkpoint.signing_data();
            let valid = verify_falcon(&validator_info.public_key, &checkpoint_data, &signature.signature)
                .map_err(|e| ConsensusError::CryptoError(e.to_string()))?;
            
            if !valid {
                return Err(ConsensusError::Unauthorized(
                    format!("Invalid checkpoint signature from validator {:?}", signature.validator)
                ));
            }
            
            pending.signatures.push(signature);
            pending.total_stake_signed += validator_stake;

            let total_stake = self.committee_manager.get_validator_set().total_active_stake();
            let threshold = (total_stake * 2) / 3 + 1;

            if pending.total_stake_signed >= threshold {
                finalized = true;
            }
        }

        if finalized {
            self.finalize_checkpoint(checkpoint_hash).await?;
        }

        Ok(finalized)
    }

    async fn finalize_checkpoint(&self, checkpoint_hash: &Hash) -> ConsensusResult<()> {
        if let Some((_, pending)) = self.pending_checkpoints.remove(checkpoint_hash) {
            let mut checkpoint = pending.checkpoint;
            checkpoint.validators = pending.signatures.iter().map(|s| s.validator).collect();
            
            self.storage.put_checkpoint(&checkpoint)
                .map_err(|e| ConsensusError::StorageError(e.to_string()))?;

            self.finalized_checkpoints.write().push(checkpoint.clone());

            self.mark_vertices_finalized(&checkpoint).await?;

            tracing::info!(
                "Checkpoint finalized: epoch={}, slot={}, vertices={}",
                checkpoint.epoch,
                checkpoint.slot,
                checkpoint.vertex_count
            );
        }

        Ok(())
    }

    async fn mark_vertices_finalized(&self, _checkpoint: &Checkpoint) -> ConsensusResult<()> {
        Ok(())
    }

    pub fn get_latest_finalized_checkpoint(&self) -> Option<Checkpoint> {
        self.finalized_checkpoints.read().last().cloned()
    }

    pub fn get_checkpoint(&self, epoch: u64, slot: u64) -> ConsensusResult<Option<Checkpoint>> {
        self.storage.get_checkpoint(epoch, slot)
            .map_err(|e| ConsensusError::StorageError(e.to_string()))
    }

    pub fn create_finality_proof(&self, checkpoint: &Checkpoint) -> ConsensusResult<FinalityProof> {
        let total_stake = self.committee_manager.get_validator_set().total_active_stake();
        let threshold = (total_stake * 2) / 3 + 1;

        let checkpoint_hash = checkpoint.hash();
        let pending = self.pending_checkpoints.get(&checkpoint_hash)
            .ok_or(ConsensusError::CheckpointVerificationFailed)?;

        let mut proof = FinalityProof::new(checkpoint.clone(), threshold);
        
        for sig in &pending.signatures {
            let validator_set = self.committee_manager.get_validator_set();
            let (stake, pubkey) = validator_set
                .get_validator(&sig.validator)
                .map(|v| (v.stake.0, v.public_key.clone()))
                .unwrap_or((0, Vec::new()));
            // CRITICAL (z3): add_signature now verifies the signature cryptographically
            if let Err(e) = proof.add_signature(sig.clone(), stake, &pubkey) {
                tracing::warn!("Skipping invalid finality signature: {}", e);
            }
        }

        Ok(proof)
    }

    pub fn verify_finality_proof(&self, proof: &FinalityProof) -> ConsensusResult<bool> {
        if proof.total_stake_signed < proof.stake_threshold {
            return Ok(false);
        }

        let checkpoint_data = proof.checkpoint.signing_data();
        
        for sig in &proof.super_committee_signatures {
            let validator_set = self.committee_manager.get_validator_set();
            let validator = validator_set.get_validator(&sig.validator);
            
            if let Some(v) = validator {
                let valid = verify_falcon(&v.public_key, &checkpoint_data, &sig.signature)
                    .map_err(|e| ConsensusError::CryptoError(e.to_string()))?;
                
                if !valid {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    pub fn finalized_slot(&self) -> u64 {
        self.finalized_checkpoints.read()
            .last()
            .map(|c| c.slot)
            .unwrap_or(0)
    }

    pub fn finalized_epoch(&self) -> u64 {
        self.finalized_checkpoints.read()
            .last()
            .map(|c| c.epoch)
            .unwrap_or(0)
    }
}
