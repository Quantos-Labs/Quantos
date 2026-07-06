//! Checkpoint pool for collecting validator signatures on external checkpoints.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use crate::l0::external::ExternalCheckpoint;
use crate::l0::hub::SignatureContribution;
use crate::l0::proof::PqcSignatureAlgo;
use crate::types::Hash;

/// A pending external checkpoint waiting for validator signatures
#[derive(Clone, Debug)]
pub struct PendingCheckpoint {
    /// The external checkpoint data
    pub checkpoint: ExternalCheckpoint,
    /// Digest that validators must sign
    pub digest: Hash,
    /// Collected signatures so far
    pub signatures: Vec<SignatureContribution>,
    /// Total stake that has signed
    pub signed_stake: u128,
    /// When this checkpoint was submitted
    pub submitted_at: Instant,
    /// Whether this checkpoint has been finalized
    pub finalized: bool,
}

/// Pool of pending external checkpoints awaiting validator signatures
pub struct CheckpointPool {
    /// Pending checkpoints indexed by their digest
    pending: Arc<RwLock<HashMap<Hash, PendingCheckpoint>>>,
    /// Maximum time a checkpoint can stay in the pool
    max_age: Duration,
    /// Maximum number of pending checkpoints
    max_pending: usize,
}

impl CheckpointPool {
    pub fn new(max_age_secs: u64, max_pending: usize) -> Self {
        Self {
            pending: Arc::new(RwLock::new(HashMap::new())),
            max_age: Duration::from_secs(max_age_secs),
            max_pending,
        }
    }

    /// Add a new checkpoint to the pool
    pub fn add_checkpoint(&self, checkpoint: ExternalCheckpoint, digest: Hash) -> Result<(), String> {
        let mut pending = self.pending.write();

        // Check if already exists
        if pending.contains_key(&digest) {
            return Err("Checkpoint already in pool".to_string());
        }

        // Check pool size limit
        if pending.len() >= self.max_pending {
            // Remove oldest non-finalized checkpoint
            if let Some(oldest) = pending
                .iter()
                .filter(|(_, p)| !p.finalized)
                .min_by_key(|(_, p)| p.submitted_at)
                .map(|(k, _)| *k)
            {
                pending.remove(&oldest);
            } else {
                return Err("Checkpoint pool is full".to_string());
            }
        }

        pending.insert(
            digest,
            PendingCheckpoint {
                checkpoint,
                digest,
                signatures: Vec::new(),
                signed_stake: 0,
                submitted_at: Instant::now(),
                finalized: false,
            },
        );

        Ok(())
    }

    /// Add a signature to a pending checkpoint
    pub fn add_signature(
        &self,
        digest: &Hash,
        contribution: SignatureContribution,
        stake: u128,
    ) -> Result<u128, String> {
        let mut pending = self.pending.write();

        let checkpoint = pending
            .get_mut(digest)
            .ok_or_else(|| "Checkpoint not found in pool".to_string())?;

        if checkpoint.finalized {
            return Err("Checkpoint already finalized".to_string());
        }

        // Check for duplicate signature
        if checkpoint
            .signatures
            .iter()
            .any(|s| s.validator == contribution.validator)
        {
            return Err("Validator already signed this checkpoint".to_string());
        }

        checkpoint.signatures.push(contribution);
        checkpoint.signed_stake = checkpoint.signed_stake.saturating_add(stake);

        Ok(checkpoint.signed_stake)
    }

    /// Get a pending checkpoint by digest
    pub fn get(&self, digest: &Hash) -> Option<PendingCheckpoint> {
        self.pending.read().get(digest).cloned()
    }

    /// Mark a checkpoint as finalized
    pub fn mark_finalized(&self, digest: &Hash) {
        if let Some(checkpoint) = self.pending.write().get_mut(digest) {
            checkpoint.finalized = true;
        }
    }

    /// Remove a checkpoint from the pool
    pub fn remove(&self, digest: &Hash) -> Option<PendingCheckpoint> {
        self.pending.write().remove(digest)
    }

    /// Clean up old checkpoints
    pub fn cleanup(&self) {
        let now = Instant::now();
        let max_age = self.max_age;

        self.pending.write().retain(|_, checkpoint| {
            // Keep finalized checkpoints for a bit longer
            let age_limit = if checkpoint.finalized {
                max_age * 2
            } else {
                max_age
            };

            now.duration_since(checkpoint.submitted_at) < age_limit
        });
    }

    /// Get all pending checkpoints that need signatures
    pub fn get_pending(&self) -> Vec<(Hash, ExternalCheckpoint)> {
        self.pending
            .read()
            .iter()
            .filter(|(_, p)| !p.finalized)
            .map(|(digest, p)| (*digest, p.checkpoint.clone()))
            .collect()
    }

    /// Get statistics
    pub fn stats(&self) -> CheckpointPoolStats {
        let pending = self.pending.read();
        let total = pending.len();
        let finalized = pending.values().filter(|p| p.finalized).count();
        let awaiting_signatures = total - finalized;

        CheckpointPoolStats {
            total,
            finalized,
            awaiting_signatures,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CheckpointPoolStats {
    pub total: usize,
    pub finalized: usize,
    pub awaiting_signatures: usize,
}
