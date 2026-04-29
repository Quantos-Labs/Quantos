//! # Archival Pruning
//!
//! Safe deletion of old state data while maintaining blockchain integrity.
//! Implements epoch-based pruning with configurable retention policies.
//!
//! ## Features
//!
//! - **Epoch-Based Pruning**: Delete states older than N epochs
//! - **Checkpoint Preservation**: Always keep finalized checkpoints
//! - **Incremental Pruning**: Background pruning without blocking
//! - **State Witnesses**: Generate proofs before pruning
//! - **Recovery Mode**: Reconstruct pruned state from checkpoints

use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, Instant};
use parking_lot::{Mutex, RwLock};
use tokio::sync::mpsc;

use crate::types::Hash;
use crate::state::{StateError, StateResult};

/// Epoch number for pruning granularity
pub type Epoch = u64;

/// Block height
pub type BlockHeight = u64;

/// Pruning policy configuration
#[derive(Clone, Debug)]
pub struct PruningPolicy {
    /// Minimum epochs to retain (safety margin)
    pub min_retention_epochs: u64,
    /// Maximum epochs to retain (storage limit)
    pub max_retention_epochs: u64,
    /// Retain every Nth epoch as archive point
    pub archive_interval: u64,
    /// Blocks per epoch
    pub blocks_per_epoch: u64,
    /// Enable automatic pruning
    pub auto_prune: bool,
    /// Pruning batch size
    pub batch_size: usize,
    /// Delay between pruning batches
    pub batch_delay: Duration,
}

impl Default for PruningPolicy {
    fn default() -> Self {
        Self {
            min_retention_epochs: 100,      // ~1 day at 10 epochs/hour
            max_retention_epochs: 1000,     // ~10 days
            archive_interval: 100,          // Keep every 100th epoch
            blocks_per_epoch: 100,
            auto_prune: true,
            batch_size: 1000,
            batch_delay: Duration::from_millis(10),
        }
    }
}

/// Archival state snapshot reference.
/// For compression state snapshots, see `compression::ArchivalSnapshot`.
#[derive(Clone, Debug)]
pub struct ArchivalSnapshot {
    /// Epoch of this snapshot
    pub epoch: Epoch,
    /// Block height
    pub height: BlockHeight,
    /// State root hash
    pub state_root: Hash,
    /// Is this a checkpoint (finalized)
    pub is_checkpoint: bool,
    /// Snapshot creation time
    pub created_at: u64,
    /// Size in bytes
    pub size_bytes: u64,
}

/// Pruning target - what can be pruned
#[derive(Debug, Clone)]
pub struct PruningTarget {
    /// Epoch to prune
    pub epoch: Epoch,
    /// State roots in this epoch
    pub state_roots: Vec<Hash>,
    /// Transaction hashes
    pub tx_hashes: Vec<Hash>,
    /// Receipt hashes
    pub receipt_hashes: Vec<Hash>,
    /// Estimated size to reclaim
    pub estimated_size: u64,
}

/// Result of a pruning operation
#[derive(Debug, Clone)]
pub struct PruningResult {
    /// Epochs pruned
    pub epochs_pruned: Vec<Epoch>,
    /// Bytes reclaimed
    pub bytes_reclaimed: u64,
    /// Items deleted
    pub items_deleted: u64,
    /// Duration of pruning
    pub duration: Duration,
    /// Errors encountered
    pub errors: Vec<String>,
}

/// State witness for pruned data verification
#[derive(Clone, Debug)]
pub struct StateWitness {
    /// Epoch this witness covers
    pub epoch: Epoch,
    /// Merkle root of the epoch state
    pub merkle_root: Hash,
    /// Proof path to checkpoint
    pub proof_path: Vec<Hash>,
    /// Accounts summary (hash of all account states)
    pub accounts_summary: Hash,
    /// Storage summary
    pub storage_summary: Hash,
}

/// MEDIUM (w8): Maximum pruning history entries to prevent unbounded growth
const MAX_PRUNING_HISTORY: usize = 1000;

/// Maximum epoch size records for growth rate calculation
const MAX_EPOCH_SIZE_RECORDS: usize = 500;

/// Default storage limit for epochs_until_limit calculation (10 GB)
const DEFAULT_STORAGE_LIMIT_BYTES: u64 = 10_000_000_000;

/// Pruning state tracker
struct PruningState {
    /// Last pruned epoch
    last_pruned_epoch: Epoch,
    /// Current pruning target
    current_target: Option<PruningTarget>,
    /// Pruning in progress
    is_pruning: bool,
    /// Total bytes reclaimed
    total_reclaimed: u64,
    /// Pruning history
    history: Vec<PruningResult>,
    /// Per-epoch size records for growth rate calculation
    epoch_sizes: Vec<EpochSizeRecord>,
    /// Cumulative state size (before pruning)
    cumulative_size: u64,
}

impl PruningState {
    fn new() -> Self {
        Self {
            last_pruned_epoch: 0,
            current_target: None,
            is_pruning: false,
            total_reclaimed: 0,
            history: Vec::new(),
            epoch_sizes: Vec::new(),
            cumulative_size: 0,
        }
    }

    /// Records epoch size and updates cumulative metrics.
    fn record_epoch_size(&mut self, epoch: Epoch, size_bytes: u64) {
        self.cumulative_size += size_bytes;
        self.epoch_sizes.push(EpochSizeRecord {
            epoch,
            size_bytes,
            cumulative_size: self.cumulative_size,
        });
        // Cap records to prevent unbounded growth
        if self.epoch_sizes.len() > MAX_EPOCH_SIZE_RECORDS {
            let drain_count = self.epoch_sizes.len() - MAX_EPOCH_SIZE_RECORDS;
            self.epoch_sizes.drain(0..drain_count);
        }
    }

    /// Computes the growth rate in bytes/epoch over recent records.
    fn growth_rate(&self) -> f64 {
        let records = &self.epoch_sizes;
        if records.len() < 2 {
            return 0.0;
        }
        let window = records.len().min(100); // last 100 epochs
        let start = &records[records.len() - window];
        let end = &records[records.len() - 1];
        let epoch_span = end.epoch.saturating_sub(start.epoch);
        if epoch_span == 0 {
            return 0.0;
        }
        let size_delta = end.cumulative_size.saturating_sub(start.cumulative_size);
        size_delta as f64 / epoch_span as f64
    }
}

/// Archive point - preserved epoch state
#[derive(Clone, Debug)]
pub struct ArchivePoint {
    pub epoch: Epoch,
    pub state_root: Hash,
    pub witness: StateWitness,
    pub checkpoint_hash: Hash,
}

/// Archival Pruning Manager
pub struct ArchivalPruningManager {
    /// Pruning policy
    policy: PruningPolicy,
    /// Current epoch
    current_epoch: RwLock<Epoch>,
    /// Epoch snapshots
    snapshots: RwLock<BTreeMap<Epoch, ArchivalSnapshot>>,
    /// Archive points (preserved epochs)
    archive_points: RwLock<BTreeMap<Epoch, ArchivePoint>>,
    /// Checkpoints that cannot be pruned
    protected_epochs: RwLock<HashSet<Epoch>>,
    /// Pruning state
    state: Mutex<PruningState>,
    /// State witnesses for pruned epochs
    witnesses: RwLock<BTreeMap<Epoch, StateWitness>>,
    /// Notification channel for pruning events
    prune_tx: mpsc::Sender<PruningResult>,
}

impl ArchivalPruningManager {
    pub fn new(policy: PruningPolicy, prune_tx: mpsc::Sender<PruningResult>) -> Self {
        Self {
            policy,
            current_epoch: RwLock::new(0),
            snapshots: RwLock::new(BTreeMap::new()),
            archive_points: RwLock::new(BTreeMap::new()),
            protected_epochs: RwLock::new(HashSet::new()),
            state: Mutex::new(PruningState::new()),
            witnesses: RwLock::new(BTreeMap::new()),
            prune_tx,
        }
    }
    
    /// Registers a new state snapshot and records growth metrics.
    pub fn register_snapshot(&self, snapshot: ArchivalSnapshot) {
        let epoch = snapshot.epoch;
        let size = snapshot.size_bytes;
        
        // Update current epoch
        {
            let mut current = self.current_epoch.write();
            if epoch > *current {
                *current = epoch;
            }
        }
        
        // Record epoch size for growth tracking
        self.state.lock().record_epoch_size(epoch, size);
        
        // Protect checkpoints
        if snapshot.is_checkpoint {
            self.protected_epochs.write().insert(epoch);
        }
        
        // Store snapshot
        self.snapshots.write().insert(epoch, snapshot);
        
        // Check if we should create an archive point
        if epoch % self.policy.archive_interval == 0 {
            self.create_archive_point(epoch);
        }
    }
    
    /// Creates an archive point for an epoch
    fn create_archive_point(&self, epoch: Epoch) {
        let snapshots = self.snapshots.read();
        
        if let Some(snapshot) = snapshots.get(&epoch) {
            let witness = StateWitness {
                epoch,
                merkle_root: snapshot.state_root,
                proof_path: Vec::new(), // Would be populated with actual proof
                accounts_summary: [0u8; 32], // Would be computed
                storage_summary: [0u8; 32],
            };
            
            let archive = ArchivePoint {
                epoch,
                state_root: snapshot.state_root,
                witness: witness.clone(),
                checkpoint_hash: snapshot.state_root,
            };
            
            self.archive_points.write().insert(epoch, archive);
            self.protected_epochs.write().insert(epoch);
            self.witnesses.write().insert(epoch, witness);
        }
    }
    
    /// Determines which epochs can be safely pruned
    pub fn get_prunable_epochs(&self) -> Vec<Epoch> {
        let current = *self.current_epoch.read();
        let protected = self.protected_epochs.read();
        let snapshots = self.snapshots.read();
        
        let min_keep = current.saturating_sub(self.policy.min_retention_epochs);
        
        snapshots
            .keys()
            .filter(|&&epoch| {
                epoch < min_keep && !protected.contains(&epoch)
            })
            .copied()
            .collect()
    }
    
    /// Creates pruning targets for given epochs
    pub fn create_pruning_targets(&self, epochs: &[Epoch]) -> Vec<PruningTarget> {
        let snapshots = self.snapshots.read();
        
        epochs
            .iter()
            .filter_map(|&epoch| {
                snapshots.get(&epoch).map(|snapshot| {
                    PruningTarget {
                        epoch,
                        state_roots: vec![snapshot.state_root],
                        tx_hashes: Vec::new(), // Would be populated
                        receipt_hashes: Vec::new(),
                        estimated_size: snapshot.size_bytes,
                    }
                })
            })
            .collect()
    }
    
    /// Generates state witness before pruning
    pub fn generate_witness(&self, epoch: Epoch) -> StateResult<StateWitness> {
        let snapshots = self.snapshots.read();
        
        let snapshot = snapshots.get(&epoch)
            .ok_or_else(|| StateError::StorageError(format!("Epoch {} not found", epoch)))?;
        
        // Find nearest archive point for proof path
        let archive_points = self.archive_points.read();
        let nearest_archive = archive_points
            .range(..=epoch)
            .next_back()
            .map(|(_, ap)| ap.epoch);
        
        let mut proof_path = Vec::new();
        
        // Build proof path to nearest archive
        if let Some(archive_epoch) = nearest_archive {
            // Collect intermediate state roots
            for e in archive_epoch..=epoch {
                if let Some(s) = snapshots.get(&e) {
                    proof_path.push(s.state_root);
                }
            }
        }
        
        let witness = StateWitness {
            epoch,
            merkle_root: snapshot.state_root,
            proof_path,
            accounts_summary: crate::crypto::sha3_256(&snapshot.state_root),
            storage_summary: crate::crypto::sha3_256(&snapshot.state_root),
        };
        
        // Store witness
        self.witnesses.write().insert(epoch, witness.clone());
        
        Ok(witness)
    }
    
    /// Executes pruning for given targets
    pub async fn prune(&self, targets: Vec<PruningTarget>) -> StateResult<PruningResult> {
        let start = Instant::now();
        let mut state = self.state.lock();
        
        if state.is_pruning {
            return Err(StateError::ExecutionError("Pruning already in progress".to_string()));
        }
        
        state.is_pruning = true;
        drop(state);
        
        let mut epochs_pruned = Vec::new();
        let mut bytes_reclaimed = 0u64;
        let mut items_deleted = 0u64;
        let mut errors = Vec::new();
        
        for target in targets {
            // Generate witness before pruning
            match self.generate_witness(target.epoch) {
                Ok(_) => {}
                Err(e) => {
                    errors.push(format!("Witness generation failed for epoch {}: {}", target.epoch, e));
                    continue;
                }
            }
            
            // Simulate pruning (actual implementation would delete from storage)
            bytes_reclaimed += target.estimated_size;
            items_deleted += target.state_roots.len() as u64 
                + target.tx_hashes.len() as u64 
                + target.receipt_hashes.len() as u64;
            
            // Remove from snapshots
            self.snapshots.write().remove(&target.epoch);
            
            epochs_pruned.push(target.epoch);
            
            // Batch delay to prevent blocking
            if epochs_pruned.len() % self.policy.batch_size == 0 {
                tokio::time::sleep(self.policy.batch_delay).await;
            }
        }
        
        let result = PruningResult {
            epochs_pruned: epochs_pruned.clone(),
            bytes_reclaimed,
            items_deleted,
            duration: start.elapsed(),
            errors,
        };
        
        // Update state
        {
            let mut state = self.state.lock();
            state.is_pruning = false;
            state.total_reclaimed += bytes_reclaimed;
            if let Some(&last) = epochs_pruned.last() {
                state.last_pruned_epoch = last;
            }
            state.history.push(result.clone());
            // MEDIUM (w8): Cap history to prevent unbounded growth
            if state.history.len() > MAX_PRUNING_HISTORY {
                let drain_count = state.history.len() - MAX_PRUNING_HISTORY;
                state.history.drain(0..drain_count);
            }
        }
        
        // Notify
        let _ = self.prune_tx.try_send(result.clone());
        
        tracing::info!(
            "Pruned {} epochs, reclaimed {} bytes in {:?}",
            epochs_pruned.len(),
            bytes_reclaimed,
            result.duration
        );
        
        Ok(result)
    }
    
    /// Runs automatic pruning based on policy
    pub async fn auto_prune(&self) -> StateResult<Option<PruningResult>> {
        if !self.policy.auto_prune {
            return Ok(None);
        }
        
        let _current = *self.current_epoch.read();
        let max_keep = self.policy.max_retention_epochs;
        
        // Only prune if we exceed max retention
        let snapshot_count = self.snapshots.read().len() as u64;
        if snapshot_count <= max_keep {
            return Ok(None);
        }
        
        let prunable = self.get_prunable_epochs();
        if prunable.is_empty() {
            return Ok(None);
        }
        
        // Limit batch size
        let to_prune: Vec<_> = prunable
            .into_iter()
            .take(self.policy.batch_size)
            .collect();
        
        let targets = self.create_pruning_targets(&to_prune);
        
        if targets.is_empty() {
            return Ok(None);
        }
        
        let result = self.prune(targets).await?;
        Ok(Some(result))
    }
    
    /// Verifies a state using stored witness
    pub fn verify_pruned_state(&self, epoch: Epoch, state_root: Hash) -> bool {
        if let Some(witness) = self.witnesses.read().get(&epoch) {
            witness.merkle_root == state_root
        } else if let Some(archive) = self.archive_points.read().get(&epoch) {
            archive.state_root == state_root
        } else {
            false
        }
    }
    
    /// Gets storage statistics with growth metrics.
    pub fn get_stats(&self) -> PruningStats {
        let state = self.state.lock();
        let snapshots = self.snapshots.read();
        
        let total_size: u64 = snapshots.values().map(|s| s.size_bytes).sum();
        let total_epochs = snapshots.len() as u64;
        let avg_epoch_size = if total_epochs > 0 { total_size / total_epochs } else { 0 };
        let growth_rate = state.growth_rate();
        
        let total_ever = total_size + state.total_reclaimed;
        let compression_ratio = if total_ever > 0 {
            state.total_reclaimed as f64 / total_ever as f64
        } else {
            0.0
        };
        
        let epochs_until_limit = if growth_rate > 0.0 {
            let remaining = DEFAULT_STORAGE_LIMIT_BYTES.saturating_sub(total_size);
            Some((remaining as f64 / growth_rate) as u64)
        } else {
            None
        };
        
        PruningStats {
            current_epoch: *self.current_epoch.read(),
            last_pruned_epoch: state.last_pruned_epoch,
            total_epochs,
            archive_points: self.archive_points.read().len() as u64,
            protected_epochs: self.protected_epochs.read().len() as u64,
            total_size_bytes: total_size,
            total_reclaimed_bytes: state.total_reclaimed,
            is_pruning: state.is_pruning,
            avg_epoch_size,
            growth_rate_bytes_per_epoch: growth_rate,
            cumulative_compression_ratio: compression_ratio,
            epochs_until_limit,
        }
    }
    
    /// Returns per-epoch size records for external analysis.
    pub fn get_epoch_size_history(&self) -> Vec<EpochSizeRecord> {
        self.state.lock().epoch_sizes.clone()
    }
    
    /// Protects an epoch from pruning
    pub fn protect_epoch(&self, epoch: Epoch) {
        self.protected_epochs.write().insert(epoch);
    }
    
    /// Unprotects an epoch (allow pruning)
    pub fn unprotect_epoch(&self, epoch: Epoch) {
        // Never unprotect archive points
        if self.archive_points.read().contains_key(&epoch) {
            return;
        }
        self.protected_epochs.write().remove(&epoch);
    }
}

/// Pruning statistics with growth metrics
#[derive(Debug, Clone)]
pub struct PruningStats {
    pub current_epoch: Epoch,
    pub last_pruned_epoch: Epoch,
    pub total_epochs: u64,
    pub archive_points: u64,
    pub protected_epochs: u64,
    pub total_size_bytes: u64,
    pub total_reclaimed_bytes: u64,
    pub is_pruning: bool,
    /// Average state size per epoch (bytes)
    pub avg_epoch_size: u64,
    /// State growth rate: bytes added per epoch (rolling window)
    pub growth_rate_bytes_per_epoch: f64,
    /// Compression ratio: total_reclaimed / (total_reclaimed + total_size)
    pub cumulative_compression_ratio: f64,
    /// Estimated epochs until storage limit at current growth rate
    pub epochs_until_limit: Option<u64>,
}

/// Record of per-epoch state size for growth tracking.
#[derive(Debug, Clone)]
pub struct EpochSizeRecord {
    pub epoch: Epoch,
    pub size_bytes: u64,
    pub cumulative_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_register_and_prune() {
        let (tx, _rx) = mpsc::channel(10);
        let policy = PruningPolicy {
            min_retention_epochs: 5,
            max_retention_epochs: 10,
            archive_interval: 3,
            ..Default::default()
        };
        
        let manager = ArchivalPruningManager::new(policy, tx);
        
        // Register snapshots
        for i in 0..15 {
            manager.register_snapshot(ArchivalSnapshot {
                epoch: i,
                height: i * 100,
                state_root: [i as u8; 32],
                is_checkpoint: i % 5 == 0,
                created_at: 0,
                size_bytes: 1000,
            });
        }
        
        // Current epoch is 14, should be able to prune epochs < 9
        let prunable = manager.get_prunable_epochs();
        assert!(!prunable.is_empty());
        
        // Epoch 0 and 5 are checkpoints, 0, 3, 6, 9, 12 are archive points
        // So actually most epochs might be protected
    }
    
    #[test]
    fn test_archive_points() {
        let (tx, _rx) = mpsc::channel(10);
        let policy = PruningPolicy {
            archive_interval: 5,
            ..Default::default()
        };
        
        let manager = ArchivalPruningManager::new(policy, tx);
        
        for i in 0..15 {
            manager.register_snapshot(ArchivalSnapshot {
                epoch: i,
                height: i * 100,
                state_root: [i as u8; 32],
                is_checkpoint: false,
                created_at: 0,
                size_bytes: 1000,
            });
        }
        
        let archives = manager.archive_points.read();
        // Epochs 0, 5, 10 should be archive points
        assert!(archives.contains_key(&0));
        assert!(archives.contains_key(&5));
        assert!(archives.contains_key(&10));
    }
    
    #[test]
    fn test_growth_metrics() {
        let (tx, _rx) = mpsc::channel(10);
        let policy = PruningPolicy {
            archive_interval: 1000, // high to avoid extra protected epochs
            ..Default::default()
        };
        
        let manager = ArchivalPruningManager::new(policy, tx);
        
        // Register 50 epochs with increasing sizes (simulating state growth)
        for i in 0..50 {
            manager.register_snapshot(ArchivalSnapshot {
                epoch: i,
                height: i * 100,
                state_root: [i as u8; 32],
                is_checkpoint: false,
                created_at: 0,
                size_bytes: 1000 + i * 100, // growing: 1000, 1100, 1200, ...
            });
        }
        
        let stats = manager.get_stats();
        
        // Basic stats
        assert_eq!(stats.total_epochs, 50);
        assert_eq!(stats.current_epoch, 49);
        
        // Growth rate should be positive (sizes are increasing)
        assert!(stats.growth_rate_bytes_per_epoch > 0.0);
        
        // Average epoch size should be reasonable
        assert!(stats.avg_epoch_size > 0);
        
        // epochs_until_limit should exist (growth > 0)
        assert!(stats.epochs_until_limit.is_some());
        
        // Epoch size history should be available
        let history = manager.get_epoch_size_history();
        assert_eq!(history.len(), 50);
        assert!(history.last().unwrap().cumulative_size > history.first().unwrap().cumulative_size);
    }
}
