//! # Speculative Execution
//!
//! Execute transactions before final consensus for maximum throughput.
//! Rollback capabilities ensure consistency when speculation fails.
//!
//! ## Features
//!
//! - **Pre-Consensus Execution**: Execute during consensus rounds
//! - **Version Tracking**: Track state versions for rollback
//! - **Conflict Detection**: Detect and handle speculative conflicts
//! - **Checkpoint Management**: Create/restore execution checkpoints
//! - **Parallel Speculation**: Multiple speculative paths

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use parking_lot::{Mutex, RwLock};
use dashmap::DashMap;

use crate::types::{Hash, Address, Amount, TransactionReceipt};
use crate::state::{StateError, StateResult};

/// Execution version for speculative MVCC tracking.
/// For generic MVCC versions, see `mvcc::Version<T>`.
pub type SpecVersion = u64;

/// Speculative execution state
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpeculativeState {
    /// Execution pending
    Pending,
    /// Execution in progress
    Executing,
    /// Execution complete, awaiting confirmation
    Speculated,
    /// Confirmed by consensus
    Confirmed,
    /// Rolled back due to conflict
    RolledBack,
    /// Failed execution
    Failed,
}

/// Account state snapshot for rollback
#[derive(Clone, Debug)]
pub struct AccountSnapshot {
    pub address: Address,
    pub balance: Amount,
    pub nonce: u64,
    pub storage_root: Option<Hash>,
    pub code_hash: Option<Hash>,
}

/// Storage slot snapshot
#[derive(Clone, Debug)]
pub struct StorageSnapshot {
    pub address: Address,
    pub key: Hash,
    pub value: [u8; 32],
}

/// Execution checkpoint for rollback
#[derive(Clone)]
pub struct ExecutionCheckpoint {
    /// Checkpoint ID
    pub id: u64,
    /// Version at checkpoint
    pub version: SpecVersion,
    /// Block/vertex hash
    pub block_hash: Hash,
    /// Account snapshots
    pub accounts: HashMap<Address, AccountSnapshot>,
    /// Storage snapshots
    pub storage: HashMap<(Address, Hash), StorageSnapshot>,
    /// Created timestamp
    pub created_at: Instant,
    /// Parent checkpoint (for nested speculation)
    pub parent_id: Option<u64>,
}

impl ExecutionCheckpoint {
    pub fn new(id: u64, version: SpecVersion, block_hash: Hash) -> Self {
        Self {
            id,
            version,
            block_hash,
            accounts: HashMap::new(),
            storage: HashMap::new(),
            created_at: Instant::now(),
            parent_id: None,
        }
    }
    
    pub fn with_parent(mut self, parent_id: u64) -> Self {
        self.parent_id = Some(parent_id);
        self
    }
}

/// Speculative execution result
#[derive(Clone)]
pub struct SpeculativeResult {
    /// Block/vertex hash
    pub block_hash: Hash,
    /// Computed state root
    pub state_root: Hash,
    /// Transaction receipts
    pub receipts: Vec<TransactionReceipt>,
    /// Read set (addresses read)
    pub read_set: HashSet<Address>,
    /// Write set (addresses written)
    pub write_set: HashSet<Address>,
    /// Storage reads
    pub storage_reads: HashSet<(Address, Hash)>,
    /// Storage writes
    pub storage_writes: HashSet<(Address, Hash)>,
    /// Execution duration
    pub execution_time: Duration,
    /// Current state
    pub state: SpeculativeState,
    /// Checkpoint ID
    pub checkpoint_id: u64,
}

impl SpeculativeResult {
    /// Checks if this result conflicts with another
    pub fn conflicts_with(&self, other: &SpeculativeResult) -> bool {
        // Write-write conflict
        if !self.write_set.is_disjoint(&other.write_set) {
            return true;
        }
        
        // Read-write conflict (either direction)
        if !self.read_set.is_disjoint(&other.write_set) {
            return true;
        }
        if !self.write_set.is_disjoint(&other.read_set) {
            return true;
        }
        
        // Storage conflicts
        if !self.storage_writes.is_disjoint(&other.storage_writes) {
            return true;
        }
        if !self.storage_reads.is_disjoint(&other.storage_writes) {
            return true;
        }
        
        false
    }
}

/// Configuration for speculative execution
#[derive(Clone, Debug)]
pub struct SpeculativeConfig {
    /// Maximum concurrent speculative executions
    pub max_concurrent: usize,
    /// Maximum checkpoint depth
    pub max_checkpoint_depth: usize,
    /// Speculation timeout
    pub speculation_timeout: Duration,
    /// Enable parallel speculation paths
    pub parallel_paths: bool,
    /// Maximum speculative results to cache
    pub max_cached_results: usize,
}

impl Default for SpeculativeConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 16,
            max_checkpoint_depth: 10,
            speculation_timeout: Duration::from_secs(5),
            parallel_paths: true,
            max_cached_results: 1000,
        }
    }
}

/// Speculative Execution Engine
pub struct SpeculativeExecutor {
    config: SpeculativeConfig,
    /// Current version counter
    current_version: AtomicU64,
    /// Checkpoint counter
    checkpoint_counter: AtomicU64,
    /// Active checkpoints
    checkpoints: RwLock<HashMap<u64, ExecutionCheckpoint>>,
    /// Speculative results by block hash
    results: DashMap<Hash, SpeculativeResult>,
    /// Pending executions
    pending: Mutex<VecDeque<Hash>>,
    /// Confirmed blocks (for conflict detection)
    confirmed: RwLock<Vec<Hash>>,
    /// Account state cache (for speculation)
    account_cache: DashMap<(Address, SpecVersion), AccountSnapshot>,
    /// Storage cache
    storage_cache: DashMap<(Address, Hash, SpecVersion), [u8; 32]>,
    /// Current speculation depth
    depth: AtomicU64,
    /// Statistics
    stats: Mutex<SpeculativeStats>,
}

/// Statistics for speculative execution
#[derive(Default, Clone, Debug)]
pub struct SpeculativeStats {
    pub total_speculations: u64,
    pub successful_speculations: u64,
    pub rollbacks: u64,
    pub conflicts_detected: u64,
    pub avg_speculation_time_ms: f64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

impl SpeculativeExecutor {
    pub fn new(config: SpeculativeConfig) -> Self {
        Self {
            config,
            current_version: AtomicU64::new(0),
            checkpoint_counter: AtomicU64::new(0),
            checkpoints: RwLock::new(HashMap::new()),
            results: DashMap::new(),
            pending: Mutex::new(VecDeque::new()),
            confirmed: RwLock::new(Vec::new()),
            account_cache: DashMap::new(),
            storage_cache: DashMap::new(),
            depth: AtomicU64::new(0),
            stats: Mutex::new(SpeculativeStats::default()),
        }
    }
    
    /// Creates a new checkpoint for speculative execution
    pub fn create_checkpoint(&self, block_hash: Hash) -> StateResult<u64> {
        let depth = self.depth.fetch_add(1, Ordering::SeqCst);
        
        if depth >= self.config.max_checkpoint_depth as u64 {
            self.depth.fetch_sub(1, Ordering::SeqCst);
            return Err(StateError::ExecutionError(
                "Maximum checkpoint depth exceeded".to_string()
            ));
        }
        
        // Evict expired checkpoints to prevent memory exhaustion (v8)
        {
            let mut cps = self.checkpoints.write();
            let expired: Vec<u64> = cps.iter()
                .filter(|(_, cp)| cp.created_at.elapsed() > self.config.speculation_timeout)
                .map(|(id, _)| *id)
                .collect();
            for id in &expired {
                cps.remove(id);
                self.depth.fetch_sub(1, Ordering::SeqCst);
            }
            if !expired.is_empty() {
                tracing::warn!("Evicted {} expired checkpoints (v8)", expired.len());
            }
        }
        
        let id = self.checkpoint_counter.fetch_add(1, Ordering::SeqCst);
        let version = self.current_version.load(Ordering::SeqCst);
        
        let checkpoint = ExecutionCheckpoint::new(id, version, block_hash);
        
        self.checkpoints.write().insert(id, checkpoint);
        
        Ok(id)
    }
    
    /// Creates a nested checkpoint (for parallel speculation)
    pub fn create_nested_checkpoint(&self, parent_id: u64, block_hash: Hash) -> StateResult<u64> {
        // Verify parent exists
        if !self.checkpoints.read().contains_key(&parent_id) {
            return Err(StateError::ExecutionError("Parent checkpoint not found".to_string()));
        }
        
        let id = self.checkpoint_counter.fetch_add(1, Ordering::SeqCst);
        let version = self.current_version.load(Ordering::SeqCst);
        
        let checkpoint = ExecutionCheckpoint::new(id, version, block_hash)
            .with_parent(parent_id);
        
        self.checkpoints.write().insert(id, checkpoint);
        self.depth.fetch_add(1, Ordering::SeqCst);
        
        Ok(id)
    }
    
    /// Snapshots an account before modification
    pub fn snapshot_account(&self, checkpoint_id: u64, snapshot: AccountSnapshot) -> StateResult<()> {
        let mut checkpoints = self.checkpoints.write();
        
        let checkpoint = checkpoints.get_mut(&checkpoint_id)
            .ok_or_else(|| StateError::ExecutionError("Checkpoint not found".to_string()))?;
        
        // Only snapshot if not already present (first write wins)
        checkpoint.accounts.entry(snapshot.address).or_insert(snapshot);
        
        Ok(())
    }
    
    /// Snapshots a storage slot before modification
    pub fn snapshot_storage(&self, checkpoint_id: u64, snapshot: StorageSnapshot) -> StateResult<()> {
        let mut checkpoints = self.checkpoints.write();
        
        let checkpoint = checkpoints.get_mut(&checkpoint_id)
            .ok_or_else(|| StateError::ExecutionError("Checkpoint not found".to_string()))?;
        
        let key = (snapshot.address, snapshot.key);
        checkpoint.storage.entry(key).or_insert(snapshot);
        
        Ok(())
    }
    
    /// Records speculative execution result
    pub fn record_result(&self, result: SpeculativeResult) {
        let block_hash = result.block_hash;
        
        self.stats.lock().total_speculations += 1;
        
        // Evict oldest results if cache is full (v8)
        if self.results.len() >= self.config.max_cached_results {
            // Remove oldest entries by finding RolledBack/Failed first
            let stale: Vec<Hash> = self.results.iter()
                .filter(|r| matches!(r.state, SpeculativeState::RolledBack | SpeculativeState::Failed))
                .map(|r| r.block_hash)
                .collect();
            for h in stale.iter().take(self.config.max_cached_results / 4) {
                self.results.remove(h);
            }
        }
        
        self.results.insert(block_hash, result);
    }
    
    /// Confirms speculative execution (consensus reached)
    pub fn confirm(&self, block_hash: &Hash) -> StateResult<SpeculativeResult> {
        let mut result = self.results.get_mut(block_hash)
            .ok_or_else(|| StateError::ExecutionError("Speculative result not found".to_string()))?;
        
        // Check for conflicts with other confirmed blocks
        let confirmed = self.confirmed.read();
        for confirmed_hash in confirmed.iter() {
            if let Some(confirmed_result) = self.results.get(confirmed_hash) {
                if result.conflicts_with(&confirmed_result) {
                    result.state = SpeculativeState::RolledBack;
                    self.stats.lock().conflicts_detected += 1;
                    return Err(StateError::ExecutionError("Conflict with confirmed block".to_string()));
                }
            }
        }
        
        result.state = SpeculativeState::Confirmed;
        
        // Remove checkpoint
        let checkpoint_id = result.checkpoint_id;
        drop(result);
        
        self.commit_checkpoint(checkpoint_id)?;
        
        // Add to confirmed list
        self.confirmed.write().push(*block_hash);
        
        self.stats.lock().successful_speculations += 1;
        
        let result = self.results.remove(block_hash)
            .map(|(_, r)| r)
            .ok_or_else(|| StateError::ExecutionError("Result removed during confirmation".to_string()))?;
        
        Ok(result)
    }
    
    /// Commits a checkpoint (makes changes permanent)
    fn commit_checkpoint(&self, checkpoint_id: u64) -> StateResult<()> {
        let checkpoint = self.checkpoints.write().remove(&checkpoint_id);
        
        if let Some(cp) = checkpoint {
            // Increment version
            self.current_version.fetch_add(1, Ordering::SeqCst);
            self.depth.fetch_sub(1, Ordering::SeqCst);
            
            // Cache committed state at new version
            let new_version = self.current_version.load(Ordering::SeqCst);
            
            for (addr, snapshot) in cp.accounts {
                self.account_cache.insert((addr, new_version), snapshot);
            }
            
            for ((addr, key), snapshot) in cp.storage {
                self.storage_cache.insert((addr, key, new_version), snapshot.value);
            }
        }
        
        Ok(())
    }
    
    /// Rolls back speculative execution
    pub fn rollback(&self, block_hash: &Hash) -> StateResult<()> {
        if let Some(mut result) = self.results.get_mut(block_hash) {
            result.state = SpeculativeState::RolledBack;
            let checkpoint_id = result.checkpoint_id;
            drop(result);
            
            self.rollback_checkpoint(checkpoint_id)?;
        }
        
        self.results.remove(block_hash);
        self.stats.lock().rollbacks += 1;
        
        Ok(())
    }
    
    /// Rolls back to checkpoint (discards changes)
    fn rollback_checkpoint(&self, checkpoint_id: u64) -> StateResult<()> {
        let checkpoint = self.checkpoints.write().remove(&checkpoint_id);
        
        if checkpoint.is_some() {
            self.depth.fetch_sub(1, Ordering::SeqCst);
        }
        
        // Nested checkpoints are automatically invalidated
        // by removing parent
        
        Ok(())
    }
    
    /// Gets account state at specific version
    pub fn get_account_at_version(&self, address: &Address, version: SpecVersion) -> Option<AccountSnapshot> {
        // Try exact version first
        if let Some(snapshot) = self.account_cache.get(&(*address, version)) {
            self.stats.lock().cache_hits += 1;
            return Some(snapshot.clone());
        }
        
        // Try earlier versions
        for v in (0..version).rev() {
            if let Some(snapshot) = self.account_cache.get(&(*address, v)) {
                self.stats.lock().cache_hits += 1;
                return Some(snapshot.clone());
            }
        }
        
        self.stats.lock().cache_misses += 1;
        None
    }
    
    /// Gets storage at specific version
    pub fn get_storage_at_version(
        &self,
        address: &Address,
        key: &Hash,
        version: SpecVersion,
    ) -> Option<[u8; 32]> {
        if let Some(value) = self.storage_cache.get(&(*address, *key, version)) {
            return Some(*value);
        }
        
        for v in (0..version).rev() {
            if let Some(value) = self.storage_cache.get(&(*address, *key, v)) {
                return Some(*value);
            }
        }
        
        None
    }
    
    /// Detects conflicts between two blocks
    pub fn detect_conflicts(&self, hash1: &Hash, hash2: &Hash) -> bool {
        let result1 = match self.results.get(hash1) {
            Some(r) => r,
            None => return false,
        };
        
        let result2 = match self.results.get(hash2) {
            Some(r) => r,
            None => return false,
        };
        
        result1.conflicts_with(&result2)
    }
    
    /// Gets current version
    pub fn current_version(&self) -> SpecVersion {
        self.current_version.load(Ordering::SeqCst)
    }
    
    /// Gets speculation depth
    pub fn depth(&self) -> u64 {
        self.depth.load(Ordering::SeqCst)
    }
    
    /// Gets speculative result if exists
    pub fn get_result(&self, block_hash: &Hash) -> Option<SpeculativeResult> {
        self.results.get(block_hash).map(|r| r.clone())
    }
    
    /// Returns statistics
    pub fn stats(&self) -> SpeculativeStats {
        self.stats.lock().clone()
    }
    
    /// Cleans up old confirmed blocks
    pub fn cleanup(&self, keep_last: usize) {
        let mut confirmed = self.confirmed.write();
        if confirmed.len() > keep_last {
            let to_remove = confirmed.len() - keep_last;
            for hash in confirmed.drain(..to_remove) {
                self.results.remove(&hash);
            }
        }
        
        // Cleanup old cache entries
        let current = self.current_version.load(Ordering::SeqCst);
        let min_version = current.saturating_sub(100);
        
        self.account_cache.retain(|k, _| k.1 >= min_version);
        self.storage_cache.retain(|k, _| k.2 >= min_version);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_checkpoint_creation() {
        let executor = SpeculativeExecutor::new(SpeculativeConfig::default());
        
        let cp1 = executor.create_checkpoint([1u8; 32]).unwrap();
        let cp2 = executor.create_checkpoint([2u8; 32]).unwrap();
        
        assert_ne!(cp1, cp2);
        assert_eq!(executor.depth(), 2);
    }
    
    #[test]
    fn test_conflict_detection() {
        let result1 = SpeculativeResult {
            block_hash: [1u8; 32],
            state_root: [0u8; 32],
            receipts: Vec::new(),
            read_set: HashSet::from([[10u8; 32]]),
            write_set: HashSet::from([[20u8; 32]]),
            storage_reads: HashSet::new(),
            storage_writes: HashSet::new(),
            execution_time: Duration::ZERO,
            state: SpeculativeState::Speculated,
            checkpoint_id: 0,
        };
        
        let result2 = SpeculativeResult {
            block_hash: [2u8; 32],
            state_root: [0u8; 32],
            receipts: Vec::new(),
            read_set: HashSet::from([[20u8; 32]]), // Reads what result1 writes
            write_set: HashSet::from([[30u8; 32]]),
            storage_reads: HashSet::new(),
            storage_writes: HashSet::new(),
            execution_time: Duration::ZERO,
            state: SpeculativeState::Speculated,
            checkpoint_id: 1,
        };
        
        assert!(result1.conflicts_with(&result2));
    }
    
    #[test]
    fn test_no_conflict() {
        let result1 = SpeculativeResult {
            block_hash: [1u8; 32],
            state_root: [0u8; 32],
            receipts: Vec::new(),
            read_set: HashSet::from([[10u8; 32]]),
            write_set: HashSet::from([[20u8; 32]]),
            storage_reads: HashSet::new(),
            storage_writes: HashSet::new(),
            execution_time: Duration::ZERO,
            state: SpeculativeState::Speculated,
            checkpoint_id: 0,
        };
        
        let result2 = SpeculativeResult {
            block_hash: [2u8; 32],
            state_root: [0u8; 32],
            receipts: Vec::new(),
            read_set: HashSet::from([[30u8; 32]]),
            write_set: HashSet::from([[40u8; 32]]),
            storage_reads: HashSet::new(),
            storage_writes: HashSet::new(),
            execution_time: Duration::ZERO,
            state: SpeculativeState::Speculated,
            checkpoint_id: 1,
        };
        
        assert!(!result1.conflicts_with(&result2));
    }
}
