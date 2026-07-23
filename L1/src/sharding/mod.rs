// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Dynamic Sharding System
//!
//! This module implements Quantos's dynamic sharding capabilities,
//! allowing the network to automatically scale based on transaction load.
//!
//! ## Overview
//!
//! Dynamic sharding enables:
//! - **Auto-scaling**: Shards split/merge based on load
//! - **Load Balancing**: Transactions redistributed across shards
//! - **Hot Spot Prevention**: Automatic rebalancing of busy shards
//!
//! ## Shard Lifecycle
//!
//! ```text
//! ┌─────────────┐    High Load    ┌─────────────┐
//! │   Shard N   │ ─────────────▶ │  Shard N    │
//! │   (busy)    │                 │  Shard N+1  │
//! └─────────────┘                 └─────────────┘
//!       SPLIT
//!
//! ┌─────────────┐    Low Load     ┌─────────────┐
//! │  Shard N    │ ─────────────▶ │   Shard N   │
//! │  Shard N+1  │                 │  (merged)   │
//! └─────────────┘                 └─────────────┘
//!       MERGE
//! ```

pub mod cross_shard;
mod stark_accelerated;
mod self_healing;

pub use cross_shard::*;
pub use stark_accelerated::*;
pub use self_healing::*;

use std::collections::HashMap;
use std::sync::Arc;
use dashmap::DashMap;
use parking_lot::{RwLock, Mutex};
use rand::RngCore;
use rand::rngs::OsRng;

use crate::types::{Address, Hash, ShardId};

/// Maximum rebalance history entries
const MAX_REBALANCE_HISTORY: usize = 10_000;

/// Configuration for dynamic sharding behavior.
#[derive(Clone, Debug)]
pub struct ShardingConfig {
    /// Minimum number of shards (cannot go below this)
    pub min_shards: u16,
    
    /// Maximum number of shards (cannot exceed this)
    pub max_shards: u16,
    
    /// TPS threshold to trigger shard split
    pub split_threshold_tps: u64,
    
    /// TPS threshold to trigger shard merge
    pub merge_threshold_tps: u64,
    
    /// Minimum time between rebalancing operations (seconds)
    pub rebalance_cooldown_secs: u64,
    
    /// Number of epochs to average for load calculation
    pub load_average_epochs: u64,
}

impl Default for ShardingConfig {
    fn default() -> Self {
        Self {
            min_shards: 100,
            max_shards: 10_000,
            split_threshold_tps: 150_000,  // Split when shard exceeds 150K TPS
            merge_threshold_tps: 10_000,    // Merge when shard below 10K TPS
            rebalance_cooldown_secs: 60,
            load_average_epochs: 10,
        }
    }
}

/// Manages dynamic shard allocation and rebalancing.
///
/// The `ShardManager` monitors transaction load across shards and
/// automatically splits or merges shards to maintain optimal performance.
///
/// # Example
///
/// ```rust,ignore
/// let manager = ShardManager::new(config);
///
/// // Report transaction load
/// manager.report_load(shard_id, 50_000);
///
/// // Check if rebalancing needed
/// if let Some(action) = manager.check_rebalance() {
///     manager.execute_rebalance(action).await?;
/// }
/// ```
pub struct ShardManager {
    config: ShardingConfig,
    
    /// Current shard allocation map
    shard_map: Arc<RwLock<ShardMap>>,
    
    /// Per-shard load metrics
    shard_loads: Arc<DashMap<ShardId, ShardLoad>>,
    
    /// History of rebalancing operations
    rebalance_history: Arc<RwLock<Vec<RebalanceEvent>>>,
    
    /// Last rebalance timestamp
    last_rebalance: Arc<RwLock<u64>>,
    
    /// Authorization token for privileged operations
    auth_token: Arc<Mutex<[u8; 32]>>,
    
    /// Rebalance lock to prevent race conditions
    rebalance_lock: Arc<Mutex<()>>,
}

/// Represents the current shard topology.
#[derive(Clone, Debug)]
pub struct ShardMap {
    /// Total number of active shards
    pub num_shards: u16,
    
    /// Address range assignments for each shard
    /// Key: shard_id, Value: (start_prefix, end_prefix)
    pub ranges: HashMap<ShardId, (u16, u16)>,
    
    /// Shard version (incremented on each topology change)
    pub version: u64,
}

impl ShardMap {
    /// Creates a new shard map with uniform distribution.
    pub fn new(num_shards: u16) -> Self {
        let mut ranges = HashMap::new();
        
        // CRITICAL: Use checked arithmetic to prevent overflow
        let range_size = u16::MAX.checked_div(num_shards.max(1)).unwrap_or(u16::MAX);
        
        for i in 0..num_shards {
            // Use checked arithmetic
            let start = i.checked_mul(range_size).unwrap_or(0);
            let end = if i == num_shards - 1 {
                u16::MAX
            } else {
                (i + 1).checked_mul(range_size)
                    .and_then(|v| v.checked_sub(1))
                    .unwrap_or(u16::MAX)
            };
            ranges.insert(i, (start, end));
        }
        
        Self {
            num_shards,
            ranges,
            version: 1,
        }
    }
    
    /// Gets the shard ID for a given address.
    pub fn get_shard(&self, address: &Address) -> ShardId {
        let prefix = u16::from_be_bytes([address[0], address[1]]);
        
        for (shard_id, (start, end)) in &self.ranges {
            if prefix >= *start && prefix <= *end {
                return *shard_id;
            }
        }
        
        // Fallback to modulo if not found
        prefix % self.num_shards
    }
}

/// Load metrics for a single shard.
#[derive(Clone, Debug, Default)]
pub struct ShardLoad {
    /// Transactions per second (rolling average)
    pub tps: u64,
    
    /// Current queue depth
    pub queue_depth: u64,
    
    /// Average transaction execution time (microseconds)
    pub avg_exec_time_us: u64,
    
    /// Number of active accounts in this shard
    pub active_accounts: u64,
    
    /// Total stake in this shard
    pub total_stake: u128,
    
    /// Load samples for averaging
    pub samples: Vec<u64>,
}

impl ShardLoad {
    /// Adds a load sample and updates the rolling average.
    pub fn add_sample(&mut self, tps: u64, max_samples: usize) {
        self.samples.push(tps);
        if self.samples.len() > max_samples {
            self.samples.remove(0);
        }
        self.tps = self.samples.iter().sum::<u64>() / self.samples.len() as u64;
    }
    
    /// Checks if the shard should be split.
    pub fn should_split(&self, threshold: u64) -> bool {
        self.tps > threshold
    }
    
    /// Checks if the shard should be merged.
    pub fn should_merge(&self, threshold: u64) -> bool {
        self.tps < threshold
    }
}

/// Represents a shard rebalancing action.
#[derive(Clone, Debug)]
pub enum RebalanceAction {
    /// Split a shard into two
    Split {
        source_shard: ShardId,
        new_shard_id: ShardId,
    },
    
    /// Merge two shards into one
    Merge {
        shard_a: ShardId,
        shard_b: ShardId,
        target_shard: ShardId,
    },
    
    /// Migrate accounts between shards
    Migrate {
        from_shard: ShardId,
        to_shard: ShardId,
        accounts: Vec<Address>,
    },
}

/// Record of a rebalancing operation.
#[derive(Clone, Debug)]
pub struct RebalanceEvent {
    /// Timestamp of the event
    pub timestamp: u64,
    
    /// Action that was taken
    pub action: RebalanceAction,
    
    /// New shard map version after this event
    pub new_version: u64,
    
    /// Duration of the rebalancing operation (milliseconds)
    pub duration_ms: u64,
}

impl ShardManager {
    /// Creates a new shard manager.
    pub fn new(config: ShardingConfig) -> Self {
        let initial_shards = (config.min_shards + config.max_shards) / 2;
        
        // HIGH: Use OsRng for cryptographically secure authorization token
        let mut token = [0u8; 32];
        OsRng.fill_bytes(&mut token);
        
        Self {
            config,
            shard_map: Arc::new(RwLock::new(ShardMap::new(initial_shards))),
            shard_loads: Arc::new(DashMap::new()),
            rebalance_history: Arc::new(RwLock::new(Vec::new())),
            last_rebalance: Arc::new(RwLock::new(0)),
            auth_token: Arc::new(Mutex::new(token)),
            rebalance_lock: Arc::new(Mutex::new(())),
        }
    }
    
    /// Returns the local bootstrap token for trusted in-crate operations.
    pub(crate) fn bootstrap_auth_token(&self) -> [u8; 32] {
        *self.auth_token.lock()
    }
    
    /// Reports load for a specific shard.
    ///
    /// This should be called periodically to update the load metrics
    /// used for rebalancing decisions.
    pub fn report_load(&self, shard_id: ShardId, tps: u64) {
        let max_samples = self.config.load_average_epochs as usize;
        
        self.shard_loads
            .entry(shard_id)
            .or_insert_with(ShardLoad::default)
            .add_sample(tps, max_samples);
    }
    
    /// Checks if rebalancing is needed and returns the action to take.
    pub fn check_rebalance(&self) -> Option<RebalanceAction> {
        let now = chrono::Utc::now().timestamp() as u64;
        let last = *self.last_rebalance.read();
        
        // Check cooldown
        if now - last < self.config.rebalance_cooldown_secs {
            return None;
        }
        
        let shard_map = self.shard_map.read();
        
        // Check for shards that need splitting
        for entry in self.shard_loads.iter() {
            let shard_id = *entry.key();
            let load = entry.value();
            
            if load.should_split(self.config.split_threshold_tps) {
                if shard_map.num_shards < self.config.max_shards {
                    return Some(RebalanceAction::Split {
                        source_shard: shard_id,
                        new_shard_id: shard_map.num_shards,
                    });
                }
            }
        }
        
        // Check for shards that can be merged
        let mut merge_candidates: Vec<(ShardId, u64)> = Vec::new();
        
        for entry in self.shard_loads.iter() {
            let shard_id = *entry.key();
            let load = entry.value();
            
            if load.should_merge(self.config.merge_threshold_tps) {
                merge_candidates.push((shard_id, load.tps));
            }
        }
        
        // Find two adjacent low-load shards to merge
        if merge_candidates.len() >= 2 && shard_map.num_shards > self.config.min_shards {
            merge_candidates.sort_by_key(|(id, _)| *id);
            
            for i in 0..merge_candidates.len() - 1 {
                let (shard_a, _) = merge_candidates[i];
                let (shard_b, _) = merge_candidates[i + 1];
                
                if shard_b == shard_a + 1 {
                    return Some(RebalanceAction::Merge {
                        shard_a,
                        shard_b,
                        target_shard: shard_a,
                    });
                }
            }
        }
        
        None
    }
    
    /// Executes a rebalancing action.
    ///
    /// # Arguments
    ///
    /// * `action` - The rebalancing action to execute
    ///
    /// # Returns
    ///
    /// The new shard map after rebalancing
    pub async fn execute_rebalance(&self, action: RebalanceAction, auth_token: &[u8; 32]) -> Result<ShardMap, ShardingError> {
        // CRITICAL: Verify authorization
        if *self.auth_token.lock() != *auth_token {
            return Err(ShardingError::Unauthorized);
        }
        
        // CRITICAL: Acquire rebalance lock to prevent race conditions
        let _lock = self.rebalance_lock.lock();
        
        let start = std::time::Instant::now();
        
        tracing::info!("Executing shard rebalance: {:?}", action);
        
        let new_map = {
            let mut shard_map = self.shard_map.write();
            
            match &action {
                RebalanceAction::Split { source_shard, new_shard_id } => {
                    // Get current range
                    let (start, end) = shard_map.ranges.get(source_shard)
                        .ok_or(ShardingError::ShardNotFound(*source_shard))?
                        .clone();
                    
                    // Split range in half
                    let mid = start + (end - start) / 2;
                    
                    shard_map.ranges.insert(*source_shard, (start, mid));
                    shard_map.ranges.insert(*new_shard_id, (mid + 1, end));
                    shard_map.num_shards += 1;
                    shard_map.version += 1;
                }
                
                RebalanceAction::Merge { shard_a, shard_b, target_shard } => {
                    let (start_a, _) = shard_map.ranges.get(shard_a)
                        .ok_or(ShardingError::ShardNotFound(*shard_a))?
                        .clone();
                    let (_, end_b) = shard_map.ranges.get(shard_b)
                        .ok_or(ShardingError::ShardNotFound(*shard_b))?
                        .clone();
                    
                    shard_map.ranges.remove(shard_b);
                    shard_map.ranges.insert(*target_shard, (start_a, end_b));
                    shard_map.num_shards -= 1;
                    shard_map.version += 1;
                }
                
                RebalanceAction::Migrate { from_shard: _, to_shard: _, accounts: _ } => {
                    // Migration doesn't change topology
                    shard_map.version += 1;
                }
            }
            
            shard_map.clone()
        };
        
        // Record the event with bounded history
        let duration = start.elapsed().as_millis() as u64;
        {
            let mut history = self.rebalance_history.write();
            
            // CRITICAL: Limit history size to prevent memory exhaustion
            if history.len() >= MAX_REBALANCE_HISTORY {
                history.remove(0);
            }
            
            history.push(RebalanceEvent {
                timestamp: chrono::Utc::now().timestamp() as u64,
                action,
                new_version: new_map.version,
                duration_ms: duration,
            });
        }
        
        *self.last_rebalance.write() = chrono::Utc::now().timestamp() as u64;
        
        tracing::info!(
            "Shard rebalance complete: {} shards, version {}, took {}ms",
            new_map.num_shards,
            new_map.version,
            duration
        );
        
        Ok(new_map)
    }
    
    /// Gets the current shard map.
    pub fn get_shard_map(&self) -> ShardMap {
        self.shard_map.read().clone()
    }
    
    /// Gets the shard ID for an address.
    pub fn get_shard_for_address(&self, address: &Address) -> ShardId {
        self.shard_map.read().get_shard(address)
    }
    
    /// Gets load for all shards.
    pub fn get_all_loads(&self) -> Vec<(ShardId, ShardLoad)> {
        self.shard_loads.iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect()
    }
    
    /// Gets rebalancing history.
    pub fn get_history(&self) -> Vec<RebalanceEvent> {
        self.rebalance_history.read().clone()
    }
}

/// Errors from the sharding system.
#[derive(Debug, thiserror::Error)]
pub enum ShardingError {
    /// Shard not found
    #[error("Shard not found: {0}")]
    ShardNotFound(ShardId),
    
    /// Cannot split (max shards reached)
    #[error("Cannot split: maximum shards ({0}) reached")]
    MaxShardsReached(u16),
    
    /// Cannot merge (min shards reached)
    #[error("Cannot merge: minimum shards ({0}) reached")]
    MinShardsReached(u16),
    
    /// Rebalancing in progress
    #[error("Rebalancing already in progress")]
    RebalanceInProgress,
    
    /// Unauthorized access
    #[error("Unauthorized access to privileged operation")]
    Unauthorized,
}

/// Cross-shard transaction coordinator.
///
/// Handles transactions that involve multiple shards,
/// ensuring atomic execution across shard boundaries.
pub struct CrossShardCoordinator {
    shard_manager: Arc<ShardManager>,
    pending_cross_shard: Arc<DashMap<Hash, CrossShardTx>>,
}

/// A cross-shard transaction.
#[derive(Clone, Debug)]
pub struct CrossShardTx {
    /// Transaction hash
    pub tx_hash: Hash,
    
    /// Source shard
    pub source_shard: ShardId,
    
    /// Destination shard
    pub dest_shard: ShardId,
    
    /// Current phase
    pub phase: CrossShardPhase,
    
    /// Timestamp when the cross-shard tx was initiated
    pub initiated_at: u64,
}

/// Phase of a cross-shard transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrossShardPhase {
    /// Prepare phase - locking resources
    Prepare,
    /// Commit phase - executing transfer
    Commit,
    /// Completed
    Complete,
    /// Aborted
    Aborted,
}

impl CrossShardCoordinator {
    /// Creates a new cross-shard coordinator.
    pub fn new(shard_manager: Arc<ShardManager>) -> Self {
        Self {
            shard_manager,
            pending_cross_shard: Arc::new(DashMap::new()),
        }
    }
    
    /// Initiates a cross-shard transaction.
    pub fn initiate(&self, tx_hash: Hash, source: ShardId, dest: ShardId) -> Result<(), ShardingError> {
        let cross_tx = CrossShardTx {
            tx_hash,
            source_shard: source,
            dest_shard: dest,
            phase: CrossShardPhase::Prepare,
            initiated_at: chrono::Utc::now().timestamp() as u64,
        };
        
        self.pending_cross_shard.insert(tx_hash, cross_tx);
        Ok(())
    }
    
    /// Advances a cross-shard transaction to the next phase.
    pub fn advance(&self, tx_hash: &Hash) -> Option<CrossShardPhase> {
        if let Some(mut tx) = self.pending_cross_shard.get_mut(tx_hash) {
            tx.phase = match tx.phase {
                CrossShardPhase::Prepare => CrossShardPhase::Commit,
                CrossShardPhase::Commit => CrossShardPhase::Complete,
                _ => return None,
            };
            Some(tx.phase.clone())
        } else {
            None
        }
    }
    
    /// Gets the status of a cross-shard transaction.
    pub fn get_status(&self, tx_hash: &Hash) -> Option<CrossShardPhase> {
        self.pending_cross_shard.get(tx_hash).map(|tx| tx.phase.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_shard_map_creation() {
        let map = ShardMap::new(100);
        assert_eq!(map.num_shards, 100);
        assert_eq!(map.ranges.len(), 100);
    }
    
    #[test]
    fn test_shard_assignment() {
        let map = ShardMap::new(100);
        let addr = [0u8; 32];
        let shard = map.get_shard(&addr);
        assert!(shard < 100);
    }
    
    #[test]
    fn test_load_sampling() {
        let mut load = ShardLoad::default();
        load.add_sample(100_000, 10);
        load.add_sample(120_000, 10);
        load.add_sample(110_000, 10);
        assert_eq!(load.tps, 110_000);
    }
}
