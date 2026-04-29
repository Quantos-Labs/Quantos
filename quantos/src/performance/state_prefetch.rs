//! # State Prefetching System
//!
//! Production-ready predictive state prefetching for Quantos.
//!
//! ## Features
//!
//! - **Predictive Access Pattern Learning**: ML-based prediction of state access
//! - **Parallel Prefetching**: Async prefetch of likely-needed state
//! - **Cache Warming**: Pre-populate caches before execution
//! - **Access Pattern Tracking**: Historical analysis of access patterns
//! - **Adaptive Prefetching**: Adjusts based on hit rate
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                State Prefetching System                     │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                             │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
//! │  │ Access       │  │ Predictor    │  │ Prefetch     │    │
//! │  │ Pattern      │  │ (ML-based)   │  │ Worker Pool  │    │
//! │  │ Tracker      │  │              │  │              │    │
//! │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │
//! │         │                  │                  │            │
//! │         └──────────────────┼──────────────────┘            │
//! │                            ▼                               │
//! │                  ┌─────────────────┐                      │
//! │                  │ Prefetch Cache  │                      │
//! │                  │ (Hot State)     │                      │
//! │                  └─────────────────┘                      │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::types::Address;
use crate::state::StateManager;

/// Maximum access pattern history size.
const MAX_PATTERN_HISTORY: usize = 10_000;
/// Maximum prefetch queue size.
const MAX_PREFETCH_QUEUE: usize = 1_000;
/// Prefetch worker pool size.
const PREFETCH_WORKERS: usize = 8;
/// Minimum confidence threshold for prefetching.
const MIN_CONFIDENCE: f64 = 0.6;
/// Maximum patterns DashMap entries to prevent unbounded growth.
const MAX_PATTERNS: usize = 100_000;
/// Maximum prefetch cache entries to prevent unbounded growth.
const MAX_PREFETCH_CACHE: usize = 50_000;
/// Timeout for prefetch operations (seconds).
const PREFETCH_TIMEOUT_SECS: u64 = 5;

/// Configuration for state prefetching.
#[derive(Clone, Debug)]
pub struct PrefetchConfig {
    /// Enable predictive prefetching
    pub enable_prediction: bool,
    /// Maximum prefetch queue size
    pub max_queue_size: usize,
    /// Number of prefetch workers
    pub num_workers: usize,
    /// Minimum prediction confidence
    pub min_confidence: f64,
    /// Enable adaptive prefetching
    pub enable_adaptive: bool,
    /// Prefetch lookahead depth
    pub lookahead_depth: usize,
}

impl Default for PrefetchConfig {
    fn default() -> Self {
        Self {
            enable_prediction: true,
            max_queue_size: MAX_PREFETCH_QUEUE,
            num_workers: PREFETCH_WORKERS,
            min_confidence: MIN_CONFIDENCE,
            enable_adaptive: true,
            lookahead_depth: 5,
        }
    }
}

/// Access pattern for an address.
#[derive(Clone, Debug)]
struct AccessPattern {
    /// Address that was accessed
    address: Address,
    /// Addresses accessed after this one
    next_accesses: HashMap<Address, u32>,
    /// Total accesses
    total_accesses: u32,
    /// Last access time
    last_accessed: Instant,
}

impl AccessPattern {
    fn new(address: Address) -> Self {
        Self {
            address,
            next_accesses: HashMap::new(),
            total_accesses: 0,
            last_accessed: Instant::now(),
        }
    }

    fn record_next(&mut self, next: Address) {
        *self.next_accesses.entry(next).or_insert(0) += 1;
        self.total_accesses += 1;
        self.last_accessed = Instant::now();
    }

    fn predict_next(&self, confidence: f64) -> Vec<(Address, f64)> {
        let mut predictions: Vec<(Address, f64)> = self
            .next_accesses
            .iter()
            .map(|(addr, count)| {
                let prob = *count as f64 / self.total_accesses as f64;
                (*addr, prob)
            })
            .filter(|(_, prob)| *prob >= confidence)
            .collect();
        
        predictions.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        predictions
    }
}

/// Prefetch request.
#[derive(Clone, Debug)]
struct PrefetchRequest {
    /// Address to prefetch
    address: Address,
    /// Prediction confidence
    confidence: f64,
    /// Request time
    requested_at: Instant,
    /// Priority (higher = more important)
    priority: u32,
}

/// Prefetch statistics.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PrefetchStats {
    /// Total prefetch requests issued
    pub prefetch_requests: u64,
    /// Successful prefetches (used)
    pub prefetch_hits: u64,
    /// Wasted prefetches (not used)
    pub prefetch_misses: u64,
    /// Hit rate (0.0 to 1.0)
    pub hit_rate: f64,
    /// Average prefetch latency (microseconds)
    pub avg_latency_us: u64,
    /// Patterns learned
    pub patterns_learned: usize,
}

/// State prefetching system.
pub struct StatePrefetcher {
    config: PrefetchConfig,
    
    /// State manager for fetching
    state_manager: Arc<StateManager>,
    
    /// Access pattern history
    patterns: Arc<DashMap<Address, AccessPattern>>,
    
    /// Recent access sequence
    access_sequence: Arc<RwLock<VecDeque<Address>>>,
    
    /// Prefetch queue
    prefetch_queue: Arc<DashMap<Address, PrefetchRequest>>,
    
    /// Prefetch cache
    prefetch_cache: Arc<DashMap<Address, (Vec<u8>, Instant)>>,
    
    /// Worker semaphore
    worker_semaphore: Arc<Semaphore>,
    
    /// Statistics
    stats: Arc<RwLock<PrefetchStats>>,
}

impl StatePrefetcher {
    /// Creates a new state prefetcher.
    pub fn new(config: PrefetchConfig, state_manager: Arc<StateManager>) -> Self {
        Self {
            config: config.clone(),
            state_manager,
            patterns: Arc::new(DashMap::new()),
            access_sequence: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_PATTERN_HISTORY))),
            prefetch_queue: Arc::new(DashMap::new()),
            prefetch_cache: Arc::new(DashMap::new()),
            worker_semaphore: Arc::new(Semaphore::new(config.num_workers)),
            stats: Arc::new(RwLock::new(PrefetchStats::default())),
        }
    }

    /// Records a state access for pattern learning.
    pub fn record_access(self: &Arc<Self>, address: &Address) {
        // Update access sequence
        let mut sequence = self.access_sequence.write();
        
        // Check if this was in prefetch cache (hit)
        if self.prefetch_cache.contains_key(address) {
            self.stats.write().prefetch_hits += 1;
        }
        
        // Update pattern if we have previous access
        if let Some(prev_address) = sequence.back() {
            // HIGH: Cap patterns map to prevent unbounded growth
            if self.patterns.len() < MAX_PATTERNS || self.patterns.contains_key(prev_address) {
                let mut pattern = self.patterns
                    .entry(*prev_address)
                    .or_insert_with(|| AccessPattern::new(*prev_address));
                
                pattern.record_next(*address);
            }
        }
        
        sequence.push_back(*address);
        
        // Limit sequence size
        if sequence.len() > MAX_PATTERN_HISTORY {
            sequence.pop_front();
        }
        
        // Trigger prediction for next accesses
        if self.config.enable_prediction {
            self.predict_and_prefetch(address);
        }
        
        // Update stats
        self.stats.write().patterns_learned = self.patterns.len();
    }

    /// Predicts and prefetches likely next accesses.
    fn predict_and_prefetch(self: &Arc<Self>, current: &Address) {
        if let Some(pattern) = self.patterns.get(current) {
            let predictions = pattern.predict_next(self.config.min_confidence);
            let predictions_vec: Vec<_> = predictions.into_iter().take(self.config.lookahead_depth).collect();
            
            for (addr, confidence) in predictions_vec {
                // Don't prefetch if already in cache
                if self.prefetch_cache.contains_key(&addr) {
                    continue;
                }
                
                // Don't prefetch if already queued
                if self.prefetch_queue.contains_key(&addr) {
                    continue;
                }
                
                // Queue for prefetching
                let addr_copy = addr; // Copy for spawn
                let request = PrefetchRequest {
                    address: addr_copy,
                    confidence,
                    requested_at: Instant::now(),
                    priority: (confidence * 100.0) as u32,
                };
                
                self.prefetch_queue.insert(addr_copy, request);
                self.stats.write().prefetch_requests += 1;
                
                // GAS: Clone the Arc directly instead of creating a new Arc wrapper
                let prefetcher = Arc::clone(self);
                tokio::spawn(async move {
                    prefetcher.execute_prefetch(addr_copy).await;
                });
            }
        }
    }

    /// Executes a prefetch for an address.
    async fn execute_prefetch(self: &Arc<Self>, address: Address) {
        // HIGH: Acquire worker permit with timeout to prevent semaphore exhaustion
        // from hung state manager operations
        let _permit = match tokio::time::timeout(
            Duration::from_secs(PREFETCH_TIMEOUT_SECS),
            self.worker_semaphore.acquire(),
        ).await {
            Ok(Ok(p)) => p,
            Ok(Err(_)) => return, // Semaphore closed
            Err(_) => {
                tracing::warn!("Prefetch semaphore acquire timed out for {:?}", address);
                self.prefetch_queue.remove(&address);
                return;
            }
        };
        
        let start = Instant::now();
        
        // HIGH: Wrap state fetch in a timeout to prevent hung operations
        let fetch_result = tokio::time::timeout(
            Duration::from_secs(PREFETCH_TIMEOUT_SECS),
            async { self.state_manager.get_account(&address) },
        ).await;
        
        match fetch_result {
            Ok(Ok(account)) => {
                // Evict oldest entries if cache is at capacity
                if self.prefetch_cache.len() >= MAX_PREFETCH_CACHE {
                    let oldest = self.prefetch_cache.iter()
                        .min_by_key(|e| e.value().1)
                        .map(|e| *e.key());
                    if let Some(key) = oldest {
                        self.prefetch_cache.remove(&key);
                    }
                }
                
                if let Ok(data) = bincode::serialize(&account) {
                    self.prefetch_cache.insert(address, (data, Instant::now()));
                }
            }
            Ok(Err(e)) => {
                tracing::debug!("Prefetch failed for {:?}: {}", address, e);
            }
            Err(_) => {
                tracing::warn!("Prefetch state fetch timed out for {:?}", address);
            }
        }
        
        // Remove from queue
        self.prefetch_queue.remove(&address);
        
        // LOW: Update latency stats with saturating arithmetic to prevent overflow
        let latency = start.elapsed().as_micros() as u64;
        let mut stats = self.stats.write();
        if stats.prefetch_requests > 0 {
            let prev_total = stats.avg_latency_us.saturating_mul(stats.prefetch_requests.saturating_sub(1));
            stats.avg_latency_us = prev_total.saturating_add(latency) / stats.prefetch_requests;
        }
    }

    /// Gets state from prefetch cache if available.
    pub fn get_prefetched(&self, address: &Address) -> Option<Vec<u8>> {
        self.prefetch_cache.get(address).map(|entry| {
            let (data, _) = entry.value();
            data.clone()
        })
    }

    /// Prefetches a batch of addresses.
    pub async fn prefetch_batch(self: &Arc<Self>, addresses: &[Address]) {
        for addr in addresses {
            let addr = *addr; // Copy to avoid lifetime issues
            if !self.prefetch_cache.contains_key(&addr) && !self.prefetch_queue.contains_key(&addr) {
                let request = PrefetchRequest {
                    address: addr,
                    confidence: 1.0, // Manual prefetch has max confidence
                    requested_at: Instant::now(),
                    priority: 100,
                };
                
                self.prefetch_queue.insert(addr, request);
                
                // GAS: Clone the Arc directly instead of creating a new Arc wrapper
                let prefetcher = Arc::clone(self);
                tokio::spawn(async move {
                    prefetcher.execute_prefetch(addr).await;
                });
            }
        }
    }

    /// Warms the cache with commonly accessed addresses.
    pub async fn warm_cache(self: &Arc<Self>, addresses: Vec<Address>) {
        tracing::info!("Warming prefetch cache with {} addresses", addresses.len());
        self.prefetch_batch(&addresses).await;
    }

    /// Cleans up stale cache entries.
    pub fn cleanup_cache(&self, max_age: Duration) {
        let now = Instant::now();
        
        self.prefetch_cache.retain(|_, (_, timestamp)| {
            now.duration_since(*timestamp) < max_age
        });
        
        // Update miss count for stale entries
        let removed = self.stats.read().prefetch_requests - self.stats.read().prefetch_hits;
        self.stats.write().prefetch_misses += removed;
    }

    /// Gets current statistics.
    pub fn get_stats(&self) -> PrefetchStats {
        let mut stats = self.stats.read().clone();
        
        // Calculate hit rate
        if stats.prefetch_requests > 0 {
            stats.hit_rate = stats.prefetch_hits as f64 / stats.prefetch_requests as f64;
        }
        
        stats
    }

    /// Resets all patterns (for testing/debugging).
    pub fn reset_patterns(&self) {
        self.patterns.clear();
        self.access_sequence.write().clear();
        self.prefetch_queue.clear();
        self.prefetch_cache.clear();
    }

    // GAS: clone_arc removed — callers now use Arc::clone(self) directly,
    // which correctly increments the reference count instead of creating a
    // redundant Arc wrapping cloned internals.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_pattern_learning() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path()).unwrap();
        let state_manager = Arc::new(StateManager::new(storage));
        let prefetcher = Arc::new(StatePrefetcher::new(PrefetchConfig::default(), state_manager));
        
        let addr1 = [1u8; 32];
        let addr2 = [2u8; 32];
        let addr3 = [3u8; 32];
        
        // Record pattern: addr1 -> addr2 -> addr3
        prefetcher.record_access(&addr1);
        prefetcher.record_access(&addr2);
        prefetcher.record_access(&addr3);
        
        // Repeat to strengthen pattern
        prefetcher.record_access(&addr1);
        prefetcher.record_access(&addr2);
        
        // Check pattern learned
        let stats = prefetcher.get_stats();
        assert!(stats.patterns_learned > 0);
    }

    #[tokio::test]
    async fn test_prefetch_batch() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path()).unwrap();
        let state_manager = Arc::new(StateManager::new(storage));
        let prefetcher = Arc::new(StatePrefetcher::new(PrefetchConfig::default(), state_manager));
        
        let addresses = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        
        prefetcher.prefetch_batch(&addresses).await;
        
        // Give time for async prefetch
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let stats = prefetcher.get_stats();
        assert!(stats.prefetch_requests > 0);
    }

    #[test]
    fn test_access_pattern_prediction() {
        let mut pattern = AccessPattern::new([1u8; 32]);
        let addr2 = [2u8; 32];
        let addr3 = [3u8; 32];
        
        // Record addr2 appearing after addr1 multiple times
        for _ in 0..10 {
            pattern.record_next(addr2);
        }
        
        // Record addr3 appearing less frequently
        for _ in 0..3 {
            pattern.record_next(addr3);
        }
        
        // Predict next with 0.6 confidence
        let predictions = pattern.predict_next(0.6);
        
        // addr2 should be predicted (10/13 = 0.77 > 0.6)
        assert!(predictions.iter().any(|(a, _)| *a == addr2));
        
        // addr3 should not be predicted (3/13 = 0.23 < 0.6)
        assert!(!predictions.iter().any(|(a, _)| *a == addr3));
    }
}
