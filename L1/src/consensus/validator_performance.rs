// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Validator Performance Tracker
//!
//! Tracks per-validator performance metrics during an epoch in RAM, then
//! flushes a serializable record to RocksDB at epoch finalization.
//!
//! Metrics are derived from consensus observations (votes received, blocks
//! proposed), not self-reported by the validator. This prevents a malicious
//! validator from inflating its own score.

use std::collections::HashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::types::Address;

/// Per-validator metrics accumulated during one epoch (in RAM).
#[derive(Clone, Debug, Default)]
pub struct EpochMetrics {
    /// Number of DAG vertices (blocks) proposed by this validator.
    pub blocks_proposed: u64,
    /// Number of votes cast by this validator.
    pub votes_cast: u64,
    /// Number of votes expected from this validator (one per slot it was
    /// assigned to a committee).
    pub votes_expected: u64,
    /// Sum of inclusion latencies for all vertices proposed (milliseconds).
    pub total_inclusion_latency_ms: u64,
    /// Number of vertices used to compute the average latency.
    pub latency_samples: u64,
    /// Total compute units (CU) included in blocks proposed by this validator.
    pub total_cu_proposed: u64,
    /// Number of checkpoint signatures submitted.
    pub checkpoint_signatures: u64,
}

impl EpochMetrics {
    /// Uptime ratio: votes_cast / votes_expected (0.0 if no votes expected).
    pub fn uptime(&self) -> f64 {
        if self.votes_expected == 0 {
            return 0.0;
        }
        (self.votes_cast as f64 / self.votes_expected as f64).clamp(0.0, 1.0)
    }

    /// Average inclusion latency in milliseconds (0.0 if no samples).
    pub fn avg_inclusion_latency_ms(&self) -> f64 {
        if self.latency_samples == 0 {
            return 0.0;
        }
        self.total_inclusion_latency_ms as f64 / self.latency_samples as f64
    }

    /// Compute the composite performance score [0.0, 1.0].
    ///
    /// Weighting:
    /// - 50% uptime (did the validator vote when expected?)
    /// - 30% CU utilization (how much useful work did the validator include?)
    /// - 20% inclusion latency (how fast were transactions included?)
    pub fn performance_score(&self) -> f64 {
        let uptime = self.uptime();

        // CU utilization: normalized by a target of 10,000 CU per slot.
        // This is a soft target; values above it are clamped to 1.0.
        let cu_target = 10_000.0;
        let cu_utilization = if self.blocks_proposed == 0 {
            0.0
        } else {
            let avg_cu = self.total_cu_proposed as f64 / self.blocks_proposed as f64;
            (avg_cu / cu_target).clamp(0.0, 1.0)
        };

        // Latency: map [0..2000ms] → [1.0..0.0], clamped.
        let latency_score = (1.0 - (self.avg_inclusion_latency_ms() / 2000.0)).clamp(0.0, 1.0);

        (0.5 * uptime + 0.3 * cu_utilization + 0.2 * latency_score).clamp(0.0, 1.0)
    }
}

/// Serializable record persisted to RocksDB at epoch finalization.
///
/// Key format: `0x19 || 0xFF || epoch_be_bytes || validator_address`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorPerformanceRecord {
    /// Epoch this record belongs to.
    pub epoch: u64,
    /// Validator address.
    pub validator: Address,
    /// Number of blocks (DAG vertices) proposed.
    pub blocks_proposed: u64,
    /// Number of votes cast.
    pub votes_cast: u64,
    /// Number of votes expected.
    pub votes_expected: u64,
    /// Average inclusion latency in milliseconds.
    pub avg_inclusion_latency_ms: f64,
    /// Total CU proposed.
    pub total_cu_proposed: u64,
    /// Number of checkpoint signatures submitted.
    pub checkpoint_signatures: u64,
    /// Composite performance score [0.0, 1.0].
    pub performance_score: f64,
    /// Uptime ratio [0.0, 1.0].
    pub uptime: f64,
    /// Reward distributed to this validator this epoch (in base units).
    pub epoch_reward: u128,
}

impl ValidatorPerformanceRecord {
    /// Build a record from the in-RAM metrics, ready for persistence.
    pub fn from_metrics(epoch: u64, validator: Address, metrics: &EpochMetrics, reward: u128) -> Self {
        Self {
            epoch,
            validator,
            blocks_proposed: metrics.blocks_proposed,
            votes_cast: metrics.votes_cast,
            votes_expected: metrics.votes_expected,
            avg_inclusion_latency_ms: metrics.avg_inclusion_latency_ms(),
            total_cu_proposed: metrics.total_cu_proposed,
            checkpoint_signatures: metrics.checkpoint_signatures,
            performance_score: metrics.performance_score(),
            uptime: metrics.uptime(),
            epoch_reward: reward,
        }
    }
}

/// In-RAM tracker for the current epoch. Reset at epoch boundaries.
pub struct ValidatorPerformanceTracker {
    /// Current epoch being tracked.
    epoch: u64,
    /// Per-validator metrics for the current epoch.
    metrics: HashMap<Address, EpochMetrics>,
}

impl ValidatorPerformanceTracker {
    pub fn new() -> Self {
        Self {
            epoch: 0,
            metrics: HashMap::new(),
        }
    }

    /// Returns the current epoch.
    pub fn current_epoch(&self) -> u64 {
        self.epoch
    }

    /// Start a new epoch: returns the completed records for persistence.
    /// The caller is responsible for flushing them to RocksDB.
    pub fn finalize_epoch(&mut self, new_epoch: u64) -> Vec<(Address, EpochMetrics)> {
        let completed: Vec<(Address, EpochMetrics)> = self.metrics.drain().collect();
        self.epoch = new_epoch;
        self.metrics.clear();
        completed
    }

    /// Record a block (DAG vertex) proposal.
    pub fn record_block_proposed(&mut self, validator: &Address, cu_included: u64) {
        let m = self.metrics.entry(*validator).or_default();
        m.blocks_proposed += 1;
        m.total_cu_proposed = m.total_cu_proposed.saturating_add(cu_included);
    }

    /// Record a vote cast by a validator.
    pub fn record_vote(&mut self, validator: &Address) {
        let m = self.metrics.entry(*validator).or_default();
        m.votes_cast += 1;
    }

    /// Record that a vote was expected from a validator (committee assignment).
    pub fn record_vote_expected(&mut self, validator: &Address) {
        let m = self.metrics.entry(*validator).or_default();
        m.votes_expected += 1;
    }

    /// Record an inclusion latency sample for a vertex proposed by a validator.
    pub fn record_inclusion_latency(&mut self, validator: &Address, latency_ms: u64) {
        let m = self.metrics.entry(*validator).or_default();
        m.total_inclusion_latency_ms = m.total_inclusion_latency_ms.saturating_add(latency_ms);
        m.latency_samples += 1;
    }

    /// Record a checkpoint signature submitted by a validator.
    pub fn record_checkpoint_signature(&mut self, validator: &Address) {
        let m = self.metrics.entry(*validator).or_default();
        m.checkpoint_signatures += 1;
    }

    /// Get metrics for a specific validator in the current epoch.
    pub fn get_metrics(&self, validator: &Address) -> Option<&EpochMetrics> {
        self.metrics.get(validator)
    }

    /// Get all metrics for the current epoch.
    pub fn all_metrics(&self) -> &HashMap<Address, EpochMetrics> {
        &self.metrics
    }
}

impl Default for ValidatorPerformanceTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe wrapper around `ValidatorPerformanceTracker` for use in
/// the consensus engine (which is shared across async tasks).
#[derive(Clone)]
pub struct SharedValidatorPerformanceTracker {
    inner: Arc<RwLock<ValidatorPerformanceTracker>>,
}

impl SharedValidatorPerformanceTracker {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(ValidatorPerformanceTracker::new())),
        }
    }

    pub fn current_epoch(&self) -> u64 {
        self.inner.read().current_epoch()
    }

    pub fn record_block_proposed(&self, validator: &Address, cu_included: u64) {
        self.inner.write().record_block_proposed(validator, cu_included);
    }

    pub fn record_vote(&self, validator: &Address) {
        self.inner.write().record_vote(validator);
    }

    pub fn record_vote_expected(&self, validator: &Address) {
        self.inner.write().record_vote_expected(validator);
    }

    pub fn record_inclusion_latency(&self, validator: &Address, latency_ms: u64) {
        self.inner.write().record_inclusion_latency(validator, latency_ms);
    }

    pub fn record_checkpoint_signature(&self, validator: &Address) {
        self.inner.write().record_checkpoint_signature(validator);
    }

    /// Finalize the current epoch and return completed metrics for persistence.
    /// The caller must persist these to RocksDB before calling other methods.
    pub fn finalize_epoch(&self, new_epoch: u64) -> Vec<(Address, EpochMetrics)> {
        self.inner.write().finalize_epoch(new_epoch)
    }

    /// Get a snapshot of metrics for a specific validator.
    pub fn get_metrics(&self, validator: &Address) -> Option<EpochMetrics> {
        self.inner.read().get_metrics(validator).cloned()
    }

    /// Get a snapshot of all metrics for the current epoch.
    pub fn all_metrics(&self) -> HashMap<Address, EpochMetrics> {
        self.inner.read().all_metrics().clone()
    }
}

impl Default for SharedValidatorPerformanceTracker {
    fn default() -> Self {
        Self::new()
    }
}

use std::sync::Arc;

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        let mut a = [0u8; 32];
        a[0] = n;
        a
    }

    #[test]
    fn test_record_block_and_vote() {
        let mut tracker = ValidatorPerformanceTracker::new();
        let v = addr(1);

        tracker.record_block_proposed(&v, 5_000);
        tracker.record_block_proposed(&v, 15_000);
        tracker.record_vote(&v);
        tracker.record_vote_expected(&v);
        tracker.record_vote_expected(&v);

        let m = tracker.get_metrics(&v).unwrap();
        assert_eq!(m.blocks_proposed, 2);
        assert_eq!(m.total_cu_proposed, 20_000);
        assert_eq!(m.votes_cast, 1);
        assert_eq!(m.votes_expected, 2);
    }

    #[test]
    fn test_performance_score() {
        let mut m = EpochMetrics::default();
        m.votes_cast = 9;
        m.votes_expected = 10;
        m.blocks_proposed = 5;
        m.total_cu_proposed = 50_000; // avg 10,000 CU → CU score = 1.0
        m.total_inclusion_latency_ms = 5_000;
        m.latency_samples = 5; // avg 1000ms → latency score = 0.5

        let score = m.performance_score();
        // uptime = 0.9, cu = 1.0, latency = 0.5
        // score = 0.5*0.9 + 0.3*1.0 + 0.2*0.5 = 0.45 + 0.3 + 0.1 = 0.85
        assert!((score - 0.85).abs() < 0.001);
    }

    #[test]
    fn test_uptime_zero_expected() {
        let m = EpochMetrics::default();
        assert_eq!(m.uptime(), 0.0);
    }

    #[test]
    fn test_finalize_epoch_resets() {
        let mut tracker = ValidatorPerformanceTracker::new();
        let v = addr(1);
        tracker.record_vote(&v);

        let completed = tracker.finalize_epoch(1);
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].0, v);
        assert_eq!(completed[0].1.votes_cast, 1);

        // After finalize, metrics are empty
        assert!(tracker.get_metrics(&v).is_none());
        assert_eq!(tracker.current_epoch(), 1);
    }

    #[test]
    fn test_record_to_persistence() {
        let mut tracker = ValidatorPerformanceTracker::new();
        let v = addr(1);

        tracker.record_block_proposed(&v, 10_000);
        tracker.record_vote(&v);
        tracker.record_vote_expected(&v);
        tracker.record_checkpoint_signature(&v);

        let completed = tracker.finalize_epoch(5);
        let record = ValidatorPerformanceRecord::from_metrics(5, v, &completed[0].1, 1_000_000);

        assert_eq!(record.epoch, 5);
        assert_eq!(record.validator, v);
        assert_eq!(record.blocks_proposed, 1);
        assert_eq!(record.votes_cast, 1);
        assert_eq!(record.votes_expected, 1);
        assert_eq!(record.checkpoint_signatures, 1);
        assert_eq!(record.epoch_reward, 1_000_000);
        assert!((record.performance_score - 1.0).abs() < 0.001); // perfect score
        assert!((record.uptime - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_shared_tracker() {
        let tracker = SharedValidatorPerformanceTracker::new();
        let v = addr(1);

        tracker.record_block_proposed(&v, 5_000);
        tracker.record_vote(&v);

        let m = tracker.get_metrics(&v).unwrap();
        assert_eq!(m.blocks_proposed, 1);
        assert_eq!(m.votes_cast, 1);

        let completed = tracker.finalize_epoch(1);
        assert_eq!(completed.len(), 1);
        assert!(tracker.get_metrics(&v).is_none());
    }
}
