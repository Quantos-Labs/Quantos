//! # Anti-Spam: Sliding Window with Exponential Decay
//!
//! Solves the EOS CPU/REX problem: inside a quota, spamming is free.
//!
//! ## Mechanism
//!
//! Instead of a fixed epoch quota, the effective quota decays exponentially
//! based on recent activity within a sliding window:
//!
//! ```text
//! quota_effective(t) = quota_base × e^(-λ × tx_count_window)
//! ```
//!
//! - Heavy user → quota decays within the window → marginal cost increases
//! - Inactive for WINDOW_SECS → quota fully restored
//! - No secondary market: quota is consumed by real activity, not lent
//!
//! ## Why This Differs from EOS
//!
//! EOS had a **static** per-epoch quota. Once you bought/rented enough stake,
//! spamming within that quota was free. Here the **marginal cost increases**
//! with each transaction within the window.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::types::Address;

/// Sliding window duration (seconds).
pub const WINDOW_SECS: u64 = 60;

/// Decay constant λ. Higher = faster quota decay under spam.
/// λ = 0.1 means 10 txs in the window reduces quota to e^(-1) ≈ 37%.
pub const DECAY_LAMBDA: f64 = 0.1;

/// Maximum tx count tracked in the window (memory cap).
pub const MAX_WINDOW_ENTRIES: usize = 10_000;

/// Minimum effective quota ratio (floor, prevents total lockout).
pub const MIN_QUOTA_RATIO: f64 = 0.05;

/// A single transaction event in the window.
#[derive(Clone, Debug)]
struct TxEvent {
    /// When this transaction was submitted
    timestamp: Instant,
    /// CU consumed by this transaction
    cu: u64,
}

/// Per-address sliding window state.
#[derive(Debug)]
struct WindowState {
    /// Recent transactions in the window
    events: VecDeque<TxEvent>,
    /// Sum of CU in the current window
    window_cu: u64,
    /// Transaction count in the current window
    window_tx_count: u64,
}

impl WindowState {
    fn new() -> Self {
        Self {
            events: VecDeque::new(),
            window_cu: 0,
            window_tx_count: 0,
        }
    }

    /// Evicts events older than WINDOW_SECS.
    fn evict_old(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(WINDOW_SECS);
        while let Some(front) = self.events.front() {
            if front.timestamp < cutoff {
                let evicted = self.events.pop_front().unwrap();
                self.window_cu = self.window_cu.saturating_sub(evicted.cu);
                self.window_tx_count = self.window_tx_count.saturating_sub(1);
            } else {
                break;
            }
        }
    }

    /// Records a new transaction.
    fn record(&mut self, cu: u64) {
        // Evict stale entries first
        self.evict_old();

        // Cap memory
        if self.events.len() >= MAX_WINDOW_ENTRIES {
            if let Some(front) = self.events.pop_front() {
                self.window_cu = self.window_cu.saturating_sub(front.cu);
                self.window_tx_count = self.window_tx_count.saturating_sub(1);
            }
        }

        self.events.push_back(TxEvent { timestamp: Instant::now(), cu });
        self.window_cu = self.window_cu.saturating_add(cu);
        self.window_tx_count += 1;
    }

    /// Computes the effective quota ratio using exponential decay.
    ///
    /// ratio = max(MIN_QUOTA_RATIO, e^(-λ × tx_count_window))
    fn effective_ratio(&mut self) -> f64 {
        self.evict_old();
        let ratio = (-DECAY_LAMBDA * self.window_tx_count as f64).exp();
        ratio.max(MIN_QUOTA_RATIO)
    }
}

/// Anti-spam engine using sliding window + exponential decay.
///
/// Thread-safe: uses `DashMap` internally.
pub struct AntiSpamEngine {
    /// Per-address window state
    windows: Arc<DashMap<Address, WindowState>>,
}

impl AntiSpamEngine {
    pub fn new() -> Self {
        Self {
            windows: Arc::new(DashMap::new()),
        }
    }

    /// Computes the effective quota for an address given its base quota.
    ///
    /// Returns `quota_base × decay_ratio` where decay_ratio ∈ [MIN_QUOTA_RATIO, 1.0].
    pub fn effective_quota(&self, addr: &Address, quota_base: u64) -> u64 {
        let mut entry = self.windows
            .entry(*addr)
            .or_insert_with(WindowState::new);

        let ratio = entry.effective_ratio();
        let effective = (quota_base as f64 * ratio).round() as u64;

        debug!(
            addr = %hex::encode(addr),
            quota_base,
            ratio,
            effective,
            window_txs = entry.window_tx_count,
            "Anti-spam effective quota"
        );

        effective
    }

    /// Records a consumed transaction for an address.
    /// Must be called after a successful quota check.
    pub fn record_tx(&self, addr: &Address, cu: u64) {
        self.windows
            .entry(*addr)
            .or_insert_with(WindowState::new)
            .record(cu);
    }

    /// Returns the current window transaction count for an address.
    pub fn window_tx_count(&self, addr: &Address) -> u64 {
        self.windows
            .get(addr)
            .map(|w| w.window_tx_count)
            .unwrap_or(0)
    }

    /// Returns the current effective ratio for an address (for metrics).
    pub fn effective_ratio(&self, addr: &Address) -> f64 {
        self.windows
            .get_mut(addr)
            .map(|mut w| w.effective_ratio())
            .unwrap_or(1.0)
    }

    /// Detects suspected spammers (window_tx_count > threshold).
    pub fn suspected_spammers(&self, threshold: u64) -> Vec<(Address, u64)> {
        let mut result = Vec::new();

        for mut entry in self.windows.iter_mut() {
            entry.evict_old();
            if entry.window_tx_count > threshold {
                result.push((*entry.key(), entry.window_tx_count));
                warn!(
                    addr = %hex::encode(entry.key()),
                    count = entry.window_tx_count,
                    "Suspected spammer detected"
                );
            }
        }

        result
    }
}

impl Default for AntiSpamEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_activity_full_quota() {
        let engine = AntiSpamEngine::new();
        let addr = [1u8; 20];
        let base = 100_000u64;

        // No activity → ratio = 1.0 → effective = base
        let effective = engine.effective_quota(&addr, base);
        assert_eq!(effective, base);
    }

    #[test]
    fn test_heavy_spam_decays_quota() {
        let engine = AntiSpamEngine::new();
        let addr = [2u8; 20];
        let base = 100_000u64;

        // Simulate 50 transactions
        for _ in 0..50 {
            engine.record_tx(&addr, 1000);
        }

        let effective = engine.effective_quota(&addr, base);

        // e^(-0.1 * 50) = e^(-5) ≈ 0.0067 → clamped to MIN_QUOTA_RATIO = 5%
        assert!(effective <= (base as f64 * 0.07) as u64);
        assert!(effective >= (base as f64 * MIN_QUOTA_RATIO * 0.99) as u64);
    }

    #[test]
    fn test_moderate_activity_partial_decay() {
        let engine = AntiSpamEngine::new();
        let addr = [3u8; 20];
        let base = 100_000u64;

        // 10 transactions → e^(-1) ≈ 37%
        for _ in 0..10 {
            engine.record_tx(&addr, 500);
        }

        let effective = engine.effective_quota(&addr, base);
        let expected = (base as f64 * (-DECAY_LAMBDA * 10.0_f64).exp()) as u64;

        assert!((effective as i64 - expected as i64).abs() < 100);
    }

    #[test]
    fn test_suspected_spammer_detection() {
        let engine = AntiSpamEngine::new();
        let spammer = [9u8; 20];

        for _ in 0..200 {
            engine.record_tx(&spammer, 100);
        }

        let spammers = engine.suspected_spammers(100);
        assert!(spammers.iter().any(|(a, _)| a == &spammer));
    }
}
