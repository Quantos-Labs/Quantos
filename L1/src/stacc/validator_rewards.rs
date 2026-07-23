// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

/// Validator rewards without fees (inflation-only).
///
/// This module provides a hookable interface; full economics are chain-specific.

#[derive(Clone, Debug)]
pub struct PerformanceScore {
    pub uptime: f64,
    pub block_cu_utilization: f64,
    pub inclusion_latency_ms: f64,
}

impl PerformanceScore {
    pub fn score(&self) -> f64 {
        // Simple bounded blend.
        let u = self.uptime.clamp(0.0, 1.0);
        let cu = self.block_cu_utilization.clamp(0.0, 1.0);
        // Lower latency is better; map [0..1000ms] => [1..0.5]
        let lat = (1.0 - (self.inclusion_latency_ms / 1000.0).clamp(0.0, 1.0) * 0.5).clamp(0.5, 1.0);
        (0.5 * u + 0.4 * cu + 0.1 * lat).clamp(0.0, 1.0)
    }
}

pub fn reward(base_inflation_reward: u64, perf: &PerformanceScore) -> u64 {
    (base_inflation_reward as f64 * perf.score()).round().clamp(0.0, u64::MAX as f64) as u64
}

