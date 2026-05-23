//! Operator-facing configuration for the L0 hub.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::l0::registry::TargetChainId;

/// Backoff parameters for the relay dispatcher.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayBackoff {
    /// Initial wait before the first retry.
    pub initial: Duration,
    /// Maximum wait between retries.
    pub max: Duration,
    /// Multiplicative factor applied at each retry.
    pub factor: f32,
    /// Maximum number of retries before giving up.
    pub max_retries: u32,
}

impl Default for RelayBackoff {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(250),
            max: Duration::from_secs(30),
            factor: 2.0,
            max_retries: 8,
        }
    }
}

impl RelayBackoff {
    /// Returns the delay to wait before the `attempt`-th retry (1-based).
    pub fn delay_for(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::from_millis(0);
        }
        let exp = (self.factor.max(1.0)).powi(attempt.saturating_sub(1) as i32);
        let raw = self.initial.as_millis() as f64 * exp as f64;
        let capped = raw.min(self.max.as_millis() as f64);
        Duration::from_millis(capped as u64)
    }
}

/// Per-target chain configuration knobs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetChainConfig {
    /// Identifier of the chain (must exist in the registry).
    pub chain_id: TargetChainId,
    /// Whether relaying to this chain is currently enabled.
    pub enabled: bool,
    /// Optional override for backoff per chain.
    pub backoff: Option<RelayBackoff>,
}

/// Global L0 configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct L0Config {
    /// Master switch. When `false`, no proof is produced or relayed.
    pub enabled: bool,
    /// Minimum stake ratio (numerator/denominator) required to emit a proof.
    /// Defaults to 2/3.
    pub stake_threshold_num: u128,
    /// Denominator of the stake threshold (see [`L0Config::stake_threshold_num`]).
    pub stake_threshold_den: u128,
    /// How often the hub builds an attestation, in slots.
    pub attestation_interval_slots: u64,
    /// Default backoff used when a target chain has no override.
    pub default_backoff: RelayBackoff,
    /// Per-chain configuration entries.
    pub targets: Vec<TargetChainConfig>,
    /// Whether to keep generated proofs in the local archive.
    pub archive_proofs: bool,
    /// Maximum number of proofs to keep in the in-memory archive.
    pub archive_capacity: usize,
}

impl Default for L0Config {
    fn default() -> Self {
        Self {
            enabled: false,
            stake_threshold_num: 2,
            stake_threshold_den: 3,
            attestation_interval_slots: 32,
            default_backoff: RelayBackoff::default(),
            targets: Vec::new(),
            archive_proofs: true,
            archive_capacity: 1024,
        }
    }
}

impl L0Config {
    /// Validates the configuration. Returns a descriptive error string
    /// when invariants are violated.
    pub fn validate(&self) -> Result<(), String> {
        if self.stake_threshold_den == 0 {
            return Err("stake_threshold_den must be non-zero".to_string());
        }
        if self.stake_threshold_num == 0 || self.stake_threshold_num > self.stake_threshold_den {
            return Err("stake_threshold_num must be within (0, stake_threshold_den]".to_string());
        }
        if self.attestation_interval_slots == 0 {
            return Err("attestation_interval_slots must be > 0".to_string());
        }
        if self.archive_capacity == 0 && self.archive_proofs {
            return Err("archive_capacity must be > 0 when archive_proofs is enabled".to_string());
        }
        Ok(())
    }

    /// Returns the threshold stake given the total stake of the active
    /// validator set.
    pub fn required_stake(&self, total_stake: u128) -> u128 {
        // ceil(total * num / den)
        let num = self.stake_threshold_num;
        let den = self.stake_threshold_den.max(1);
        total_stake
            .saturating_mul(num)
            .saturating_add(den - 1)
            / den
    }
}
