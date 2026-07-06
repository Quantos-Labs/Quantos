//! # Tokenomics — Validator Security Budget
//!
//! Solves the long-term security budget problem: zero fees means validators
//! are funded 100% by inflation, which is unsustainable and dilutive.
//!
//! ## 3-Source Revenue Model
//!
//! Validator rewards come from three sources:
//!
//! 1. **Targeted inflation** — 3-5% annual, declines as rent grows
//! 2. **State rent** — grows with adoption, replaces inflation progressively
//! 3. **Slash redistribution** — slashed stake redistributed to honest validators
//!
//! ## Inflation Schedule
//!
//! ```text
//! inflation(t) = max(MIN_INFLATION, BASE_INFLATION × (1 - staking_rate / TARGET_STAKING_RATE))
//! ```
//!
//! - Low staking → high inflation (incentivize staking)
//! - High staking → low inflation (sustainable)
//! - At full adoption, rent covers validator costs → inflation → MIN_INFLATION
//!
//! ## Token Supply
//!
//! - Initial supply: 1,000,000,000 QTS (1B)
//! - Annual emission: variable (3-5% initially, declining)
//! - Burn: 20% of state rent collected each epoch (deflationary pressure)
//!
//! ## References
//!
//! - Polkadot NPoS (Nakov et al.): variable inflation targeting 75% staking rate
//! - Ethereum post-merge: base fee burn (EIP-1559) as deflationary mechanism

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info};

// ── Supply constants ──────────────────────────────────────────────────────────

/// Initial total supply of QTS tokens.
pub const INITIAL_SUPPLY: u128 = 1_000_000_000;

/// Target staking rate (67% of supply staked = optimal security).
pub const TARGET_STAKING_RATE: f64 = 0.67;

/// Maximum annual inflation (applied at staking_rate = 0).
pub const MAX_ANNUAL_INFLATION: f64 = 0.05; // 5%

/// Minimum annual inflation (floor — never drops below this).
pub const MIN_ANNUAL_INFLATION: f64 = 0.01; // 1%

/// Fraction of rent burned each epoch (deflationary).
pub const RENT_BURN_RATIO: f64 = 0.20;

/// Fraction of slashed stake redistributed to honest validators.
pub const SLASH_VALIDATOR_SHARE: f64 = 0.80;

/// Fraction of slashed stake burned.
pub const SLASH_BURN_RATIO: f64 = 0.20;

/// Slots per epoch (200ms/slot × 43200 slots = ~2.4h per epoch).
pub const SLOTS_PER_EPOCH: u64 = 43_200;

/// Epochs per year (365.25 days / 2.4h).
pub const EPOCHS_PER_YEAR: u64 = 3_652;

// ── Epoch reward computation ──────────────────────────────────────────────────

/// Computes the current annual inflation rate based on staking rate.
///
/// Formula: inflation = max(MIN, BASE × (1 - staking_rate / TARGET_STAKING_RATE))
///
/// - staking_rate = 0.00 → inflation = MAX_ANNUAL_INFLATION (5%)
/// - staking_rate = 0.67 → inflation = MIN_ANNUAL_INFLATION (1%)
/// - staking_rate > 0.67 → inflation = MIN_ANNUAL_INFLATION (floor)
pub fn annual_inflation_rate(staking_rate: f64) -> f64 {
    let base = MAX_ANNUAL_INFLATION * (1.0 - (staking_rate / TARGET_STAKING_RATE).min(1.0));
    base.max(MIN_ANNUAL_INFLATION)
}

/// Computes the inflation emission for one epoch.
///
/// epoch_emission = total_supply × annual_inflation / epochs_per_year
pub fn epoch_inflation_emission(total_supply: u128, staking_rate: f64) -> u128 {
    let rate = annual_inflation_rate(staking_rate);
    let annual_emission = (total_supply as f64 * rate).round() as u128;
    annual_emission / EPOCHS_PER_YEAR as u128
}

/// Full epoch reward for validators from all 3 sources.
#[derive(Clone, Debug)]
pub struct EpochReward {
    /// Source 1: inflation-based emission
    pub inflation_emission: u128,
    /// Source 2: state rent redistribution (after burn)
    pub rent_share: u128,
    /// Source 3: slash redistribution
    pub slash_share: u128,
    /// Total burned this epoch
    pub total_burned: u128,
    /// Annual inflation rate at time of computation
    pub inflation_rate: f64,
}

impl EpochReward {
    /// Total reward available to distribute to validators.
    pub fn total_validator_reward(&self) -> u128 {
        self.inflation_emission
            .saturating_add(self.rent_share)
            .saturating_add(self.slash_share)
    }
}

/// Per-validator reward based on stake weight and performance.
#[derive(Clone, Debug)]
pub struct ValidatorEpochReward {
    /// Validator address
    pub validator: [u8; 20],
    /// Stake weight (fraction of total stake)
    pub stake_weight: f64,
    /// Performance score [0.0, 1.0]
    pub performance: f64,
    /// Reward earned this epoch
    pub reward: u128,
}

/// Tokenomics engine — computes epoch rewards and manages supply.
pub struct TokenomicsEngine {
    /// Current total supply (mutable: inflation adds, burns remove)
    total_supply: Arc<AtomicU64>,
    /// Current total staked amount
    total_staked: Arc<AtomicU64>,
    /// Epoch counter
    current_epoch: Arc<AtomicU64>,
    /// Cumulative burned (for analytics)
    total_burned_all_time: Arc<AtomicU64>,
}

impl TokenomicsEngine {
    pub fn new(initial_supply: u64, initial_staked: u64) -> Self {
        Self {
            total_supply: Arc::new(AtomicU64::new(initial_supply)),
            total_staked: Arc::new(AtomicU64::new(initial_staked)),
            current_epoch: Arc::new(AtomicU64::new(0)),
            total_burned_all_time: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Returns current staking rate.
    pub fn staking_rate(&self) -> f64 {
        let supply = self.total_supply.load(Ordering::Relaxed) as f64;
        let staked = self.total_staked.load(Ordering::Relaxed) as f64;
        if supply == 0.0 { return 0.0; }
        (staked / supply).min(1.0)
    }

    /// Computes epoch rewards given rent collected and slashes.
    ///
    /// # Arguments
    /// - `rent_collected_cu`: total CU collected as rent this epoch
    /// - `slash_amount`: total QTS slashed from validators this epoch
    /// - `cu_to_qts`: conversion rate (CU → QTS, network-defined)
    pub fn compute_epoch_reward(
        &self,
        rent_collected_cu: u64,
        slash_amount: u128,
        cu_to_qts: f64,
    ) -> EpochReward {
        let supply = self.total_supply.load(Ordering::Relaxed) as u128;
        let staking_rate = self.staking_rate();

        // Source 1: Inflation
        let inflation_emission = epoch_inflation_emission(supply, staking_rate);

        // Source 2: Rent (20% burned, 80% to validators)
        let rent_qts = (rent_collected_cu as f64 * cu_to_qts) as u128;
        let rent_burned = (rent_qts as f64 * RENT_BURN_RATIO).round() as u128;
        let rent_share = rent_qts.saturating_sub(rent_burned);

        // Source 3: Slash redistribution (80% to validators, 20% burned)
        let slash_burned = (slash_amount as f64 * SLASH_BURN_RATIO).round() as u128;
        let slash_share = (slash_amount as f64 * SLASH_VALIDATOR_SHARE).round() as u128;

        // Total burned this epoch
        let total_burned = rent_burned.saturating_add(slash_burned);

        let reward = EpochReward {
            inflation_emission,
            rent_share,
            slash_share,
            total_burned,
            inflation_rate: annual_inflation_rate(staking_rate),
        };

        info!(
            epoch = self.current_epoch.load(Ordering::Relaxed),
            inflation_rate = reward.inflation_rate,
            inflation_emission,
            rent_share,
            slash_share,
            total_burned,
            total_validator_reward = reward.total_validator_reward(),
            "Epoch reward computed"
        );

        reward
    }

    /// Distributes epoch rewards to validators proportional to stake × performance.
    pub fn distribute_epoch_reward(
        &self,
        epoch_reward: &EpochReward,
        validators: &[([u8; 20], u128, f64)], // (address, stake, performance)
        total_stake: u128,
    ) -> Vec<ValidatorEpochReward> {
        let total_reward = epoch_reward.total_validator_reward();
        let mut distributions = Vec::new();

        for (addr, stake, performance) in validators {
            let stake_weight = if total_stake == 0 {
                0.0
            } else {
                *stake as f64 / total_stake as f64
            };

            // Reward = total_reward × stake_weight × performance
            let raw_reward = (total_reward as f64 * stake_weight * performance.clamp(0.0, 1.0))
                .round() as u128;

            debug!(
                validator = %hex::encode(addr),
                stake_weight,
                performance,
                reward = raw_reward,
                "Validator epoch reward"
            );

            distributions.push(ValidatorEpochReward {
                validator: *addr,
                stake_weight,
                performance: *performance,
                reward: raw_reward,
            });
        }

        distributions
    }

    /// Applies epoch: mints inflation, burns rent/slash, advances epoch counter.
    pub fn apply_epoch(&self, epoch_reward: &EpochReward) {
        let epoch = self.current_epoch.fetch_add(1, Ordering::Relaxed) + 1;

        // Mint inflation
        let mint = epoch_reward.inflation_emission as u64;
        self.total_supply.fetch_add(mint, Ordering::Relaxed);

        // Burn
        let burn = epoch_reward.total_burned as u64;
        let supply = self.total_supply.load(Ordering::Relaxed);
        self.total_supply.store(supply.saturating_sub(burn), Ordering::Relaxed);
        self.total_burned_all_time.fetch_add(burn, Ordering::Relaxed);

        info!(
            epoch,
            minted = mint,
            burned = burn,
            new_supply = self.total_supply.load(Ordering::Relaxed),
            total_burned_all_time = self.total_burned_all_time.load(Ordering::Relaxed),
            "Epoch applied"
        );
    }

    pub fn total_supply(&self) -> u64 {
        self.total_supply.load(Ordering::Relaxed)
    }

    pub fn total_staked(&self) -> u64 {
        self.total_staked.load(Ordering::Relaxed)
    }

    pub fn update_total_staked(&self, staked: u64) {
        self.total_staked.store(staked, Ordering::Relaxed);
    }

    pub fn total_burned_all_time(&self) -> u64 {
        self.total_burned_all_time.load(Ordering::Relaxed)
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch.load(Ordering::Relaxed)
    }
}

// ── Sustainability metrics ────────────────────────────────────────────────────

/// Reports the long-term sustainability of validator rewards.
#[derive(Clone, Debug)]
pub struct SustainabilityReport {
    /// Annual inflation rate
    pub annual_inflation: f64,
    /// Staking rate
    pub staking_rate: f64,
    /// Fraction of validator revenue from rent (not inflation)
    pub rent_coverage: f64,
    /// Net annual supply change (inflation - burn)
    pub net_annual_change_pct: f64,
    /// Estimated years until rent covers 50% of rewards
    pub years_to_rent_parity: Option<f64>,
}

impl SustainabilityReport {
    pub fn compute(
        inflation_emission: u128,
        rent_share: u128,
        slash_share: u128,
        total_burned: u128,
        staking_rate: f64,
        total_supply: u128,
    ) -> Self {
        let total_reward = inflation_emission + rent_share + slash_share;
        let rent_coverage = if total_reward == 0 {
            0.0
        } else {
            (rent_share + slash_share) as f64 / total_reward as f64
        };

        let annual_inflation = annual_inflation_rate(staking_rate);

        // Annual burn estimate
        let annual_burn_epoch = total_burned as f64 * EPOCHS_PER_YEAR as f64;
        let annual_inflation_abs = total_supply as f64 * annual_inflation;
        let net_change = (annual_inflation_abs - annual_burn_epoch) / total_supply as f64;

        // Simple linear estimate for rent parity
        let years_to_rent_parity = if rent_coverage >= 0.5 {
            Some(0.0)
        } else if rent_share > 0 {
            let years = (0.5 - rent_coverage) / (rent_share as f64 / inflation_emission as f64 * 0.3);
            Some(years.max(0.0))
        } else {
            None
        };

        Self {
            annual_inflation,
            staking_rate,
            rent_coverage,
            net_annual_change_pct: net_change * 100.0,
            years_to_rent_parity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inflation_at_zero_staking() {
        // staking = 0 → inflation = MAX (5%)
        let rate = annual_inflation_rate(0.0);
        assert!((rate - MAX_ANNUAL_INFLATION).abs() < 1e-9);
    }

    #[test]
    fn test_inflation_at_target_staking() {
        // staking = TARGET → inflation = MIN (1%)
        let rate = annual_inflation_rate(TARGET_STAKING_RATE);
        assert!((rate - MIN_ANNUAL_INFLATION).abs() < 1e-9);
    }

    #[test]
    fn test_inflation_above_target_clamped() {
        // staking > TARGET → inflation = MIN (floor)
        let rate = annual_inflation_rate(0.9);
        assert!((rate - MIN_ANNUAL_INFLATION).abs() < 1e-9);
    }

    #[test]
    fn test_epoch_emission_reasonable() {
        // At 50% staking: ~3% annual / 3652 epochs ≈ 0.00082% per epoch
        let emission = epoch_inflation_emission(INITIAL_SUPPLY, 0.5);
        let expected = (INITIAL_SUPPLY as f64 * 0.025 / EPOCHS_PER_YEAR as f64) as u128;
        // Allow ±10% tolerance
        assert!((emission as i128 - expected as i128).unsigned_abs() < expected / 10);
    }

    #[test]
    fn test_three_source_reward() {
        let engine = TokenomicsEngine::new(1_000_000_000, 500_000_000);
        let reward = engine.compute_epoch_reward(1_000_000, 50_000, 0.001);

        assert!(reward.inflation_emission > 0);
        assert!(reward.total_validator_reward() > 0);
        // Burn should be positive (from rent)
        assert!(reward.total_burned > 0);
    }

    #[test]
    fn test_apply_epoch_mint_and_burn() {
        let engine = TokenomicsEngine::new(1_000_000_000, 670_000_000);
        let initial_supply = engine.total_supply();

        let reward = engine.compute_epoch_reward(5_000_000, 0, 0.001);
        engine.apply_epoch(&reward);

        // Supply increased by inflation, decreased by burn
        let net = reward.inflation_emission.saturating_sub(reward.total_burned) as u64;
        assert_eq!(engine.total_supply(), initial_supply + net as u64);
    }
}
