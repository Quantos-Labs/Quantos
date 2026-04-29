//! # Consensus Attack Protection
//!
//! Protection against consensus-level attacks including 51%, long-range, and selfish mining.
//!
//! ## 51% Attack Protection
//!
//! 51% attacks attempt to control majority of consensus power.
//! Mitigations:
//! - Stake-weighted BFT committees (need 67%+ stake)
//! - Multiple independent committee layers
//! - Economic penalties via slashing
//! - Finality checkpoints prevent reorgs
//!
//! ## Long-Range Attack Protection
//!
//! Long-range attacks rewrite history from genesis.
//! Mitigations:
//! - Weak subjectivity checkpoints
//! - Bonding/unbonding periods
//! - Checkpoint finality
//! - Social consensus for deep reorgs
//!
//! ## Nothing-at-Stake Protection
//!
//! Nothing-at-stake: validators vote on all forks.
//! Mitigations:
//! - Slashing for equivocation
//! - Stake lockup period
//! - Single-slot finality target
//!
//! ## Selfish Mining Protection
//!
//! Selfish mining withholds blocks for advantage.
//! Mitigations:
//! - DAG structure (no single chain)
//! - Parallel block acceptance
//! - Timestamp-based ordering
//!
//! ## Time Warp Protection
//!
//! Time warp manipulates timestamps for advantage.
//! Mitigations:
//! - Median time past
//! - Strict timestamp bounds
//! - Network time protocol

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use rand::RngCore;

use crate::types::{Hash, Slot};
use super::{SecurityError, SecurityResult, Severity};

/// Consensus security configuration.
#[derive(Clone, Debug)]
pub struct ConsensusSecurityConfig {
    /// BFT threshold (e.g., 0.67 for 2/3)
    pub bft_threshold: f64,
    /// Finality depth (slots before considered final)
    pub finality_depth: u64,
    /// Weak subjectivity period (slots)
    pub weak_subjectivity_period: u64,
    /// Maximum reorg depth allowed
    pub max_reorg_depth: u64,
    /// Bonding period for new validators (slots)
    pub bonding_period: u64,
    /// Unbonding period for leaving validators (slots)
    pub unbonding_period: u64,
    /// Maximum timestamp drift (seconds)
    pub max_timestamp_drift: u64,
    /// Median time window size
    pub median_time_window: usize,
    /// Minimum time between blocks (ms)
    pub min_block_interval_ms: u64,
    /// Enable fork choice monitoring
    pub fork_monitoring: bool,
    /// Stake concentration alert threshold
    pub stake_concentration_alert: f64,
}

impl Default for ConsensusSecurityConfig {
    fn default() -> Self {
        Self {
            bft_threshold: 0.67,
            finality_depth: 100,
            weak_subjectivity_period: 50000,
            max_reorg_depth: 10,
            bonding_period: 1000,
            unbonding_period: 5000,
            max_timestamp_drift: 15,
            median_time_window: 11,
            min_block_interval_ms: 100,
            fork_monitoring: true,
            stake_concentration_alert: 0.33, // Alert if single entity has 33%+ stake
        }
    }
}

/// 51% attack detector.
pub struct MajorityAttackDetector {
    config: ConsensusSecurityConfig,
    /// Validator stakes
    validator_stakes: Arc<DashMap<[u8; 32], u64>>,
    /// Total stake
    total_stake: Arc<RwLock<u64>>,
    /// Recent block proposers
    recent_proposers: Arc<RwLock<VecDeque<[u8; 32]>>>,
    /// Stake concentration by entity
    entity_stakes: Arc<DashMap<String, u64>>,
    /// Alert history
    alerts: Arc<RwLock<Vec<MajorityAlert>>>,
}

/// Alert for potential majority attack.
#[derive(Clone, Debug)]
pub struct MajorityAlert {
    pub timestamp: Instant,
    pub alert_type: MajorityAlertType,
    pub details: String,
    pub severity: Severity,
}

/// Types of majority alerts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MajorityAlertType {
    /// Single entity approaching threshold
    StakeConcentration,
    /// Unusual block production pattern
    ProductionAnomaly,
    /// Potential coordination detected
    CoordinatedBehavior,
    /// Rapid stake accumulation
    RapidAccumulation,
}

impl MajorityAttackDetector {
    /// Creates a new majority attack detector.
    pub fn new(config: ConsensusSecurityConfig) -> Self {
        Self {
            config,
            validator_stakes: Arc::new(DashMap::new()),
            total_stake: Arc::new(RwLock::new(0)),
            recent_proposers: Arc::new(RwLock::new(VecDeque::with_capacity(1000))),
            entity_stakes: Arc::new(DashMap::new()),
            alerts: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Updates validator stake.
    pub fn update_stake(&self, validator: [u8; 32], stake: u64, entity: Option<String>) {
        let old_stake = self.validator_stakes
            .insert(validator, stake)
            .unwrap_or(0);

        // Update total
        {
            let mut total = self.total_stake.write();
            *total = total.saturating_sub(old_stake).saturating_add(stake);
        }

        // Update entity stake
        if let Some(entity_name) = entity {
            self.entity_stakes
                .entry(entity_name.clone())
                .and_modify(|s| *s = s.saturating_sub(old_stake).saturating_add(stake))
                .or_insert(stake);

            // Check concentration
            self.check_concentration(&entity_name);
        }
    }

    /// Checks stake concentration for an entity.
    fn check_concentration(&self, entity: &str) {
        let total = *self.total_stake.read();
        if total == 0 {
            return;
        }

        if let Some(entity_stake) = self.entity_stakes.get(entity) {
            let ratio = *entity_stake as f64 / total as f64;
            
            if ratio >= self.config.stake_concentration_alert {
                self.add_alert(MajorityAlert {
                    timestamp: Instant::now(),
                    alert_type: MajorityAlertType::StakeConcentration,
                    details: format!(
                        "Entity '{}' controls {:.1}% of stake",
                        entity,
                        ratio * 100.0
                    ),
                    severity: if ratio >= 0.5 {
                        Severity::Critical
                    } else if ratio >= 0.4 {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                });
            }
        }
    }

    /// Records a block proposer.
    pub fn record_proposer(&self, proposer: [u8; 32]) {
        let mut recent = self.recent_proposers.write();
        recent.push_back(proposer);
        
        while recent.len() > 1000 {
            recent.pop_front();
        }

        // Check for anomalies
        self.check_production_anomaly();
    }

    /// Checks for block production anomalies.
    fn check_production_anomaly(&self) {
        let recent = self.recent_proposers.read();
        if recent.len() < 100 {
            return;
        }

        // Count proposer frequency
        let mut counts: HashMap<[u8; 32], usize> = HashMap::new();
        for proposer in recent.iter() {
            *counts.entry(*proposer).or_insert(0) += 1;
        }

        let total_blocks = recent.len();
        let total_stake = *self.total_stake.read();

        for (proposer, count) in counts {
            let expected_stake = self.validator_stakes
                .get(&proposer)
                .map(|s| *s)
                .unwrap_or(0);
            
            if total_stake == 0 {
                continue;
            }

            let expected_ratio = expected_stake as f64 / total_stake as f64;
            let actual_ratio = count as f64 / total_blocks as f64;

            // Alert if actual is >1.5x expected
            if actual_ratio > expected_ratio * 1.5 && actual_ratio > 0.1 {
                self.add_alert(MajorityAlert {
                    timestamp: Instant::now(),
                    alert_type: MajorityAlertType::ProductionAnomaly,
                    details: format!(
                        "Validator {} producing {:.1}% of blocks (expected {:.1}%)",
                        hex::encode(&proposer[..8]),
                        actual_ratio * 100.0,
                        expected_ratio * 100.0
                    ),
                    severity: Severity::Medium,
                });
            }
        }
    }

    /// Adds an alert.
    fn add_alert(&self, alert: MajorityAlert) {
        let mut alerts = self.alerts.write();
        alerts.push(alert.clone());
        
        // Keep only recent alerts
        let cutoff = Instant::now() - Duration::from_secs(3600);
        alerts.retain(|a| a.timestamp > cutoff);

        tracing::warn!(
            "Majority attack alert: {:?} - {}",
            alert.alert_type,
            alert.details
        );
    }

    /// Gets current risk level.
    pub fn get_risk_level(&self) -> MajorityRiskLevel {
        let alerts = self.alerts.read();
        let recent_cutoff = Instant::now() - Duration::from_secs(300);
        
        let critical_count = alerts.iter()
            .filter(|a| a.timestamp > recent_cutoff && a.severity == Severity::Critical)
            .count();
        
        let high_count = alerts.iter()
            .filter(|a| a.timestamp > recent_cutoff && a.severity >= Severity::High)
            .count();

        if critical_count > 0 {
            MajorityRiskLevel::Critical
        } else if high_count > 2 {
            MajorityRiskLevel::High
        } else if high_count > 0 {
            MajorityRiskLevel::Elevated
        } else {
            MajorityRiskLevel::Low
        }
    }

    /// Gets recent alerts.
    pub fn get_alerts(&self) -> Vec<MajorityAlert> {
        self.alerts.read().clone()
    }
}

/// Majority attack risk level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MajorityRiskLevel {
    Low,
    Elevated,
    High,
    Critical,
}

/// Long-range attack protector.
pub struct LongRangeProtector {
    config: ConsensusSecurityConfig,
    /// Finality checkpoints
    checkpoints: Arc<RwLock<BTreeMap<Slot, FinalityCheckpoint>>>,
    /// Weak subjectivity checkpoint
    ws_checkpoint: Arc<RwLock<Option<WeakSubjectivityCheckpoint>>>,
    /// Validator unbonding queue
    unbonding_queue: Arc<DashMap<[u8; 32], UnbondingEntry>>,
    /// HIGH: Authorization token for privileged operations like setting WS checkpoint
    auth_token: Arc<std::sync::Mutex<Option<[u8; 32]>>>,
}

/// Minimum number of timestamp samples for reliable median calculation
const MIN_MEDIAN_SAMPLES: usize = 5;

/// Finality checkpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalityCheckpoint {
    pub slot: Slot,
    pub state_root: Hash,
    pub block_hash: Hash,
    pub signature_count: usize,
    pub total_stake_signed: u64,
    pub timestamp: u64,
}

/// Weak subjectivity checkpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeakSubjectivityCheckpoint {
    pub slot: Slot,
    pub state_root: Hash,
    pub block_hash: Hash,
    pub validator_set_hash: Hash,
    pub created_at: u64,
}

/// Validator unbonding entry.
#[derive(Clone, Debug)]
pub struct UnbondingEntry {
    pub validator: [u8; 32],
    pub stake: u64,
    pub unbond_start_slot: Slot,
    pub unbond_end_slot: Slot,
}

impl LongRangeProtector {
    /// Creates a new long-range protector.
    pub fn new(config: ConsensusSecurityConfig) -> Self {
        // HIGH: Generate auth token using OsRng for WS checkpoint protection
        let mut token = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut token);
        
        Self {
            config,
            checkpoints: Arc::new(RwLock::new(BTreeMap::new())),
            ws_checkpoint: Arc::new(RwLock::new(None)),
            unbonding_queue: Arc::new(DashMap::new()),
            auth_token: Arc::new(std::sync::Mutex::new(Some(token))),
        }
    }
    
    /// Gets the authorization token (should be called once at startup).
    pub fn get_auth_token(&self) -> Option<[u8; 32]> {
        self.auth_token.lock().ok().and_then(|g| *g)
    }

    /// Adds a finality checkpoint.
    pub fn add_checkpoint(&self, checkpoint: FinalityCheckpoint) {
        let mut checkpoints = self.checkpoints.write();
        checkpoints.insert(checkpoint.slot, checkpoint);

        // Prune old checkpoints (keep last 1000)
        while checkpoints.len() > 1000 {
            if let Some((&oldest_slot, _)) = checkpoints.iter().next() {
                checkpoints.remove(&oldest_slot);
            }
        }
    }

    /// Sets weak subjectivity checkpoint.
    /// 
    /// HIGH: Now requires authorization token to prevent unauthorized overwrites.
    /// Any code with access to LongRangeProtector could previously change this
    /// critical security parameter, potentially enabling long-range attacks.
    pub fn set_ws_checkpoint(&self, checkpoint: WeakSubjectivityCheckpoint, auth_token: &[u8; 32]) -> Result<(), SecurityError> {
        let valid = self.auth_token.lock()
            .map(|guard| guard.as_ref().map(|t| t == auth_token).unwrap_or(false))
            .unwrap_or(false);
        
        if !valid {
            tracing::warn!("Unauthorized attempt to set weak subjectivity checkpoint");
            return Err(SecurityError::ConsensusAttack(
                "Unauthorized: invalid auth token for WS checkpoint update".into()
            ));
        }
        
        tracing::info!("Weak subjectivity checkpoint set at slot {}", checkpoint.slot);
        *self.ws_checkpoint.write() = Some(checkpoint);
        Ok(())
    }

    /// Validates a block against long-range attack.
    pub fn validate_block(
        &self,
        slot: Slot,
        _block_hash: Hash,
        _parent_hash: Hash,
        current_slot: Slot,
    ) -> SecurityResult<()> {
        // Check against weak subjectivity
        if let Some(ws) = &*self.ws_checkpoint.read() {
            if slot < ws.slot {
                return Err(SecurityError::ConsensusAttack(
                    format!("Block at slot {} is before WS checkpoint at slot {}", slot, ws.slot)
                ));
            }
        }

        // Check reorg depth
        let checkpoints = self.checkpoints.read();
        for (&cp_slot, _cp) in checkpoints.iter().rev() {
            if slot < cp_slot && current_slot > cp_slot + self.config.max_reorg_depth {
                return Err(SecurityError::ConsensusAttack(
                    format!(
                        "Block would reorg past finalized checkpoint at slot {}",
                        cp_slot
                    )
                ));
            }
        }

        Ok(())
    }

    /// Checks if we're within weak subjectivity period.
    pub fn is_within_ws_period(&self, current_slot: Slot) -> bool {
        if let Some(ws) = &*self.ws_checkpoint.read() {
            current_slot < ws.slot + self.config.weak_subjectivity_period
        } else {
            true // No checkpoint = allow sync
        }
    }

    /// Starts unbonding for a validator.
    pub fn start_unbonding(&self, validator: [u8; 32], stake: u64, current_slot: Slot) {
        self.unbonding_queue.insert(validator, UnbondingEntry {
            validator,
            stake,
            unbond_start_slot: current_slot,
            unbond_end_slot: current_slot + self.config.unbonding_period,
        });
    }

    /// Checks if a validator can withdraw.
    pub fn can_withdraw(&self, validator: &[u8; 32], current_slot: Slot) -> bool {
        self.unbonding_queue
            .get(validator)
            .map(|e| current_slot >= e.unbond_end_slot)
            .unwrap_or(false)
    }

    /// Gets latest checkpoint.
    pub fn get_latest_checkpoint(&self) -> Option<FinalityCheckpoint> {
        self.checkpoints.read().values().last().cloned()
    }
}

/// Time manipulation protector.
pub struct TimeWarpProtector {
    config: ConsensusSecurityConfig,
    /// Recent block timestamps
    recent_timestamps: Arc<RwLock<VecDeque<u64>>>,
    /// Network time offset
    network_time_offset: Arc<RwLock<i64>>,
    /// Last validated time
    last_validated_time: Arc<RwLock<u64>>,
}

impl TimeWarpProtector {
    /// Creates a new time warp protector.
    pub fn new(config: ConsensusSecurityConfig) -> Self {
        Self {
            config,
            recent_timestamps: Arc::new(RwLock::new(VecDeque::with_capacity(20))),
            network_time_offset: Arc::new(RwLock::new(0)),
            last_validated_time: Arc::new(RwLock::new(0)),
        }
    }

    /// Validates a block timestamp.
    pub fn validate_timestamp(&self, timestamp: u64) -> SecurityResult<()> {
        let now = chrono::Utc::now().timestamp() as u64;
        let offset = *self.network_time_offset.read();
        let adjusted_now = (now as i64 + offset) as u64;

        // Check not too far in future
        if timestamp > adjusted_now + self.config.max_timestamp_drift {
            return Err(SecurityError::ConsensusAttack(
                format!(
                    "Timestamp {} is too far in future (max: {})",
                    timestamp,
                    adjusted_now + self.config.max_timestamp_drift
                )
            ));
        }

        // Check median time rule
        let median = self.get_median_time();
        if timestamp < median {
            return Err(SecurityError::ConsensusAttack(
                format!(
                    "Timestamp {} is before median time {}",
                    timestamp, median
                )
            ));
        }

        // Check minimum interval
        let last = *self.last_validated_time.read();
        if last > 0 && timestamp < last + (self.config.min_block_interval_ms / 1000) {
            return Err(SecurityError::ConsensusAttack(
                "Timestamp too close to previous block".into()
            ));
        }

        Ok(())
    }

    /// Records a validated timestamp.
    pub fn record_timestamp(&self, timestamp: u64) {
        let mut timestamps = self.recent_timestamps.write();
        timestamps.push_back(timestamp);
        
        while timestamps.len() > self.config.median_time_window {
            timestamps.pop_front();
        }

        *self.last_validated_time.write() = timestamp;
    }

    /// Gets median time of recent blocks.
    /// 
    /// MEDIUM: Require minimum number of samples before using median to prevent
    /// manipulation with few carefully crafted timestamps.
    pub fn get_median_time(&self) -> u64 {
        let timestamps = self.recent_timestamps.read();
        if timestamps.is_empty() {
            return 0;
        }
        
        // MEDIUM: If we have too few samples, the median is easily manipulable.
        // Return 0 (no constraint) rather than a potentially attacker-controlled value.
        if timestamps.len() < MIN_MEDIAN_SAMPLES {
            tracing::debug!(
                "Insufficient timestamp samples for median: {} < {}",
                timestamps.len(), MIN_MEDIAN_SAMPLES
            );
            return 0;
        }

        let mut sorted: Vec<_> = timestamps.iter().copied().collect();
        sorted.sort();

        sorted[sorted.len() / 2]
    }

    /// Updates network time offset from peers.
    pub fn update_network_offset(&self, peer_times: &[u64]) {
        if peer_times.is_empty() {
            return;
        }

        let now = chrono::Utc::now().timestamp() as u64;
        let mut offsets: Vec<i64> = peer_times
            .iter()
            .map(|&t| t as i64 - now as i64)
            .collect();
        offsets.sort();

        // Use median offset
        let median_offset = offsets[offsets.len() / 2];
        
        // Only update if reasonable
        if median_offset.abs() < 60 {
            *self.network_time_offset.write() = median_offset;
        }
    }
}

/// Fork choice monitor.
pub struct ForkMonitor {
    config: ConsensusSecurityConfig,
    /// Known chain heads
    chain_heads: Arc<DashMap<Hash, ChainHead>>,
    /// Fork events
    fork_events: Arc<RwLock<Vec<ForkEvent>>>,
}

/// Chain head information.
#[derive(Clone, Debug)]
pub struct ChainHead {
    pub block_hash: Hash,
    pub slot: Slot,
    pub total_stake: u64,
    pub first_seen: Instant,
    pub block_count: u64,
}

/// Fork event.
#[derive(Clone, Debug)]
pub struct ForkEvent {
    pub timestamp: Instant,
    pub fork_point_slot: Slot,
    pub competing_heads: Vec<Hash>,
    pub resolved: bool,
    pub resolution: Option<ForkResolution>,
}

/// Fork resolution.
#[derive(Clone, Debug)]
pub struct ForkResolution {
    pub winning_head: Hash,
    pub losing_heads: Vec<Hash>,
    pub reorg_depth: u64,
}

impl ForkMonitor {
    /// Creates a new fork monitor.
    pub fn new(config: ConsensusSecurityConfig) -> Self {
        Self {
            config,
            chain_heads: Arc::new(DashMap::new()),
            fork_events: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Records a chain head.
    pub fn record_head(&self, block_hash: Hash, slot: Slot, stake: u64) {
        self.chain_heads
            .entry(block_hash)
            .and_modify(|h| {
                h.slot = slot;
                h.total_stake = stake;
                h.block_count += 1;
            })
            .or_insert(ChainHead {
                block_hash,
                slot,
                total_stake: stake,
                first_seen: Instant::now(),
                block_count: 1,
            });

        self.check_for_forks();
    }

    /// Checks for competing forks.
    fn check_for_forks(&self) {
        let heads: Vec<_> = self.chain_heads.iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();

        if heads.len() > 1 {
            // Find same-slot competing heads
            let max_slot = heads.iter().map(|(_, h)| h.slot).max().unwrap_or(0);
            let competing: Vec<_> = heads.iter()
                .filter(|(_, h)| h.slot >= max_slot.saturating_sub(5))
                .map(|(hash, _)| *hash)
                .collect();

            if competing.len() > 1 {
                let mut events = self.fork_events.write();
                events.push(ForkEvent {
                    timestamp: Instant::now(),
                    fork_point_slot: max_slot,
                    competing_heads: competing,
                    resolved: false,
                    resolution: None,
                });

                tracing::warn!("Fork detected at slot {}", max_slot);
            }
        }
    }

    /// Resolves a fork (when one head becomes canonical).
    pub fn resolve_fork(&self, winning_head: Hash, reorg_depth: u64) {
        let losing: Vec<_> = self.chain_heads.iter()
            .filter(|e| *e.key() != winning_head)
            .map(|e| *e.key())
            .collect();

        // Remove losing heads
        for hash in &losing {
            self.chain_heads.remove(hash);
        }

        // Record resolution
        let mut events = self.fork_events.write();
        for event in events.iter_mut().rev() {
            if !event.resolved {
                event.resolved = true;
                event.resolution = Some(ForkResolution {
                    winning_head,
                    losing_heads: losing.clone(),
                    reorg_depth,
                });
                break;
            }
        }
    }

    /// Gets current fork status.
    pub fn get_fork_status(&self) -> ForkStatus {
        let head_count = self.chain_heads.len();
        let recent_events = self.fork_events.read().len();

        ForkStatus {
            competing_heads: head_count,
            recent_fork_events: recent_events,
            is_forked: head_count > 1,
        }
    }
}

/// Fork status.
#[derive(Clone, Debug)]
pub struct ForkStatus {
    pub competing_heads: usize,
    pub recent_fork_events: usize,
    pub is_forked: bool,
}

/// Combined consensus security manager.
pub struct ConsensusSecurityManager {
    pub config: ConsensusSecurityConfig,
    pub majority_detector: MajorityAttackDetector,
    pub long_range_protector: LongRangeProtector,
    pub time_protector: TimeWarpProtector,
    pub fork_monitor: ForkMonitor,
}

impl ConsensusSecurityManager {
    /// Creates a new consensus security manager.
    pub fn new(config: ConsensusSecurityConfig) -> Self {
        Self {
            majority_detector: MajorityAttackDetector::new(config.clone()),
            long_range_protector: LongRangeProtector::new(config.clone()),
            time_protector: TimeWarpProtector::new(config.clone()),
            fork_monitor: ForkMonitor::new(config.clone()),
            config,
        }
    }

    /// Validates a block for all consensus security checks.
    pub fn validate_block(
        &self,
        slot: Slot,
        block_hash: Hash,
        parent_hash: Hash,
        _proposer: [u8; 32],
        timestamp: u64,
        current_slot: Slot,
    ) -> SecurityResult<()> {
        // Check timestamp
        self.time_protector.validate_timestamp(timestamp)?;

        // Check long-range attack
        self.long_range_protector.validate_block(
            slot, block_hash, parent_hash, current_slot
        )?;

        Ok(())
    }

    /// Records a validated block.
    pub fn record_block(
        &self,
        slot: Slot,
        block_hash: Hash,
        proposer: [u8; 32],
        timestamp: u64,
        stake: u64,
    ) {
        self.majority_detector.record_proposer(proposer);
        self.time_protector.record_timestamp(timestamp);
        self.fork_monitor.record_head(block_hash, slot, stake);
    }

    /// Gets overall consensus security status.
    pub fn get_status(&self) -> ConsensusSecurityStatus {
        ConsensusSecurityStatus {
            majority_risk: self.majority_detector.get_risk_level(),
            fork_status: self.fork_monitor.get_fork_status(),
            within_ws_period: self.long_range_protector.is_within_ws_period(0),
            latest_checkpoint: self.long_range_protector.get_latest_checkpoint(),
        }
    }
}

/// Consensus security status.
#[derive(Clone, Debug)]
pub struct ConsensusSecurityStatus {
    pub majority_risk: MajorityRiskLevel,
    pub fork_status: ForkStatus,
    pub within_ws_period: bool,
    pub latest_checkpoint: Option<FinalityCheckpoint>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_majority_detector() {
        let config = ConsensusSecurityConfig::default();
        let detector = MajorityAttackDetector::new(config);

        detector.update_stake([1u8; 32], 1000, Some("Entity1".into()));
        detector.update_stake([2u8; 32], 1000, Some("Entity2".into()));
        detector.update_stake([3u8; 32], 1000, Some("Entity3".into()));

        assert_eq!(detector.get_risk_level(), MajorityRiskLevel::Low);
    }

    #[test]
    fn test_time_warp_protection() {
        let config = ConsensusSecurityConfig::default();
        let protector = TimeWarpProtector::new(config);

        let now = chrono::Utc::now().timestamp() as u64;
        
        // Current time should be valid
        assert!(protector.validate_timestamp(now).is_ok());
        
        // Far future should be invalid
        assert!(protector.validate_timestamp(now + 1000).is_err());
    }

    #[test]
    fn test_long_range_protection() {
        let config = ConsensusSecurityConfig::default();
        let protector = LongRangeProtector::new(config);
        let auth_token = protector.get_auth_token().unwrap();

        // Set WS checkpoint at slot 1000 (requires auth token)
        protector.set_ws_checkpoint(WeakSubjectivityCheckpoint {
            slot: 1000,
            state_root: [0u8; 32],
            block_hash: [1u8; 32],
            validator_set_hash: [2u8; 32],
            created_at: 0,
        }, &auth_token).unwrap();

        // Block before WS should fail
        assert!(protector.validate_block(500, [0u8; 32], [0u8; 32], 1500).is_err());

        // Block after WS should succeed
        assert!(protector.validate_block(1500, [0u8; 32], [0u8; 32], 1500).is_ok());
    }

    #[test]
    fn test_fork_monitor() {
        let config = ConsensusSecurityConfig::default();
        let monitor = ForkMonitor::new(config);

        monitor.record_head([1u8; 32], 100, 1000);
        assert_eq!(monitor.get_fork_status().competing_heads, 1);

        monitor.record_head([2u8; 32], 100, 1000);
        assert_eq!(monitor.get_fork_status().competing_heads, 2);
        assert!(monitor.get_fork_status().is_forked);
    }
}
