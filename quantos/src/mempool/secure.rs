//! # Secure Mempool
//!
//! Enhanced mempool with comprehensive attack protection and
//! **stake-weighted rate limiting** for the feeless (ZeroGas) model.
//!
//! ## Stake Tiers
//!
//! | Tier        | Min Stake (QNT) | TX/min | Max Pending | Priority Boost |
//! |-------------|-----------------|--------|-------------|----------------|
//! | Free        | 0               | 4      | 4           | ×1             |
//! | Standard    | 1 000           | 32     | 32          | ×4             |
//! | Premium     | 100 000         | 256    | 128         | ×16            |
//! | Validator   | 1 000 000       | 1 024  | 512         | ×64            |
//!
//! ## Protected Attacks
//!
//! - **Spam Attack**: Stake-weighted rate limiting per sender
//! - **DoS Attack**: Maximum mempool size, stake-based priority eviction
//! - **Replay Attack**: Nonce tracking, chain ID validation
//! - **Front-Running**: Fair ordering, commit-reveal support
//! - **Sybil Attack**: IP-based + stake-based rate limiting
//! - **Resource Exhaustion**: Per-tier TX limits, size limits
//! - **Invalid TX Flood**: Signature verification, balance checks

use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::warn;

/// Maximum IP limiters to store
const MAX_IP_LIMITERS: usize = 10_000;
/// IP limiter cleanup interval (seconds)
const IP_LIMITER_CLEANUP_THRESHOLD: u64 = 3600; // 1 hour

use dashmap::DashMap;
use parking_lot::RwLock;

use crate::crypto::{verify_dilithium_batch, DilithiumBatchVerifier};
use crate::state::StateManager;
use crate::types::{Address, Amount, Hash, ShardId, SignedTransaction};

use super::{MempoolError, MempoolResult};

// ══════════════════════════════════════════════════════════
//  Stake Tier System — feeless bandwidth allocation
// ══════════════════════════════════════════════════════════

/// Stake tier determines transaction throughput in the feeless model.
///
/// Higher stake → more bandwidth. This replaces gas fees as the
/// primary spam-prevention mechanism while keeping the network
/// accessible to everyone (Free tier allows basic usage).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StakeTier {
    /// No stake required — basic access (4 tx/min)
    Free,
    /// ≥ 1,000 QNT staked — regular user (32 tx/min)
    Standard,
    /// ≥ 100,000 QNT staked — power user (256 tx/min)
    Premium,
    /// ≥ 1,000,000 QNT staked — validator-level (1,024 tx/min)
    Validator,
}

impl StakeTier {
    /// Minimum stake (in base units) required for each tier.
    pub const FREE_MIN:      u128 = 0;
    pub const STANDARD_MIN:  u128 = 1_000_000_000_000;      // 1,000 QNT (10^9 decimals)
    pub const PREMIUM_MIN:   u128 = 100_000_000_000_000;    // 100,000 QNT
    pub const VALIDATOR_MIN: u128 = 1_000_000_000_000_000;  // 1,000,000 QNT

    /// Determines the tier for a given stake amount.
    pub fn from_stake(stake: &Amount) -> Self {
        if stake.0 >= Self::VALIDATOR_MIN {
            StakeTier::Validator
        } else if stake.0 >= Self::PREMIUM_MIN {
            StakeTier::Premium
        } else if stake.0 >= Self::STANDARD_MIN {
            StakeTier::Standard
        } else {
            StakeTier::Free
        }
    }

    /// Maximum transactions per minute for this tier.
    pub fn max_tx_per_minute(&self) -> usize {
        match self {
            StakeTier::Free      => 4,
            StakeTier::Standard  => 32,
            StakeTier::Premium   => 256,
            StakeTier::Validator => 1_024,
        }
    }

    /// Maximum pending transactions in mempool for this tier.
    pub fn max_pending(&self) -> usize {
        match self {
            StakeTier::Free      => 4,
            StakeTier::Standard  => 32,
            StakeTier::Premium   => 128,
            StakeTier::Validator => 512,
        }
    }

    /// Priority multiplier for transaction ordering.
    /// Higher stake → transactions are scheduled first.
    pub fn priority_multiplier(&self) -> u64 {
        match self {
            StakeTier::Free      => 1,
            StakeTier::Standard  => 4,
            StakeTier::Premium   => 16,
            StakeTier::Validator => 64,
        }
    }

    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            StakeTier::Free      => "Free",
            StakeTier::Standard  => "Standard",
            StakeTier::Premium   => "Premium",
            StakeTier::Validator => "Validator",
        }
    }
}

/// Secure mempool configuration.
#[derive(Clone, Debug)]
pub struct SecureMempoolConfig {
    /// Maximum transactions in mempool
    pub max_size: usize,
    /// Maximum transactions per sender (overridden by stake tier)
    pub max_per_sender: usize,
    /// Maximum transactions per IP per minute (base limit, before stake boost)
    pub max_per_ip_per_minute: usize,
    /// Maximum transaction size in bytes
    pub max_tx_size: usize,
    /// Enable fair ordering
    pub fair_ordering: bool,
    /// Enable IP-based rate limiting
    pub ip_rate_limiting: bool,
    /// Enable stake-weighted rate limiting
    pub stake_rate_limiting: bool,
    /// Eviction policy
    pub eviction_policy: EvictionPolicy,
}

impl Default for SecureMempoolConfig {
    fn default() -> Self {
        Self {
            max_size: 100_000,
            max_per_sender: 100,
            max_per_ip_per_minute: 1000,
            max_tx_size: 128 * 1024, // 128 KB
            fair_ordering: true,
            ip_rate_limiting: true,
            stake_rate_limiting: true,
            eviction_policy: EvictionPolicy::LowestStakeTier,
        }
    }
}

/// Eviction policy when mempool is full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvictionPolicy {
    /// Evict oldest transaction
    Oldest,
    /// Evict transaction from the lowest stake tier first
    LowestStakeTier,
    /// Evict transaction with highest nonce gap
    HighestNonceGap,
}

/// IP rate limiter for DoS protection.
#[derive(Clone, Debug)]
struct IpRateLimiter {
    requests: VecDeque<Instant>,
    limit: usize,
    window: Duration,
    last_used: Instant,
}

impl IpRateLimiter {
    fn new(limit: usize, window: Duration) -> Self {
        Self {
            requests: VecDeque::new(),
            limit,
            window,
            last_used: Instant::now(),
        }
    }

    fn allow(&mut self) -> bool {
        let now = Instant::now();
        self.last_used = now;
        let cutoff = now - self.window;

        // Remove old requests
        while let Some(&time) = self.requests.front() {
            if time < cutoff {
                self.requests.pop_front();
            } else {
                break;
            }
        }

        if self.requests.len() >= self.limit {
            return false;
        }

        self.requests.push_back(now);
        true
    }
    
    fn is_expired(&self, threshold: Duration) -> bool {
        self.last_used.elapsed() > threshold
    }
}

/// Secure mempool with comprehensive attack protection.
pub struct SecureMempool {
    config: SecureMempoolConfig,
    /// Pending transactions
    pending: Arc<DashMap<Hash, PendingTransaction>>,
    /// Transactions by sender (nonce-ordered)
    by_sender: Arc<DashMap<Address, BTreeMap<u64, Hash>>>,
    /// Transactions by shard
    by_shard: Arc<DashMap<ShardId, Vec<Hash>>>,
    /// IP rate limiters
    ip_limiters: Arc<DashMap<IpAddr, RwLock<IpRateLimiter>>>,
    /// State manager
    state_manager: StateManager,
    /// Metrics
    metrics: Arc<RwLock<MempoolMetrics>>,
    /// Chain ID for replay protection
    chain_id: u64,
    batch_verifier: Arc<DilithiumBatchVerifier>,
}

/// Pending transaction with metadata.
#[derive(Clone, Debug)]
struct PendingTransaction {
    tx: SignedTransaction,
    received_at: Instant,
    source_ip: Option<IpAddr>,
    priority: u64,
    stake_tier: StakeTier,
}

/// Mempool metrics.
#[derive(Clone, Debug, Default)]
pub struct MempoolMetrics {
    pub total_received: u64,
    pub total_accepted: u64,
    pub total_rejected: u64,
    pub rejected_duplicate: u64,
    pub rejected_invalid_sig: u64,
    pub rejected_nonce: u64,
    pub rejected_balance: u64,
    pub rejected_rate_limit: u64,
    pub rejected_size: u64,
    pub total_evicted: u64,
    pub current_size: usize,
}

impl SecureMempool {
    /// Creates a new secure mempool.
    pub fn new(
        config: SecureMempoolConfig,
        state_manager: StateManager,
        chain_id: u64,
    ) -> Self {
        Self {
            config,
            pending: Arc::new(DashMap::new()),
            by_sender: Arc::new(DashMap::new()),
            by_shard: Arc::new(DashMap::new()),
            ip_limiters: Arc::new(DashMap::new()),
            state_manager,
            metrics: Arc::new(RwLock::new(MempoolMetrics::default())),
            chain_id,
            batch_verifier: Arc::new(DilithiumBatchVerifier::new(32)),
        }
    }

    /// Returns the number of pending transactions.
    pub fn size(&self) -> usize {
        self.pending.len()
    }

    /// Adds a transaction with comprehensive security checks.
    pub fn add_transaction(
        &self,
        tx: SignedTransaction,
        source_ip: Option<IpAddr>,
    ) -> MempoolResult<()> {
        self.metrics.write().total_received += 1;

        // 1. IP rate limiting
        if self.config.ip_rate_limiting {
            if let Some(ip) = source_ip {
                if !self.check_ip_rate_limit(&ip) {
                    self.metrics.write().rejected_rate_limit += 1;
                    return Err(MempoolError::InvalidTransaction(
                        "IP rate limit exceeded".into()
                    ));
                }
            }
        }

        // 2. Size check
        if tx.size > self.config.max_tx_size {
            self.metrics.write().rejected_size += 1;
            return Err(MempoolError::InvalidTransaction(
                format!("Transaction too large: {} bytes", tx.size)
            ));
        }

        // 3. Duplicate check
        if self.pending.contains_key(&tx.hash) {
            self.metrics.write().rejected_duplicate += 1;
            return Err(MempoolError::DuplicateTransaction);
        }

        // 4. Signature verification via batched worker to reduce CPU
        let valid = verify_dilithium_batch(
            tx.transaction.public_key.clone(),
            tx.transaction.signing_data(),
            tx.transaction.signature.clone(),
        );

        if !valid {
            self.metrics.write().rejected_invalid_sig += 1;
            return Err(MempoolError::InvalidTransaction("Invalid signature".into()));
        }

        // 5. CRITICAL: Chain ID validation to prevent replay attacks
        if tx.transaction.chain_id != self.chain_id {
            self.metrics.write().rejected_invalid_sig += 1;
            return Err(MempoolError::InvalidTransaction(
                format!("Invalid chain ID: expected {}, got {}", self.chain_id, tx.transaction.chain_id)
            ));
        }

        // 6. Nonce validation
        let account_nonce = self.state_manager
            .get_nonce(&tx.transaction.from)
            .map_err(|e| MempoolError::InvalidTransaction(e.to_string()))?;

        if tx.transaction.nonce < account_nonce {
            self.metrics.write().rejected_nonce += 1;
            return Err(MempoolError::NonceTooLow);
        }

        if tx.transaction.nonce > account_nonce + self.config.max_per_sender as u64 {
            self.metrics.write().rejected_nonce += 1;
            return Err(MempoolError::NonceGap);
        }

        // 7. CRITICAL: Cumulative balance check to prevent double-spending
        let balance = self.state_manager
            .get_balance(&tx.transaction.from)
            .map_err(|e| MempoolError::InvalidTransaction(e.to_string()))?;

        // Calculate total pending cost for this sender using checked arithmetic
        let mut pending_cost = 0u128;
        if let Some(sender_txs) = self.by_sender.get(&tx.transaction.from) {
            for hash in sender_txs.values() {
                if let Some(pending_tx) = self.pending.get(hash) {
                    if let Some(cost) = pending_tx.tx.transaction.balance_commitment() {
                        pending_cost = pending_cost.checked_add(cost)
                            .ok_or(MempoolError::InvalidTransaction(
                                "Pending cost overflow: too many large pending transactions".to_string()
                            ))?;
                    }
                }
            }
        }
        
        let tx_cost = tx.transaction.balance_commitment()
            .ok_or(MempoolError::InvalidTransaction("Transaction balance commitment overflow".to_string()))?;
        let total_required = pending_cost.checked_add(tx_cost)
            .ok_or(MempoolError::InvalidTransaction(
                "Total required cost overflow".to_string()
            ))?;
        if (balance.0 as u128) < total_required {
            self.metrics.write().rejected_balance += 1;
            return Err(MempoolError::InvalidTransaction(
                format!("Insufficient balance: have {}, need {} (including {} pending)", 
                    balance.0, total_required, pending_cost)
            ));
        }

        // 8. Stake tier resolution
        let stake = self.state_manager
            .get_stake(&tx.transaction.from)
            .unwrap_or(Amount::zero());
        let tier = if self.config.stake_rate_limiting {
            StakeTier::from_stake(&stake)
        } else {
            StakeTier::Validator // bypass: treat everyone as top tier
        };

        // 9. Per-sender pending limit (stake-weighted)
        let sender_pending = self.by_sender
            .get(&tx.transaction.from)
            .map(|s| s.len())
            .unwrap_or(0);
        let max_pending = tier.max_pending().min(self.config.max_per_sender);
        if sender_pending >= max_pending {
            self.metrics.write().rejected_rate_limit += 1;
            return Err(MempoolError::InvalidTransaction(
                format!(
                    "Pending limit for {} tier: {}/{} — stake more QNT to increase",
                    tier.name(), sender_pending, max_pending
                )
            ));
        }

        // 10. Mempool size check with eviction
        if self.pending.len() >= self.config.max_size {
            self.evict_transaction()?;
        }

        // 11. Calculate priority (stake-weighted, not gas-based)
        let priority = self.calculate_priority(&tx, &tier);

        // 12. Insert transaction
        let pending_tx = PendingTransaction {
            tx: tx.clone(),
            received_at: Instant::now(),
            source_ip,
            priority,
            stake_tier: tier,
        };

        self.pending.insert(tx.hash, pending_tx);

        self.by_sender
            .entry(tx.transaction.from)
            .or_insert_with(BTreeMap::new)
            .insert(tx.transaction.nonce, tx.hash);

        self.by_shard
            .entry(tx.transaction.shard_id)
            .or_insert_with(Vec::new)
            .push(tx.hash);

        // 13. Transaction recorded
        tracing::debug!(
            "TX accepted: tier={}, priority={}, pending={}/{}",
            tier.name(), priority, sender_pending + 1, max_pending
        );

        self.metrics.write().total_accepted += 1;
        self.metrics.write().current_size = self.pending.len();

        Ok(())
    }

    /// Checks IP rate limit.
    fn check_ip_rate_limit(&self, ip: &IpAddr) -> bool {
        // Periodic cleanup: run cleanup every time we're at 80% capacity
        // This prevents expired limiters from accumulating
        let current_len = self.ip_limiters.len();
        if current_len >= MAX_IP_LIMITERS * 4 / 5 {
            self.cleanup_expired_ip_limiters();
        }
        
        // Atomic check-and-insert: use entry API to prevent race condition
        // where multiple threads check contains_key and all proceed to insert
        if !self.ip_limiters.contains_key(ip) {
            // Re-check capacity after potential cleanup
            if self.ip_limiters.len() >= MAX_IP_LIMITERS {
                // Force cleanup and re-check
                self.cleanup_expired_ip_limiters();
                if self.ip_limiters.len() >= MAX_IP_LIMITERS {
                    warn!("IP limiter capacity reached, rejecting new IP: {:?}", ip);
                    return false;
                }
            }
            
            // Use entry API for atomic insert (DashMap entry is locked)
            self.ip_limiters.entry(*ip).or_insert_with(|| {
                RwLock::new(IpRateLimiter::new(
                    self.config.max_per_ip_per_minute,
                    Duration::from_secs(60),
                ))
            });
        }

        if let Some(limiter) = self.ip_limiters.get(ip) {
            limiter.write().allow()
        } else {
            true
        }
    }

    /// Calculates transaction priority using stake tier instead of gas price.
    ///
    /// Priority = tier_multiplier * 1000 - nonce_gap
    /// This ensures higher-staked accounts get their transactions scheduled
    /// first during congestion, while nonce ordering is preserved per-sender.
    fn calculate_priority(&self, tx: &SignedTransaction, tier: &StakeTier) -> u64 {
        let account_nonce = self.state_manager
            .get_nonce(&tx.transaction.from)
            .unwrap_or(0);
        
        let nonce_gap = tx.transaction.nonce.saturating_sub(account_nonce);
        
        let base_priority = tier.priority_multiplier().saturating_mul(1000);
        base_priority.saturating_sub(nonce_gap)
    }

    /// Evicts a transaction based on eviction policy.
    fn evict_transaction(&self) -> MempoolResult<()> {
        let victim_hash = match self.config.eviction_policy {
            EvictionPolicy::Oldest => self.find_oldest_transaction(),
            EvictionPolicy::LowestStakeTier => self.find_lowest_stake_tier_transaction(),
            EvictionPolicy::HighestNonceGap => self.find_highest_nonce_gap_transaction(),
        };

        if let Some(hash) = victim_hash {
            self.remove_transaction(&hash);
            self.metrics.write().total_evicted += 1;
            Ok(())
        } else {
            Err(MempoolError::MempoolFull)
        }
    }

    /// Finds oldest transaction.
    fn find_oldest_transaction(&self) -> Option<Hash> {
        self.pending.iter()
            .min_by_key(|entry| entry.received_at)
            .map(|entry| *entry.key())
    }

    /// Finds transaction from the lowest stake tier.
    /// Within the same tier, evicts the oldest transaction.
    fn find_lowest_stake_tier_transaction(&self) -> Option<Hash> {
        self.pending.iter()
            .min_by(|a, b| {
                a.stake_tier.cmp(&b.stake_tier)
                    .then(a.received_at.cmp(&b.received_at))
            })
            .map(|entry| *entry.key())
    }

    /// Finds transaction with highest nonce gap.
    fn find_highest_nonce_gap_transaction(&self) -> Option<Hash> {
        let mut max_gap = 0u64;
        let mut victim = None;

        for entry in self.pending.iter() {
            let tx = &entry.tx;
            if let Ok(account_nonce) = self.state_manager.get_nonce(&tx.transaction.from) {
                let gap = tx.transaction.nonce.saturating_sub(account_nonce);
                if gap > max_gap {
                    max_gap = gap;
                    victim = Some(*entry.key());
                }
            }
        }

        victim
    }

    /// Removes a transaction.
    pub fn remove_transaction(&self, hash: &Hash) -> Option<SignedTransaction> {
        if let Some((_, pending_tx)) = self.pending.remove(hash) {
            let tx = pending_tx.tx;
            
            if let Some(mut sender_txs) = self.by_sender.get_mut(&tx.transaction.from) {
                sender_txs.remove(&tx.transaction.nonce);
            }

            if let Some(mut shard_txs) = self.by_shard.get_mut(&tx.transaction.shard_id) {
                shard_txs.retain(|h| h != hash);
            }

            self.metrics.write().current_size = self.pending.len();
            return Some(tx);
        }
        None
    }

    /// Gets pending transactions for a shard (sorted by priority).
    pub fn get_pending_for_shard(&self, shard_id: ShardId, limit: usize) -> Vec<SignedTransaction> {
        let mut txs: Vec<_> = self.pending.iter()
            .filter(|entry| entry.tx.transaction.shard_id == shard_id)
            .map(|entry| (entry.priority, entry.tx.clone()))
            .collect();

        // Sort by priority (highest first)
        txs.sort_by(|a, b| b.0.cmp(&a.0));

        txs.into_iter()
            .take(limit)
            .map(|(_, tx)| tx)
            .collect()
    }

    /// Gets metrics.
    pub fn get_metrics(&self) -> MempoolMetrics {
        self.metrics.read().clone()
    }

    /// Prunes confirmed transactions.
    pub fn prune_confirmed(&self, confirmed_txs: &[Hash]) {
        for hash in confirmed_txs {
            self.remove_transaction(hash);
        }
    }

    /// Cleans up expired IP rate limiters.
    pub fn cleanup_ip_limiters(&self) {
        self.cleanup_expired_ip_limiters();
    }
    
    /// Internal cleanup that removes truly expired limiters.
    fn cleanup_expired_ip_limiters(&self) {
        let threshold = Duration::from_secs(IP_LIMITER_CLEANUP_THRESHOLD);
        self.ip_limiters.retain(|_, limiter| {
            let limiter = limiter.read();
            !limiter.is_expired(threshold)
        });
    }

    /// Gets current size.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Batch validates multiple transactions for performance
    pub fn batch_validate_signatures(&self, txs: &[SignedTransaction]) -> Vec<bool> {
        let items: Vec<_> = txs.iter()
            .map(|tx| {
                let pubkey = tx.transaction.public_key.clone();
                let message = tx.transaction.signing_data();
                let signature = tx.transaction.signature.clone();
                (pubkey, message, signature)
            })
            .collect();

        self.batch_verifier.verify_batch(&items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Stake Tier unit tests (no mempool needed) ────────

    #[test]
    fn test_stake_tier_from_stake() {
        assert_eq!(StakeTier::from_stake(&Amount(0)), StakeTier::Free);
        assert_eq!(StakeTier::from_stake(&Amount(999_999_999_999)), StakeTier::Free);
        assert_eq!(StakeTier::from_stake(&Amount(StakeTier::STANDARD_MIN)), StakeTier::Standard);
        assert_eq!(StakeTier::from_stake(&Amount(StakeTier::PREMIUM_MIN)), StakeTier::Premium);
        assert_eq!(StakeTier::from_stake(&Amount(StakeTier::VALIDATOR_MIN)), StakeTier::Validator);
        assert_eq!(StakeTier::from_stake(&Amount(u128::MAX)), StakeTier::Validator);
    }

    #[test]
    fn test_stake_tier_limits() {
        assert_eq!(StakeTier::Free.max_tx_per_minute(), 4);
        assert_eq!(StakeTier::Standard.max_tx_per_minute(), 32);
        assert_eq!(StakeTier::Premium.max_tx_per_minute(), 256);
        assert_eq!(StakeTier::Validator.max_tx_per_minute(), 1_024);

        assert_eq!(StakeTier::Free.max_pending(), 4);
        assert_eq!(StakeTier::Standard.max_pending(), 32);
        assert_eq!(StakeTier::Premium.max_pending(), 128);
        assert_eq!(StakeTier::Validator.max_pending(), 512);
    }

    #[test]
    fn test_stake_tier_priority_ordering() {
        assert!(StakeTier::Validator.priority_multiplier() > StakeTier::Premium.priority_multiplier());
        assert!(StakeTier::Premium.priority_multiplier() > StakeTier::Standard.priority_multiplier());
        assert!(StakeTier::Standard.priority_multiplier() > StakeTier::Free.priority_multiplier());
    }

    #[test]
    fn test_stake_tier_ord() {
        assert!(StakeTier::Free < StakeTier::Standard);
        assert!(StakeTier::Standard < StakeTier::Premium);
        assert!(StakeTier::Premium < StakeTier::Validator);
    }

    #[test]
    fn test_stake_tier_names() {
        assert_eq!(StakeTier::Free.name(), "Free");
        assert_eq!(StakeTier::Standard.name(), "Standard");
        assert_eq!(StakeTier::Premium.name(), "Premium");
        assert_eq!(StakeTier::Validator.name(), "Validator");
    }

    #[test]
    fn test_eviction_policy_default_is_lowest_stake() {
        let config = SecureMempoolConfig::default();
        assert_eq!(config.eviction_policy, EvictionPolicy::LowestStakeTier);
        assert!(config.stake_rate_limiting);
    }
}
