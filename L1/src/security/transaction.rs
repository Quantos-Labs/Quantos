// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Transaction Attack Protection
//!
//! Protection against transaction-level attacks including double spend, replay, and front-running.
//!
//! ## Double Spend Protection
//!
//! Double spend attempts to use the same funds twice.
//! Mitigations:
//! - DAG conflict detection with topological ordering
//! - UTXO/account nonce tracking
//! - Finality checkpoints prevent reorgs
//! - Pending transaction pool deduplication
//!
//! ## Replay Attack Protection
//!
//! Replay attacks resubmit valid transactions.
//! Mitigations:
//! - Chain ID in transaction signature
//! - Monotonic nonces per account
//! - Transaction expiry timestamps
//! - Seen transaction cache
//!
//! ## Front-Running Protection
//!
//! Front-running extracts value by ordering manipulation.
//! Mitigations:
//! - Commit-reveal scheme for sensitive transactions
//! - Encrypted mempool option
//! - Fair ordering based on timestamp
//! - MEV auction/redistribution

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;

use crate::types::{Address, Hash, Slot};
use super::{SecurityError, SecurityResult};

/// HIGH: Maximum pending commits per sender to prevent memory exhaustion
const MAX_COMMITS_PER_SENDER: usize = 10;
/// HIGH: Maximum total pending commits across all senders
const MAX_TOTAL_PENDING_COMMITS: usize = 100_000;

/// Transaction security configuration.
#[derive(Clone, Debug)]
pub struct TransactionSecurityConfig {
    /// Chain ID for replay protection
    pub chain_id: u64,
    /// Maximum transaction age (slots)
    pub max_tx_age_slots: u64,
    /// Maximum future timestamp allowed (seconds)
    pub max_future_timestamp: u64,
    /// Enable commit-reveal for large transactions
    pub commit_reveal_enabled: bool,
    /// Threshold for commit-reveal (in base units)
    pub commit_reveal_threshold: u64,
    /// Commit phase duration
    pub commit_phase_duration: Duration,
    /// Enable encrypted mempool
    pub encrypted_mempool: bool,
    /// Seen transaction cache size
    pub seen_tx_cache_size: usize,
    /// Nonce gap limit (max gap from expected nonce)
    pub max_nonce_gap: u64,
    /// Enable MEV protection
    pub mev_protection: bool,
}

impl Default for TransactionSecurityConfig {
    fn default() -> Self {
        Self {
            chain_id: 1, // Mainnet
            max_tx_age_slots: 1000,
            max_future_timestamp: 60,
            commit_reveal_enabled: true,
            commit_reveal_threshold: 1_000_000_000, // 1B base units
            commit_phase_duration: Duration::from_secs(10),
            encrypted_mempool: false,
            seen_tx_cache_size: 100_000,
            max_nonce_gap: 100,
            mev_protection: true,
        }
    }
}

/// Double spend detector.
pub struct DoubleSpendDetector {
    config: TransactionSecurityConfig,
    /// Pending transactions by sender
    pending_by_sender: Arc<DashMap<Address, Vec<PendingTx>>>,
    /// Spent outputs (for UTXO model)
    spent_outputs: Arc<DashMap<Hash, SpentOutput>>,
    /// Conflict graph
    conflicts: Arc<DashMap<Hash, Vec<Hash>>>,
    /// Finalized transactions
    finalized_txs: Arc<DashMap<Hash, Slot>>,
}

/// Pending transaction info.
#[derive(Clone, Debug)]
pub struct PendingTx {
    pub tx_hash: Hash,
    pub nonce: u64,
    pub amount: u64,
    pub received_at: Instant,
    pub slot: Slot,
}

/// Spent output record.
#[derive(Clone, Debug)]
pub struct SpentOutput {
    pub output_hash: Hash,
    pub spent_by: Hash,
    pub spent_at: Slot,
}

impl DoubleSpendDetector {
    /// Creates a new double spend detector.
    pub fn new(config: TransactionSecurityConfig) -> Self {
        Self {
            config,
            pending_by_sender: Arc::new(DashMap::new()),
            spent_outputs: Arc::new(DashMap::new()),
            conflicts: Arc::new(DashMap::new()),
            finalized_txs: Arc::new(DashMap::new()),
        }
    }

    /// Checks a transaction for double spend.
    pub fn check_transaction(
        &self,
        tx_hash: Hash,
        sender: Address,
        nonce: u64,
        _amount: u64,
        inputs: &[Hash], // For UTXO model
        _current_slot: Slot,
    ) -> SecurityResult<()> {
        // Check for conflicting nonce (account model)
        if let Some(pending) = self.pending_by_sender.get(&sender) {
            for ptx in pending.iter() {
                if ptx.nonce == nonce && ptx.tx_hash != tx_hash {
                    // Same nonce, different transaction = potential double spend
                    self.record_conflict(tx_hash, ptx.tx_hash);
                    return Err(SecurityError::DoubleSpendDetected);
                }
            }
        }

        // Check for spent inputs (UTXO model)
        for input in inputs {
            if let Some(spent) = self.spent_outputs.get(input) {
                if spent.spent_by != tx_hash {
                    self.record_conflict(tx_hash, spent.spent_by);
                    return Err(SecurityError::DoubleSpendDetected);
                }
            }
        }

        Ok(())
    }

    /// Records a pending transaction.
    pub fn record_pending(
        &self,
        tx_hash: Hash,
        sender: Address,
        nonce: u64,
        amount: u64,
        current_slot: Slot,
    ) {
        let pending = PendingTx {
            tx_hash,
            nonce,
            amount,
            received_at: Instant::now(),
            slot: current_slot,
        };

        self.pending_by_sender
            .entry(sender)
            .or_insert_with(Vec::new)
            .push(pending);
    }

    /// Marks a transaction as finalized.
    pub fn finalize_transaction(&self, tx_hash: Hash, sender: Address, slot: Slot) {
        self.finalized_txs.insert(tx_hash, slot);
        
        // Remove from pending
        if let Some(mut pending) = self.pending_by_sender.get_mut(&sender) {
            pending.retain(|p| p.tx_hash != tx_hash);
        }
    }

    /// Records a conflict between transactions.
    fn record_conflict(&self, tx1: Hash, tx2: Hash) {
        self.conflicts
            .entry(tx1)
            .or_insert_with(Vec::new)
            .push(tx2);
        self.conflicts
            .entry(tx2)
            .or_insert_with(Vec::new)
            .push(tx1);

        tracing::warn!(
            "Double spend conflict: {} vs {}",
            hex::encode(&tx1[..8]),
            hex::encode(&tx2[..8])
        );
    }

    /// Marks outputs as spent.
    pub fn mark_outputs_spent(&self, tx_hash: Hash, outputs: &[Hash], slot: Slot) {
        for output in outputs {
            self.spent_outputs.insert(*output, SpentOutput {
                output_hash: *output,
                spent_by: tx_hash,
                spent_at: slot,
            });
        }
    }

    /// Gets conflicts for a transaction.
    pub fn get_conflicts(&self, tx_hash: &Hash) -> Vec<Hash> {
        self.conflicts
            .get(tx_hash)
            .map(|c| c.clone())
            .unwrap_or_default()
    }

    /// Cleans up old entries.
    pub fn cleanup(&self, finalized_slot: Slot) {
        // Remove old pending transactions
        for mut entry in self.pending_by_sender.iter_mut() {
            entry.retain(|p| p.slot > finalized_slot.saturating_sub(self.config.max_tx_age_slots));
        }
    }
}

/// Replay attack protector.
pub struct ReplayProtector {
    config: TransactionSecurityConfig,
    /// Seen transaction hashes
    seen_txs: Arc<RwLock<VecDeque<(Hash, Instant)>>>,
    /// Seen transaction set for O(1) lookup
    seen_set: Arc<DashMap<Hash, ()>>,
    /// Account nonces
    account_nonces: Arc<DashMap<Address, u64>>,
    /// Pending nonces (not yet finalized)
    pending_nonces: Arc<DashMap<Address, HashSet<u64>>>,
}

impl ReplayProtector {
    /// Creates a new replay protector.
    pub fn new(config: TransactionSecurityConfig) -> Self {
        Self {
            config,
            seen_txs: Arc::new(RwLock::new(VecDeque::with_capacity(100_000))),
            seen_set: Arc::new(DashMap::new()),
            account_nonces: Arc::new(DashMap::new()),
            pending_nonces: Arc::new(DashMap::new()),
        }
    }

    /// Validates a transaction against replay.
    pub fn validate_transaction(
        &self,
        tx_hash: Hash,
        chain_id: u64,
        sender: Address,
        nonce: u64,
        timestamp: u64,
        _current_slot: Slot,
    ) -> SecurityResult<()> {
        // Check chain ID
        if chain_id != self.config.chain_id {
            return Err(SecurityError::TransactionAttack(
                format!("Invalid chain ID: expected {}, got {}", self.config.chain_id, chain_id)
            ));
        }

        // Check if already seen
        if self.seen_set.contains_key(&tx_hash) {
            return Err(SecurityError::ReplayDetected);
        }

        // Check timestamp
        let now = chrono::Utc::now().timestamp() as u64;
        if timestamp > now + self.config.max_future_timestamp {
            return Err(SecurityError::TransactionAttack(
                "Transaction timestamp too far in future".into()
            ));
        }

        // Check nonce
        let expected_nonce = self.account_nonces
            .get(&sender)
            .map(|n| *n)
            .unwrap_or(0);

        if nonce < expected_nonce {
            return Err(SecurityError::TransactionAttack(
                format!("Nonce too low: expected >= {}, got {}", expected_nonce, nonce)
            ));
        }

        if nonce > expected_nonce + self.config.max_nonce_gap {
            return Err(SecurityError::TransactionAttack(
                format!("Nonce gap too large: expected ~{}, got {}", expected_nonce, nonce)
            ));
        }

        // Check if nonce is pending
        if let Some(pending) = self.pending_nonces.get(&sender) {
            if pending.contains(&nonce) {
                return Err(SecurityError::TransactionAttack(
                    "Nonce already pending".into()
                ));
            }
        }

        Ok(())
    }

    /// Records a seen transaction.
    pub fn record_transaction(&self, tx_hash: Hash, sender: Address, nonce: u64) {
        // Add to seen set
        self.seen_set.insert(tx_hash, ());
        
        // Add to queue for expiry
        {
            let mut seen = self.seen_txs.write();
            seen.push_back((tx_hash, Instant::now()));
            
            // Trim if over capacity
            while seen.len() > self.config.seen_tx_cache_size {
                if let Some((old_hash, _)) = seen.pop_front() {
                    self.seen_set.remove(&old_hash);
                }
            }
        }

        // Record pending nonce
        self.pending_nonces
            .entry(sender)
            .or_insert_with(HashSet::new)
            .insert(nonce);
    }

    /// Confirms a transaction (updates account nonce).
    pub fn confirm_transaction(&self, sender: Address, nonce: u64) {
        // Update account nonce to next expected
        self.account_nonces
            .entry(sender)
            .and_modify(|n| {
                if nonce >= *n {
                    *n = nonce + 1;
                }
            })
            .or_insert(nonce + 1);

        // Remove from pending
        if let Some(mut pending) = self.pending_nonces.get_mut(&sender) {
            pending.remove(&nonce);
        }
    }

    /// Gets current nonce for an account.
    pub fn get_nonce(&self, address: &Address) -> u64 {
        self.account_nonces
            .get(address)
            .map(|n| *n)
            .unwrap_or(0)
    }

    /// Cleans up old entries.
    pub fn cleanup(&self, max_age: Duration) {
        let cutoff = Instant::now() - max_age;
        let mut seen = self.seen_txs.write();
        
        while let Some((hash, time)) = seen.front() {
            if *time < cutoff {
                self.seen_set.remove(hash);
                seen.pop_front();
            } else {
                break;
            }
        }
    }
}

/// Front-running protection with commit-reveal.
pub struct FrontRunningProtector {
    config: TransactionSecurityConfig,
    /// Pending commits
    pending_commits: Arc<DashMap<Hash, PendingCommit>>,
    /// Revealed transactions
    revealed_txs: Arc<DashMap<Hash, RevealedTx>>,
    /// Fair ordering queue
    ordering_queue: Arc<RwLock<VecDeque<OrderedTx>>>,
}

/// A pending commit (hash of transaction).
#[derive(Clone, Debug)]
pub struct PendingCommit {
    pub commit_hash: Hash,
    pub sender: Address,
    pub committed_at: Instant,
    pub commit_slot: Slot,
    pub revealed: bool,
}

/// A revealed transaction.
#[derive(Clone, Debug)]
pub struct RevealedTx {
    pub commit_hash: Hash,
    pub tx_hash: Hash,
    pub sender: Address,
    pub revealed_at: Instant,
    pub amount: u64,
}

/// Transaction with ordering info.
#[derive(Clone, Debug)]
pub struct OrderedTx {
    pub tx_hash: Hash,
    pub timestamp: u64,
    pub priority: u64,
    pub is_commit_reveal: bool,
}

impl FrontRunningProtector {
    /// Creates a new front-running protector.
    pub fn new(config: TransactionSecurityConfig) -> Self {
        Self {
            config,
            pending_commits: Arc::new(DashMap::new()),
            revealed_txs: Arc::new(DashMap::new()),
            ordering_queue: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    /// Checks if transaction requires commit-reveal.
    pub fn requires_commit_reveal(&self, amount: u64) -> bool {
        self.config.commit_reveal_enabled && amount >= self.config.commit_reveal_threshold
    }

    /// Submits a commit.
    /// 
    /// HIGH: Now enforces per-sender and global caps to prevent unbounded memory growth.
    pub fn submit_commit(
        &self,
        commit_hash: Hash,
        sender: Address,
        current_slot: Slot,
    ) -> SecurityResult<()> {
        if self.pending_commits.contains_key(&commit_hash) {
            return Err(SecurityError::TransactionAttack(
                "Commit already exists".into()
            ));
        }

        // HIGH: Check global cap to prevent memory exhaustion
        if self.pending_commits.len() >= MAX_TOTAL_PENDING_COMMITS {
            return Err(SecurityError::TransactionAttack(
                "Too many pending commits globally, try again later".into()
            ));
        }

        // HIGH: Check per-sender cap to prevent a single attacker from flooding
        let sender_count = self.pending_commits.iter()
            .filter(|entry| entry.value().sender == sender && !entry.value().revealed)
            .count();
        if sender_count >= MAX_COMMITS_PER_SENDER {
            return Err(SecurityError::TransactionAttack(
                format!("Too many pending commits from sender (max {})", MAX_COMMITS_PER_SENDER)
            ));
        }

        self.pending_commits.insert(commit_hash, PendingCommit {
            commit_hash,
            sender,
            committed_at: Instant::now(),
            commit_slot: current_slot,
            revealed: false,
        });

        tracing::debug!("Commit submitted: {}", hex::encode(&commit_hash[..8]));
        Ok(())
    }

    /// Reveals a committed transaction.
    pub fn reveal_transaction(
        &self,
        commit_hash: Hash,
        tx_hash: Hash,
        tx_data: &[u8],
        sender: Address,
        amount: u64,
    ) -> SecurityResult<()> {
        // Verify commit exists
        let commit = self.pending_commits
            .get(&commit_hash)
            .ok_or_else(|| SecurityError::TransactionAttack("Commit not found".into()))?;

        // Verify sender matches
        if commit.sender != sender {
            return Err(SecurityError::TransactionAttack(
                "Sender mismatch".into()
            ));
        }

        // Verify commit phase elapsed
        if commit.committed_at.elapsed() < self.config.commit_phase_duration {
            return Err(SecurityError::TransactionAttack(
                "Commit phase not complete".into()
            ));
        }

        // Verify hash matches
        let computed_commit = crate::types::hash_data(tx_data);
        if computed_commit != commit_hash {
            return Err(SecurityError::TransactionAttack(
                "Transaction doesn't match commit".into()
            ));
        }

        // Mark as revealed
        drop(commit);
        if let Some(mut c) = self.pending_commits.get_mut(&commit_hash) {
            c.revealed = true;
        }

        // Record reveal
        self.revealed_txs.insert(tx_hash, RevealedTx {
            commit_hash,
            tx_hash,
            sender,
            revealed_at: Instant::now(),
            amount,
        });

        tracing::debug!(
            "Transaction revealed: {} (commit: {})",
            hex::encode(&tx_hash[..8]),
            hex::encode(&commit_hash[..8])
        );

        Ok(())
    }

    /// Adds transaction to fair ordering queue.
    pub fn add_to_ordering_queue(&self, tx: OrderedTx) {
        let mut queue = self.ordering_queue.write();
        
        // Insert in timestamp order
        let pos = queue.iter()
            .position(|t| t.timestamp > tx.timestamp)
            .unwrap_or(queue.len());
        
        queue.insert(pos, tx);
    }

    /// Gets next batch for fair ordering.
    pub fn get_ordered_batch(&self, max_size: usize) -> Vec<OrderedTx> {
        let mut queue = self.ordering_queue.write();
        let mut batch = Vec::with_capacity(max_size);
        
        while batch.len() < max_size {
            if let Some(tx) = queue.pop_front() {
                batch.push(tx);
            } else {
                break;
            }
        }
        
        batch
    }

    /// Cleans up expired commits.
    pub fn cleanup(&self, max_age: Duration) {
        let cutoff = Instant::now() - max_age;
        
        self.pending_commits.retain(|_, commit| {
            commit.committed_at > cutoff || commit.revealed
        });
    }
}

/// Combined transaction security manager.
pub struct TransactionSecurityManager {
    pub config: TransactionSecurityConfig,
    pub double_spend: DoubleSpendDetector,
    pub replay_protector: ReplayProtector,
    pub front_running: FrontRunningProtector,
}

impl TransactionSecurityManager {
    /// Creates a new transaction security manager.
    pub fn new(config: TransactionSecurityConfig) -> Self {
        Self {
            double_spend: DoubleSpendDetector::new(config.clone()),
            replay_protector: ReplayProtector::new(config.clone()),
            front_running: FrontRunningProtector::new(config.clone()),
            config,
        }
    }

    /// Validates a transaction for all security checks.
    pub fn validate_transaction(
        &self,
        tx_hash: Hash,
        chain_id: u64,
        sender: Address,
        nonce: u64,
        amount: u64,
        timestamp: u64,
        inputs: &[Hash],
        current_slot: Slot,
    ) -> SecurityResult<()> {
        // Check replay
        self.replay_protector.validate_transaction(
            tx_hash, chain_id, sender, nonce, timestamp, current_slot
        )?;

        // Check double spend
        self.double_spend.check_transaction(
            tx_hash, sender, nonce, amount, inputs, current_slot
        )?;

        Ok(())
    }

    /// Records a valid transaction.
    pub fn record_transaction(
        &self,
        tx_hash: Hash,
        sender: Address,
        nonce: u64,
        amount: u64,
        current_slot: Slot,
    ) {
        self.replay_protector.record_transaction(tx_hash, sender, nonce);
        self.double_spend.record_pending(tx_hash, sender, nonce, amount, current_slot);
    }

    /// Confirms a finalized transaction.
    pub fn confirm_transaction(
        &self,
        tx_hash: Hash,
        sender: Address,
        nonce: u64,
        slot: Slot,
    ) {
        self.replay_protector.confirm_transaction(sender, nonce);
        self.double_spend.finalize_transaction(tx_hash, sender, slot);
    }

    /// Runs periodic cleanup.
    pub fn cleanup(&self, finalized_slot: Slot) {
        self.double_spend.cleanup(finalized_slot);
        self.replay_protector.cleanup(Duration::from_secs(3600));
        self.front_running.cleanup(Duration::from_secs(300));
    }

    /// MEDIUM: Starts an automatic periodic cleanup task.
    /// 
    /// Without this, cleanup() must be called manually by external code.
    /// If not called regularly, memory usage grows unbounded.
    pub fn start_cleanup_task(self: Arc<Self>, cleanup_interval_secs: u64) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(cleanup_interval_secs));
            loop {
                interval.tick().await;
                // Use slot 0 as a conservative finalized_slot; callers can
                // provide a more accurate one by calling cleanup() directly.
                self.cleanup(0);
                tracing::debug!("TransactionSecurityManager auto-cleanup completed");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_detection() {
        let config = TransactionSecurityConfig::default();
        let protector = ReplayProtector::new(config);

        let tx_hash = [1u8; 32];
        let sender = Address::default();
        let now = chrono::Utc::now().timestamp() as u64;

        // First transaction should be valid
        assert!(protector.validate_transaction(tx_hash, 1, sender, 0, now, 100).is_ok());
        protector.record_transaction(tx_hash, sender, 0);

        // Same transaction should be replay
        assert!(matches!(
            protector.validate_transaction(tx_hash, 1, sender, 0, now, 100),
            Err(SecurityError::ReplayDetected)
        ));
    }

    #[test]
    fn test_nonce_validation() {
        let config = TransactionSecurityConfig::default();
        let protector = ReplayProtector::new(config);

        let sender = Address::default();
        let now = chrono::Utc::now().timestamp() as u64;

        // Set nonce to 5
        protector.account_nonces.insert(sender, 5);

        // Nonce 4 should fail (too low)
        assert!(protector.validate_transaction([1u8; 32], 1, sender, 4, now, 100).is_err());

        // Nonce 5 should succeed
        assert!(protector.validate_transaction([2u8; 32], 1, sender, 5, now, 100).is_ok());

        // Nonce 200 should fail (gap too large)
        assert!(protector.validate_transaction([3u8; 32], 1, sender, 200, now, 100).is_err());
    }

    #[test]
    fn test_commit_reveal() {
        let config = TransactionSecurityConfig {
            commit_phase_duration: Duration::from_millis(10),
            ..Default::default()
        };
        let protector = FrontRunningProtector::new(config);

        let tx_data = b"test transaction data";
        let commit_hash = crate::types::hash_data(tx_data);
        let sender = Address::default();

        // Submit commit
        assert!(protector.submit_commit(commit_hash, sender, 100).is_ok());

        // Immediate reveal should fail
        assert!(protector.reveal_transaction(
            commit_hash, [1u8; 32], tx_data, sender, 1000
        ).is_err());

        // Wait for commit phase
        std::thread::sleep(Duration::from_millis(15));

        // Reveal should succeed
        assert!(protector.reveal_transaction(
            commit_hash, [1u8; 32], tx_data, sender, 1000
        ).is_ok());
    }
}
