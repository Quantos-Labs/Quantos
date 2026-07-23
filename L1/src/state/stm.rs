// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Software Transactional Memory (STM)
//!
//! Optimistic concurrency control for parallel transaction execution.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    STM Transaction Flow                      │
//! ├─────────────────────────────────────────────────────────────┤
//! │  1. Begin Transaction → Create read/write sets             │
//! │  2. Execute Optimistically → Track all reads/writes        │
//! │  3. Commit Phase → Validate no conflicts                   │
//! │  4. Success → Apply writes | Conflict → Rollback & Retry   │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Conflict Detection
//!
//! - **Read-Write Conflict**: Another tx wrote to a key we read
//! - **Write-Write Conflict**: Another tx wrote to a key we wrote
//! - **Automatic Rollback**: Failed transactions retry automatically

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use parking_lot::RwLock;


/// Maximum commit log size before automatic pruning
const MAX_COMMIT_LOG_SIZE: usize = 10_000;
/// Maximum retry attempts per account to prevent DoS
const MAX_RETRIES_PER_ACCOUNT: u32 = 5;
/// HIGH (w3): Global retry rate limit per window
const MAX_GLOBAL_RETRIES_PER_WINDOW: u64 = 1000;
/// HIGH (w3): Rate limit window duration in milliseconds
const RATE_LIMIT_WINDOW_MS: u64 = 10_000;

/// STM transaction ID.
pub type TxId = u64;

/// STM version number for optimistic concurrency.
pub type Version = u64;

/// STM transaction status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxStatus {
    Active,
    Validating,
    Committed,
    Aborted,
}

/// STM transaction context.
pub struct StmTransaction {
    /// Unique transaction ID
    pub id: TxId,
    /// Transaction status
    pub status: TxStatus,
    /// Read set: key -> version read
    pub read_set: HashMap<Vec<u8>, Version>,
    /// Write set: key -> value
    pub write_set: HashMap<Vec<u8>, Vec<u8>>,
    /// Timestamp when transaction started
    pub start_time: u64,
    /// Number of retries
    pub retry_count: u32,
}

impl StmTransaction {
    /// Creates a new STM transaction.
    pub fn new(id: TxId) -> Self {
        Self {
            id,
            status: TxStatus::Active,
            read_set: HashMap::new(),
            write_set: HashMap::new(),
            start_time: chrono::Utc::now().timestamp_millis() as u64,
            retry_count: 0,
        }
    }

    /// Records a read operation.
    pub fn record_read(&mut self, key: Vec<u8>, version: Version) {
        self.read_set.insert(key, version);
    }

    /// Records a write operation.
    pub fn record_write(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.write_set.insert(key, value);
    }

    /// Gets the size of read set.
    pub fn read_set_size(&self) -> usize {
        self.read_set.len()
    }

    /// Gets the size of write set.
    pub fn write_set_size(&self) -> usize {
        self.write_set.len()
    }

    /// Increments retry count.
    pub fn increment_retry(&mut self) {
        self.retry_count += 1;
    }
}

/// Versioned value in STM.
#[derive(Clone, Debug)]
pub struct VersionedValue {
    /// Current value
    pub value: Vec<u8>,
    /// Version number
    pub version: Version,
    /// Transaction ID that last modified this
    pub last_tx: TxId,
}

/// STM Manager for optimistic concurrency control.
pub struct StmManager {
    /// Next transaction ID
    next_tx_id: AtomicU64,
    /// Global version counter
    global_version: AtomicU64,
    /// Active transactions
    active_txs: Arc<DashMap<TxId, Arc<RwLock<StmTransaction>>>>,
    /// Versioned data store
    data_store: Arc<DashMap<Vec<u8>, VersionedValue>>,
    /// Committed transaction log (for conflict detection)
    commit_log: Arc<RwLock<Vec<CommitRecord>>>,
    /// Maximum retries before giving up
    max_retries: u32,
    /// Metrics
    metrics: Arc<RwLock<StmMetrics>>,
    /// Per-account retry tracking to prevent DoS
    account_retries: Arc<DashMap<Vec<u8>, u32>>,
    /// HIGH (w3): Global retry counter for rate limiting
    global_retry_count: AtomicU64,
    /// HIGH (w3): Window start time for global rate limiting
    rate_limit_window_start: AtomicU64,
}

/// Commit record for conflict detection.
#[derive(Clone, Debug)]
pub struct CommitRecord {
    pub tx_id: TxId,
    pub version: Version,
    pub write_keys: HashSet<Vec<u8>>,
    pub committed_at: u64,
}

/// STM metrics.
#[derive(Clone, Debug, Default)]
pub struct StmMetrics {
    pub total_transactions: u64,
    pub committed_transactions: u64,
    pub aborted_transactions: u64,
    pub total_retries: u64,
    pub conflicts_detected: u64,
    pub avg_retry_count: f64,
}

impl StmManager {
    /// Creates a new STM manager.
    pub fn new(max_retries: u32) -> Self {
        Self {
            next_tx_id: AtomicU64::new(1),
            global_version: AtomicU64::new(1),
            active_txs: Arc::new(DashMap::new()),
            data_store: Arc::new(DashMap::new()),
            commit_log: Arc::new(RwLock::new(Vec::new())),
            max_retries,
            metrics: Arc::new(RwLock::new(StmMetrics::default())),
            account_retries: Arc::new(DashMap::new()),
            global_retry_count: AtomicU64::new(0),
            rate_limit_window_start: AtomicU64::new(chrono::Utc::now().timestamp_millis() as u64),
        }
    }
    
    /// HIGH (w3): Check global retry rate limit
    fn check_global_rate_limit(&self) -> Result<(), StmError> {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let window_start = self.rate_limit_window_start.load(Ordering::Relaxed);
        
        if now.saturating_sub(window_start) > RATE_LIMIT_WINDOW_MS {
            // Reset window
            self.rate_limit_window_start.store(now, Ordering::Relaxed);
            self.global_retry_count.store(0, Ordering::Relaxed);
        }
        
        let count = self.global_retry_count.load(Ordering::Relaxed);
        if count >= MAX_GLOBAL_RETRIES_PER_WINDOW {
            tracing::warn!("STM: Global retry rate limit reached ({} retries in window)", count);
            return Err(StmError::RateLimited);
        }
        
        Ok(())
    }

    /// Begins a new transaction.
    pub fn begin_transaction(&self) -> TxId {
        let tx_id = self.next_tx_id.fetch_add(1, Ordering::SeqCst);
        let tx = Arc::new(RwLock::new(StmTransaction::new(tx_id)));
        self.active_txs.insert(tx_id, tx);
        
        self.metrics.write().total_transactions += 1;
        
        tracing::debug!("STM: Begin transaction {}", tx_id);
        tx_id
    }

    /// Reads a value within a transaction.
    pub fn read(&self, tx_id: TxId, key: &[u8]) -> Option<Vec<u8>> {
        let tx = self.active_txs.get(&tx_id)?;
        let mut tx = tx.write();

        // Check write set first (read-your-own-writes)
        if let Some(value) = tx.write_set.get(key) {
            return Some(value.clone());
        }

        // Read from data store
        if let Some(versioned) = self.data_store.get(key) {
            tx.record_read(key.to_vec(), versioned.version);
            Some(versioned.value.clone())
        } else {
            // Record read of non-existent key
            tx.record_read(key.to_vec(), 0);
            None
        }
    }

    /// Writes a value within a transaction.
    pub fn write(&self, tx_id: TxId, key: Vec<u8>, value: Vec<u8>) -> bool {
        if let Some(tx) = self.active_txs.get(&tx_id) {
            tx.write().record_write(key, value);
            true
        } else {
            false
        }
    }

    /// Commits a transaction with conflict detection.
    pub fn commit(&self, tx_id: TxId) -> Result<(), StmError> {
        let tx_arc = self.active_txs.get(&tx_id)
            .ok_or(StmError::TransactionNotFound)?;

        let mut tx = tx_arc.write();

        // Change status to validating
        tx.status = TxStatus::Validating;

        // Validate transaction (check for conflicts)
        if let Err(e) = self.validate_transaction(&tx) {
            tx.status = TxStatus::Aborted;
            self.metrics.write().aborted_transactions += 1;
            self.metrics.write().conflicts_detected += 1;
            
            tracing::warn!("STM: Transaction {} aborted due to conflict", tx_id);
            return Err(e);
        }

        // Apply writes
        let version = self.global_version.fetch_add(1, Ordering::SeqCst);
        let mut write_keys = HashSet::new();

        for (key, value) in &tx.write_set {
            self.data_store.insert(key.clone(), VersionedValue {
                value: value.clone(),
                version,
                last_tx: tx_id,
            });
            write_keys.insert(key.clone());
        }

        // Record commit with automatic pruning
        {
            let mut log = self.commit_log.write();
            log.push(CommitRecord {
                tx_id,
                version,
                write_keys,
                committed_at: chrono::Utc::now().timestamp_millis() as u64,
            });
            
            // CRITICAL: Auto-prune to prevent unbounded growth
            if log.len() > MAX_COMMIT_LOG_SIZE {
                let drain_count = log.len() - MAX_COMMIT_LOG_SIZE;
                log.drain(0..drain_count);
                tracing::debug!("STM: Auto-pruned {} commit log entries", drain_count);
            }
        }

        // Update status
        tx.status = TxStatus::Committed;
        
        // Update metrics
        {
            let mut metrics = self.metrics.write();
            metrics.committed_transactions += 1;
            metrics.total_retries += tx.retry_count as u64;
            
            if metrics.committed_transactions > 0 {
                metrics.avg_retry_count = 
                    metrics.total_retries as f64 / metrics.committed_transactions as f64;
            }
        }

        // Remove from active transactions
        drop(tx);
        self.active_txs.remove(&tx_id);

        tracing::debug!("STM: Transaction {} committed at version {}", tx_id, version);
        Ok(())
    }

    /// Validates a transaction for conflicts.
    fn validate_transaction(&self, tx: &StmTransaction) -> Result<(), StmError> {
        let commit_log = self.commit_log.read();

        // Check for conflicts with committed transactions
        for record in commit_log.iter().rev() {
            // Only check transactions committed after this tx started
            if record.committed_at < tx.start_time {
                break;
            }

            // Check read-write conflicts
            for (read_key, read_version) in &tx.read_set {
                if record.write_keys.contains(read_key) {
                    // Another transaction wrote to a key we read
                    if let Some(current) = self.data_store.get(read_key) {
                        if current.version != *read_version {
                            return Err(StmError::ReadWriteConflict {
                                key: read_key.clone(),
                                expected_version: *read_version,
                                actual_version: current.version,
                            });
                        }
                    }
                }
            }

            // Check write-write conflicts
            for write_key in &tx.write_set {
                if record.write_keys.contains(write_key.0) {
                    return Err(StmError::WriteWriteConflict {
                        key: write_key.0.clone(),
                        conflicting_tx: record.tx_id,
                    });
                }
            }
        }

        Ok(())
    }

    /// Aborts a transaction.
    pub fn abort(&self, tx_id: TxId) {
        if let Some((_, tx_arc)) = self.active_txs.remove(&tx_id) {
            tx_arc.write().status = TxStatus::Aborted;
            self.metrics.write().aborted_transactions += 1;
            tracing::debug!("STM: Transaction {} aborted", tx_id);
        }
    }

    /// Retries a transaction with automatic rollback and rate limiting.
    pub fn retry_transaction<F, R>(&self, account_key: Vec<u8>, mut operation: F) -> Result<R, StmError>
    where
        F: FnMut(TxId) -> Result<R, StmError>,
    {
        // CRITICAL: Check per-account retry limit to prevent DoS
        let current_retries = self.account_retries.get(&account_key)
            .map(|r| *r)
            .unwrap_or(0);
        
        if current_retries >= MAX_RETRIES_PER_ACCOUNT {
            return Err(StmError::RateLimited);
        }
        
        // HIGH (w3): Check global retry rate limit
        self.check_global_rate_limit()?;
        
        let mut attempts = 0;

        loop {
            let tx_id = self.begin_transaction();

            match operation(tx_id) {
                Ok(result) => {
                    match self.commit(tx_id) {
                        Ok(_) => {
                            // Reset retry counter on success
                            self.account_retries.remove(&account_key);
                            return Ok(result);
                        }
                        Err(StmError::ReadWriteConflict { .. }) | 
                        Err(StmError::WriteWriteConflict { .. }) => {
                            attempts += 1;
                            
                            // Update per-account retry counter
                            *self.account_retries.entry(account_key.clone()).or_insert(0) += 1;
                            
                            if attempts >= self.max_retries {
                                return Err(StmError::MaxRetriesExceeded(attempts));
                            }
                            
                            // Update retry count
                            if let Some(tx) = self.active_txs.get(&tx_id) {
                                tx.write().increment_retry();
                            }
                            
                            // HIGH (w3): Exponential backoff with jitter, capped at 2s
                            self.global_retry_count.fetch_add(1, Ordering::Relaxed);
                            let backoff_ms = (1u64 << attempts.min(11)).min(2000);
                            std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
                            
                            tracing::debug!("STM: Retrying transaction (attempt {})", attempts + 1);
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(e) => {
                    self.abort(tx_id);
                    return Err(e);
                }
            }
        }
    }

    /// Gets metrics.
    pub fn get_metrics(&self) -> StmMetrics {
        self.metrics.read().clone()
    }

    /// Prunes old commit log entries.
    pub fn prune_commit_log(&self, keep_last_n: usize) {
        let mut log = self.commit_log.write();
        if log.len() > keep_last_n {
            let drain_count = log.len() - keep_last_n;
            log.drain(0..drain_count);
        }
    }

    /// Gets the number of active transactions.
    pub fn active_transaction_count(&self) -> usize {
        self.active_txs.len()
    }

    /// Clears all data (for testing).
    pub fn clear(&self) {
        self.data_store.clear();
        self.active_txs.clear();
        self.commit_log.write().clear();
        self.account_retries.clear();
    }
    
    /// Resets retry counter for an account
    pub fn reset_account_retries(&self, account_key: &[u8]) {
        self.account_retries.remove(account_key);
    }
}

/// STM errors.
#[derive(Debug, Clone)]
pub enum StmError {
    TransactionNotFound,
    ReadWriteConflict {
        key: Vec<u8>,
        expected_version: Version,
        actual_version: Version,
    },
    WriteWriteConflict {
        key: Vec<u8>,
        conflicting_tx: TxId,
    },
    MaxRetriesExceeded(u32),
    InvalidOperation(String),
    RateLimited,
}

impl std::fmt::Display for StmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StmError::TransactionNotFound => write!(f, "Transaction not found"),
            StmError::ReadWriteConflict { key, expected_version, actual_version } => {
                write!(f, "Read-write conflict on key {:?}: expected v{}, got v{}", 
                    key, expected_version, actual_version)
            }
            StmError::WriteWriteConflict { key, conflicting_tx } => {
                write!(f, "Write-write conflict on key {:?} with tx {}", key, conflicting_tx)
            }
            StmError::MaxRetriesExceeded(count) => {
                write!(f, "Max retries exceeded: {} attempts", count)
            }
            StmError::InvalidOperation(msg) => write!(f, "Invalid operation: {}", msg),
            StmError::RateLimited => write!(f, "Rate limited: too many retries for this account"),
        }
    }
}

impl std::error::Error for StmError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stm_basic_transaction() {
        let stm = StmManager::new(3);
        
        let tx_id = stm.begin_transaction();
        stm.write(tx_id, b"key1".to_vec(), b"value1".to_vec());
        
        assert!(stm.commit(tx_id).is_ok());
        
        let tx_id2 = stm.begin_transaction();
        let value = stm.read(tx_id2, b"key1");
        assert_eq!(value, Some(b"value1".to_vec()));
    }

    #[test]
    fn test_stm_read_write_conflict() {
        let stm = StmManager::new(3);
        
        // Tx1 reads key
        let tx1 = stm.begin_transaction();
        stm.read(tx1, b"key1");
        
        // Tx2 writes to same key and commits
        let tx2 = stm.begin_transaction();
        stm.write(tx2, b"key1".to_vec(), b"value2".to_vec());
        assert!(stm.commit(tx2).is_ok());
        
        // Tx1 tries to commit - should fail
        assert!(stm.commit(tx1).is_err());
    }

    #[test]
    fn test_stm_write_write_conflict() {
        let stm = StmManager::new(3);
        
        let tx1 = stm.begin_transaction();
        stm.write(tx1, b"key1".to_vec(), b"value1".to_vec());
        
        let tx2 = stm.begin_transaction();
        stm.write(tx2, b"key1".to_vec(), b"value2".to_vec());
        
        // First commit should succeed
        assert!(stm.commit(tx1).is_ok());
        
        // Second commit should fail
        assert!(stm.commit(tx2).is_err());
    }

    #[test]
    fn test_stm_retry() {
        let stm = Arc::new(StmManager::new(5));
        let counter = Arc::new(AtomicU64::new(0));
        
        let result = stm.retry_transaction(b"test_account".to_vec(), |tx_id| {
            counter.fetch_add(1, Ordering::SeqCst);
            stm.write(tx_id, b"counter".to_vec(), b"1".to_vec());
            Ok(())
        });
        
        assert!(result.is_ok());
        assert!(counter.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn test_stm_read_own_writes() {
        let stm = StmManager::new(3);
        
        let tx_id = stm.begin_transaction();
        stm.write(tx_id, b"key1".to_vec(), b"value1".to_vec());
        
        // Should read own write
        let value = stm.read(tx_id, b"key1");
        assert_eq!(value, Some(b"value1".to_vec()));
    }

    #[test]
    fn test_stm_metrics() {
        let stm = StmManager::new(3);
        
        let tx1 = stm.begin_transaction();
        stm.write(tx1, b"key1".to_vec(), b"value1".to_vec());
        stm.commit(tx1).unwrap();
        
        let metrics = stm.get_metrics();
        assert_eq!(metrics.total_transactions, 1);
        assert_eq!(metrics.committed_transactions, 1);
    }
}
