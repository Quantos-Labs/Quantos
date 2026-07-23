// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Multi-Version Concurrency Control (MVCC)
//!
//! Enables parallel state access without locks through versioned data.
//! Each transaction sees a consistent snapshot while others modify state.
//!
//! ## Features
//!
//! - **Snapshot Isolation**: Each transaction sees consistent state
//! - **Optimistic Concurrency**: Validate at commit time
//! - **Version Chains**: Efficient historical access
//! - **Garbage Collection**: Cleanup old versions
//! - **Conflict Detection**: Detect write-write conflicts

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use parking_lot::{Mutex, RwLock};

use crate::types::{Hash, Address, Amount};
use crate::state::{StateError, StateResult};

/// Transaction ID for MVCC
pub type TxnId = u64;

/// Timestamp for versioning
pub type Timestamp = u64;

/// Version of a value
#[derive(Clone, Debug)]
pub struct Version<T: Clone> {
    /// Version timestamp
    pub timestamp: Timestamp,
    /// Transaction that created this version
    pub created_by: TxnId,
    /// The actual value
    pub value: T,
    /// Previous version (for version chain)
    pub prev_version: Option<Timestamp>,
    /// Is this version committed?
    pub committed: bool,
}

impl<T: Clone> Version<T> {
    pub fn new(timestamp: Timestamp, created_by: TxnId, value: T) -> Self {
        Self {
            timestamp,
            created_by,
            value,
            prev_version: None,
            committed: false,
        }
    }
}

/// Versioned value with history
pub struct VersionedValue<T: Clone> {
    /// All versions sorted by timestamp
    versions: BTreeMap<Timestamp, Version<T>>,
    /// Latest committed timestamp
    latest_committed: Option<Timestamp>,
}

impl<T: Clone> VersionedValue<T> {
    pub fn new() -> Self {
        Self {
            versions: BTreeMap::new(),
            latest_committed: None,
        }
    }
    
    /// Adds a new version
    pub fn add_version(&mut self, version: Version<T>) {
        let ts = version.timestamp;
        let prev = self.latest_committed;
        
        let mut v = version;
        v.prev_version = prev;
        
        self.versions.insert(ts, v);
    }
    
    /// Gets version visible to given timestamp
    pub fn get_visible(&self, read_ts: Timestamp) -> Option<&T> {
        // Find latest committed version <= read_ts
        for (_ts, version) in self.versions.range(..=read_ts).rev() {
            if version.committed {
                return Some(&version.value);
            }
        }
        None
    }
    
    /// Gets version created by specific transaction
    pub fn get_by_txn(&self, txn_id: TxnId) -> Option<&T> {
        for version in self.versions.values() {
            if version.created_by == txn_id {
                return Some(&version.value);
            }
        }
        None
    }
    
    /// Commits a version
    pub fn commit(&mut self, timestamp: Timestamp) -> bool {
        if let Some(version) = self.versions.get_mut(&timestamp) {
            version.committed = true;
            self.latest_committed = Some(timestamp);
            true
        } else {
            false
        }
    }
    
    /// Aborts (removes) a version
    pub fn abort(&mut self, timestamp: Timestamp) {
        self.versions.remove(&timestamp);
    }
    
    /// Garbage collects old versions
    pub fn gc(&mut self, min_active_ts: Timestamp) {
        // Keep only versions that might be visible
        let to_remove: Vec<_> = self.versions
            .range(..min_active_ts)
            .filter(|(ts, v)| {
                // Keep if it's the latest committed before min_active
                v.committed && self.latest_committed.map_or(true, |l| **ts < l)
            })
            .map(|(ts, _)| *ts)
            .collect();
        
        // Keep at least one committed version
        let committed_count = self.versions.values().filter(|v| v.committed).count();
        if committed_count > 1 {
            for ts in to_remove.into_iter().take(committed_count - 1) {
                self.versions.remove(&ts);
            }
        }
    }
}

impl<T: Clone> Default for VersionedValue<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Account state for MVCC
#[derive(Clone, Debug)]
pub struct MVCCAccountState {
    pub address: Address,
    pub balance: Amount,
    pub nonce: u64,
    pub code_hash: Option<Hash>,
    pub storage_root: Option<Hash>,
}

/// Transaction state in MVCC
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionState {
    Active,
    Validating,
    Committed,
    Aborted,
}

/// Active transaction
pub struct MVCCTransaction {
    /// Transaction ID
    pub id: TxnId,
    /// Start timestamp (snapshot point)
    pub start_ts: Timestamp,
    /// Commit timestamp (assigned at commit)
    pub commit_ts: Option<Timestamp>,
    /// Read set
    pub read_set: HashSet<Address>,
    /// Write set with new values
    pub write_set: HashMap<Address, MVCCAccountState>,
    /// Storage read set
    pub storage_reads: HashSet<(Address, Hash)>,
    /// Storage write set
    pub storage_writes: HashMap<(Address, Hash), [u8; 32]>,
    /// Transaction state
    pub state: TransactionState,
    /// Start time
    pub started_at: Instant,
}

/// Reference to transaction data for validation (avoids Clone requirement)
struct MVCCTransactionRef<'a> {
    id: TxnId,
    start_ts: Timestamp,
    read_set: &'a HashSet<Address>,
    write_set: &'a HashMap<Address, MVCCAccountState>,
    storage_reads: &'a HashSet<(Address, Hash)>,
    storage_writes: &'a HashMap<(Address, Hash), [u8; 32]>,
}

impl MVCCTransaction {
    pub fn new(id: TxnId, start_ts: Timestamp) -> Self {
        Self {
            id,
            start_ts,
            commit_ts: None,
            read_set: HashSet::new(),
            write_set: HashMap::new(),
            storage_reads: HashSet::new(),
            storage_writes: HashMap::new(),
            state: TransactionState::Active,
            started_at: Instant::now(),
        }
    }
    
    /// Records a read
    pub fn record_read(&mut self, address: Address) {
        self.read_set.insert(address);
    }
    
    /// Records a write
    pub fn record_write(&mut self, address: Address, state: MVCCAccountState) {
        self.write_set.insert(address, state);
    }
    
    /// Records storage read
    pub fn record_storage_read(&mut self, address: Address, key: Hash) {
        self.storage_reads.insert((address, key));
    }
    
    /// Records storage write
    pub fn record_storage_write(&mut self, address: Address, key: Hash, value: [u8; 32]) {
        self.storage_writes.insert((address, key), value);
    }
}

/// MVCC configuration
#[derive(Clone, Debug)]
pub struct MVCCConfig {
    /// Maximum active transactions
    pub max_active_txns: usize,
    /// Transaction timeout
    pub txn_timeout: Duration,
    /// GC interval
    pub gc_interval: Duration,
    /// Keep minimum versions per key
    pub min_versions_per_key: usize,
}

impl Default for MVCCConfig {
    fn default() -> Self {
        Self {
            max_active_txns: 10000,
            txn_timeout: Duration::from_secs(30),
            gc_interval: Duration::from_secs(60),
            min_versions_per_key: 2,
        }
    }
}

/// MVCC Store
pub struct MVCCStore {
    config: MVCCConfig,
    /// Global timestamp counter
    timestamp: AtomicU64,
    /// Transaction ID counter
    txn_counter: AtomicU64,
    /// Account versions
    accounts: RwLock<HashMap<Address, VersionedValue<MVCCAccountState>>>,
    /// Storage versions
    storage: RwLock<HashMap<(Address, Hash), VersionedValue<[u8; 32]>>>,
    /// Active transactions
    active_txns: RwLock<HashMap<TxnId, MVCCTransaction>>,
    /// Committed transaction timestamps (for validation)
    committed_txns: Mutex<BTreeMap<Timestamp, TxnId>>,
    /// Statistics
    stats: Mutex<MVCCStats>,
}

/// MVCC statistics
#[derive(Default, Clone, Debug)]
pub struct MVCCStats {
    pub transactions_started: u64,
    pub transactions_committed: u64,
    pub transactions_aborted: u64,
    pub conflicts_detected: u64,
    pub gc_runs: u64,
    pub versions_collected: u64,
}

impl MVCCStore {
    pub fn new(config: MVCCConfig) -> Self {
        Self {
            config,
            timestamp: AtomicU64::new(1),
            txn_counter: AtomicU64::new(1),
            accounts: RwLock::new(HashMap::new()),
            storage: RwLock::new(HashMap::new()),
            active_txns: RwLock::new(HashMap::new()),
            committed_txns: Mutex::new(BTreeMap::new()),
            stats: Mutex::new(MVCCStats::default()),
        }
    }
    
    /// Starts a new transaction
    pub fn begin_transaction(&self) -> StateResult<TxnId> {
        let active_count = self.active_txns.read().len();
        if active_count >= self.config.max_active_txns {
            return Err(StateError::ExecutionError(
                "Too many active transactions".to_string()
            ));
        }
        
        let txn_id = self.txn_counter.fetch_add(1, Ordering::SeqCst);
        let start_ts = self.timestamp.load(Ordering::SeqCst);
        
        let txn = MVCCTransaction::new(txn_id, start_ts);
        self.active_txns.write().insert(txn_id, txn);
        
        self.stats.lock().transactions_started += 1;
        
        Ok(txn_id)
    }
    
    /// Reads account state in transaction context
    pub fn read_account(&self, txn_id: TxnId, address: &Address) -> StateResult<Option<MVCCAccountState>> {
        let mut txns = self.active_txns.write();
        let txn = txns.get_mut(&txn_id)
            .ok_or_else(|| StateError::ExecutionError("Transaction not found".to_string()))?;
        
        if txn.state != TransactionState::Active {
            return Err(StateError::ExecutionError("Transaction not active".to_string()));
        }
        
        // Check write set first (read your own writes)
        if let Some(state) = txn.write_set.get(address) {
            return Ok(Some(state.clone()));
        }
        
        // Record read
        txn.record_read(*address);
        let start_ts = txn.start_ts;
        drop(txns);
        
        // Read from versioned store
        let accounts = self.accounts.read();
        if let Some(versioned) = accounts.get(address) {
            Ok(versioned.get_visible(start_ts).cloned())
        } else {
            Ok(None)
        }
    }
    
    /// Writes account state in transaction context
    pub fn write_account(&self, txn_id: TxnId, state: MVCCAccountState) -> StateResult<()> {
        let mut txns = self.active_txns.write();
        let txn = txns.get_mut(&txn_id)
            .ok_or_else(|| StateError::ExecutionError("Transaction not found".to_string()))?;
        
        if txn.state != TransactionState::Active {
            return Err(StateError::ExecutionError("Transaction not active".to_string()));
        }
        
        txn.record_write(state.address, state);
        
        Ok(())
    }
    
    /// Reads storage in transaction context
    pub fn read_storage(
        &self,
        txn_id: TxnId,
        address: &Address,
        key: &Hash,
    ) -> StateResult<Option<[u8; 32]>> {
        let mut txns = self.active_txns.write();
        let txn = txns.get_mut(&txn_id)
            .ok_or_else(|| StateError::ExecutionError("Transaction not found".to_string()))?;
        
        // Check write set first
        if let Some(value) = txn.storage_writes.get(&(*address, *key)) {
            return Ok(Some(*value));
        }
        
        txn.record_storage_read(*address, *key);
        let start_ts = txn.start_ts;
        drop(txns);
        
        let storage = self.storage.read();
        if let Some(versioned) = storage.get(&(*address, *key)) {
            Ok(versioned.get_visible(start_ts).copied())
        } else {
            Ok(None)
        }
    }
    
    /// Writes storage in transaction context
    pub fn write_storage(
        &self,
        txn_id: TxnId,
        address: Address,
        key: Hash,
        value: [u8; 32],
    ) -> StateResult<()> {
        let mut txns = self.active_txns.write();
        let txn = txns.get_mut(&txn_id)
            .ok_or_else(|| StateError::ExecutionError("Transaction not found".to_string()))?;
        
        if txn.state != TransactionState::Active {
            return Err(StateError::ExecutionError("Transaction not active".to_string()));
        }
        
        txn.record_storage_write(address, key, value);
        
        Ok(())
    }
    
    /// Validates and commits transaction
    pub fn commit(&self, txn_id: TxnId) -> StateResult<Timestamp> {
        // Get transaction and mark as validating
        let (read_set, write_set, storage_reads, storage_writes, start_ts, _checkpoint_id) = {
            let mut txns = self.active_txns.write();
            let txn = txns.get_mut(&txn_id)
                .ok_or_else(|| StateError::ExecutionError("Transaction not found".to_string()))?;
            
            if txn.state != TransactionState::Active {
                return Err(StateError::ExecutionError("Transaction not active".to_string()));
            }
            
            txn.state = TransactionState::Validating;
            (
                txn.read_set.clone(),
                txn.write_set.clone(),
                txn.storage_reads.clone(),
                txn.storage_writes.clone(),
                txn.start_ts,
                txn.id,
            )
        };
        
        // Create a temporary struct for validation
        let txn = MVCCTransactionRef {
            id: txn_id,
            start_ts,
            read_set: &read_set,
            write_set: &write_set,
            storage_reads: &storage_reads,
            storage_writes: &storage_writes,
        };
        
        // Assign commit timestamp
        let commit_ts = self.timestamp.fetch_add(1, Ordering::SeqCst);
        
        // Validate: check for conflicts
        if !self.validate(&txn, commit_ts)? {
            // Conflict detected - abort
            self.abort(txn_id)?;
            self.stats.lock().conflicts_detected += 1;
            return Err(StateError::ExecutionError("Conflict detected".to_string()));
        }
        
        // Apply writes to versioned store
        self.apply_writes(&write_set, &storage_writes, txn_id, commit_ts)?;
        
        // Mark as committed
        {
            let mut txns = self.active_txns.write();
            if let Some(t) = txns.get_mut(&txn_id) {
                t.state = TransactionState::Committed;
                t.commit_ts = Some(commit_ts);
            }
        }
        
        // Record in committed transactions
        self.committed_txns.lock().insert(commit_ts, txn_id);
        
        // Remove from active
        self.active_txns.write().remove(&txn_id);
        
        self.stats.lock().transactions_committed += 1;
        
        Ok(commit_ts)
    }
    
    /// Validates transaction against concurrent modifications (v4: full conflict detection)
    fn validate(&self, txn: &MVCCTransactionRef, commit_ts: Timestamp) -> StateResult<bool> {
        let accounts = self.accounts.read();
        
        // Check account read-write conflicts:
        // If any address we read was modified by a committed txn after our start
        for addr in txn.read_set {
            if let Some(versioned) = accounts.get(addr) {
                for (_version_ts, version) in versioned.versions.range(txn.start_ts..commit_ts) {
                    if version.committed && version.created_by != txn.id {
                        return Ok(false);
                    }
                }
            }
        }
        
        // Check account write-write conflicts (v4):
        // If any address we write was also written by a committed txn after our start
        for addr in txn.write_set.keys() {
            if let Some(versioned) = accounts.get(addr) {
                for (_version_ts, version) in versioned.versions.range(txn.start_ts..commit_ts) {
                    if version.committed && version.created_by != txn.id {
                        return Ok(false);
                    }
                }
            }
        }
        
        drop(accounts);
        let storage = self.storage.read();
        
        // Check storage read-write conflicts (v4):
        for (addr, key) in txn.storage_reads {
            if let Some(versioned) = storage.get(&(*addr, *key)) {
                for (_version_ts, version) in versioned.versions.range(txn.start_ts..commit_ts) {
                    if version.committed && version.created_by != txn.id {
                        return Ok(false);
                    }
                }
            }
        }
        
        // Check storage write-write conflicts (v4):
        for (addr, key) in txn.storage_writes.keys() {
            if let Some(versioned) = storage.get(&(*addr, *key)) {
                for (_version_ts, version) in versioned.versions.range(txn.start_ts..commit_ts) {
                    if version.committed && version.created_by != txn.id {
                        return Ok(false);
                    }
                }
            }
        }
        
        Ok(true)
    }
    
    /// Applies transaction writes to store
    fn apply_writes(
        &self,
        write_set: &HashMap<Address, MVCCAccountState>,
        storage_writes: &HashMap<(Address, Hash), [u8; 32]>,
        txn_id: TxnId,
        commit_ts: Timestamp,
    ) -> StateResult<()> {
        // Apply account writes
        {
            let mut accounts = self.accounts.write();
            for (addr, state) in write_set {
                let versioned = accounts.entry(*addr).or_insert_with(VersionedValue::new);
                let mut version = Version::new(commit_ts, txn_id, state.clone());
                version.committed = true;
                versioned.add_version(version);
                versioned.latest_committed = Some(commit_ts);
            }
        }
        
        // Apply storage writes
        {
            let mut storage = self.storage.write();
            for ((addr, key), value) in storage_writes {
                let versioned = storage.entry((*addr, *key)).or_insert_with(VersionedValue::new);
                let mut version = Version::new(commit_ts, txn_id, *value);
                version.committed = true;
                versioned.add_version(version);
                versioned.latest_committed = Some(commit_ts);
            }
        }
        
        Ok(())
    }
    
    /// Aborts transaction
    pub fn abort(&self, txn_id: TxnId) -> StateResult<()> {
        let mut txns = self.active_txns.write();
        
        if let Some(txn) = txns.get_mut(&txn_id) {
            txn.state = TransactionState::Aborted;
        }
        
        txns.remove(&txn_id);
        
        self.stats.lock().transactions_aborted += 1;
        
        Ok(())
    }
    
    /// Runs garbage collection
    pub fn gc(&self) {
        // Find minimum active timestamp
        let min_active_ts = self.active_txns.read()
            .values()
            .map(|t| t.start_ts)
            .min()
            .unwrap_or(self.timestamp.load(Ordering::SeqCst));
        
        let mut versions_collected = 0u64;
        
        // GC accounts
        {
            let mut accounts = self.accounts.write();
            for versioned in accounts.values_mut() {
                let before = versioned.versions.len();
                versioned.gc(min_active_ts);
                versions_collected += (before - versioned.versions.len()) as u64;
            }
        }
        
        // GC storage
        {
            let mut storage = self.storage.write();
            for versioned in storage.values_mut() {
                let before = versioned.versions.len();
                versioned.gc(min_active_ts);
                versions_collected += (before - versioned.versions.len()) as u64;
            }
        }
        
        // Cleanup old committed records
        {
            let mut committed = self.committed_txns.lock();
            let to_remove: Vec<_> = committed.range(..min_active_ts).map(|(ts, _)| *ts).collect();
            for ts in to_remove {
                committed.remove(&ts);
            }
        }
        
        let mut stats = self.stats.lock();
        stats.gc_runs += 1;
        stats.versions_collected += versions_collected;
    }
    
    /// Cleans up timed out transactions
    pub fn cleanup_timeouts(&self) {
        let now = Instant::now();
        let timeout = self.config.txn_timeout;
        
        let to_abort: Vec<_> = self.active_txns.read()
            .iter()
            .filter(|(_, txn)| now.duration_since(txn.started_at) > timeout)
            .map(|(id, _)| *id)
            .collect();
        
        for txn_id in to_abort {
            let _ = self.abort(txn_id);
        }
    }
    
    /// Gets current timestamp
    pub fn current_timestamp(&self) -> Timestamp {
        self.timestamp.load(Ordering::SeqCst)
    }
    
    /// Gets active transaction count
    pub fn active_count(&self) -> usize {
        self.active_txns.read().len()
    }
    
    /// Returns statistics
    pub fn stats(&self) -> MVCCStats {
        self.stats.lock().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basic_transaction() {
        let store = MVCCStore::new(MVCCConfig::default());
        
        let txn1 = store.begin_transaction().unwrap();
        
        let state = MVCCAccountState {
            address: [1u8; 32],
            balance: Amount(1000),
            nonce: 0,
            code_hash: None,
            storage_root: None,
        };
        
        store.write_account(txn1, state.clone()).unwrap();
        
        // Read own write
        let read = store.read_account(txn1, &[1u8; 32]).unwrap();
        assert!(read.is_some());
        assert_eq!(read.unwrap().balance.0, 1000);
        
        store.commit(txn1).unwrap();
    }
    
    #[test]
    fn test_snapshot_isolation() {
        let store = MVCCStore::new(MVCCConfig::default());
        
        // Setup initial state
        let txn_setup = store.begin_transaction().unwrap();
        store.write_account(txn_setup, MVCCAccountState {
            address: [1u8; 32],
            balance: Amount(1000),
            nonce: 0,
            code_hash: None,
            storage_root: None,
        }).unwrap();
        store.commit(txn_setup).unwrap();
        
        // Start two concurrent transactions
        let txn1 = store.begin_transaction().unwrap();
        let txn2 = store.begin_transaction().unwrap();
        
        // txn1 reads
        let read1 = store.read_account(txn1, &[1u8; 32]).unwrap().unwrap();
        assert_eq!(read1.balance.0, 1000);
        
        // txn2 modifies and commits
        store.write_account(txn2, MVCCAccountState {
            address: [1u8; 32],
            balance: Amount(2000),
            nonce: 1,
            code_hash: None,
            storage_root: None,
        }).unwrap();
        store.commit(txn2).unwrap();
        
        // txn1 still sees old value (snapshot isolation)
        let read1_after = store.read_account(txn1, &[1u8; 32]).unwrap().unwrap();
        assert_eq!(read1_after.balance.0, 1000);
    }
    
    #[test]
    fn test_write_write_conflict() {
        let store = MVCCStore::new(MVCCConfig::default());
        
        // Setup
        let txn_setup = store.begin_transaction().unwrap();
        store.write_account(txn_setup, MVCCAccountState {
            address: [1u8; 32],
            balance: Amount(1000),
            nonce: 0,
            code_hash: None,
            storage_root: None,
        }).unwrap();
        store.commit(txn_setup).unwrap();
        
        // Two concurrent transactions read the same account
        let txn1 = store.begin_transaction().unwrap();
        let txn2 = store.begin_transaction().unwrap();
        
        store.read_account(txn1, &[1u8; 32]).unwrap();
        store.read_account(txn2, &[1u8; 32]).unwrap();
        
        // Both try to write
        store.write_account(txn1, MVCCAccountState {
            address: [1u8; 32],
            balance: Amount(1500),
            nonce: 1,
            code_hash: None,
            storage_root: None,
        }).unwrap();
        
        store.write_account(txn2, MVCCAccountState {
            address: [1u8; 32],
            balance: Amount(2000),
            nonce: 1,
            code_hash: None,
            storage_root: None,
        }).unwrap();
        
        // First commit succeeds
        store.commit(txn1).unwrap();
        
        // Second should detect conflict
        let result = store.commit(txn2);
        assert!(result.is_err());
    }
}
