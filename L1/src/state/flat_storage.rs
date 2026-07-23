// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Flat Storage
//!
//! O(1) direct access to account state without Merkle tree traversal.
//! Optimizes hot path reads while maintaining Merkle proofs for verification.
//!
//! ## Features
//!
//! - **Direct Key-Value Access**: Skip Merkle traversal for reads
//! - **Delta Tracking**: Track changes for Merkle updates
//! - **Hot/Cold Separation**: Keep frequently accessed data in memory
//! - **Lazy Merkle Updates**: Batch Merkle tree updates
//! - **Cache Integration**: LRU cache for hot accounts

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;
use parking_lot::{Mutex, RwLock};

use crate::types::{Hash, Address, Amount};
use crate::state::StateResult;

/// Account state in flat storage
#[derive(Clone, Debug)]
pub struct FlatAccountState {
    /// Account address (key)
    pub address: Address,
    /// Balance
    pub balance: Amount,
    /// Nonce
    pub nonce: u64,
    /// Code hash (for contracts)
    pub code_hash: Option<Hash>,
    /// Storage root (for contracts)
    pub storage_root: Option<Hash>,
    /// Last modified block
    pub last_modified: u64,
    /// Is this a hot account (frequently accessed)
    pub is_hot: bool,
    /// Access count for hot/cold classification
    pub access_count: u64,
}

impl FlatAccountState {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            balance: Amount::zero(),
            nonce: 0,
            code_hash: None,
            storage_root: None,
            last_modified: 0,
            is_hot: false,
            access_count: 0,
        }
    }
    
    /// Computes state hash for Merkle tree
    pub fn state_hash(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&self.address);
        data.extend_from_slice(&self.balance.0.to_le_bytes());
        data.extend_from_slice(&self.nonce.to_le_bytes());
        if let Some(ref code_hash) = self.code_hash {
            data.extend_from_slice(code_hash);
        }
        if let Some(ref storage_root) = self.storage_root {
            data.extend_from_slice(storage_root);
        }
        crate::crypto::sha3_256(&data)
    }
}

/// Storage slot value
#[derive(Clone, Debug)]
pub struct StorageSlot {
    pub key: Hash,
    pub value: [u8; 32],
    pub last_modified: u64,
}

/// Delta entry for tracking changes
#[derive(Clone, Debug)]
pub struct StateDelta {
    /// Account deltas
    pub account_changes: HashMap<Address, AccountDelta>,
    /// Storage deltas  
    pub storage_changes: HashMap<Address, HashMap<Hash, StorageDelta>>,
    /// Block number
    pub block_number: u64,
    /// State root before changes
    pub prev_state_root: Hash,
    /// State root after changes
    pub new_state_root: Option<Hash>,
}

impl StateDelta {
    pub fn new(block_number: u64, prev_state_root: Hash) -> Self {
        Self {
            account_changes: HashMap::new(),
            storage_changes: HashMap::new(),
            block_number,
            prev_state_root,
            new_state_root: None,
        }
    }
    
    pub fn is_empty(&self) -> bool {
        self.account_changes.is_empty() && self.storage_changes.is_empty()
    }
}

/// Account change type
#[derive(Clone, Debug)]
pub enum AccountDelta {
    Created(FlatAccountState),
    Modified { old: FlatAccountState, new: FlatAccountState },
    Deleted(FlatAccountState),
}

/// Storage change type
#[derive(Clone, Debug)]
pub enum StorageDelta {
    Set { old: Option<[u8; 32]>, new: [u8; 32] },
    Deleted { old: [u8; 32] },
}

/// LRU cache entry
struct CacheEntry<V> {
    value: V,
    last_access: Instant,
    access_count: u64,
}

/// Simple LRU cache for hot accounts
pub struct LRUCache<K: std::hash::Hash + Eq + Clone, V: Clone> {
    entries: HashMap<K, CacheEntry<V>>,
    order: VecDeque<K>,
    capacity: usize,
    hits: u64,
    misses: u64,
}

impl<K: std::hash::Hash + Eq + Clone, V: Clone> LRUCache<K, V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
            hits: 0,
            misses: 0,
        }
    }
    
    pub fn get(&mut self, key: &K) -> Option<&V> {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.last_access = Instant::now();
            entry.access_count += 1;
            self.hits += 1;
            
            // Move to front
            self.order.retain(|k| k != key);
            self.order.push_front(key.clone());
            
            Some(&entry.value)
        } else {
            self.misses += 1;
            None
        }
    }
    
    pub fn insert(&mut self, key: K, value: V) {
        // Evict if at capacity
        while self.entries.len() >= self.capacity {
            if let Some(old_key) = self.order.pop_back() {
                self.entries.remove(&old_key);
            }
        }
        
        self.entries.insert(key.clone(), CacheEntry {
            value,
            last_access: Instant::now(),
            access_count: 1,
        });
        self.order.push_front(key);
    }
    
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.order.retain(|k| k != key);
        self.entries.remove(key).map(|e| e.value)
    }
    
    pub fn contains(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }
    
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 { 0.0 } else { self.hits as f64 / total as f64 }
    }
    
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    
    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }
}

/// Flat storage configuration
#[derive(Clone, Debug)]
pub struct FlatStorageConfig {
    /// Cache capacity for hot accounts
    pub account_cache_size: usize,
    /// Cache capacity for hot storage slots
    pub storage_cache_size: usize,
    /// Access threshold to classify as hot
    pub hot_threshold: u64,
    /// Batch size for Merkle updates
    pub merkle_batch_size: usize,
    /// Enable delta compression
    pub compress_deltas: bool,
    /// Maximum pending deltas before flush
    pub max_pending_deltas: usize,
    /// HIGH (w5): Maximum accounts in flat storage
    pub max_accounts: usize,
}

impl Default for FlatStorageConfig {
    fn default() -> Self {
        Self {
            account_cache_size: 100_000,
            storage_cache_size: 500_000,
            hot_threshold: 10,
            merkle_batch_size: 1000,
            compress_deltas: true,
            max_pending_deltas: 100,
            max_accounts: 10_000_000,
        }
    }
}

/// Flat Storage Manager - O(1) state access
pub struct FlatStorage {
    config: FlatStorageConfig,
    /// Main account storage (flat key-value)
    accounts: RwLock<HashMap<Address, FlatAccountState>>,
    /// Contract storage (address -> key -> value)
    storage: RwLock<HashMap<Address, HashMap<Hash, [u8; 32]>>>,
    /// Hot account cache
    account_cache: Mutex<LRUCache<Address, FlatAccountState>>,
    /// Hot storage cache
    storage_cache: Mutex<LRUCache<(Address, Hash), [u8; 32]>>,
    /// Pending deltas not yet applied to Merkle tree
    pending_deltas: RwLock<Vec<StateDelta>>,
    /// Current state root (from Merkle tree)
    state_root: RwLock<Hash>,
    /// Current block number
    current_block: RwLock<u64>,
    /// Dirty accounts needing Merkle update
    dirty_accounts: Mutex<HashSet<Address>>,
    /// Statistics
    stats: Mutex<FlatStorageStats>,
}

/// Statistics for flat storage
#[derive(Default, Clone, Debug)]
pub struct FlatStorageStats {
    pub total_reads: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub total_writes: u64,
    pub merkle_updates: u64,
    pub deltas_flushed: u64,
}

impl FlatStorage {
    pub fn new(config: FlatStorageConfig) -> Self {
        Self {
            account_cache: Mutex::new(LRUCache::new(config.account_cache_size)),
            storage_cache: Mutex::new(LRUCache::new(config.storage_cache_size)),
            config,
            accounts: RwLock::new(HashMap::new()),
            storage: RwLock::new(HashMap::new()),
            pending_deltas: RwLock::new(Vec::new()),
            state_root: RwLock::new([0u8; 32]),
            current_block: RwLock::new(0),
            dirty_accounts: Mutex::new(HashSet::new()),
            stats: Mutex::new(FlatStorageStats::default()),
        }
    }
    
    /// O(1) account read - checks cache first, then flat storage
    pub fn get_account(&self, address: &Address) -> Option<FlatAccountState> {
        self.stats.lock().total_reads += 1;
        
        // Check cache first
        {
            let mut cache = self.account_cache.lock();
            if let Some(account) = cache.get(address) {
                self.stats.lock().cache_hits += 1;
                return Some(account.clone());
            }
        }
        
        self.stats.lock().cache_misses += 1;
        
        // Fall back to flat storage
        let accounts = self.accounts.read();
        if let Some(mut account) = accounts.get(address).cloned() {
            account.access_count += 1;
            
            // Promote to cache if hot
            if account.access_count >= self.config.hot_threshold {
                account.is_hot = true;
                self.account_cache.lock().insert(*address, account.clone());
            }
            
            Some(account)
        } else {
            None
        }
    }
    
    /// O(1) account write with delta tracking
    pub fn set_account(&self, account: FlatAccountState) -> StateResult<()> {
        let address = account.address;
        let block = *self.current_block.read();
        
        self.stats.lock().total_writes += 1;
        
        // Get old state for delta
        let old_state = self.accounts.read().get(&address).cloned();
        
        // Update flat storage
        {
            let mut accounts = self.accounts.write();
            accounts.insert(address, account.clone());
        }
        
        // Update cache if present
        {
            let mut cache = self.account_cache.lock();
            if cache.contains(&address) || account.is_hot {
                cache.insert(address, account.clone());
            }
        }
        
        // Mark as dirty for Merkle update
        self.dirty_accounts.lock().insert(address);
        
        // Record delta
        self.record_account_delta(address, old_state, account, block);
        
        Ok(())
    }
    
    /// O(1) storage slot read
    pub fn get_storage(&self, address: &Address, key: &Hash) -> Option<[u8; 32]> {
        self.stats.lock().total_reads += 1;
        
        // Check cache first
        {
            let mut cache = self.storage_cache.lock();
            if let Some(value) = cache.get(&(*address, *key)) {
                self.stats.lock().cache_hits += 1;
                return Some(*value);
            }
        }
        
        self.stats.lock().cache_misses += 1;
        
        // Fall back to flat storage
        let storage = self.storage.read();
        storage.get(address).and_then(|slots| slots.get(key).copied())
    }
    
    /// O(1) storage slot write
    pub fn set_storage(&self, address: &Address, key: Hash, value: [u8; 32]) -> StateResult<()> {
        let block = *self.current_block.read();
        
        self.stats.lock().total_writes += 1;
        
        // Get old value for delta
        let old_value = self.get_storage(address, &key);
        
        // Update flat storage
        {
            let mut storage = self.storage.write();
            storage.entry(*address)
                .or_insert_with(HashMap::new)
                .insert(key, value);
        }
        
        // Update cache
        self.storage_cache.lock().insert((*address, key), value);
        
        // Mark account as dirty
        self.dirty_accounts.lock().insert(*address);
        
        // Record delta
        self.record_storage_delta(*address, key, old_value, value, block);
        
        Ok(())
    }
    
    /// Delete storage slot
    pub fn delete_storage(&self, address: &Address, key: &Hash) -> StateResult<Option<[u8; 32]>> {
        let old_value = {
            let mut storage = self.storage.write();
            if let Some(slots) = storage.get_mut(address) {
                slots.remove(key)
            } else {
                None
            }
        };
        
        if old_value.is_some() {
            self.storage_cache.lock().remove(&(*address, *key));
            self.dirty_accounts.lock().insert(*address);
        }
        
        Ok(old_value)
    }
    
    /// Records account delta
    fn record_account_delta(
        &self,
        address: Address,
        old: Option<FlatAccountState>,
        new: FlatAccountState,
        block: u64,
    ) {
        let mut deltas = self.pending_deltas.write();
        
        // HIGH (w5): Enforce max pending deltas to prevent unbounded growth
        if deltas.len() >= self.config.max_pending_deltas {
            tracing::warn!("Pending deltas at capacity ({}), dropping oldest", self.config.max_pending_deltas);
            deltas.remove(0);
        }
        
        // Find or create delta for this block
        let delta = if let Some(d) = deltas.iter_mut().find(|d| d.block_number == block) {
            d
        } else {
            deltas.push(StateDelta::new(block, *self.state_root.read()));
            deltas.last_mut().unwrap()
        };
        
        let account_delta = match old {
            Some(old_state) => AccountDelta::Modified { old: old_state, new },
            None => AccountDelta::Created(new),
        };
        
        delta.account_changes.insert(address, account_delta);
    }
    
    /// Records storage delta
    fn record_storage_delta(
        &self,
        address: Address,
        key: Hash,
        old: Option<[u8; 32]>,
        new: [u8; 32],
        block: u64,
    ) {
        let mut deltas = self.pending_deltas.write();
        
        // HIGH (w5): Enforce max pending deltas
        if deltas.len() >= self.config.max_pending_deltas {
            tracing::warn!("Pending deltas at capacity ({}), dropping oldest", self.config.max_pending_deltas);
            deltas.remove(0);
        }
        
        let delta = if let Some(d) = deltas.iter_mut().find(|d| d.block_number == block) {
            d
        } else {
            deltas.push(StateDelta::new(block, *self.state_root.read()));
            deltas.last_mut().unwrap()
        };
        
        delta.storage_changes
            .entry(address)
            .or_insert_with(HashMap::new)
            .insert(key, StorageDelta::Set { old, new });
    }
    
    /// Gets all dirty accounts needing Merkle update
    pub fn get_dirty_accounts(&self) -> Vec<Address> {
        self.dirty_accounts.lock().iter().copied().collect()
    }
    
    /// Clears dirty accounts after Merkle update
    pub fn clear_dirty(&self, addresses: &[Address]) {
        let mut dirty = self.dirty_accounts.lock();
        for addr in addresses {
            dirty.remove(addr);
        }
        self.stats.lock().merkle_updates += 1;
    }
    
    /// Flushes pending deltas
    pub fn flush_deltas(&self) -> Vec<StateDelta> {
        let mut deltas = self.pending_deltas.write();
        let flushed = std::mem::take(&mut *deltas);
        self.stats.lock().deltas_flushed += flushed.len() as u64;
        flushed
    }
    
    /// Sets current block number
    pub fn set_block(&self, block: u64) {
        *self.current_block.write() = block;
    }
    
    /// Sets state root after Merkle update
    pub fn set_state_root(&self, root: Hash) {
        *self.state_root.write() = root;
    }
    
    /// Gets current state root
    pub fn state_root(&self) -> Hash {
        *self.state_root.read()
    }
    
    /// Batch account read
    pub fn get_accounts_batch(&self, addresses: &[Address]) -> Vec<Option<FlatAccountState>> {
        addresses.iter().map(|addr| self.get_account(addr)).collect()
    }
    
    /// Batch account write
    pub fn set_accounts_batch(&self, accounts: Vec<FlatAccountState>) -> StateResult<()> {
        for account in accounts {
            self.set_account(account)?;
        }
        Ok(())
    }
    
    /// Gets all storage for an account
    pub fn get_all_storage(&self, address: &Address) -> HashMap<Hash, [u8; 32]> {
        self.storage.read()
            .get(address)
            .cloned()
            .unwrap_or_default()
    }
    
    /// Returns statistics
    pub fn stats(&self) -> FlatStorageStats {
        self.stats.lock().clone()
    }
    
    /// Returns cache hit rate
    pub fn cache_hit_rate(&self) -> f64 {
        let stats = self.stats.lock();
        let total = stats.cache_hits + stats.cache_misses;
        if total == 0 { 0.0 } else { stats.cache_hits as f64 / total as f64 }
    }
    
    /// Returns number of accounts
    pub fn account_count(&self) -> usize {
        self.accounts.read().len()
    }
    
    /// Prefetches accounts into cache
    pub fn prefetch(&self, addresses: &[Address]) {
        let accounts = self.accounts.read();
        let mut cache = self.account_cache.lock();
        
        for address in addresses {
            if !cache.contains(address) {
                if let Some(account) = accounts.get(address) {
                    cache.insert(*address, account.clone());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_account_crud() {
        let storage = FlatStorage::new(FlatStorageConfig::default());
        
        let account = FlatAccountState {
            address: [1u8; 32],
            balance: Amount(1000),
            nonce: 5,
            ..FlatAccountState::new([1u8; 32])
        };
        
        storage.set_account(account.clone()).unwrap();
        
        let retrieved = storage.get_account(&[1u8; 32]).unwrap();
        assert_eq!(retrieved.balance, account.balance);
        assert_eq!(retrieved.nonce, account.nonce);
    }
    
    #[test]
    fn test_storage_crud() {
        let storage = FlatStorage::new(FlatStorageConfig::default());
        
        let address = [1u8; 32];
        let key = [2u8; 32];
        let value = [3u8; 32];
        
        storage.set_storage(&address, key, value).unwrap();
        
        let retrieved = storage.get_storage(&address, &key).unwrap();
        assert_eq!(retrieved, value);
    }
    
    #[test]
    fn test_cache_promotion() {
        let config = FlatStorageConfig {
            hot_threshold: 3,
            account_cache_size: 10,
            ..Default::default()
        };
        let storage = FlatStorage::new(config);
        
        let account = FlatAccountState::new([1u8; 32]);
        storage.set_account(account).unwrap();
        
        // Access multiple times
        for _ in 0..5 {
            storage.get_account(&[1u8; 32]);
        }
        
        // Should now be in cache
        let stats = storage.stats();
        assert!(stats.cache_hits > 0);
    }
}
