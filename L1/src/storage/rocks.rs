// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use rocksdb::{DB, Options, ColumnFamilyDescriptor, WriteBatch, IteratorMode, ReadOptions};
use std::sync::Arc;
use std::path::{Path, PathBuf};
use dashmap::DashMap;
use parking_lot::Mutex;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::storage::{StorageError, StorageResult, keys::*};
use crate::types::{
    Account, Address, Checkpoint, DAGVertex, Hash, ShardId,
    SignedTransaction, TransactionReceipt, Validator, ValidatorSet,
};

/// Maximum contract storage key size (1KB)
const MAX_STORAGE_KEY_SIZE: usize = 1024;
/// Maximum contract storage value size (1MB)
const MAX_STORAGE_VALUE_SIZE: usize = 1024 * 1024;
/// Maximum storage entries per contract
const MAX_STORAGE_ENTRIES_PER_CONTRACT: usize = 100_000;
/// Maximum shards to prune per iteration
const MAX_SHARDS_TO_PRUNE: u16 = 100;
/// Maximum heights to prune per shard
const MAX_HEIGHTS_PER_SHARD: u64 = 1000;
/// HIGH (x5): Maximum memory for bulk contract storage reads (50MB)
const MAX_STORAGE_READ_BYTES: usize = 50 * 1024 * 1024;

#[derive(Clone)]
pub struct Storage {
    db: Arc<DB>,
    db_path: PathBuf,
    backup_path: PathBuf,
    pruning_config: PruningConfig,
    /// Track contract storage sizes to prevent exhaustion
    contract_storage_counts: Arc<DashMap<Address, usize>>,
    /// HIGH (x2): Authorization token for privileged operations
    auth_token: Arc<Mutex<[u8; 32]>>,
    /// CRITICAL (x1): Track the latest known slot for pruning validation
    latest_known_slot: Arc<std::sync::atomic::AtomicU64>,
}

/// Pruning configuration.
#[derive(Clone, Debug)]
pub struct PruningConfig {
    /// Keep last N blocks
    pub keep_last_blocks: u64,
    /// Enable automatic pruning
    pub auto_prune: bool,
    /// Prune interval in blocks
    pub prune_interval: u64,
}

impl Storage {
    pub fn new<P: AsRef<Path>>(path: P) -> StorageResult<Self> {
        Self::new_with_pruning(path, PruningConfig::default())
    }

    pub fn new_with_pruning<P: AsRef<Path>>(path: P, pruning_config: PruningConfig) -> StorageResult<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_max_open_files(10000);
        opts.set_keep_log_file_num(10);
        opts.set_max_total_wal_size(512 * 1024 * 1024);
        opts.increase_parallelism(num_cpus::get() as i32);
        opts.set_max_background_jobs(4);
        opts.set_write_buffer_size(256 * 1024 * 1024);
        opts.set_max_write_buffer_number(4);
        opts.set_target_file_size_base(256 * 1024 * 1024);
        
        // Enable LZ4 compression
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        opts.set_bottommost_compression_type(rocksdb::DBCompressionType::Zstd);
        
        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_ACCOUNTS, Options::default()),
            ColumnFamilyDescriptor::new(CF_VERTICES, Options::default()),
            ColumnFamilyDescriptor::new(CF_TRANSACTIONS, Options::default()),
            ColumnFamilyDescriptor::new(CF_RECEIPTS, Options::default()),
            ColumnFamilyDescriptor::new(CF_CHECKPOINTS, Options::default()),
            ColumnFamilyDescriptor::new(CF_VALIDATORS, Options::default()),
            ColumnFamilyDescriptor::new(CF_STATE, Options::default()),
            ColumnFamilyDescriptor::new(CF_DAG_TIPS, Options::default()),
            ColumnFamilyDescriptor::new(CF_DAG_HEIGHTS, Options::default()),
            ColumnFamilyDescriptor::new(CF_METADATA, Options::default()),
            ColumnFamilyDescriptor::new(CF_CONTRACTS, Options::default()),
            ColumnFamilyDescriptor::new(CF_CONTRACT_STORAGE, Options::default()),
            ColumnFamilyDescriptor::new(CF_QN8_COLLECTIONS, Options::default()),
            ColumnFamilyDescriptor::new(CF_QN8_OWNER_TOKENS, Options::default()),
            ColumnFamilyDescriptor::new(CF_QN4_TOKENS, Options::default()),
            ColumnFamilyDescriptor::new(CF_QN4_OWNER_BALANCES, Options::default()),
        ];

        let db_path = path.as_ref().to_path_buf();
        let backup_path = db_path.parent()
            .unwrap_or(Path::new("."))
            .join("backups");

        let db = DB::open_cf_descriptors(&opts, &db_path, cfs)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        // HIGH (x2): Generate cryptographically secure auth token
        let mut token = [0u8; 32];
        OsRng.fill_bytes(&mut token);
        
        let storage = Self { 
            db: Arc::new(db),
            db_path,
            backup_path,
            pruning_config,
            contract_storage_counts: Arc::new(DashMap::new()),
            auth_token: Arc::new(Mutex::new(token)),
            latest_known_slot: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        };
        
        // HIGH (x4): Reload persisted storage counts from DB
        storage.reload_storage_counts();
        
        Ok(storage)
    }
    
    /// Returns the local bootstrap token for trusted in-crate maintenance.
    pub(crate) fn bootstrap_auth_token(&self) -> [u8; 32] {
        *self.auth_token.lock()
    }
    
    /// HIGH (x2): Verify auth token
    fn verify_auth(&self, token: &[u8; 32]) -> StorageResult<()> {
        let expected = self.auth_token.lock();
        if token != &*expected {
            return Err(StorageError::Unauthorized("Invalid auth token".to_string()));
        }
        Ok(())
    }
    
    /// CRITICAL (x1): Update the latest known slot (call this when processing blocks)
    pub fn update_latest_slot(&self, slot: u64) {
        self.latest_known_slot.fetch_max(slot, std::sync::atomic::Ordering::Relaxed);
    }
    
    /// HIGH (x4): Reload storage counts from DB on startup
    fn reload_storage_counts(&self) {
        if let Ok(Some(cf)) = self.db.cf_handle(CF_METADATA).ok_or(()).map(Some) {
            let prefix = vec![STORAGE_COUNT_PREFIX, PREFIX_SEPARATOR];
            let iter = self.db.iterator_cf(&cf, IteratorMode::From(&prefix, rocksdb::Direction::Forward));
            
            for item in iter {
                if let Ok((key, value)) = item {
                    if !key.starts_with(&prefix) {
                        break;
                    }
                    if key.len() >= prefix.len() + 32 {
                        let mut address = [0u8; 32];
                        address.copy_from_slice(&key[prefix.len()..prefix.len() + 32]);
                        if value.len() >= 8 {
                            let count = u64::from_le_bytes(value[..8].try_into().unwrap_or([0; 8])) as usize;
                            self.contract_storage_counts.insert(address, count);
                        }
                    }
                }
            }
            tracing::info!("Reloaded {} contract storage counts from DB", self.contract_storage_counts.len());
        }
    }
    
    /// HIGH (x4): Persist a contract's storage count to DB
    fn persist_storage_count(&self, address: &Address, count: usize) -> StorageResult<()> {
        if let Some(cf) = self.db.cf_handle(CF_METADATA) {
            let mut key = vec![STORAGE_COUNT_PREFIX, PREFIX_SEPARATOR];
            key.extend_from_slice(address);
            let value = (count as u64).to_le_bytes();
            self.db.put_cf(&cf, &key, &value)
                .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
        }
        Ok(())
    }

    pub fn get_account(&self, address: &Address) -> StorageResult<Option<Account>> {
        let cf = self.db.cf_handle(CF_ACCOUNTS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = account_key(address);
        match self.db.get_cf(&cf, &key) {
            Ok(Some(data)) => {
                let account: Account = bincode::deserialize(&data)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(Some(account))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::DatabaseError(e.to_string())),
        }
    }

    pub fn put_account(&self, account: &Account) -> StorageResult<()> {
        let cf = self.db.cf_handle(CF_ACCOUNTS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = account_key(&account.address);
        let data = bincode::serialize(account)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        
        self.db.put_cf(&cf, &key, &data)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    /// Iterates all persisted accounts in deterministic key order.
    ///
    /// State roots must be computed from durable storage, not from in-memory
    /// caches, otherwise two nodes with different cache warmth can fork.
    pub fn iter_accounts(&self) -> StorageResult<Vec<Account>> {
        let cf = self.db.cf_handle(CF_ACCOUNTS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;

        let prefix = vec![0x01, PREFIX_SEPARATOR];
        let read_opts = ReadOptions::default();
        let iter = self.db.iterator_cf_opt(
            &cf,
            read_opts,
            IteratorMode::From(&prefix, rocksdb::Direction::Forward),
        );

        let mut accounts = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::DatabaseError(e.to_string()))?;
            if !key.starts_with(&prefix) {
                break;
            }

            let account: Account = bincode::deserialize(&value)
                .map_err(|e| StorageError::SerializationError(e.to_string()))?;
            accounts.push(account);
        }

        accounts.sort_by(|a, b| a.address.cmp(&b.address));
        Ok(accounts)
    }

    pub fn get_vertex(&self, hash: &Hash) -> StorageResult<Option<DAGVertex>> {
        let cf = self.db.cf_handle(CF_VERTICES)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = vertex_key(hash);
        match self.db.get_cf(&cf, &key) {
            Ok(Some(data)) => {
                let vertex: DAGVertex = bincode::deserialize(&data)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(Some(vertex))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::DatabaseError(e.to_string())),
        }
    }

    pub fn put_vertex(&self, vertex: &DAGVertex) -> StorageResult<()> {
        let cf_vertices = self.db.cf_handle(CF_VERTICES)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        let cf_heights = self.db.cf_handle(CF_DAG_HEIGHTS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let mut batch = WriteBatch::default();
        
        let key = vertex_key(&vertex.hash);
        let data = bincode::serialize(vertex)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        batch.put_cf(&cf_vertices, &key, &data);
        
        let height_key = vertex_by_height_key(vertex.shard_id, vertex.height);
        batch.put_cf(&cf_heights, &height_key, &vertex.hash);
        
        self.db.write(batch)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    pub fn get_transaction(&self, hash: &Hash) -> StorageResult<Option<SignedTransaction>> {
        let cf = self.db.cf_handle(CF_TRANSACTIONS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = transaction_key(hash);
        match self.db.get_cf(&cf, &key) {
            Ok(Some(data)) => {
                let tx: SignedTransaction = bincode::deserialize(&data)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(Some(tx))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::DatabaseError(e.to_string())),
        }
    }

    pub fn put_transaction(&self, tx: &SignedTransaction) -> StorageResult<()> {
        let cf = self.db.cf_handle(CF_TRANSACTIONS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = transaction_key(&tx.hash);
        let data = bincode::serialize(tx)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        
        self.db.put_cf(&cf, &key, &data)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    pub fn put_transactions_batch(&self, txs: &[SignedTransaction]) -> StorageResult<()> {
        let cf = self.db.cf_handle(CF_TRANSACTIONS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let mut batch = WriteBatch::default();
        for tx in txs {
            let key = transaction_key(&tx.hash);
            let data = bincode::serialize(tx)
                .map_err(|e| StorageError::SerializationError(e.to_string()))?;
            batch.put_cf(&cf, &key, &data);
        }
        
        self.db.write(batch)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    pub fn get_recent_receipts(&self, limit: usize) -> StorageResult<Vec<TransactionReceipt>> {
        let cf = self.db.cf_handle(CF_RECEIPTS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;

        let prefix: Vec<u8> = vec![0x05, PREFIX_SEPARATOR];
        let iter = self.db.prefix_iterator_cf(&cf, &prefix);
        let mut receipts = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::DatabaseError(e.to_string()))?;
            if !key.starts_with(&prefix) {
                break;
            }
            if let Ok(r) = bincode::deserialize::<TransactionReceipt>(&value) {
                receipts.push(r);
            }
        }
        receipts.sort_by(|a, b| b.slot.cmp(&a.slot));
        receipts.truncate(limit);
        Ok(receipts)
    }

    pub fn get_receipts_since_slot(&self, since_slot: u64, limit: usize) -> StorageResult<Vec<TransactionReceipt>> {
        let cf = self.db.cf_handle(CF_RECEIPTS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;

        let prefix: Vec<u8> = vec![0x05, PREFIX_SEPARATOR];
        let iter = self.db.prefix_iterator_cf(&cf, &prefix);
        let mut receipts = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::DatabaseError(e.to_string()))?;
            if !key.starts_with(&prefix) {
                break;
            }
            if let Ok(r) = bincode::deserialize::<TransactionReceipt>(&value) {
                if r.slot >= since_slot {
                    receipts.push(r);
                }
            }
        }
        receipts.sort_by(|a, b| a.slot.cmp(&b.slot));
        receipts.truncate(limit);
        Ok(receipts)
    }

    pub fn get_receipt(&self, tx_hash: &Hash) -> StorageResult<Option<TransactionReceipt>> {
        let cf = self.db.cf_handle(CF_RECEIPTS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = receipt_key(tx_hash);
        match self.db.get_cf(&cf, &key) {
            Ok(Some(data)) => {
                let receipt: TransactionReceipt = bincode::deserialize(&data)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(Some(receipt))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::DatabaseError(e.to_string())),
        }
    }

    pub fn put_receipt(&self, receipt: &TransactionReceipt) -> StorageResult<()> {
        let cf = self.db.cf_handle(CF_RECEIPTS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = receipt_key(&receipt.tx_hash);
        let data = bincode::serialize(receipt)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        
        self.db.put_cf(&cf, &key, &data)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    pub fn get_checkpoint(&self, epoch: u64, slot: u64) -> StorageResult<Option<Checkpoint>> {
        let cf = self.db.cf_handle(CF_CHECKPOINTS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = checkpoint_key(epoch, slot);
        match self.db.get_cf(&cf, &key) {
            Ok(Some(data)) => {
                let checkpoint: Checkpoint = bincode::deserialize(&data)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(Some(checkpoint))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::DatabaseError(e.to_string())),
        }
    }

    pub fn put_checkpoint(&self, checkpoint: &Checkpoint) -> StorageResult<()> {
        let cf = self.db.cf_handle(CF_CHECKPOINTS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        let cf_meta = self.db.cf_handle(CF_METADATA)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let mut batch = WriteBatch::default();
        
        let key = checkpoint_key(checkpoint.epoch, checkpoint.slot);
        let data = bincode::serialize(checkpoint)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        batch.put_cf(&cf, &key, &data);
        
        let hash_key = checkpoint_by_hash_key(&checkpoint.hash());
        batch.put_cf(&cf, &hash_key, &data);
        
        batch.put_cf(&cf_meta, &latest_checkpoint_key(), &data);
        
        self.db.write(batch)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    pub fn get_latest_checkpoint(&self) -> StorageResult<Option<Checkpoint>> {
        let cf = self.db.cf_handle(CF_METADATA)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        match self.db.get_cf(&cf, &latest_checkpoint_key()) {
            Ok(Some(data)) => {
                let checkpoint: Checkpoint = bincode::deserialize(&data)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(Some(checkpoint))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::DatabaseError(e.to_string())),
        }
    }

    pub fn get_validator(&self, address: &Address) -> StorageResult<Option<Validator>> {
        let cf = self.db.cf_handle(CF_VALIDATORS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = validator_key(address);
        match self.db.get_cf(&cf, &key) {
            Ok(Some(data)) => {
                let validator: Validator = bincode::deserialize(&data)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(Some(validator))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::DatabaseError(e.to_string())),
        }
    }

    pub fn put_validator(&self, validator: &Validator) -> StorageResult<()> {
        let cf = self.db.cf_handle(CF_VALIDATORS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = validator_key(&validator.address);
        let data = bincode::serialize(validator)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        
        self.db.put_cf(&cf, &key, &data)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    pub fn get_validator_set(&self, epoch: u64) -> StorageResult<Option<ValidatorSet>> {
        let cf = self.db.cf_handle(CF_VALIDATORS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = validator_set_key(epoch);
        match self.db.get_cf(&cf, &key) {
            Ok(Some(data)) => {
                let set: ValidatorSet = bincode::deserialize(&data)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(Some(set))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::DatabaseError(e.to_string())),
        }
    }

    pub fn put_validator_set(&self, epoch: u64, set: &ValidatorSet) -> StorageResult<()> {
        let cf = self.db.cf_handle(CF_VALIDATORS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = validator_set_key(epoch);
        let data = bincode::serialize(set)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        
        self.db.put_cf(&cf, &key, &data)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    pub fn get_dag_tips(&self, shard_id: ShardId) -> StorageResult<Vec<Hash>> {
        let cf = self.db.cf_handle(CF_DAG_TIPS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = dag_tip_key(shard_id);
        match self.db.get_cf(&cf, &key) {
            Ok(Some(data)) => {
                let tips: Vec<Hash> = bincode::deserialize(&data)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(tips)
            }
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(StorageError::DatabaseError(e.to_string())),
        }
    }

    pub fn put_dag_tips(&self, shard_id: ShardId, tips: &[Hash]) -> StorageResult<()> {
        let cf = self.db.cf_handle(CF_DAG_TIPS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = dag_tip_key(shard_id);
        let data = bincode::serialize(tips)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        
        self.db.put_cf(&cf, &key, &data)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    pub fn get_state_root(&self, slot: u64) -> StorageResult<Option<Hash>> {
        let cf = self.db.cf_handle(CF_STATE)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = state_root_key(slot);
        match self.db.get_cf(&cf, &key) {
            Ok(Some(data)) => {
                let hash: Hash = data.try_into()
                    .map_err(|_| StorageError::Corruption("Invalid hash length".to_string()))?;
                Ok(Some(hash))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::DatabaseError(e.to_string())),
        }
    }

    pub fn put_state_root(&self, slot: u64, root: &Hash) -> StorageResult<()> {
        let cf = self.db.cf_handle(CF_STATE)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = state_root_key(slot);
        self.db.put_cf(&cf, &key, root)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    pub fn flush(&self) -> StorageResult<()> {
        self.db.flush()
            .map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    /// Creates a checkpoint backup of the database.
    /// HIGH (x2): Requires auth token to prevent unauthorized backup creation
    pub fn create_backup(&self, auth_token: &[u8; 32]) -> StorageResult<()> {
        self.verify_auth(auth_token)?;
        std::fs::create_dir_all(&self.backup_path)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        let checkpoint_path = self.backup_path.join(format!(
            "checkpoint_{}",
            chrono::Utc::now().timestamp()
        ));

        let checkpoint = rocksdb::checkpoint::Checkpoint::new(&self.db)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        checkpoint.create_checkpoint(&checkpoint_path)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        tracing::info!("Database checkpoint created at {:?}", checkpoint_path);
        Ok(())
    }

    /// Gets backup path.
    pub fn backup_path(&self) -> &std::path::Path {
        &self.backup_path
    }

    /// Prunes old data keeping only the last N blocks.
    /// CRITICAL (x1): Validates current_slot against latest known slot
    /// HIGH (x2): Requires auth token
    pub fn prune_old_data(&self, current_slot: u64, max_shards: u16, auth_token: &[u8; 32]) -> StorageResult<u64> {
        self.verify_auth(auth_token)?;
        
        if current_slot < self.pruning_config.keep_last_blocks {
            return Ok(0);
        }
        
        // CRITICAL (x1): Validate current_slot is not unreasonably in the future
        let latest = self.latest_known_slot.load(std::sync::atomic::Ordering::Relaxed);
        // Allow a small buffer (1000 slots) beyond latest known for legitimate use
        if latest > 0 && current_slot > latest.saturating_add(1000) {
            return Err(StorageError::InvalidInput(format!(
                "Pruning slot {} is too far ahead of latest known slot {}",
                current_slot, latest
            )));
        }

        let prune_before_slot = current_slot - self.pruning_config.keep_last_blocks;
        let mut pruned_count = 0u64;

        // Prune old vertices
        let cf_vertices = self.db.cf_handle(CF_VERTICES)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        let cf_heights = self.db.cf_handle(CF_DAG_HEIGHTS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;

        // CRITICAL: Limit shards to prevent unbounded iteration
        let shards_to_prune = max_shards.min(MAX_SHARDS_TO_PRUNE);
        
        // CRITICAL: Limit heights per shard to prevent DoS
        let start_height = if prune_before_slot > MAX_HEIGHTS_PER_SHARD {
            prune_before_slot - MAX_HEIGHTS_PER_SHARD
        } else {
            0
        };

        // Iterate through limited shards
        for shard_id in 0..shards_to_prune {
            for height in start_height..prune_before_slot {
                let height_key = vertex_by_height_key(shard_id, height);
                if let Ok(Some(vertex_hash)) = self.db.get_cf(&cf_heights, &height_key) {
                    // CRITICAL: Validate hash conversion instead of silent failure
                    let hash_slice: &[u8] = vertex_hash.as_ref();
                    let hash: Hash = hash_slice.try_into()
                        .map_err(|_: std::array::TryFromSliceError| StorageError::Corruption(format!("Invalid vertex hash at shard {} height {}", shard_id, height)))?;
                    
                    let vertex_key = vertex_key(&hash);
                    self.db.delete_cf(&cf_vertices, &vertex_key)
                        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
                    self.db.delete_cf(&cf_heights, &height_key)
                        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
                    pruned_count += 1;
                }
            }
        }

        // GAS (x7): Use range-based deletion instead of iterating all slots from 0
        // Only prune the window between (prune_before_slot - MAX_HEIGHTS_PER_SHARD) and prune_before_slot
        let cf_state = self.db.cf_handle(CF_STATE)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let state_prune_start = if prune_before_slot > MAX_HEIGHTS_PER_SHARD {
            prune_before_slot - MAX_HEIGHTS_PER_SHARD
        } else {
            0
        };
        for slot in state_prune_start..prune_before_slot {
            let key = state_root_key(slot);
            self.db.delete_cf(&cf_state, &key)
                .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
        }

        tracing::info!("Pruned {} old entries before slot {} (shards: {}, heights: {}-{})", 
            pruned_count, prune_before_slot, shards_to_prune, start_height, prune_before_slot);
        Ok(pruned_count)
    }
    
    /// Prunes old data in batches (for incremental pruning)
    pub fn prune_old_data_batch(&self, current_slot: u64, _shard_start: u16, shard_count: u16, auth_token: &[u8; 32]) -> StorageResult<u64> {
        self.prune_old_data(current_slot, shard_count, auth_token)
    }

    /// Compacts the database to reclaim space.
    /// HIGH (x2): Requires auth token to prevent unauthorized compaction DoS
    pub fn compact(&self, auth_token: &[u8; 32]) -> StorageResult<()> {
        self.verify_auth(auth_token)?;
        self.db.compact_range::<&[u8], &[u8]>(None, None);
        tracing::info!("Database compaction completed");
        Ok(())
    }

    /// Gets database statistics.
    pub fn get_stats(&self) -> StorageResult<String> {
        let stats = self.db.property_value("rocksdb.stats")
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
        Ok(stats.unwrap_or_else(|| "No stats available".to_string()))
    }

    /// Gets approximate database size in bytes.
    pub fn get_size(&self) -> StorageResult<u64> {
        let mut total_size = 0u64;
        
        if let Ok(Some(size_str)) = self.db.property_value("rocksdb.total-sst-files-size") {
            if let Ok(size) = size_str.parse::<u64>() {
                total_size += size;
            }
        }
        
        Ok(total_size)
    }

    // ========================================================================
    // Contract Storage Methods
    // ========================================================================

    /// Stores deployed contract info.
    pub fn put_deployed_contract(&self, metadata: &crate::vm::DeployedContract) -> StorageResult<()> {
        let cf = self.db.cf_handle(CF_CONTRACTS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = contract_metadata_key(&metadata.address);
        let data = bincode::serialize(metadata)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        
        self.db.put_cf(&cf, &key, &data)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    pub fn delete_deployed_contract(&self, address: &Address) -> StorageResult<()> {
        let cf = self.db.cf_handle(CF_CONTRACTS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;

        let key = contract_metadata_key(address);
        self.db.delete_cf(&cf, &key)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    /// Gets deployed contract info.
    pub fn get_deployed_contract(&self, address: &Address) -> StorageResult<Option<crate::vm::DeployedContract>> {
        let cf = self.db.cf_handle(CF_CONTRACTS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = contract_metadata_key(address);
        match self.db.get_cf(&cf, &key) {
            Ok(Some(data)) => {
                let metadata: crate::vm::DeployedContract = bincode::deserialize(&data)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(Some(metadata))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::DatabaseError(e.to_string())),
        }
    }

    /// Stores raw contract bytecode for persistence across restarts.
    pub fn put_contract_bytecode(&self, address: &Address, bytecode: &[u8]) -> StorageResult<()> {
        let cf = self.db.cf_handle(CF_CONTRACTS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = contract_bytecode_key(address);
        self.db.put_cf(&cf, &key, bytecode)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    pub fn delete_contract_bytecode(&self, address: &Address) -> StorageResult<()> {
        let cf = self.db.cf_handle(CF_CONTRACTS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;

        let key = contract_bytecode_key(address);
        self.db.delete_cf(&cf, &key)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    /// Gets raw contract bytecode.
    pub fn get_contract_bytecode(&self, address: &Address) -> StorageResult<Option<Vec<u8>>> {
        let cf = self.db.cf_handle(CF_CONTRACTS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = contract_bytecode_key(address);
        match self.db.get_cf(&cf, &key) {
            Ok(data) => Ok(data),
            Err(e) => Err(StorageError::DatabaseError(e.to_string())),
        }
    }

    /// Lists all deployed contract addresses and their bytecode for reload on startup.
    pub fn get_all_contracts(&self) -> StorageResult<Vec<(Address, Vec<u8>)>> {
        let cf = self.db.cf_handle(CF_CONTRACTS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let bytecode_prefix: Vec<u8> = vec![0x11, PREFIX_SEPARATOR];
        let mut contracts = Vec::new();
        
        let iter = self.db.prefix_iterator_cf(&cf, &bytecode_prefix);
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::DatabaseError(e.to_string()))?;
            if !key.starts_with(&bytecode_prefix) {
                break;
            }
            if key.len() >= bytecode_prefix.len() + 32 {
                let mut address = [0u8; 32];
                address.copy_from_slice(&key[bytecode_prefix.len()..bytecode_prefix.len() + 32]);
                contracts.push((address, value.to_vec()));
            }
        }
        
        Ok(contracts)
    }

    /// Loads all storage for a contract.
    /// CRITICAL: Use snapshot to prevent race conditions
    pub fn get_contract_storage(&self, contract_address: &Address) -> StorageResult<std::collections::HashMap<Vec<u8>, Vec<u8>>> {
        let cf = self.db.cf_handle(CF_CONTRACT_STORAGE)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let prefix = contract_storage_prefix(contract_address);
        let mut storage = std::collections::HashMap::new();
        
        // CRITICAL: Use snapshot for consistent reads
        let snapshot = self.db.snapshot();
        let mut read_opts = ReadOptions::default();
        read_opts.set_snapshot(&snapshot);
        
        let iter = self.db.iterator_cf_opt(&cf, read_opts, IteratorMode::From(&prefix, rocksdb::Direction::Forward));
        
        let mut entry_count = 0;
        // HIGH (x5): Track total memory to prevent OOM
        let mut total_bytes: usize = 0;
        
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::DatabaseError(e.to_string()))?;
            
            // Check if key still has our prefix
            if !key.starts_with(&prefix) {
                break;
            }
            
            // CRITICAL: Limit number of entries to prevent memory exhaustion
            entry_count += 1;
            if entry_count > MAX_STORAGE_ENTRIES_PER_CONTRACT {
                return Err(StorageError::StorageExhaustion(format!(
                    "Contract {} exceeds maximum storage entries ({})",
                    hex::encode(contract_address),
                    MAX_STORAGE_ENTRIES_PER_CONTRACT
                )));
            }
            
            // HIGH (x5): Check total memory allocation
            total_bytes = total_bytes.saturating_add(key.len()).saturating_add(value.len());
            if total_bytes > MAX_STORAGE_READ_BYTES {
                return Err(StorageError::StorageExhaustion(format!(
                    "Contract {} storage read exceeds memory limit ({} bytes)",
                    hex::encode(contract_address),
                    MAX_STORAGE_READ_BYTES
                )));
            }
            
            // Extract storage key (remove prefix)
            let storage_key = key[prefix.len()..].to_vec();
            storage.insert(storage_key, value.to_vec());
        }
        
        Ok(storage)
    }

    /// Updates contract storage (writes and deletes).
    /// CRITICAL: Validate sizes to prevent storage exhaustion
    pub fn update_contract_storage(
        &self,
        contract_address: &Address,
        writes: &std::collections::HashMap<Vec<u8>, Vec<u8>>,
        deletes: &[Vec<u8>],
    ) -> StorageResult<()> {
        let cf = self.db.cf_handle(CF_CONTRACT_STORAGE)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        // CRITICAL: Validate all keys and values before writing
        for (storage_key, value) in writes {
            if storage_key.len() > MAX_STORAGE_KEY_SIZE {
                return Err(StorageError::InvalidInput(format!(
                    "Storage key too large: {} bytes (max: {})",
                    storage_key.len(),
                    MAX_STORAGE_KEY_SIZE
                )));
            }
            if value.len() > MAX_STORAGE_VALUE_SIZE {
                return Err(StorageError::InvalidInput(format!(
                    "Storage value too large: {} bytes (max: {})",
                    value.len(),
                    MAX_STORAGE_VALUE_SIZE
                )));
            }
        }
        
        // HIGH (x3): Use entry API for atomic check-then-update to prevent race condition
        let mut entry = self.contract_storage_counts.entry(*contract_address).or_insert(0);
        let current_count = *entry;
        
        let net_change = writes.len() as i64 - deletes.len() as i64;
        let projected_count = if net_change >= 0 {
            current_count.saturating_add(net_change as usize)
        } else {
            current_count.saturating_sub((-net_change) as usize)
        };
        
        if projected_count > MAX_STORAGE_ENTRIES_PER_CONTRACT {
            return Err(StorageError::StorageExhaustion(format!(
                "Contract {} would exceed maximum storage entries ({} + {} > {})",
                hex::encode(contract_address),
                current_count,
                net_change,
                MAX_STORAGE_ENTRIES_PER_CONTRACT
            )));
        }
        
        let mut batch = WriteBatch::default();
        
        // Apply writes
        for (storage_key, value) in writes {
            let key = contract_storage_key(contract_address, storage_key);
            batch.put_cf(&cf, &key, value);
        }
        
        // Apply deletes
        for storage_key in deletes {
            let key = contract_storage_key(contract_address, storage_key);
            batch.delete_cf(&cf, &key);
        }
        
        self.db.write(batch)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
        
        // HIGH (x3): Update count atomically (we still hold the entry lock)
        *entry = projected_count;
        drop(entry);
        
        // HIGH (x4): Persist storage count to DB
        self.persist_storage_count(contract_address, projected_count)?;
        
        Ok(())
    }

    pub fn update_multiple_contract_storages(
        &self,
        writes_by_contract: &std::collections::HashMap<Address, std::collections::HashMap<Vec<u8>, Vec<u8>>>,
        deletes_by_contract: &std::collections::HashMap<Address, Vec<Vec<u8>>>,
    ) -> StorageResult<()> {
        let cf_storage = self.db.cf_handle(CF_CONTRACT_STORAGE)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        let cf_meta = self.db.cf_handle(CF_METADATA)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;

        let mut all_addresses = std::collections::BTreeSet::new();
        for address in writes_by_contract.keys() {
            all_addresses.insert(*address);
        }
        for address in deletes_by_contract.keys() {
            all_addresses.insert(*address);
        }

        let mut projected_counts = Vec::new();

        for address in &all_addresses {
            let writes = writes_by_contract.get(address);
            let deletes = deletes_by_contract.get(address);

            if let Some(contract_writes) = writes {
                for (storage_key, value) in contract_writes {
                    if storage_key.len() > MAX_STORAGE_KEY_SIZE {
                        return Err(StorageError::InvalidInput(format!(
                            "Storage key too large: {} bytes (max: {})",
                            storage_key.len(),
                            MAX_STORAGE_KEY_SIZE
                        )));
                    }
                    if value.len() > MAX_STORAGE_VALUE_SIZE {
                        return Err(StorageError::InvalidInput(format!(
                            "Storage value too large: {} bytes (max: {})",
                            value.len(),
                            MAX_STORAGE_VALUE_SIZE
                        )));
                    }
                }
            }

            let current_count = self.contract_storage_counts.get(address)
                .map(|entry| *entry)
                .unwrap_or(0);
            let write_count = writes.map(|items| items.len()).unwrap_or(0);
            let delete_count = deletes.map(|items| items.len()).unwrap_or(0);
            let net_change = write_count as i64 - delete_count as i64;
            let projected_count = if net_change >= 0 {
                current_count.saturating_add(net_change as usize)
            } else {
                current_count.saturating_sub((-net_change) as usize)
            };

            if projected_count > MAX_STORAGE_ENTRIES_PER_CONTRACT {
                return Err(StorageError::StorageExhaustion(format!(
                    "Contract {} would exceed maximum storage entries ({} + {} > {})",
                    hex::encode(address),
                    current_count,
                    net_change,
                    MAX_STORAGE_ENTRIES_PER_CONTRACT
                )));
            }

            projected_counts.push((*address, projected_count));
        }

        let mut batch = WriteBatch::default();

        for (address, writes) in writes_by_contract {
            for (storage_key, value) in writes {
                let key = contract_storage_key(address, storage_key);
                batch.put_cf(&cf_storage, &key, value);
            }
        }

        for (address, deletes) in deletes_by_contract {
            for storage_key in deletes {
                let key = contract_storage_key(address, storage_key);
                batch.delete_cf(&cf_storage, &key);
            }
        }

        for (address, projected_count) in &projected_counts {
            let mut key = vec![STORAGE_COUNT_PREFIX, PREFIX_SEPARATOR];
            key.extend_from_slice(address);
            let value = (*projected_count as u64).to_le_bytes();
            batch.put_cf(&cf_meta, &key, value);
        }

        self.db.write(batch)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        for (address, projected_count) in projected_counts {
            self.contract_storage_counts.insert(address, projected_count);
        }

        Ok(())
    }

    /// Gets a single storage value for a contract.
    pub fn get_contract_storage_value(
        &self,
        contract_address: &Address,
        storage_key: &[u8],
    ) -> StorageResult<Option<Vec<u8>>> {
        let cf = self.db.cf_handle(CF_CONTRACT_STORAGE)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = contract_storage_key(contract_address, storage_key);
        match self.db.get_cf(&cf, &key) {
            Ok(Some(value)) => Ok(Some(value.to_vec())),
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::DatabaseError(e.to_string())),
        }
    }

    /// Deletes all storage entries for a contract.
    ///
    /// Used for EVM SELFDESTRUCT / full contract deletion.
    pub fn delete_contract_storage_all(&self, contract_address: &Address) -> StorageResult<()> {
        let cf = self.db.cf_handle(CF_CONTRACT_STORAGE)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;

        let prefix = contract_storage_prefix(contract_address);
        let mut batch = WriteBatch::default();

        // Snapshot to iterate consistently.
        let snapshot = self.db.snapshot();
        let mut read_opts = ReadOptions::default();
        read_opts.set_snapshot(&snapshot);

        let iter = self.db.iterator_cf_opt(
            &cf,
            read_opts,
            IteratorMode::From(&prefix, rocksdb::Direction::Forward),
        );

        let mut deleted = 0usize;
        for item in iter {
            let (key, _value) = item.map_err(|e| StorageError::DatabaseError(e.to_string()))?;
            if !key.starts_with(&prefix) {
                break;
            }
            batch.delete_cf(&cf, &key);
            deleted = deleted.saturating_add(1);
        }

        if deleted == 0 {
            return Ok(());
        }

        self.db.write(batch)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        // Best-effort: clear cached count (count will be recomputed on restart if needed).
        self.contract_storage_counts.insert(*contract_address, 0);
        Ok(())
    }

    // ========================================================================
    // QN8 NFT Collection Storage Methods
    // ========================================================================

    /// Stores a QN8 collection.
    pub fn put_qn8_collection(
        &self,
        collection_address: &Address,
        token: &crate::standards::qn8::QN8Token,
    ) -> StorageResult<()> {
        let cf = self.db.cf_handle(CF_QN8_COLLECTIONS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = qn8_collection_key(collection_address);
        let data = bincode::serialize(token)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        
        self.db.put_cf(&cf, &key, &data)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    /// Gets a QN8 collection by address.
    pub fn get_qn8_collection(
        &self,
        collection_address: &Address,
    ) -> StorageResult<Option<crate::standards::qn8::QN8Token>> {
        let cf = self.db.cf_handle(CF_QN8_COLLECTIONS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = qn8_collection_key(collection_address);
        match self.db.get_cf(&cf, &key) {
            Ok(Some(data)) => {
                let token: crate::standards::qn8::QN8Token = bincode::deserialize(&data)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(Some(token))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::DatabaseError(e.to_string())),
        }
    }

    /// Updates the owner-tokens index for a given owner + collection.
    pub fn put_qn8_owner_tokens(
        &self,
        owner_address: &Address,
        collection_address: &Address,
        token_ids: &[u64],
    ) -> StorageResult<()> {
        let cf = self.db.cf_handle(CF_QN8_OWNER_TOKENS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = qn8_owner_tokens_key(owner_address, collection_address);
        let data = bincode::serialize(token_ids)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        
        self.db.put_cf(&cf, &key, &data)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    /// Gets token IDs owned by an address in a specific collection.
    pub fn get_qn8_owner_tokens(
        &self,
        owner_address: &Address,
        collection_address: &Address,
    ) -> StorageResult<Vec<u64>> {
        let cf = self.db.cf_handle(CF_QN8_OWNER_TOKENS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let key = qn8_owner_tokens_key(owner_address, collection_address);
        match self.db.get_cf(&cf, &key) {
            Ok(Some(data)) => {
                let ids: Vec<u64> = bincode::deserialize(&data)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(ids)
            }
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(StorageError::DatabaseError(e.to_string())),
        }
    }

    /// Gets all collection addresses that an owner has tokens in.
    /// Returns Vec<(collection_address, token_ids)>.
    pub fn get_qn8_owner_all_tokens(
        &self,
        owner_address: &Address,
    ) -> StorageResult<Vec<(Address, Vec<u64>)>> {
        let cf = self.db.cf_handle(CF_QN8_OWNER_TOKENS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let prefix = qn8_owner_prefix(owner_address);
        let iter = self.db.iterator_cf(&cf, IteratorMode::From(&prefix, rocksdb::Direction::Forward));
        
        let mut results = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::DatabaseError(e.to_string()))?;
            if !key.starts_with(&prefix) {
                break;
            }
            // Extract collection address from key (after prefix)
            if key.len() >= prefix.len() + 32 {
                let mut collection_addr = [0u8; 32];
                collection_addr.copy_from_slice(&key[prefix.len()..prefix.len() + 32]);
                let token_ids: Vec<u64> = bincode::deserialize(&value)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                if !token_ids.is_empty() {
                    results.push((collection_addr, token_ids));
                }
            }
        }
        
        Ok(results)
    }

    /// Lists all QN8 collections.
    pub fn list_qn8_collections(&self) -> StorageResult<Vec<(Address, crate::standards::qn8::QN8Token)>> {
        let cf = self.db.cf_handle(CF_QN8_COLLECTIONS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        
        let prefix = qn8_collections_prefix();
        let iter = self.db.iterator_cf(&cf, IteratorMode::From(&prefix, rocksdb::Direction::Forward));
        
        let mut results = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::DatabaseError(e.to_string()))?;
            if !key.starts_with(&prefix) {
                break;
            }
            if key.len() >= prefix.len() + 32 {
                let mut addr = [0u8; 32];
                addr.copy_from_slice(&key[prefix.len()..prefix.len() + 32]);
                let token: crate::standards::qn8::QN8Token = bincode::deserialize(&value)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                results.push((addr, token));
            }
        }
        
        Ok(results)
    }

    // ========================================================================
    // QN4 Fungible Token Storage
    // ========================================================================

    pub fn put_qn4_token(&self, token_address: &Address, token: &crate::standards::qn4::QN4Token) -> StorageResult<()> {
        let cf = self.db.cf_handle(CF_QN4_TOKENS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        let key = qn4_token_key(token_address);
        let data = bincode::serialize(token).map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db.put_cf(&cf, &key, &data).map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    pub fn get_qn4_token(&self, token_address: &Address) -> StorageResult<Option<crate::standards::qn4::QN4Token>> {
        let cf = self.db.cf_handle(CF_QN4_TOKENS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        let key = qn4_token_key(token_address);
        match self.db.get_cf(&cf, &key) {
            Ok(Some(data)) => {
                let token: crate::standards::qn4::QN4Token = bincode::deserialize(&data)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(Some(token))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::DatabaseError(e.to_string())),
        }
    }

    pub fn put_qn4_owner_balance(&self, owner: &Address, token_address: &Address, balance: u64) -> StorageResult<()> {
        let cf = self.db.cf_handle(CF_QN4_OWNER_BALANCES)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        let key = qn4_owner_balance_key(owner, token_address);
        if balance == 0 {
            self.db.delete_cf(&cf, &key).map_err(|e| StorageError::DatabaseError(e.to_string()))
        } else {
            let data = bincode::serialize(&balance).map_err(|e| StorageError::SerializationError(e.to_string()))?;
            self.db.put_cf(&cf, &key, &data).map_err(|e| StorageError::DatabaseError(e.to_string()))
        }
    }

    pub fn get_qn4_owner_balance(&self, owner: &Address, token_address: &Address) -> StorageResult<u64> {
        let cf = self.db.cf_handle(CF_QN4_OWNER_BALANCES)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        let key = qn4_owner_balance_key(owner, token_address);
        match self.db.get_cf(&cf, &key) {
            Ok(Some(data)) => Ok(bincode::deserialize(&data).map_err(|e| StorageError::SerializationError(e.to_string()))?),
            Ok(None) => Ok(0),
            Err(e) => Err(StorageError::DatabaseError(e.to_string())),
        }
    }

    pub fn get_qn4_owner_all_balances(&self, owner: &Address) -> StorageResult<Vec<(Address, u64)>> {
        let cf = self.db.cf_handle(CF_QN4_OWNER_BALANCES)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        let prefix = qn4_owner_prefix(owner);
        let iter = self.db.iterator_cf(&cf, IteratorMode::From(&prefix, rocksdb::Direction::Forward));
        let mut results = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::DatabaseError(e.to_string()))?;
            if !key.starts_with(&prefix) { break; }
            if key.len() >= prefix.len() + 32 {
                let mut token_addr = [0u8; 32];
                token_addr.copy_from_slice(&key[prefix.len()..prefix.len() + 32]);
                let balance: u64 = bincode::deserialize(&value).map_err(|e| StorageError::SerializationError(e.to_string()))?;
                if balance > 0 { results.push((token_addr, balance)); }
            }
        }
        Ok(results)
    }

    pub fn list_qn4_tokens(&self) -> StorageResult<Vec<(Address, crate::standards::qn4::QN4Token)>> {
        let cf = self.db.cf_handle(CF_QN4_TOKENS)
            .ok_or_else(|| StorageError::DatabaseError("CF not found".to_string()))?;
        let prefix = qn4_tokens_prefix();
        let iter = self.db.iterator_cf(&cf, IteratorMode::From(&prefix, rocksdb::Direction::Forward));
        let mut results = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::DatabaseError(e.to_string()))?;
            if !key.starts_with(&prefix) { break; }
            if key.len() >= prefix.len() + 32 {
                let mut addr = [0u8; 32];
                addr.copy_from_slice(&key[prefix.len()..prefix.len() + 32]);
                let token: crate::standards::qn4::QN4Token = bincode::deserialize(&value)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                results.push((addr, token));
            }
        }
        Ok(results)
    }
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self {
            keep_last_blocks: 100_000,
            auto_prune: true,
            prune_interval: 1000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::types::Amount;

    #[test]
    fn test_storage_account() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path()).unwrap();
        
        let address = [1u8; 32];
        let account = Account::with_balance(address, Amount(1000));
        
        storage.put_account(&account).unwrap();
        let loaded = storage.get_account(&address).unwrap().unwrap();
        
        assert_eq!(loaded.address, address);
        assert_eq!(loaded.balance.0, 1000);
    }

    #[test]
    fn test_storage_checkpoint() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path()).unwrap();
        
        let checkpoint = Checkpoint::genesis();
        storage.put_checkpoint(&checkpoint).unwrap();
        
        let loaded = storage.get_latest_checkpoint().unwrap().unwrap();
        assert_eq!(loaded.epoch, 0);
    }
}
