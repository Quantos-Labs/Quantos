// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

mod secure;
mod adaptive_routing;
pub mod fair_ordering;
pub mod encrypted_mempool;
pub mod accountable_leader;
pub mod mempool_policy;
pub mod pbs;
pub mod blob_transactions;

pub use secure::*;
pub use adaptive_routing::*;
pub use fair_ordering::*;
pub use encrypted_mempool::*;
pub use accountable_leader::*;
pub use mempool_policy::*;
pub use pbs::*;
pub use blob_transactions::*;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use crossbeam_channel::{bounded, Sender, Receiver};
use tracing::warn;

/// Maximum transactions per shard index
const MAX_SHARD_TXS: usize = 10_000;

use crate::crypto::verify_ml_dsa_65;
use crate::network::prefilter_tx_bytes;
use crate::state::StateManager;
use crate::stacc::{ActivationLedger, ACTIVATION_DEPOSIT, QuotaManager};
use crate::stacc::quota::{StakeProvider, AncienneteProvider};
use crate::stacc::mempool::StaccAdmission;
use crate::types::{
    Address, Hash, ShardId, SignedTransaction, hash_data,
};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum MempoolError {
    #[error("Transaction already exists")]
    DuplicateTransaction,
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),
    #[error("Mempool full")]
    MempoolFull,
    #[error("Nonce too low")]
    NonceTooLow,
    #[error("Nonce gap detected")]
    NonceGap,
}

pub type MempoolResult<T> = Result<T, MempoolError>;

pub struct Mempool {
    pending: Arc<DashMap<Hash, SignedTransaction>>,
    by_sender: Arc<DashMap<Address, BTreeMap<u64, Hash>>>,
    by_shard: Arc<DashMap<ShardId, Vec<Hash>>>,
    state_manager: StateManager,
    max_size: usize,
    max_per_sender: usize,
    tx_sender: Sender<SignedTransaction>,
    tx_receiver: Receiver<SignedTransaction>,
    /// STACC admission + WFQ ordering per shard mempool instance.
    stacc: Arc<Mutex<StaccAdmission<ZeroStakeProvider, FixedAgeProvider>>>,
    /// Whether STACC must see sender as activated before admitting tx.
    stacc_require_activation: bool,
}

#[derive(Clone)]
struct ZeroStakeProvider;
impl StakeProvider for ZeroStakeProvider {
    fn stake_of(&self, _addr: &Address) -> u128 { 0 }
    fn total_stake(&self) -> u128 { 0 }
}

#[derive(Clone)]
struct FixedAgeProvider;
impl AncienneteProvider for FixedAgeProvider {
    fn anciennete_factor(&self, _addr: &Address, _now_block: u64) -> f64 { 1.0 }
}

impl Mempool {
    pub fn new(state_manager: StateManager, max_size: usize, stacc_require_activation: bool) -> Self {
        let (tx_sender, tx_receiver) = bounded(10000);
        let activation = ActivationLedger::default();
        let quota = QuotaManager::new(ZeroStakeProvider, FixedAgeProvider);
        let stacc = if stacc_require_activation {
            StaccAdmission::new_with_policy(activation, quota, true, true)
        } else {
            // Testnet/devnet QTEST-only mode: no activation deposit and no CU quota gate.
            StaccAdmission::new_with_policy(activation, quota, false, false)
        };
        
        Self {
            pending: Arc::new(DashMap::new()),
            by_sender: Arc::new(DashMap::new()),
            by_shard: Arc::new(DashMap::new()),
            state_manager,
            max_size,
            max_per_sender: 100,
            tx_sender,
            tx_receiver,
            stacc: Arc::new(Mutex::new(stacc)),
            stacc_require_activation,
        }
    }

    pub fn add_transaction(&self, tx: SignedTransaction) -> MempoolResult<()> {
        self.add_transactions_batch(vec![tx])
            .into_iter()
            .next()
            .unwrap_or(Ok([0u8; 32]))
            .map(|_hash| ())
    }

    /// Add a batch of transactions in one pass: validate all signatures in
    /// parallel, then insert each transaction atomically.
    /// On success returns the transaction hash so callers can map results.
    pub fn add_transactions_batch(&self, txs: Vec<SignedTransaction>) -> Vec<MempoolResult<Hash>> {
        let mut results: Vec<MempoolResult<Hash>> = (0..txs.len()).map(|_| Ok([0u8; 32])).collect();

        // Phase 1: Batch validation OUTSIDE any lock.
        let validation_results = self.validate_transactions_batch(&txs);

        // Phase 2: per-tx insertion (already atomic via DashMap entry API).
        for (i, (tx, validation)) in txs.into_iter().zip(validation_results.into_iter()).enumerate() {
            let hash = tx.hash;
            if let Err(e) = validation {
                results[i] = Err(e);
                continue;
            }

            // STACC admission (has its own internal mutex)
            let now_block = 0u64;
            if !self.stacc_require_activation {
                self.stacc.lock().activation.activate(tx.transaction.from, now_block);
            } else if let Ok(acct) = self.state_manager.get_account(&tx.transaction.from) {
                if acct.stake.0 >= ACTIVATION_DEPOSIT as u128 {
                    self.stacc.lock().activation.activate(tx.transaction.from, now_block);
                }
            }
            if let Err(e) = self.stacc.lock().admit(tx.clone(), now_block) {
                results[i] = Err(e);
                continue;
            }

            let hash = tx.hash;
            let sender = tx.transaction.from;
            let nonce = tx.transaction.nonce;
            let shard_id = tx.transaction.shard_id;

            if self.pending.len() >= self.max_size {
                results[i] = Err(MempoolError::MempoolFull);
                continue;
            }

            match self.pending.entry(hash) {
                dashmap::mapref::entry::Entry::Occupied(_) => {
                    results[i] = Err(MempoolError::DuplicateTransaction);
                    continue;
                }
                dashmap::mapref::entry::Entry::Vacant(vacant) => {
                    vacant.insert(tx.clone());
                }
            }

            self.by_sender
                .entry(sender)
                .or_insert_with(BTreeMap::new)
                .insert(nonce, hash);

            let mut shard_txs = self.by_shard
                .entry(shard_id)
                .or_insert_with(Vec::new);

            if shard_txs.len() >= MAX_SHARD_TXS {
                if let Some(_old_hash) = shard_txs.first().copied() {
                    shard_txs.remove(0);
                }
            }
            shard_txs.push(hash);
            drop(shard_txs);

            if let Err(e) = self.tx_sender.try_send(tx) {
                warn!("Failed to send transaction to subscribers: {:?}", e);
            }

            results[i] = Ok(hash);
        }

        results
    }

    fn validate_transaction(&self, tx: &SignedTransaction) -> MempoolResult<()> {
        match self.add_transactions_batch(vec![tx.clone()]).into_iter().next() {
            Some(result) => result.map(|_hash| ()),
            None => Err(MempoolError::InvalidTransaction("empty validation batch".to_string())),
        }
    }

    /// Validate a batch of transactions. Prefilter and all ML-DSA-65 signatures
    /// are verified in parallel via `verify_ml_dsa_65_parallel_batch`.
    fn validate_transactions_batch(&self, txs: &[SignedTransaction]) -> Vec<MempoolResult<()>> {
        // Stateless prefilter to drop obvious garbage before expensive verify.
        let mut results: Vec<MempoolResult<()>> = (0..txs.len()).map(|_| Ok(())).collect();
        let mut verify_inputs = Vec::with_capacity(txs.len());
        let mut verify_indices = Vec::with_capacity(txs.len());

        for (i, tx) in txs.iter().enumerate() {
            if results[i].is_err() {
                continue;
            }

            let tx_bytes = match bincode::serialize(tx) {
                Ok(b) => b,
                Err(e) => {
                    results[i] = Err(MempoolError::InvalidTransaction(format!("Failed to serialize: {}", e)));
                    continue;
                }
            };
            if let Err(e) = prefilter_tx_bytes(&tx_bytes) {
                tracing::warn!("Prefilter rejected tx: {}", e);
                results[i] = Err(MempoolError::InvalidTransaction(format!("Prefilter: {}", e)));
                continue;
            }

            verify_inputs.push((
                tx.transaction.public_key.clone(),
                tx.transaction.signing_data(),
                tx.transaction.signature.clone(),
            ));
            verify_indices.push(i);
        }

        // One parallel batch verification for the whole set.
        let verify_results = crate::crypto::verify_ml_dsa_65_parallel_batch(&verify_inputs);
        for (batch_idx, valid) in verify_results.into_iter().enumerate() {
            let i = verify_indices[batch_idx];
            if !valid {
                tracing::error!("SIGCHECK: signature did not verify (valid=false)");
                results[i] = Err(MempoolError::InvalidTransaction("Invalid signature".to_string()));
            }
        }

        // Nonce checks (cannot be batched across senders easily, but are cheap).
        for (i, tx) in txs.iter().enumerate() {
            if results[i].is_err() {
                continue;
            }
            let account_nonce = match self.state_manager.get_nonce(&tx.transaction.from) {
                Ok(n) => n,
                Err(e) => {
                    results[i] = Err(MempoolError::InvalidTransaction(e.to_string()));
                    continue;
                }
            };
            if tx.transaction.nonce < account_nonce {
                results[i] = Err(MempoolError::NonceTooLow);
                continue;
            }
            if tx.transaction.nonce > account_nonce + self.max_per_sender as u64 {
                results[i] = Err(MempoolError::NonceGap);
            }
        }

        results
    }

    pub fn get_transaction(&self, hash: &Hash) -> Option<SignedTransaction> {
        self.pending.get(hash).map(|tx| tx.clone())
    }

    pub fn remove_transaction(&self, hash: &Hash) -> Option<SignedTransaction> {
        if let Some((_, tx)) = self.pending.remove(hash) {
            let sender = tx.transaction.from;
            let nonce = tx.transaction.nonce;
            let shard_id = tx.transaction.shard_id;

            if let Some(mut sender_txs) = self.by_sender.get_mut(&sender) {
                sender_txs.remove(&nonce);
            }

            if let Some(mut shard_txs) = self.by_shard.get_mut(&shard_id) {
                shard_txs.retain(|h| h != hash);
            }

            return Some(tx);
        }
        None
    }

    pub fn remove_transactions(&self, hashes: &[Hash]) {
        for hash in hashes {
            self.remove_transaction(hash);
        }
    }

    pub fn get_pending_for_shard(&self, shard_id: ShardId, limit: usize) -> Vec<SignedTransaction> {
        self.get_ready_antichain_for_shard(shard_id, limit)
    }

    /// Select a conflict-minimized, nonce-ready antichain for DAG vertex assembly.
    pub fn get_ready_antichain_for_shard(&self, shard_id: ShardId, limit: usize) -> Vec<SignedTransaction> {
        if limit == 0 {
            return Vec::new();
        }

        let shard_hashes: Vec<Hash> = self.by_shard
            .get(&shard_id)
            .map(|v| v.iter().copied().collect())
            .unwrap_or_default();

        if shard_hashes.is_empty() {
            return Vec::new();
        }

        #[derive(Clone)]
        struct Candidate {
            tx: SignedTransaction,
            score: u128,
        }

        let mut candidates = Vec::with_capacity(shard_hashes.len());
        for h in shard_hashes {
            let Some(tx_ref) = self.pending.get(&h) else { continue; };
            let tx = tx_ref.clone();
            let fee_signal = tx.transaction.amount.0 as u128;
            let cu_signal = tx.transaction.max_compute_units.max(1) as u128;
            let boost_signal = tx.transaction.boost_locked_tokens() as u128;
            let score = (boost_signal.saturating_mul(10) + fee_signal.saturating_mul(2))
                .saturating_mul(1_000_000)
                / cu_signal;
            candidates.push(Candidate { tx, score });
        }

        candidates.sort_by(|a, b| b.score.cmp(&a.score));

        let mut selected = Vec::new();
        let mut expected_nonce: BTreeMap<Address, u64> = BTreeMap::new();
        let mut account_locks: BTreeMap<Address, ()> = BTreeMap::new();
        let mut resource_locks: BTreeMap<Hash, ()> = BTreeMap::new();

        for candidate in candidates {
            if selected.len() >= limit {
                break;
            }

            let tx = candidate.tx;
            let sender = tx.transaction.from;

            let sender_expected = *expected_nonce.entry(sender).or_insert_with(|| {
                self.state_manager.get_nonce(&sender).unwrap_or(0)
            });

            if tx.transaction.nonce != sender_expected {
                continue;
            }

            let from = tx.transaction.from;
            let to = tx.transaction.to;
            if account_locks.contains_key(&from) || account_locks.contains_key(&to) {
                continue;
            }

            let resource_key = resource_conflict_key(&tx);
            if resource_locks.contains_key(&resource_key) {
                continue;
            }

            account_locks.insert(from, ());
            account_locks.insert(to, ());
            resource_locks.insert(resource_key, ());
            // Advance expected nonce so sequential txs from same sender can be included
            *expected_nonce.get_mut(&sender).unwrap() = sender_expected + 1;
            selected.push(tx);
        }

        selected
    }

    pub fn get_executable_transactions(&self, sender: &Address) -> Vec<SignedTransaction> {
        let mut txs = Vec::new();
        
        let expected_nonce = self.state_manager
            .get_nonce(sender)
            .unwrap_or(0);

        if let Some(sender_txs) = self.by_sender.get(sender) {
            let mut current_nonce = expected_nonce;
            
            for (nonce, hash) in sender_txs.iter() {
                if *nonce != current_nonce {
                    break;
                }
                
                if let Some(tx) = self.pending.get(hash) {
                    txs.push(tx.clone());
                    current_nonce += 1;
                }
            }
        }

        txs
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn pending_count_for_shard(&self, shard_id: ShardId) -> usize {
        self.by_shard.get(&shard_id).map(|v| v.len()).unwrap_or(0)
    }

    pub fn pending_count_for_sender(&self, sender: &Address) -> usize {
        self.by_sender.get(sender).map(|v| v.len()).unwrap_or(0)
    }

    pub fn subscribe(&self) -> Receiver<SignedTransaction> {
        self.tx_receiver.clone()
    }

    pub fn clear(&self) {
        self.pending.clear();
        self.by_sender.clear();
        self.by_shard.clear();
    }

    pub fn prune_confirmed(&self, confirmed_txs: &[Hash]) {
        for hash in confirmed_txs {
            self.remove_transaction(hash);
        }
    }
}
pub struct ShardedMempool {
    shards: Arc<DashMap<ShardId, Mempool>>,
    state_manager: StateManager,
    num_shards: u16,
    /// PRODUCTION: Adaptive Mempool Router for optimal shard placement
    amr_router: Arc<AdaptiveMempoolRouter>,
    /// Performance metrics
    routing_metrics: Arc<RwLock<RoutingMetrics>>,
}

/// AMR routing performance metrics
#[derive(Clone, Debug, Default)]
pub struct RoutingMetrics {
    total_routed: u64,
    routing_time_us: u64,
    conflicts_avoided: u64,
    load_balanced: u64,
}

impl ShardedMempool {
    pub fn new(
        state_manager: StateManager,
        num_shards: u16,
        max_per_shard: usize,
        stacc_require_activation: bool,
    ) -> Self {
        let shards = Arc::new(DashMap::new());
        
        for i in 0..num_shards {
            shards.insert(
                i,
                Mempool::new(state_manager.clone(), max_per_shard, stacc_require_activation),
            );
        }

        Self {
            shards,
            state_manager,
            num_shards,
            amr_router: Arc::new(AdaptiveMempoolRouter::new(num_shards)),
            routing_metrics: Arc::new(RwLock::new(RoutingMetrics::default())),
        }
    }

    /// PRODUCTION: Add transaction with AMR-based optimal routing
    pub fn add_transaction(&self, tx: SignedTransaction) -> MempoolResult<()> {
        let start = std::time::Instant::now();
        
        // CRITICAL: Use the shard_id from the signed transaction
        // Modifying shard_id would invalidate the signature since signing_data() includes it
        let target_shard = tx.transaction.shard_id;
        
        // AMR: Get suggested shard for metrics comparison (read-only)
        let suggested_shard = self.amr_router.route_transaction(&tx);
        
        // Add to mempool using the signed shard_id (not the suggested one)
        let result = if let Some(mempool) = self.shards.get(&target_shard) {
            mempool.add_transaction(tx)
        } else {
            Err(MempoolError::InvalidTransaction("Invalid shard".to_string()))
        };
        
        // Update metrics using the ACTUAL shard used, not the suggested one
        // This ensures the ML model trains on correct routing outcomes
        let routing_time = start.elapsed().as_micros() as u64;
        let mut metrics = self.routing_metrics.write();
        metrics.total_routed += 1;
        metrics.routing_time_us += routing_time;
        
        if result.is_ok() {
            // Only count as load-balanced if the actual shard matched the suggestion
            if suggested_shard == target_shard {
                metrics.load_balanced += 1;
            }
        }
        
        result
    }

    /// Add a batch of transactions in one pass. Grouped by signed shard_id,
    /// each shard batch is validated (ML-DSA signatures in parallel) and
    /// inserted atomically. Returns the transaction hash for each success.
    pub fn add_transactions_batch(&self, txs: Vec<SignedTransaction>) -> Vec<MempoolResult<Hash>> {
        let mut results: Vec<MempoolResult<Hash>> = (0..txs.len()).map(|_| Ok([0u8; 32])).collect();

        // Group by signed shard_id to avoid crossing shards.
        let mut per_shard: HashMap<ShardId, Vec<(usize, SignedTransaction)>> = HashMap::new();
        for (i, tx) in txs.into_iter().enumerate() {
            per_shard
                .entry(tx.transaction.shard_id)
                .or_insert_with(Vec::new)
                .push((i, tx));
        }

        // Process each shard independently. The underlying Mempool validates
        // signatures in parallel across the whole shard batch.
        for (shard_id, indexed_txs) in per_shard {
            let (indices, txs): (Vec<usize>, Vec<SignedTransaction>) = indexed_txs.into_iter().unzip();
            let mempool = match self.shards.get(&shard_id) {
                Some(m) => m,
                None => {
                    for i in indices {
                        results[i] = Err(MempoolError::InvalidTransaction("Invalid shard".to_string()));
                    }
                    continue;
                }
            };

            let batch_results = mempool.add_transactions_batch(txs);
            for (i, res) in indices.into_iter().zip(batch_results.into_iter()) {
                results[i] = res;
            }

            // Update AMR routing metrics for the batch.
            let mut metrics = self.routing_metrics.write();
            metrics.total_routed += 1;
            metrics.load_balanced += 1;
        }

        results
    }
    
    /// Reports TX execution outcome back to AMR for learning
    pub fn report_execution(&self, tx_hash: Hash, shard_id: ShardId, success: bool, conflicts: u32) {
        self.amr_router.report_execution(tx_hash, shard_id, success, conflicts);
        
        if conflicts == 0 {
            self.routing_metrics.write().conflicts_avoided += 1;
        }
    }
    
    /// Updates shard load metrics
    pub fn update_shard_load(&self, shard_id: ShardId, tx_count: usize, avg_cu_used: u64) {
        self.amr_router.update_shard_load(shard_id, tx_count, avg_cu_used);
    }
    
    /// Gets routing metrics
    pub fn get_routing_metrics(&self) -> RoutingMetrics {
        self.routing_metrics.read().clone()
    }

    pub fn get_pending_for_shard(&self, shard_id: ShardId, limit: usize) -> Vec<SignedTransaction> {
        self.shards
            .get(&shard_id)
            .map(|m| m.get_pending_for_shard(shard_id, limit))
            .unwrap_or_default()
    }

    pub fn pending_count_for_shard(&self, shard_id: ShardId) -> usize {
        self.shards
            .get(&shard_id)
            .map(|m| m.pending_count_for_shard(shard_id))
            .unwrap_or(0)
    }

    pub fn get_ready_antichain_for_shard(&self, shard_id: ShardId, limit: usize) -> Vec<SignedTransaction> {
        self.shards
            .get(&shard_id)
            .map(|m| m.get_ready_antichain_for_shard(shard_id, limit))
            .unwrap_or_default()
    }

    pub fn remove_transactions(&self, shard_id: ShardId, hashes: &[Hash]) {
        if let Some(mempool) = self.shards.get(&shard_id) {
            mempool.remove_transactions(hashes);
        }
    }

    pub fn total_pending(&self) -> usize {
        self.shards.iter().map(|m| m.pending_count()).sum()
    }
}

fn resource_conflict_key(tx: &SignedTransaction) -> Hash {
    let mut key = Vec::with_capacity(2 + 32 + 32 + 16);
    key.push(tx.transaction.tx_type.clone() as u8);
    key.push(tx.transaction.vm_kind as u8);
    key.extend_from_slice(&tx.transaction.to);
    key.extend_from_slice(&tx.transaction.from);
    let prefix_len = tx.transaction.data.len().min(16);
    key.extend_from_slice(&tx.transaction.data[..prefix_len]);
    hash_data(&key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::storage::Storage;
    use crate::crypto::MlDsa65Keypair;
    use crate::types::{Amount, Transaction, TransactionType};

    fn create_test_tx(keypair: &MlDsa65Keypair, nonce: u64, shard_id: ShardId) -> SignedTransaction {
        create_test_tx_to(keypair, nonce, shard_id, [2u8; 32])
    }

    fn create_test_tx_to(
        keypair: &MlDsa65Keypair,
        nonce: u64,
        shard_id: ShardId,
        to: Address,
    ) -> SignedTransaction {
        let mut tx = Transaction::new(
            TransactionType::Transfer,
            keypair.address(),
            to,
            Amount(100),
            nonce,
            100_000,
            None,
            Vec::new(),
            shard_id,
        );
        
        let sig = keypair.sign(&tx.signing_data()).unwrap();
        tx.set_signature(sig, keypair.public_key.clone())
            .expect("Failed to set signature");
        
        SignedTransaction::new(tx)
    }

    #[test]
    fn test_mempool_add_remove() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path()).unwrap();
        let state = StateManager::new(storage);
        let mempool = Mempool::new(state, 1000, false);

        let keypair = MlDsa65Keypair::generate().unwrap();
        let tx = create_test_tx(&keypair, 0, 0);
        let hash = tx.hash;

        mempool.add_transaction(tx).unwrap();
        assert_eq!(mempool.pending_count(), 1);

        mempool.remove_transaction(&hash);
        assert_eq!(mempool.pending_count(), 0);
    }

    #[test]
    fn test_antichain_skips_nonce_gaps() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path()).unwrap();
        let state = StateManager::new(storage);
        let mempool = Mempool::new(state, 1000, false);

        let keypair = MlDsa65Keypair::generate().unwrap();
        let tx0 = create_test_tx(&keypair, 0, 0);
        let tx1 = create_test_tx(&keypair, 1, 0);

        mempool.add_transaction(tx1).unwrap();
        let selected_before = mempool.get_ready_antichain_for_shard(0, 100);
        assert!(selected_before.is_empty());

        mempool.add_transaction(tx0).unwrap();
        let selected_after = mempool.get_ready_antichain_for_shard(0, 100);
        assert_eq!(selected_after.len(), 1);
        assert_eq!(selected_after[0].transaction.nonce, 0);
    }

    #[test]
    fn test_antichain_filters_account_conflicts() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path()).unwrap();
        let state = StateManager::new(storage);
        let mempool = Mempool::new(state, 1000, false);

        let key_a = MlDsa65Keypair::generate().unwrap();
        let key_b = MlDsa65Keypair::generate().unwrap();
        let shared_to: Address = [9u8; 32];

        let tx_a = create_test_tx_to(&key_a, 0, 0, shared_to);
        let tx_b = create_test_tx_to(&key_b, 0, 0, shared_to);

        mempool.add_transaction(tx_a).unwrap();
        mempool.add_transaction(tx_b).unwrap();

        let selected = mempool.get_ready_antichain_for_shard(0, 100);
        assert_eq!(selected.len(), 1);
    }
}
