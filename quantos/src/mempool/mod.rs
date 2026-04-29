mod secure;
mod adaptive_routing;
pub mod fair_ordering;
pub mod encrypted_mempool;
pub mod pbs;
pub mod blob_transactions;

pub use secure::*;
pub use adaptive_routing::*;
pub use fair_ordering::*;
pub use encrypted_mempool::*;
pub use pbs::*;
pub use blob_transactions::*;

use std::collections::BTreeMap;
use std::sync::Arc;
use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use crossbeam_channel::{bounded, Sender, Receiver};
use tracing::warn;

/// Maximum transactions per shard index
const MAX_SHARD_TXS: usize = 10_000;

use crate::crypto::verify_dilithium;
use crate::state::StateManager;
use crate::types::{
    Address, Hash, ShardId, SignedTransaction,
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
    /// Lock for atomic transaction insertion
    insert_lock: Arc<Mutex<()>>,
}

impl Mempool {
    pub fn new(state_manager: StateManager, max_size: usize) -> Self {
        let (tx_sender, tx_receiver) = bounded(10000);
        
        Self {
            pending: Arc::new(DashMap::new()),
            by_sender: Arc::new(DashMap::new()),
            by_shard: Arc::new(DashMap::new()),
            state_manager,
            max_size,
            max_per_sender: 100,
            tx_sender,
            tx_receiver,
            insert_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn add_transaction(&self, tx: SignedTransaction) -> MempoolResult<()> {
        // CRITICAL: Atomic check-and-insert to prevent race condition
        let _lock = self.insert_lock.lock();
        
        if self.pending.contains_key(&tx.hash) {
            return Err(MempoolError::DuplicateTransaction);
        }

        if self.pending.len() >= self.max_size {
            return Err(MempoolError::MempoolFull);
        }

        self.validate_transaction(&tx)?;

        let sender = tx.transaction.from;
        let nonce = tx.transaction.nonce;
        let shard_id = tx.transaction.shard_id;
        let hash = tx.hash;

        self.by_sender
            .entry(sender)
            .or_insert_with(BTreeMap::new)
            .insert(nonce, hash);

        // CRITICAL: Limit shard index size to prevent DoS
        let mut shard_txs = self.by_shard
            .entry(shard_id)
            .or_insert_with(Vec::new);
        
        if shard_txs.len() >= MAX_SHARD_TXS {
            // Remove oldest transaction from shard index
            if let Some(_old_hash) = shard_txs.first().copied() {
                shard_txs.remove(0);
            }
        }
        shard_txs.push(hash);
        drop(shard_txs);

        self.pending.insert(hash, tx.clone());

        // CRITICAL: Handle channel overflow with logging
        if let Err(e) = self.tx_sender.try_send(tx) {
            warn!("Failed to send transaction to subscribers: {:?}", e);
        }

        Ok(())
    }

    fn validate_transaction(&self, tx: &SignedTransaction) -> MempoolResult<()> {
        let signing_data = tx.transaction.signing_data();
        let valid = verify_dilithium(
            &tx.transaction.public_key,
            &signing_data,
            &tx.transaction.signature,
        ).map_err(|e| {
            MempoolError::InvalidTransaction(e.to_string())
        })?;

        if !valid {
            tracing::error!("SIGCHECK: signature did not verify (valid=false)");
            return Err(MempoolError::InvalidTransaction("Invalid signature".to_string()));
        }

        let account_nonce = self.state_manager
            .get_nonce(&tx.transaction.from)
            .map_err(|e| MempoolError::InvalidTransaction(e.to_string()))?;

        if tx.transaction.nonce < account_nonce {
            return Err(MempoolError::NonceTooLow);
        }

        if tx.transaction.nonce > account_nonce + self.max_per_sender as u64 {
            return Err(MempoolError::NonceGap);
        }

        Ok(())
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
        // OPTIMIZATION: Collect and sort only what we need
        if let Some(shard_txs) = self.by_shard.get(&shard_id) {
            let mut txs: Vec<SignedTransaction> = Vec::new();
            
            // Only process up to limit * 2 transactions for efficiency
            let process_limit = (limit * 2).min(shard_txs.len());
            
            for hash in shard_txs.iter().take(process_limit) {
                if let Some(tx) = self.pending.get(hash) {
                    txs.push(tx.clone());
                }
            }
            
            // Sort by gas price (descending) then nonce (ascending)
            txs.sort_by(|a, b| {
                b.transaction.gas_price.cmp(&a.transaction.gas_price)
                    .then_with(|| a.transaction.nonce.cmp(&b.transaction.nonce))
            });
            
            txs.truncate(limit);
            txs
        } else {
            Vec::new()
        }
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
    pub fn new(state_manager: StateManager, num_shards: u16, max_per_shard: usize) -> Self {
        let shards = Arc::new(DashMap::new());
        
        for i in 0..num_shards {
            shards.insert(i, Mempool::new(state_manager.clone(), max_per_shard));
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
    
    /// Reports TX execution outcome back to AMR for learning
    pub fn report_execution(&self, tx_hash: Hash, shard_id: ShardId, success: bool, conflicts: u32) {
        self.amr_router.report_execution(tx_hash, shard_id, success, conflicts);
        
        if conflicts == 0 {
            self.routing_metrics.write().conflicts_avoided += 1;
        }
    }
    
    /// Updates shard load metrics
    pub fn update_shard_load(&self, shard_id: ShardId, tx_count: usize, avg_gas_used: u64) {
        self.amr_router.update_shard_load(shard_id, tx_count, avg_gas_used);
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

    pub fn remove_transactions(&self, shard_id: ShardId, hashes: &[Hash]) {
        if let Some(mempool) = self.shards.get(&shard_id) {
            mempool.remove_transactions(hashes);
        }
    }

    pub fn total_pending(&self) -> usize {
        self.shards.iter().map(|m| m.pending_count()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::storage::Storage;
    use crate::crypto::DilithiumKeypair;
    use crate::types::{Amount, Transaction, TransactionType};

    fn create_test_tx(keypair: &DilithiumKeypair, nonce: u64, shard_id: ShardId) -> SignedTransaction {
        let mut tx = Transaction::new(
            TransactionType::Transfer,
            keypair.address(),
            [2u8; 32],
            Amount(100),
            nonce,
            21000,
            1000000000,
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
        let mempool = Mempool::new(state, 1000);

        let keypair = DilithiumKeypair::generate().unwrap();
        let tx = create_test_tx(&keypair, 0, 0);
        let hash = tx.hash;

        mempool.add_transaction(tx).unwrap();
        assert_eq!(mempool.pending_count(), 1);

        mempool.remove_transaction(&hash);
        assert_eq!(mempool.pending_count(), 0);
    }
}
