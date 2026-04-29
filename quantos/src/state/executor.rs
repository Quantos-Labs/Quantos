use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use rayon::prelude::*;
use dashmap::DashMap;

use crate::state::{StateManager, StateResult, StateError};
use crate::types::{
    Address, Amount, Hash, ShardId, SignedTransaction, 
    TransactionReceipt, TransactionStatus, DAGVertex,
};
use crate::crypto::merkle_root;

pub struct ParallelExecutor {
    state_manager: StateManager,
    num_shards: u16,
    shard_states: Arc<DashMap<ShardId, ShardState>>,
}

struct ShardState {
    pending_accounts: DashMap<Address, Amount>,
    pending_nonces: DashMap<Address, u64>,
}

impl ShardState {
    fn new() -> Self {
        Self {
            pending_accounts: DashMap::new(),
            pending_nonces: DashMap::new(),
        }
    }
}

impl ParallelExecutor {
    pub fn new(state_manager: StateManager, num_shards: u16) -> Self {
        let shard_states = Arc::new(DashMap::new());
        for i in 0..num_shards {
            shard_states.insert(i, ShardState::new());
        }

        Self {
            state_manager,
            num_shards,
            shard_states,
        }
    }

    pub fn execute_vertex(&self, vertex: &DAGVertex) -> StateResult<(Hash, Vec<TransactionReceipt>)> {
        let shard_id = vertex.shard_id;
        
        let (valid_txs, conflicts) = self.detect_conflicts(&vertex.transactions);
        
        // CRITICAL: Always produce a receipt — failed TXs get success=false
        let receipts: Vec<TransactionReceipt> = valid_txs
            .par_iter()
            .map(|tx| {
                match self.execute_transaction(tx, shard_id) {
                    Ok(receipt) => receipt,
                    Err(e) => {
                        tracing::warn!("Transaction {} execution failed: {}", hex::encode(&tx.hash[..8]), e);
                        TransactionReceipt {
                            tx_hash: tx.hash,
                            status: TransactionStatus::Failed(format!("{}", e)),
                            gas_used: tx.transaction.gas_limit,
                            vertex_hash: [0u8; 32],
                            shard_id: tx.transaction.shard_id,
                            logs: Vec::new(),
                            slot: 0,
                            from: tx.transaction.from,
                            to: tx.transaction.to,
                            success: false,
                        }
                    }
                }
            })
            .collect();
        
        let conflict_receipts: Vec<TransactionReceipt> = conflicts
            .iter()
            .map(|tx| {
                match self.execute_transaction(tx, shard_id) {
                    Ok(receipt) => receipt,
                    Err(e) => {
                        tracing::warn!("Conflict transaction {} execution failed: {}", hex::encode(&tx.hash[..8]), e);
                        TransactionReceipt {
                            tx_hash: tx.hash,
                            status: TransactionStatus::Failed(format!("{}", e)),
                            gas_used: tx.transaction.gas_limit,
                            vertex_hash: [0u8; 32],
                            shard_id: tx.transaction.shard_id,
                            logs: Vec::new(),
                            slot: 0,
                            from: tx.transaction.from,
                            to: tx.transaction.to,
                            success: false,
                        }
                    }
                }
            })
            .collect();

        let mut all_receipts = receipts;
        all_receipts.extend(conflict_receipts);

        let state_root = self.state_manager.compute_state_root()?;

        Ok((state_root, all_receipts))
    }

    /// HIGH (w4): Improved conflict detection that properly tracks all account touches.
    /// A tx touches both `from` and `to` addresses. If ANY address is shared between
    /// two transactions, they must be serialized. Only the earliest tx per conflict
    /// group runs in parallel; the rest are serialized.
    fn detect_conflicts<'a>(&self, txs: &'a [SignedTransaction]) -> (Vec<&'a SignedTransaction>, Vec<&'a SignedTransaction>) {
        // Map: address -> list of tx indices that touch it
        let mut address_to_txs: HashMap<Address, Vec<usize>> = HashMap::new();
        
        for (idx, tx) in txs.iter().enumerate() {
            address_to_txs.entry(tx.transaction.from).or_default().push(idx);
            if tx.transaction.from != tx.transaction.to {
                address_to_txs.entry(tx.transaction.to).or_default().push(idx);
            }
        }
        
        // Mark all tx indices that conflict (share an address with another tx)
        let mut conflicting_indices: HashSet<usize> = HashSet::new();
        
        for (_addr, tx_indices) in &address_to_txs {
            if tx_indices.len() > 1 {
                // All but the first tx touching this address are conflicts
                for &idx in &tx_indices[1..] {
                    conflicting_indices.insert(idx);
                }
            }
        }
        
        let mut valid = Vec::new();
        let mut conflicts = Vec::new();
        
        for (idx, tx) in txs.iter().enumerate() {
            if conflicting_indices.contains(&idx) {
                conflicts.push(tx);
            } else {
                valid.push(tx);
            }
        }

        (valid, conflicts)
    }

    fn execute_transaction(
        &self,
        tx: &SignedTransaction,
        _shard_id: ShardId,
    ) -> StateResult<TransactionReceipt> {
        // CRITICAL: Wrap in catch_unwind to prevent panics from crashing executor
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.state_manager.apply_transaction(tx)
        })) {
            Ok(result) => result,
            Err(_) => Err(StateError::ExecutionError("Transaction execution panicked".to_string())),
        }
    }

    pub fn execute_parallel_shards(
        &self,
        shard_txs: Vec<(ShardId, Vec<SignedTransaction>)>,
    ) -> Vec<(ShardId, Hash, Vec<TransactionReceipt>)> {
        shard_txs
            .par_iter()
            .map(|(shard_id, txs)| {
                let receipts: Vec<TransactionReceipt> = txs
                    .iter()
                    .map(|tx| {
                        match self.execute_transaction(tx, *shard_id) {
                            Ok(receipt) => receipt,
                            Err(e) => {
                                tracing::warn!("Shard TX {} failed: {}", hex::encode(&tx.hash[..8]), e);
                                TransactionReceipt {
                                    tx_hash: tx.hash,
                                    status: TransactionStatus::Failed(format!("{}", e)),
                                    gas_used: tx.transaction.gas_limit,
                                    vertex_hash: [0u8; 32],
                                    shard_id: tx.transaction.shard_id,
                                    logs: Vec::new(),
                                    slot: 0,
                                    from: tx.transaction.from,
                                    to: tx.transaction.to,
                                    success: false,
                                }
                            }
                        }
                    })
                    .collect();
                
                let tx_hashes: Vec<Hash> = receipts.iter().map(|r| r.tx_hash).collect();
                let state_root = merkle_root(&tx_hashes);
                
                (*shard_id, state_root, receipts)
            })
            .collect()
    }

    pub fn rollback_shard(&self, shard_id: ShardId) {
        if let Some(shard_state) = self.shard_states.get(&shard_id) {
            shard_state.pending_accounts.clear();
            shard_state.pending_nonces.clear();
        }
    }

    pub fn commit_shard(&self, _shard_id: ShardId, auth_token: &[u8; 32]) -> StateResult<()> {
        self.state_manager.commit_pending(auth_token)
            .map(|_| ())
    }
}

pub struct OptimisticExecutor {
    executor: ParallelExecutor,
    speculative_results: Arc<DashMap<Hash, SpeculativeResult>>,
}

struct SpeculativeResult {
    vertex_hash: Hash,
    state_root: Hash,
    receipts: Vec<TransactionReceipt>,
    conflicts: Vec<Hash>,
}

impl OptimisticExecutor {
    pub fn new(state_manager: StateManager, num_shards: u16) -> Self {
        Self {
            executor: ParallelExecutor::new(state_manager, num_shards),
            speculative_results: Arc::new(DashMap::new()),
        }
    }

    pub fn speculative_execute(&self, vertex: &DAGVertex) -> StateResult<Hash> {
        let (state_root, receipts) = self.executor.execute_vertex(vertex)?;
        
        self.speculative_results.insert(vertex.hash, SpeculativeResult {
            vertex_hash: vertex.hash,
            state_root,
            receipts,
            conflicts: Vec::new(),
        });

        Ok(state_root)
    }

    pub fn confirm_execution(&self, vertex_hash: &Hash) -> Option<(Hash, Vec<TransactionReceipt>)> {
        self.speculative_results.remove(vertex_hash)
            .map(|(_, result)| (result.state_root, result.receipts))
    }

    pub fn rollback_execution(&self, vertex_hash: &Hash) {
        self.speculative_results.remove(vertex_hash);
    }

    pub fn get_speculative_result(&self, vertex_hash: &Hash) -> Option<Hash> {
        self.speculative_results.get(vertex_hash)
            .map(|r| r.state_root)
    }
}
