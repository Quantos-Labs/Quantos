use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use dashmap::DashMap;
use tokio::sync::mpsc;

/// Maximum pending vertices to prevent memory exhaustion
const MAX_PENDING_VERTICES: usize = 100_000;

/// Maximum vertex payload size (2 MB) to prevent memory exhaustion via oversized vertices
const MAX_VERTEX_PAYLOAD_SIZE: usize = 2 * 1024 * 1024;

/// Automatic cleanup interval in seconds (aggressive to limit attack window)
const CLEANUP_INTERVAL_SECS: u64 = 3;

/// Maximum age for pending vertices in seconds
const MAX_PENDING_AGE_SECS: u64 = 30;

use crate::consensus::{ConsensusError, ConsensusResult, CommitteeManager};
use crate::crypto::{sign_dilithium, verify_dilithium, DilithiumBatchVerifier, DILITHIUM3_PUBLIC_KEY_SIZE};
use crate::dag::DAGGraph;
use crate::mempool::ShardedMempool;
use crate::state::OptimisticExecutor;
use crate::types::{Address, CommitteeVote, Hash, ShardId, SignedTransaction, DAGVertex, VertexStatus};

#[derive(Clone)]
pub struct FastPath {
    dag: Arc<DAGGraph>,
    mempool: Arc<ShardedMempool>,
    executor: Arc<OptimisticExecutor>,
    committee_manager: Arc<CommitteeManager>,
    pending_vertices: Arc<DashMap<Hash, PendingVertex>>,
    confirmed_vertices: Arc<DashMap<Hash, DAGVertex>>,
    vertex_sender: mpsc::Sender<DAGVertex>,
    /// Batch signature verifier for performance
    batch_verifier: Arc<DilithiumBatchVerifier>,
    /// Signature aggregator for bandwidth optimization
    sig_aggregator: Arc<crate::crypto::signature_aggregation::SignatureAggregator>,
    /// Track pending vertex count for memory limits
    pending_count: Arc<AtomicUsize>,
}

struct PendingVertex {
    vertex: DAGVertex,
    votes: Vec<CommitteeVote>,
    received_at: Instant,
    /// Atomic flag to prevent race conditions in confirmation
    pre_confirmed: AtomicBool,
}

impl FastPath {
    pub fn new(
        dag: Arc<DAGGraph>,
        mempool: Arc<ShardedMempool>,
        executor: Arc<OptimisticExecutor>,
        committee_manager: Arc<CommitteeManager>,
        vertex_sender: mpsc::Sender<DAGVertex>,
    ) -> Self {
        let fast_path = Self {
            dag,
            mempool,
            executor,
            committee_manager,
            pending_vertices: Arc::new(DashMap::new()),
            confirmed_vertices: Arc::new(DashMap::new()),
            vertex_sender,
            batch_verifier: Arc::new(DilithiumBatchVerifier::new(64)),
            sig_aggregator: Arc::new(crate::crypto::signature_aggregation::SignatureAggregator::new(1000)),
            pending_count: Arc::new(AtomicUsize::new(0)),
        };

        // Start automatic cleanup task
        fast_path.start_cleanup_task();

        fast_path
    }

    /// Starts a background task for automatic cleanup of old pending vertices.
    fn start_cleanup_task(&self) {
        let pending_vertices = self.pending_vertices.clone();
        let executor = self.executor.clone();
        let pending_count = self.pending_count.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));
            loop {
                interval.tick().await;
                
                let now = Instant::now();
                let max_age = Duration::from_secs(MAX_PENDING_AGE_SECS);
                let mut to_remove = Vec::new();

                for entry in pending_vertices.iter() {
                    if now.duration_since(entry.received_at) > max_age {
                        to_remove.push(*entry.key());
                    }
                }

                for hash in to_remove {
                    pending_vertices.remove(&hash);
                    executor.rollback_execution(&hash);
                    pending_count.fetch_sub(1, Ordering::Relaxed);
                }
            }
        });
    }

    pub async fn process_transaction(&self, tx: SignedTransaction) -> ConsensusResult<()> {
        self.mempool.add_transaction(tx)
            .map_err(|e| ConsensusError::InvalidVertex(e.to_string()))?;
        Ok(())
    }

    /// Creates a vertex for a shard
    /// 
    /// Production-ready vertex creation with:
    /// - Parallel transaction processing
    /// - Batch state execution
    /// - Memory limit enforcement
    pub async fn create_vertex(
        &self,
        shard_id: ShardId,
        creator: Address,
        secret_key: &[u8],
        public_key: &[u8],
    ) -> ConsensusResult<DAGVertex> {
        // DAG-native selection: pull a nonce-ready conflict-minimized antichain.
        let transactions = self.mempool.get_ready_antichain_for_shard(shard_id, 10000);
        
        if transactions.is_empty() {
            return Err(ConsensusError::InvalidVertex("No transactions".to_string()));
        }

        // Create vertex structure
        let mut vertex = self.dag.create_vertex(shard_id, transactions, creator)
            .map_err(|e| ConsensusError::InvalidVertex(e.to_string()))?;

        // Speculative execution (parallelized internally by OptimisticExecutor)
        let state_root = self.executor.speculative_execute(&vertex)
            .map_err(|e| ConsensusError::InvalidVertex(e.to_string()))?;
        
        vertex.set_state_root(state_root);

        // Sign vertex
        let signature = sign_dilithium(secret_key, &vertex.signing_data())
            .map_err(|e| ConsensusError::CryptoError(e.to_string()))?;
        vertex.set_signature(signature, public_key)
            .map_err(|e| ConsensusError::CryptoError(e))?;

        // Check memory limits before adding
        if self.pending_count.load(Ordering::Relaxed) >= MAX_PENDING_VERTICES {
            return Err(ConsensusError::ResourceExhausted(
                format!("Pending vertices limit reached: {}", MAX_PENDING_VERTICES)
            ));
        }

        // Add to pending
        self.pending_vertices.insert(vertex.hash, PendingVertex {
            vertex: vertex.clone(),
            votes: Vec::new(),
            received_at: Instant::now(),
            pre_confirmed: AtomicBool::new(false),
        });
        self.pending_count.fetch_add(1, Ordering::Relaxed);

        // Remove processed transactions from mempool
        let tx_hashes: Vec<Hash> = vertex.transactions.iter().map(|tx| tx.hash).collect();
        self.mempool.remove_transactions(shard_id, &tx_hashes);

        // Broadcast vertex
        let _ = self.vertex_sender.send(vertex.clone()).await;

        tracing::debug!(
            "Created vertex {} for shard {} with {} txs, state_root: 0x{}",
            hex::encode(&vertex.hash[..4]),
            shard_id,
            vertex.tx_count(),
            hex::encode(&state_root[..4])
        );

        Ok(vertex)
    }
    
    /// Parallel vertex production across multiple shards
    /// 
    /// Production optimization:
    /// - Process multiple shards concurrently
    /// - Batch transaction fetching
    /// - Atomic vertex creation
    pub async fn create_vertices_parallel(
        &self,
        shard_ids: Vec<ShardId>,
        creator: Address,
        secret_key: &[u8],
        public_key: &[u8],
    ) -> Vec<ConsensusResult<DAGVertex>> {
        use futures::future::join_all;
        
        let tasks: Vec<_> = shard_ids.into_iter()
            .map(|shard_id| {
                let secret_key = secret_key.to_vec();
                let public_key = public_key.to_vec();
                let self_clone = self.clone();
                async move {
                    self_clone.create_vertex(shard_id, creator, &secret_key, &public_key).await
                }
            })
            .collect();
        
        join_all(tasks).await
    }

    pub async fn receive_vertex(&self, vertex: DAGVertex) -> ConsensusResult<()> {
        if self.pending_vertices.contains_key(&vertex.hash) {
            return Ok(());
        }

        // Bound vertex payload size to prevent memory exhaustion via oversized vertices
        let vertex_size: usize = vertex.transactions.iter()
            .map(|tx| tx.transaction.data.len() + tx.transaction.signature.len() + 128)
            .sum();
        if vertex_size > MAX_VERTEX_PAYLOAD_SIZE {
            return Err(ConsensusError::ResourceExhausted(
                format!("Vertex payload too large: {} bytes (max {})", vertex_size, MAX_VERTEX_PAYLOAD_SIZE)
            ));
        }

        for parent in &vertex.parents {
            if !self.dag.get_vertex(parent)
                .map_err(|e| ConsensusError::StorageError(e.to_string()))?
                .is_some()
            {
                return Err(ConsensusError::InvalidVertex("Missing parent".to_string()));
            }
        }

        let state_root = self.executor.speculative_execute(&vertex)
            .map_err(|e| ConsensusError::InvalidVertex(e.to_string()))?;

        if state_root != vertex.state_root {
            self.executor.rollback_execution(&vertex.hash);
            return Err(ConsensusError::InvalidVertex("State root mismatch".to_string()));
        }

        // Check memory limits before adding
        if self.pending_count.load(Ordering::Relaxed) >= MAX_PENDING_VERTICES {
            self.executor.rollback_execution(&vertex.hash);
            return Err(ConsensusError::ResourceExhausted(
                format!("Pending vertices limit reached: {}", MAX_PENDING_VERTICES)
            ));
        }

        self.pending_vertices.insert(vertex.hash, PendingVertex {
            vertex: vertex.clone(),
            votes: Vec::new(),
            received_at: Instant::now(),
            pre_confirmed: AtomicBool::new(false),
        });
        self.pending_count.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    pub async fn receive_vote(&self, vote: CommitteeVote) -> ConsensusResult<()> {
        let epoch = self.committee_manager.current_epoch();
        
        if let Some(mut pending) = self.pending_vertices.get_mut(&vote.vertex_hash) {
            let committee = self.committee_manager
                .get_committee_for_shard(epoch, pending.vertex.shard_id)
                .ok_or(ConsensusError::NotCommitteeMember)?;

            if !committee.has_member(&vote.validator) {
                return Err(ConsensusError::NotCommitteeMember);
            }

            if pending.votes.iter().any(|existing| existing.validator == vote.validator) {
                return Err(ConsensusError::InvalidVote(
                    "duplicate vote from validator".to_string()
                ));
            }

            let validator_set = self.committee_manager.get_validator_set();
            let validator_info = validator_set.get_validator(&vote.validator)
                .ok_or_else(|| ConsensusError::InvalidValidator(
                    format!("Validator {:?} not found", vote.validator)
                ))?;

            let signature_valid = verify_dilithium(
                &validator_info.public_key,
                &vote.signing_data(),
                &vote.signature,
            ).map_err(|e| ConsensusError::CryptoError(e.to_string()))?;
            if !signature_valid {
                return Err(ConsensusError::InvalidVote(
                    "invalid vote signature".to_string()
                ));
            }

            pending.votes.push(vote);

            let approve_stake: u128 = pending.votes.iter()
                .filter(|v| v.approve)
                .filter_map(|v| validator_set.get_validator(&v.validator))
                .map(|validator| validator.effective_stake())
                .sum();

            let quorum = committee.quorum_threshold()
                .map_err(|e| ConsensusError::InvalidVertex(e.to_string()))?;

            // Atomic check-and-set to prevent race condition
            if approve_stake >= quorum {
                // Try to atomically set pre_confirmed from false to true
                if pending.pre_confirmed.compare_exchange(
                    false,
                    true,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ).is_ok() {
                    // Only one thread will succeed in this exchange
                    pending.vertex.status = VertexStatus::PreConfirmed;
                    
                    // Clone vertex before dropping the lock
                    let vertex = pending.vertex.clone();
                    drop(pending);
                    
                    self.confirm_vertex(&vertex).await?;
                }
            }
        }

        Ok(())
    }

    async fn confirm_vertex(&self, vertex: &DAGVertex) -> ConsensusResult<()> {
        self.executor.confirm_execution(&vertex.hash);

        self.dag.add_vertex(vertex.clone())
            .map_err(|e| ConsensusError::StorageError(e.to_string()))?;

        let tx_hashes: Vec<Hash> = vertex.transactions.iter().map(|t| t.hash).collect();
        self.mempool.remove_transactions(vertex.shard_id, &tx_hashes);

        self.confirmed_vertices.insert(vertex.hash, vertex.clone());

        self.dag.update_vertex_status_internal(&vertex.hash, VertexStatus::Confirmed)
            .map_err(|e| ConsensusError::StorageError(e.to_string()))?;

        Ok(())
    }

    pub fn create_vote(
        &self,
        vertex_hash: Hash,
        validator: Address,
        approve: bool,
        stake_weight: u64,
        secret_key: &[u8],
    ) -> ConsensusResult<CommitteeVote> {
        let mut vote = CommitteeVote::new(validator, vertex_hash, approve, stake_weight);
        
        let signature = sign_dilithium(secret_key, &vote.signing_data())
            .map_err(|e| ConsensusError::CryptoError(e.to_string()))?;

        if secret_key.len() < DILITHIUM3_PUBLIC_KEY_SIZE {
            return Err(ConsensusError::CryptoError(
                "Dilithium secret key is too short to derive public key".to_string()
            ));
        }
        let public_key_offset = secret_key.len() - DILITHIUM3_PUBLIC_KEY_SIZE;
        let public_key = &secret_key[public_key_offset..];

        vote.set_signature(signature, public_key)
            .map_err(|e| ConsensusError::CryptoError(e))?;

        Ok(vote)
    }

    pub fn get_pending_vertex(&self, hash: &Hash) -> Option<DAGVertex> {
        self.pending_vertices.get(hash).map(|p| p.vertex.clone())
    }

    pub fn get_confirmed_vertex(&self, hash: &Hash) -> Option<DAGVertex> {
        self.confirmed_vertices.get(hash).map(|v| v.clone())
    }

    pub fn pending_count(&self) -> usize {
        self.pending_count.load(Ordering::Relaxed)
    }

    /// Gets the maximum allowed pending vertices.

/// Gets the maximum allowed pending vertices.
pub fn max_pending_vertices(&self) -> usize {
    MAX_PENDING_VERTICES
}

    pub fn confirmed_count(&self) -> usize {
        self.dag.vertex_count()
    }

    /// Batch verifies multiple vertices efficiently
    pub async fn batch_verify_vertices(&self, vertices: &[DAGVertex]) -> Vec<bool> {
        if vertices.is_empty() {
            return Vec::new();
        }

        let items: Vec<_> = vertices.iter()
            .map(|v| {
                let pubkey = v.creator.to_vec();
                let message = v.signing_data();
                let signature = v.signature.clone();
                (pubkey, message, signature)
            })
            .collect();

        self.batch_verifier.verify_batch(&items)
    }

    /// Creates aggregated signature for committee votes
    pub fn aggregate_committee_signatures(
        &self,
        votes: &[CommitteeVote],
    ) -> Result<crate::crypto::signature_aggregation::AggregatedSignature, ConsensusError> {
        let signatures: Vec<_> = votes.iter().map(|v| v.signature.clone()).collect();
        let public_keys: Vec<_> = votes.iter().map(|v| v.validator.to_vec()).collect();
        let message = votes[0].vertex_hash.to_vec();

        self.sig_aggregator.aggregate(signatures, public_keys, &message)
            .map_err(|e| ConsensusError::CryptoError(e.to_string()))
    }
}

pub struct AggregatedVoting {
    votes_by_vertex: DashMap<Hash, Vec<CommitteeVote>>,
}

impl AggregatedVoting {
    pub fn new() -> Self {
        Self {
            votes_by_vertex: DashMap::new(),
        }
    }

    pub fn add_vote(&self, vote: CommitteeVote) {
        self.votes_by_vertex
            .entry(vote.vertex_hash)
            .or_insert_with(Vec::new)
            .push(vote);
    }

    pub fn aggregate_votes(
        &self,
        vertex_hash: &Hash,
        committee_id: u16,
    ) -> Option<crate::types::AggregatedSignature> {
        let votes = self.votes_by_vertex.get(vertex_hash)?;
        
        let mut aggregated = crate::types::AggregatedSignature::new(*vertex_hash, committee_id);
        
        for vote in votes.iter() {
            if vote.approve {
                aggregated.validators.push(vote.validator);
                aggregated.total_stake += vote.stake_weight;
            }
        }

        if aggregated.validators.is_empty() {
            return None;
        }

        let mut combined_sigs = Vec::new();
        for vote in votes.iter() {
            if vote.approve {
                combined_sigs.extend(&vote.signature);
            }
        }
        aggregated.aggregated_sig = combined_sigs;

        let mut bitmap = vec![0u8; (votes.len() + 7) / 8];
        for (i, vote) in votes.iter().enumerate() {
            if vote.approve {
                bitmap[i / 8] |= 1 << (i % 8);
            }
        }
        aggregated.bitmap = bitmap;

        Some(aggregated)
    }

    pub fn clear_vertex(&self, vertex_hash: &Hash) {
        self.votes_by_vertex.remove(vertex_hash);
    }
}

impl Default for AggregatedVoting {
    fn default() -> Self {
        Self::new()
    }
}
