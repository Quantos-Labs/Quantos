use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;
use parking_lot::RwLock;

use crate::consensus::{
    ConsensusError, ConsensusResult, CommitteeManager, FastPath, FinalityLayer,
    FinalizedCheckpoint, CrossShardAtomicProtocol, ShardOperation, AtomicResult,
    AtomicStatus,
};
use crate::crypto::{DilithiumKeypair, FalconKeypair, VRFKeypair};
use crate::dag::DAGGraph;
use crate::l0::{FinalityHub, HttpRelayTransport, RelayDispatcher, ChainRegistry, ValidatorSetSnapshot};
use crate::l0::hub::SignatureContribution;
use crate::l0::proof::PqcSignatureAlgo;
use crate::mempool::ShardedMempool;
use crate::state::{StateManager, OptimisticExecutor};
use crate::storage::Storage;
use crate::types::{
    Address, Checkpoint, CommitteeVote, DAGVertex, Hash,
    ShardId, SignedTransaction, Validator,
};
use crate::NodeConfig;

pub struct QuantosConsensus {
    config: NodeConfig,
    storage: Storage,
    state_manager: StateManager,
    dag: Arc<DAGGraph>,
    mempool: Arc<ShardedMempool>,
    executor: Arc<OptimisticExecutor>,
    committee_manager: Arc<CommitteeManager>,
    fast_path: Arc<FastPath>,
    finality: Arc<FinalityLayer>,
    current_slot: Arc<RwLock<u64>>,
    validator_keys: Option<ValidatorKeys>,
    /// PRODUCTION: Cross-Shard Atomic Protocol
    csap: Arc<CrossShardAtomicProtocol>,
    /// L0 finality hub (optional, enabled via config)
    finality_hub: Option<Arc<FinalityHub>>,
    /// L0 relay dispatcher (optional, enabled via config)
    relay_dispatcher: Option<Arc<RelayDispatcher>>,
}

struct ValidatorKeys {
    signing_key: DilithiumKeypair,
    vrf_key: VRFKeypair,
    finality_key: FalconKeypair,
    address: Address,
}

impl QuantosConsensus {
    pub async fn new(
        config: NodeConfig,
        state_manager: StateManager,
        storage: Storage,
    ) -> ConsensusResult<Self> {
        let dag = Arc::new(DAGGraph::new(
            storage.clone(),
            config.min_dag_parents,
            config.max_dag_parents,
        ));

        let mempool = Arc::new(ShardedMempool::new(
            state_manager.clone(),
            config.num_shards as u16,
            100_000,
            config.stacc_require_activation,
        ));

        let executor = Arc::new(OptimisticExecutor::new(
            state_manager.clone(),
            config.num_shards as u16,
        ));

        let committee_manager = Arc::new(CommitteeManager::new(
            storage.clone(),
            config.num_committees as u16,
            config.validators_per_committee,
        ));
        let (vertex_tx, _vertex_rx) = mpsc::channel(10000);

        let fast_path = Arc::new(FastPath::new(
            dag.clone(),
            mempool.clone(),
            executor.clone(),
            committee_manager.clone(),
            vertex_tx,
        ));

        let finality = Arc::new(FinalityLayer::new(
            storage.clone(),
            dag.clone(),
            committee_manager.clone(),
            config.checkpoint_interval,
            config.num_shards as u16,
        ));
        
        // PRODUCTION: Initialize Cross-Shard Atomic Protocol
        // Generate a temporary keypair for CSAP - will be replaced when validator keys are set
        let csap_keypair = crate::crypto::DilithiumKeypair::generate()
            .expect("Failed to generate CSAP keypair");
        let csap = Arc::new(CrossShardAtomicProtocol::new(
            dag.clone(),
            state_manager.clone(),
            committee_manager.clone(),
            csap_keypair,
        ));

        // Initialize optional L0 finality hub and relay dispatcher
        let (finality_hub, relay_dispatcher) = if config.l0_config.enabled {
            let hub = match FinalityHub::new(config.l0_config.clone()) {
                Ok(h) => Arc::new(h),
                Err(e) => {
                    tracing::warn!("L0 hub initialization failed: {}", e);
                    return Err(ConsensusError::InvalidData(format!("L0 hub init: {}", e)));
                }
            };
            let registry = ChainRegistry::with_defaults();
            let mut transports = std::collections::HashMap::new();
            for adapter in registry.live_targets() {
                transports.insert(adapter.id.clone(), Arc::new(HttpRelayTransport::new()) as Arc<dyn crate::l0::relay::RelayTransport>);
            }
            let dispatcher = Arc::new(RelayDispatcher::new(
                config.l0_config.clone(),
                registry,
                transports,
            ));
            tracing::info!("L0 finality hub and relay dispatcher initialized");
            (Some(hub), Some(dispatcher))
        } else {
            (None, None)
        };

        Ok(Self {
            config,
            storage,
            state_manager,
            dag,
            mempool,
            executor,
            committee_manager,
            fast_path,
            finality,
            current_slot: Arc::new(RwLock::new(0)),
            validator_keys: None,
            csap,
            finality_hub,
            relay_dispatcher,
        })
    }

    pub fn set_validator_keys(
        &mut self,
        signing_key: DilithiumKeypair,
        vrf_key: VRFKeypair,
        finality_key: FalconKeypair,
    ) {
        let address = signing_key.address();

        // Register validator in committee manager for single-node testnet.
        // Validator registration is a local node bootstrap operation here; the
        // public auth-token getter has intentionally been removed.
        let validator = Validator {
            address,
            public_key: signing_key.public_key.clone(),
            finality_public_key: finality_key.public_key.clone(),
            stake: crate::types::Amount(1_000_000),
            commission_rate: 0,
            active: true,
            jailed: false,
            slash_count: 0,
            last_active_slot: 0,
            vrf_public_key: vrf_key.public_key().to_vec(),
        };
        if let Err(e) = self.committee_manager.add_validator(validator) {
            tracing::warn!("Failed to register validator: {}", e);
        }

        // Authorize this validator to create vertices in the DAG
        self.dag.add_authorized_creator(address);

        self.validator_keys = Some(ValidatorKeys {
            signing_key,
            vrf_key,
            finality_key,
            address,
        });
    }

    pub async fn run(&self) -> ConsensusResult<()> {
        tracing::info!("Starting Quantos Consensus");

        self.initialize_genesis().await?;

        let slot_duration = Duration::from_millis(self.config.committee_rotation_ms);
        let mut slot_ticker = interval(slot_duration);

        let cleanup_interval = Duration::from_secs(10);
        let mut cleanup_ticker = interval(cleanup_interval);

        loop {
            tokio::select! {
                _ = slot_ticker.tick() => {
                    self.on_slot_tick().await?;
                }
                _ = cleanup_ticker.tick() => {
                    // Cleanup happens automatically in FastPath background task
                }
            }
        }
    }

    async fn initialize_genesis(&self) -> ConsensusResult<()> {
        for shard_id in 0..self.config.num_shards as u16 {
            let genesis = crate::dag::GenesisVertex::create(shard_id)
                .map_err(|e| ConsensusError::InvalidVertex(e.to_string()))?;
            self.dag.add_vertex(genesis)
                .map_err(|e| ConsensusError::StorageError(e.to_string()))?;
        }

        let genesis_checkpoint = Checkpoint::genesis();
        self.storage.put_checkpoint(&genesis_checkpoint)
            .map_err(|e| ConsensusError::StorageError(e.to_string()))?;

        tracing::info!("Genesis initialized for {} shards", self.config.num_shards);
        Ok(())
    }

    async fn on_slot_tick(&self) -> ConsensusResult<()> {
        let slot = {
            let mut current = self.current_slot.write();
            *current += 1;
            *current
        };

        let epoch = slot / 32;

        if slot % 32 == 0 {
            let randomness = self.compute_epoch_randomness(epoch);
            self.committee_manager.rotate_committees(epoch, slot, &randomness)?;
            tracing::debug!("Committees rotated for epoch {}", epoch);
        }

        if let Some(ref keys) = self.validator_keys {
            self.try_produce_vertices(keys, slot).await?;
        }

        if let Some(checkpoint) = self.finality.maybe_create_checkpoint(slot).await? {
            tracing::info!("Checkpoint created at slot {}", slot);

            if let Some(ref keys) = self.validator_keys {
                match self.finality.sign_checkpoint(
                    &checkpoint.hash(),
                    keys.address,
                    &keys.finality_key,
                ).await {
                    Ok(sig) => {
                        if let Ok(Some(finalized)) = self.finality.receive_checkpoint_signature(&checkpoint.hash(), sig).await {
                            tracing::info!("Checkpoint finalized at slot {}", slot);
                            self.build_and_dispatch_l0_proof(&finalized).await;
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Checkpoint signing skipped: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    async fn build_and_dispatch_l0_proof(&self, finalized: &FinalizedCheckpoint) {
        let Some(hub) = &self.finality_hub else { return; };
        let Some(dispatcher) = &self.relay_dispatcher else { return; };

        let validator_set = self.committee_manager.get_validator_set();
        let records: Vec<crate::l0::proof::ValidatorRecord> = validator_set.validators.iter().map(|v| crate::l0::proof::ValidatorRecord {
            address: v.address,
            public_key: v.finality_public_key.clone(),
            stake: v.effective_stake(),
        }).collect();

        let snapshot = ValidatorSetSnapshot {
            root: ValidatorSetSnapshot::compute_root(&records),
            validators: records,
        };

        let contributions: Vec<SignatureContribution> = finalized.signatures.iter().map(|s| SignatureContribution {
            validator: s.validator,
            algo: PqcSignatureAlgo::Falcon512,
            signature: s.signature.clone(),
        }).collect();

        match hub.build_proof(&finalized.checkpoint, &snapshot, &contributions) {
            Ok(proof) => {
                let proof_hash = hex::encode(proof.proof_hash());
                tracing::info!("L0 proof built: hash={}", proof_hash);
                let outcomes = dispatcher.dispatch(&proof);
                for outcome in outcomes {
                    match outcome.status {
                        crate::l0::relay::RelayStatus::Delivered { receipt } => {
                            tracing::info!("L0 proof delivered to {} | receipt={}", outcome.chain, receipt);
                        }
                        crate::l0::relay::RelayStatus::Failed { reason } => {
                            tracing::warn!("L0 proof failed to {} | reason={}", outcome.chain, reason);
                        }
                        crate::l0::relay::RelayStatus::Pending { attempts } => {
                            tracing::debug!("L0 proof pending to {} | attempts={}", outcome.chain, attempts);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("L0 proof build failed: {}", e);
            }
        }
    }

    async fn try_produce_vertices(&self, keys: &ValidatorKeys, slot: u64) -> ConsensusResult<()> {
        let epoch = slot / 32;

        for shard_id in 0..self.config.num_shards as u16 {
            let committee_id = shard_id % self.config.num_committees as u16;
            
            // Single-node testnet: produce vertices even without committee membership
            let is_member = self.committee_manager.is_committee_member(epoch, committee_id, &keys.address);
            let single_node = self.committee_manager.total_validators() <= 1;
            
            if is_member || single_node {
                let pending = self.mempool.get_pending_for_shard(shard_id, 1);
                if !pending.is_empty() {
                    match self.fast_path.create_vertex(
                        shard_id,
                        keys.address,
                        &keys.signing_key.secret_key,
                        &keys.signing_key.public_key,
                    ).await {
                        Ok(vertex) => {
                            let tx_count = vertex.tx_count();
                            // Confirm speculative execution and persist receipts
                            if let Some((_state_root, receipts)) = self.executor.confirm_execution(&vertex.hash) {
                                for receipt in &receipts {
                                    if let Err(e) = self.storage.put_receipt(receipt) {
                                        tracing::error!("Failed to store receipt: {}", e);
                                    }
                                }
                                // Also persist each transaction for getTransactionByHash
                                for tx in &vertex.transactions {
                                    if let Err(e) = self.storage.put_transaction(tx) {
                                        tracing::error!("Failed to store transaction: {}", e);
                                    }
                                }
                                tracing::info!(
                                    "Committed vertex {} for shard {} — {} txs, {} receipts",
                                    hex::encode(&vertex.hash[..4]),
                                    shard_id,
                                    tx_count,
                                    receipts.len()
                                );
                            } else {
                                tracing::warn!(
                                    "Produced vertex {} for shard {} with {} txs but no speculative result found",
                                    hex::encode(&vertex.hash[..4]),
                                    shard_id,
                                    tx_count
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!("No vertex produced for shard {}: {}", shard_id, e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn compute_epoch_randomness(&self, epoch: u64) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&epoch.to_le_bytes());
        
        if let Some(checkpoint) = self.finality.get_latest_finalized_checkpoint() {
            data.extend_from_slice(&checkpoint.hash());
        }
        
        crate::types::hash_data(&data)
    }

    pub async fn submit_transaction(&self, tx: SignedTransaction) -> ConsensusResult<Hash> {
        let hash = tx.hash;
        self.fast_path.process_transaction(tx).await?;
        Ok(hash)
    }
    
    /// PRODUCTION: Execute atomic cross-shard operation
    pub async fn execute_atomic_swap(
        &self,
        operations: Vec<ShardOperation>,
    ) -> ConsensusResult<AtomicResult> {
        let atomic_id = crate::types::hash_data(&bincode::serialize(&operations).unwrap_or_default());
        
        tracing::info!(
            "Executing atomic operation {} across {} shards",
            hex::encode(&atomic_id[..4]),
            operations.len()
        );
        
        self.csap.execute_atomic(atomic_id, operations)
            .await
            .map_err(|e| ConsensusError::InvalidVertex(format!("Atomic operation failed: {}", e)))
    }
    
    /// Gets status of atomic operation
    pub fn get_atomic_status(&self, atomic_id: &Hash) -> Option<AtomicStatus> {
        self.csap.get_status(atomic_id)
    }
    
    /// Gets mempool for external access
    pub fn mempool(&self) -> &Arc<ShardedMempool> {
        &self.mempool
    }

    pub async fn receive_vertex(&self, vertex: DAGVertex) -> ConsensusResult<()> {
        self.fast_path.receive_vertex(vertex).await
    }

    pub async fn receive_vote(&self, vote: CommitteeVote) -> ConsensusResult<()> {
        self.fast_path.receive_vote(vote).await
    }

    pub fn get_vertex(&self, hash: &Hash) -> Option<DAGVertex> {
        self.fast_path.get_confirmed_vertex(hash)
            .or_else(|| self.fast_path.get_pending_vertex(hash))
    }

    pub fn get_dag_tips(&self, shard_id: ShardId) -> Vec<Hash> {
        self.dag.get_tips(shard_id)
    }

    pub fn current_slot(&self) -> u64 {
        *self.current_slot.read()
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_slot() / 32
    }

    pub fn finalized_slot(&self) -> u64 {
        self.finality.finalized_slot()
    }

    pub fn state_manager(&self) -> &StateManager {
        &self.state_manager
    }

    pub fn storage(&self) -> &Storage {
        &self.storage
    }

    pub fn dag(&self) -> &Arc<DAGGraph> {
        &self.dag
    }

    pub fn committee_manager(&self) -> &Arc<CommitteeManager> {
        &self.committee_manager
    }

    pub fn pending_tx_count(&self) -> usize {
        self.mempool.total_pending()
    }

    pub fn confirmed_vertex_count(&self) -> usize {
        self.fast_path.confirmed_count()
    }

    pub fn register_validator(&self, validator: Validator) -> Result<(), String> {
        self.committee_manager.add_validator(validator)
    }

    pub fn get_metrics(&self) -> ConsensusMetrics {
        ConsensusMetrics {
            current_slot: self.current_slot(),
            current_epoch: self.current_epoch(),
            finalized_slot: self.finalized_slot(),
            pending_transactions: self.pending_tx_count(),
            pending_vertices: self.fast_path.pending_count(),
            confirmed_vertices: self.confirmed_vertex_count(),
            total_validators: self.committee_manager.get_validator_set().validators.len(),
        }
    }

    pub fn l0_hub(&self) -> Option<Arc<FinalityHub>> {
        self.finality_hub.clone()
    }

    pub fn l0_relay_dispatcher(&self) -> Option<Arc<RelayDispatcher>> {
        self.relay_dispatcher.clone()
    }
}

impl Clone for QuantosConsensus {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            storage: self.storage.clone(),
            state_manager: self.state_manager.clone(),
            dag: self.dag.clone(),
            mempool: self.mempool.clone(),
            executor: self.executor.clone(),
            committee_manager: self.committee_manager.clone(),
            fast_path: self.fast_path.clone(),
            finality: self.finality.clone(),
            current_slot: self.current_slot.clone(),
            validator_keys: None,
            csap: self.csap.clone(),
            finality_hub: self.finality_hub.clone(),
            relay_dispatcher: self.relay_dispatcher.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConsensusMetrics {
    pub current_slot: u64,
    pub current_epoch: u64,
    pub finalized_slot: u64,
    pub pending_transactions: usize,
    pub pending_vertices: usize,
    pub confirmed_vertices: usize,
    pub total_validators: usize,
}
