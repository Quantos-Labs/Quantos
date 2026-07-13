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
use crate::crypto::{DilithiumKeypair, MlDsa65Keypair, VRFKeypair};
use crate::dag::DAGGraph;
use crate::l0::{CheckpointGossip, CheckpointPool, FinalityHub, HttpRelayTransport, LightClientRegistry, RelayDispatcher, ChainRegistry, ValidatorSetSnapshot, SubnetManager, SubnetId, SubnetConfig};
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
    /// L0 checkpoint pool for external checkpoints
    checkpoint_pool: Option<Arc<CheckpointPool>>,
    /// L0 checkpoint gossip for propagating checkpoints
    checkpoint_gossip: Option<Arc<CheckpointGossip>>,
    /// L0 light client registry for verifying external checkpoints
    light_client_registry: Option<Arc<LightClientRegistry>>,
    /// L0 Sovereign Subnet manager
    subnet_manager: Option<Arc<SubnetManager>>,
}

struct ValidatorKeys {
    signing_key: DilithiumKeypair,
    vrf_key: VRFKeypair,
    finality_key: MlDsa65Keypair,
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

        // Initialize optional L0 finality hub, relay dispatcher, checkpoint pool, gossip, and light clients
        let (finality_hub, relay_dispatcher, checkpoint_pool, checkpoint_gossip, light_client_registry, subnet_manager) = if config.l0_config.enabled {
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
            // Initialize checkpoint pool: 1 hour max age, 1000 max pending
            let pool = Arc::new(CheckpointPool::new(3600, 1000));
            
            // Initialize checkpoint gossip
            let (gossip, _gossip_rx) = CheckpointGossip::new(pool.clone());
            let gossip = Arc::new(gossip);
            
            // Initialize light client registry with default clients
            let light_clients = Arc::new(LightClientRegistry::with_defaults());

            // Initialize sovereign subnet manager
            let subnets = Arc::new(SubnetManager::new());
            
            tracing::info!("L0 finality hub, relay dispatcher, checkpoint pool, gossip, light clients, and subnet manager initialized");
            (Some(hub), Some(dispatcher), Some(pool), Some(gossip), Some(light_clients), Some(subnets))
        } else {
            (None, None, None, None, None, None)
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
            checkpoint_pool,
            checkpoint_gossip,
            light_client_registry,
            subnet_manager,
        })
    }

    pub fn set_validator_keys(
        &mut self,
        genesis: &crate::genesis::GenesisConfig,
        signing_key: DilithiumKeypair,
        vrf_key: VRFKeypair,
        finality_key: MlDsa65Keypair,
    ) {
        let address = signing_key.address();
        let address_hex = hex::encode(&address);

        // Register all genesis validators in the committee manager so the
        // network starts with the exact validator set defined by genesis.
        for gv in &genesis.validators {
            let Ok(vaddr) = crate::genesis::GenesisConfig::parse_address(&gv.address) else {
                continue;
            };
            let Ok(vpubkey) = hex::decode(&gv.public_key) else {
                continue;
            };
            let validator = Validator {
                address: vaddr,
                public_key: vpubkey,
                finality_public_key: Vec::new(), // populated later when finality key is known
                stake: crate::types::Amount(gv.stake),
                commission_rate: gv.commission_bps,
                active: true,
                jailed: false,
                slash_count: 0,
                last_active_slot: 0,
                vrf_public_key: Vec::new(), // populated below
            };
            if let Err(e) = self.committee_manager.add_validator(validator) {
                tracing::warn!("Failed to register genesis validator {}: {}", gv.address, e);
            }
        }

        // If this node owns one of the genesis validators, add its VRF/ML-DSA-65
        // public keys and authorize it to create vertices.
        let mut local_vrf_pubkey = Vec::new();
        for gv in &genesis.validators {
            if gv.address.eq_ignore_ascii_case(&address_hex) {
                local_vrf_pubkey = vrf_key.public_key().to_vec();
                self.committee_manager.update_validator_vrf(&address, local_vrf_pubkey.clone());
                self.committee_manager.update_validator_finality_key(&address, finality_key.public_key.clone());
                self.dag.add_authorized_creator(address);
                tracing::info!("Local validator {} authorized from genesis", address_hex);
                break;
            }
        }

        if local_vrf_pubkey.is_empty() {
            tracing::warn!(
                "Local validator address {} is not present in genesis; node will not produce vertices",
                address_hex
            );
        }

        // Collect all VRF public keys from genesis validators that have one.
        let vrf_pubkeys: Vec<Vec<u8>> = genesis.validators.iter()
            .filter_map(|gv| {
                if gv.address.eq_ignore_ascii_case(&address_hex) {
                    Some(vrf_key.public_key().to_vec())
                } else {
                    None // unknown VRF keys for other validators until discovered on the network
                }
            })
            .collect();

        if !vrf_pubkeys.is_empty() {
            if let Err(e) = self.committee_manager.initialize_threshold_vrf(vrf_pubkeys) {
                tracing::warn!("Threshold VRF init: {}", e);
            }
        }

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
                    if let Err(e) = self.on_slot_tick().await {
                        tracing::error!("on_slot_tick error: {} — consensus loop continuing", e);
                    }
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
        tracing::debug!("on_slot_tick: slot={}, epoch={}", slot, epoch);

        if slot % 32 == 0 {
            let randomness = self.compute_epoch_randomness(epoch);
            self.committee_manager.rotate_committees(epoch, slot, &randomness)?;
            tracing::info!("Committees rotated for epoch {}", epoch);
        }

        if let Some(ref keys) = self.validator_keys {
            tracing::debug!("Calling try_produce_vertices for slot {}", slot);
            self.try_produce_vertices(keys, slot).await?;
            tracing::debug!("try_produce_vertices done for slot {}", slot);
        }

        tracing::debug!("Checking checkpoint for slot {}", slot);
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
                            let finalized = finalized.clone();
                            let hub = self.finality_hub.clone();
                            let dispatcher = self.relay_dispatcher.clone();
                            let validator_set = self.committee_manager.get_validator_set();
                            tracing::info!("L0 dispatch gate: hub={} dispatcher={}", hub.is_some(), dispatcher.is_some());
                            tokio::task::spawn_blocking(move || {
                                if let (Some(hub), Some(dispatcher)) = (hub, dispatcher) {
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
                                        algo: PqcSignatureAlgo::MlDsa65,
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
                            });
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Checkpoint signing skipped: {}", e);
                    }
                }
            }
        }

        tracing::info!("on_slot_tick completed: slot={}", slot);
        Ok(())
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

    /// Computes per-epoch randomness used for committee selection.
    ///
    /// Uses the validator's QR-VRF key (SPHINCS+ PRF) when available. The PRF
    /// output is deterministic and reproducible for a given (key, seed), but
    /// note that *cryptographic* output-uniqueness is NOT enforced here: a
    /// signature-based VRF admits multiple valid signatures, so this path does
    /// not by itself prevent grinding (see `crypto::vrf_hashbased`, finding V1).
    /// Network anti-grinding relies on beacon aggregation + VDF, not on this
    /// per-validator output. Falls back to plain SHA3-256 only at genesis
    /// (before validator keys are loaded).
    fn compute_epoch_randomness(&self, epoch: u64) -> Hash {
        // Canonical seed: epoch_bytes ++ prev_finalized_checkpoint_hash
        let mut seed_data = Vec::new();
        seed_data.extend_from_slice(&epoch.to_le_bytes());
        if let Some(checkpoint) = self.finality.get_latest_finalized_checkpoint() {
            seed_data.extend_from_slice(&checkpoint.hash());
        }
        let seed = crate::types::hash_data(&seed_data);

        // QR-VRF path: SPHINCS+ PRF over the seed → deterministic, PQ-secure output
        if let Some(ref keys) = self.validator_keys {
            match keys.vrf_key.prove(&seed) {
                Ok(proof) => {
                    tracing::info!(
                        epoch = epoch,
                        output = %hex::encode(&proof.output[..8]),
                        "QR-VRF epoch randomness generated (SPHINCS+ PRF)"
                    );
                    return proof.output;
                }
                Err(e) => {
                    tracing::warn!(
                        epoch = epoch,
                        error = %e,
                        "QR-VRF prove failed — falling back to plain hash randomness"
                    );
                }
            }
        }

        // Fallback: genesis epoch or no validator key loaded yet
        tracing::debug!(epoch, "Using plain hash randomness (no validator key)");
        seed
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

    pub fn num_shards(&self) -> usize {
        self.config.num_shards
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

    /// Returns a ValidatorSetSnapshot for L0 finality proofs
    pub fn get_validator_snapshot(&self) -> Option<ValidatorSetSnapshot> {
        let validator_set = self.committee_manager.get_validator_set();
        let active = validator_set.active_validators();
        
        if active.is_empty() {
            return None;
        }

        use crate::l0::proof::ValidatorRecord;
        
        let validators: Vec<ValidatorRecord> = active
            .iter()
            .map(|v| ValidatorRecord {
                address: v.address,
                public_key: v.public_key.clone(),
                stake: v.stake.0,
            })
            .collect();

        let root = ValidatorSetSnapshot::compute_root(&validators);

        Some(ValidatorSetSnapshot {
            root,
            validators,
        })
    }

    /// Returns the checkpoint pool if L0 is enabled
    pub fn checkpoint_pool(&self) -> Option<Arc<CheckpointPool>> {
        self.checkpoint_pool.clone()
    }

    /// Returns the checkpoint gossip if L0 is enabled
    pub fn checkpoint_gossip(&self) -> Option<Arc<CheckpointGossip>> {
        self.checkpoint_gossip.clone()
    }

    /// Returns the light client registry if L0 is enabled
    pub fn light_client_registry(&self) -> Option<Arc<LightClientRegistry>> {
        self.light_client_registry.clone()
    }

    /// Returns the sovereign subnet manager if L0 is enabled
    pub fn subnet_manager(&self) -> Option<Arc<SubnetManager>> {
        self.subnet_manager.clone()
    }

    /// Sign an external checkpoint if this node is a validator
    pub fn sign_external_checkpoint(&self, digest: &Hash) -> Option<SignatureContribution> {
        let keys = self.validator_keys.as_ref()?;

        // Sign with ML-DSA-65 (finality key) or Dilithium (signing key)
        let (algo, signature) = if let Ok(sig) = keys.finality_key.sign(digest) {
            (PqcSignatureAlgo::MlDsa65, sig)
        } else if let Ok(sig) = keys.signing_key.sign(digest) {
            (PqcSignatureAlgo::Dilithium3, sig)
        } else {
            return None;
        };

        Some(SignatureContribution {
            validator: keys.address,
            algo,
            signature,
        })
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
            checkpoint_pool: self.checkpoint_pool.clone(),
            checkpoint_gossip: self.checkpoint_gossip.clone(),
            light_client_registry: self.light_client_registry.clone(),
            subnet_manager: self.subnet_manager.clone(),
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
