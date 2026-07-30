// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;
use parking_lot::RwLock;

use crate::consensus::{
    ConsensusError, ConsensusResult, CommitteeManager, FastPath, FinalityLayer,
    FinalizedCheckpoint, CrossShardAtomicProtocol, ShardOperation, AtomicResult,
    AtomicStatus, SharedValidatorPerformanceTracker, ValidatorPerformanceRecord,
};
use crate::crypto::{MlDsa65Keypair, VRFKeypair};
use crate::dag::{DAGGraph, TxIngressBuffer, VertexBuilder};
use crate::l0::{CheckpointGossip, CheckpointPool, FinalityHub, HttpRelayTransport, LightClientRegistry, RelayDispatcher, ChainRegistry, ValidatorSetSnapshot, SubnetManager, SubnetId, SubnetConfig};
use crate::l0::hub::SignatureContribution;
use crate::l0::proof::PqcSignatureAlgo;
use crate::mempool::{ZeroStakeProvider, FixedAgeProvider};
use crate::state::{StateManager, OptimisticExecutor};
use crate::stacc::{ActivationLedger, QuotaManager, StaccAdmission};
use crate::storage::Storage;
use crate::types::{
    Address, Checkpoint, CommitteeVote, DAGVertex, Hash,
    ShardId, SignedTransaction, TransactionReceipt, Validator,
};
use crate::NodeConfig;

pub struct QuantosConsensus {
    config: NodeConfig,
    storage: Storage,
    state_manager: StateManager,
    dag: Arc<DAGGraph>,
    ingress: Arc<TxIngressBuffer>,
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
    /// Validator performance tracker (per-epoch metrics in RAM, flushed to RocksDB)
    performance_tracker: SharedValidatorPerformanceTracker,
}

#[derive(Clone)]
struct ValidatorKeys {
    signing_key: MlDsa65Keypair,
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

        let ingress = Arc::new(TxIngressBuffer::new(
            state_manager.clone(),
            config.num_shards as u16,
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

        // Build the DAG-native VertexBuilder with STACC admission.
        let activation = ActivationLedger::default();
        let quota = QuotaManager::new(ZeroStakeProvider, FixedAgeProvider);
        let stacc = if config.stacc_require_activation {
            StaccAdmission::new_with_policy(activation, quota, true, true)
        } else {
            StaccAdmission::new_with_policy(activation, quota, false, false)
        };
        let vertex_builder = Arc::new(parking_lot::Mutex::new(
            VertexBuilder::new(ingress.clone(), state_manager.clone(), stacc),
        ));

        let fast_path = Arc::new(FastPath::new(
            dag.clone(),
            ingress.clone(),
            vertex_builder.clone(),
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
        let csap_keypair = crate::crypto::MlDsa65Keypair::generate()
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
            ingress,
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
            performance_tracker: SharedValidatorPerformanceTracker::new(),
        })
    }

    pub fn set_validator_keys(
        &mut self,
        genesis: &crate::genesis::GenesisConfig,
        signing_key: MlDsa65Keypair,
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
                "Local validator address {} is not present in genesis; registering as ephemeral validator for single-node mode",
                address_hex
            );
            // Register the ephemeral validator so the node can produce
            // vertices, sign checkpoints, and build L0 proofs.
            let ephemeral = crate::types::Validator {
                address,
                public_key: signing_key.public_key.clone(),
                finality_public_key: finality_key.public_key.clone(),
                stake: crate::types::Amount(10_000_000_000_000_000_000_000_000),
                commission_rate: 0,
                active: true,
                jailed: false,
                slash_count: 0,
                last_active_slot: 0,
                vrf_public_key: vrf_key.public_key().to_vec(),
            };
            if let Err(e) = self.committee_manager.add_validator(ephemeral) {
                tracing::warn!("Failed to register ephemeral validator: {}", e);
            } else {
                local_vrf_pubkey = vrf_key.public_key().to_vec();
                self.dag.add_authorized_creator(address);
                tracing::info!("Ephemeral validator {} registered", address_hex);
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

        // Epoch boundary: finalize performance records and persist to RocksDB
        if slot % 32 == 0 && slot > 0 {
            let prev_epoch = self.performance_tracker.current_epoch();
            if prev_epoch != epoch {
                self.finalize_and_persist_epoch(prev_epoch, epoch);
            }
        }

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
                let checkpoint_hash = checkpoint.hash();
                match self.finality.sign_checkpoint(
                    &checkpoint_hash,
                    keys.address,
                    &keys.finality_key,
                ).await {
                    Ok(sig) => {
                        self.performance_tracker.record_checkpoint_signature(&keys.address);
                        match self.finality.receive_checkpoint_signature(&checkpoint.hash(), sig).await {
                            Ok(Some(finalized)) => {
                                tracing::info!("Checkpoint finalized at slot {}", slot);
                                let finalized = finalized.clone();
                                let hub = self.finality_hub.clone();
                                let dispatcher = self.relay_dispatcher.clone();
                                let validator_set = self.committee_manager.get_validator_set();
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
                            Ok(None) => {
                                tracing::debug!("Checkpoint not yet finalized at slot {}", slot);
                            }
                            Err(e) => {
                                tracing::warn!("Checkpoint signature reception failed at slot {}: {}", slot, e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Checkpoint signing failed: {}", e);
                    }
                }
            }
        }

        tracing::debug!("on_slot_tick completed: slot={}", slot);
        Ok(())
    }

    async fn try_produce_vertices(&self, keys: &ValidatorKeys, slot: u64) -> ConsensusResult<()> {
        Self::try_produce_vertices_static(
            &self.config, &self.fast_path, &self.ingress, &self.storage,
            &self.committee_manager, &self.current_slot, keys, slot,
        ).await?;

        // Record block proposal in performance tracker
        // Count CU from committed vertices at this slot
        let validator_set = self.committee_manager.get_validator_set();
        for v in &validator_set.validators {
            if v.address == keys.address {
                // Approximate CU: count pending txs that were processed
                // The actual CU is tracked in receipts, but for performance tracking
                // we use a simpler heuristic: 1 block proposed per slot with active shards
                self.performance_tracker.record_block_proposed(&keys.address, 0);
                break;
            }
        }

        Ok(())
    }

    async fn try_produce_vertices_static(
        config: &NodeConfig,
        fast_path: &Arc<FastPath>,
        ingress: &Arc<TxIngressBuffer>,
        storage: &Storage,
        committee_manager: &Arc<CommitteeManager>,
        _current_slot: &Arc<RwLock<u64>>,
        keys: &ValidatorKeys,
        slot: u64,
    ) -> ConsensusResult<()> {
        let epoch = slot / 32;
        let total_validators = committee_manager.total_validators();
        let single_node = total_validators <= 1;
        // Auto-confirm mode: if we control all validators on this node, skip voting
        let auto_confirm = total_validators <= 5;

        // Phase 1: Collect non-empty shards that we're allowed to produce for
        let active_shards: Vec<u16> = (0..config.num_shards as u16)
            .filter(|&shard_id| {
                if single_node || auto_confirm {
                    return true;
                }
                let committee_id = shard_id % config.num_committees as u16;
                committee_manager.is_committee_member(epoch, committee_id, &keys.address)
            })
            .filter(|&shard_id| ingress.pending_for_shard(shard_id) > 0)
            .collect();

        if active_shards.is_empty() {
            tracing::debug!("No active shards with pending txs for slot {}", slot);
            return Ok(());
        }

        tracing::info!("Creating vertices for {} active shards at slot {}", active_shards.len(), slot);

        // Phase 2: Create vertices in parallel across shards (rayon, CPU-bound)
        let results = fast_path.create_vertices_parallel(
            active_shards,
            keys.address,
            &keys.signing_key.secret_key,
            &keys.signing_key.public_key,
        );

        // Log any vertex creation failures for diagnosis
        for r in &results {
            if let Err(e) = r {
                tracing::warn!("Vertex creation failed at slot {}: {}", slot, e);
            }
        }

        // Phase 3: Confirm vertices
        let mut all_receipts = Vec::new();
        let mut all_txs = Vec::new();
        let mut committed_count = 0;

        if auto_confirm {
            // Batch confirm: collect all successful vertices, confirm in one pass
            let successful_vertices: Vec<DAGVertex> = results
                .into_iter()
                .filter_map(|r| r.ok())
                .collect();

            if successful_vertices.is_empty() {
                return Ok(());
            }

            let batch_results = fast_path.confirm_vertices_batch_direct(&successful_vertices).await?;

            for (vertex, (_state_root, receipts, txs)) in successful_vertices.iter().zip(batch_results.iter()) {
                let tx_count = vertex.tx_count();
                let shard_id = vertex.shard_id;
                let vhash = vertex.hash;
                let mut fixed_receipts: Vec<TransactionReceipt> = receipts.iter().map(|r| {
                    let mut r = r.clone();
                    r.slot = slot;
                    r.vertex_hash = vhash;
                    r
                }).collect();
                all_receipts.append(&mut fixed_receipts);
                all_txs.extend(txs.clone());
                committed_count += 1;

                tracing::info!(
                    "Committed vertex {} for shard {} — {} txs",
                    hex::encode(&vertex.hash[..4]),
                    shard_id,
                    tx_count,
                );
            }
        } else {
            // Multi-node: create self-vote and submit for each vertex
            for vertex_result in results {
                match vertex_result {
                    Ok(vertex) => {
                        let tx_count = vertex.tx_count();
                        let shard_id = vertex.shard_id;

                        let vote = fast_path.create_vote(
                            vertex.hash,
                            keys.address,
                            true,
                            1,
                            &keys.signing_key.secret_key,
                        )?;
                        let confirm_result = fast_path.receive_vote(vote).await?;

                        if let Some((_state_root, receipts)) = confirm_result {
                            let vhash = vertex.hash;
                            let mut fixed_receipts: Vec<TransactionReceipt> = receipts.into_iter().map(|mut r| {
                                r.slot = slot;
                                r.vertex_hash = vhash;
                                r
                            }).collect();
                            all_receipts.append(&mut fixed_receipts);
                            all_txs.extend(vertex.transactions);
                            committed_count += 1;

                            tracing::info!(
                                "Committed vertex {} for shard {} — {} txs",
                                hex::encode(&vertex.hash[..4]),
                                shard_id,
                                tx_count,
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!("No vertex produced: {}", e);
                    }
                }
            }
        }

        if committed_count > 0 {
            if let Err(e) = storage.put_finalized_batch(&all_receipts, &all_txs) {
                tracing::error!(
                    "Failed to store {} receipts and {} transactions: {}",
                    all_receipts.len(),
                    all_txs.len(),
                    e
                );
            } else {
                tracing::info!(
                    "Finalized slot {} — {} vertices, {} receipts, {} transactions",
                    slot,
                    committed_count,
                    all_receipts.len(),
                    all_txs.len()
                );
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

    /// Submit a batch of transactions in one pass.
    ///
    /// Routes each transaction through the DAG-native ingress buffer, which
    /// validates ML-DSA-65 signatures and routes to the appropriate shard channel.
    pub fn submit_transactions_batch(&self, txs: Vec<SignedTransaction>) -> Vec<ConsensusResult<Hash>> {
        txs.into_iter()
            .map(|tx| {
                let hash = tx.hash;
                if self.ingress.ingest(tx) {
                    Ok(hash)
                } else {
                    Err(ConsensusError::InvalidVertex("Transaction rejected by ingress buffer".to_string()))
                }
            })
            .collect()
    }
    
    /// PRODUCTION: Execute atomic cross-shard operation
    pub async fn execute_atomic_swap(
        &self,
        operations: Vec<ShardOperation>,
    ) -> ConsensusResult<AtomicResult> {
        let atomic_id = crate::types::hash_data(
            &bincode::serialize(&operations)
                .map_err(|e| ConsensusError::InvalidData(format!("Failed to serialize operations: {}", e)))?
        );
        
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
    
    /// Gets the ingress buffer for external access (replaces mempool accessor)
    pub fn ingress(&self) -> &Arc<TxIngressBuffer> {
        &self.ingress
    }

    pub async fn receive_vertex(&self, vertex: DAGVertex) -> ConsensusResult<()> {
        self.fast_path.receive_vertex(vertex).await
    }

    pub async fn receive_vote(&self, vote: CommitteeVote) -> ConsensusResult<()> {
        self.performance_tracker.record_vote(&vote.validator);
        let _ = self.fast_path.receive_vote(vote).await?;
        Ok(())
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
        self.ingress.total_pending()
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

        // Sign with ML-DSA-65 (finality key preferred, signing key as fallback)
        let (algo, signature) = if let Ok(sig) = keys.finality_key.sign(digest) {
            (PqcSignatureAlgo::MlDsa65, sig)
        } else if let Ok(sig) = keys.signing_key.sign(digest) {
            (PqcSignatureAlgo::MlDsa65, sig)
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

    /// Returns the validator performance tracker for RPC access.
    pub fn performance_tracker(&self) -> &SharedValidatorPerformanceTracker {
        &self.performance_tracker
    }

    /// Finalize the current epoch: flush in-RAM metrics, build serializable
    /// records, and persist them to RocksDB.
    fn finalize_and_persist_epoch(&self, prev_epoch: u64, new_epoch: u64) {
        let completed = self.performance_tracker.finalize_epoch(new_epoch);

        if completed.is_empty() {
            return;
        }

        let validator_set = self.committee_manager.get_validator_set();
        let total_stake: u128 = validator_set.validators.iter()
            .map(|v| v.effective_stake())
            .sum();

        let mut records = Vec::with_capacity(completed.len());
        for (addr, metrics) in &completed {
            // Compute reward using the tokenomics engine (simplified: no rent/slash for now)
            let stake = validator_set.validators.iter()
                .find(|v| v.address == *addr)
                .map(|v| v.effective_stake())
                .unwrap_or(0);

            let stake_weight = if total_stake == 0 {
                0.0
            } else {
                stake as f64 / total_stake as f64
            };

            let performance = metrics.performance_score();
            // Base epoch reward: 1,000,000,000 base units (placeholder, will be
            // replaced by TokenomicsEngine::compute_epoch_reward output)
            let base_reward = 1_000_000_000u128;
            let reward = (base_reward as f64 * stake_weight * performance).round() as u128;

            let record = ValidatorPerformanceRecord::from_metrics(
                prev_epoch, *addr, metrics, reward,
            );
            records.push(record);
        }

        // Persist records to RocksDB
        for record in &records {
            match bincode::serialize(record) {
                Ok(value) => {
                    let key = crate::storage::validator_performance_key(prev_epoch, &record.validator);
                    if let Err(e) = self.storage.put_validator_performance(&key, &value) {
                        tracing::warn!("Failed to persist validator performance for {:?} epoch {}: {}", record.validator, prev_epoch, e);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to serialize validator performance record: {}", e);
                }
            }
        }

        tracing::info!(
            epoch = prev_epoch,
            records = records.len(),
            "Validator performance records persisted"
        );
    }
}

impl Clone for QuantosConsensus {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            storage: self.storage.clone(),
            state_manager: self.state_manager.clone(),
            dag: self.dag.clone(),
            ingress: self.ingress.clone(),
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
            performance_tracker: self.performance_tracker.clone(),
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
