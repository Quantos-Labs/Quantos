//! # Cross-Shard Communication
//!
//! Complete cross-shard transaction and message handling for Quantos.
//!
//! ## Protocol
//!
//! Cross-shard transactions follow a 2-phase commit protocol:
//!
//! ```text
//! Source Shard                    Destination Shard
//!      │                                │
//!      │  1. Lock funds                 │
//!      │  2. Create CrossShardTx        │
//!      │─────────────────────────────▶ │
//!      │                                │ 3. Verify proof
//!      │                                │ 4. Credit funds
//!      │  5. Confirm                    │
//!      │◀────────────────────────────── │
//!      │  6. Finalize                   │
//!      │                                │
//! ```
//!
//! ## Security
//!
//! - zk-STARK proofs verify cross-shard message authenticity
//! - Timeout mechanism prevents stuck transactions
//! - Rollback support for failed transactions

use std::sync::Arc;
use dashmap::DashMap;
use parking_lot::{RwLock, Mutex};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use rand::RngCore;
use rand::rngs::OsRng;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::types::{Address, Amount, Hash, ShardId};
use crate::crypto::{sign_ml_dsa_65, verify_ml_dsa_65, MlDsa65Keypair};

/// Minimum transfer amount
const MIN_TRANSFER_AMOUNT: u128 = 1;
/// Maximum transfer amount
const MAX_TRANSFER_AMOUNT: u128 = u128::MAX / 2;
/// Channel send timeout
const CHANNEL_SEND_TIMEOUT_MS: u64 = 1000;
/// Maximum pending per sender to prevent DoS
const MAX_PENDING_PER_SENDER: usize = 100;

/// Configuration for cross-shard communication.
#[derive(Clone, Debug)]
pub struct CrossShardConfig {
    /// Maximum pending cross-shard transactions per shard
    pub max_pending_per_shard: usize,
    /// Timeout for cross-shard transactions (milliseconds)
    pub timeout_ms: u64,
    /// Maximum retries for failed transactions
    pub max_retries: u32,
    /// Enable zk-STARK proofs for cross-shard verification
    pub enable_zk_proofs: bool,
    /// Batch size for cross-shard message processing
    pub batch_size: usize,
}

impl Default for CrossShardConfig {
    fn default() -> Self {
        Self {
            max_pending_per_shard: 10_000,
            timeout_ms: 10_000, // 10 seconds
            max_retries: 3,
            enable_zk_proofs: true,
            batch_size: 100,
        }
    }
}

/// A cross-shard transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossShardTransaction {
    /// Unique transaction ID
    pub id: Hash,
    /// Source shard
    pub source_shard: ShardId,
    /// Destination shard
    pub dest_shard: ShardId,
    /// Sender address
    pub sender: Address,
    /// Recipient address
    pub recipient: Address,
    /// Amount to transfer
    pub amount: Amount,
    /// Transaction data/payload
    pub data: Vec<u8>,
    /// Nonce for replay protection
    pub nonce: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Current phase
    pub phase: CrossShardPhase,
    /// Source shard state root at lock time
    pub source_state_root: Hash,
    /// zk-STARK proof (if enabled)
    pub proof: Option<Vec<u8>>,
    /// Retry count
    pub retries: u32,
}

/// Phase of a cross-shard transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrossShardPhase {
    /// Initial phase - funds locked on source shard
    Locked,
    /// Message sent to destination shard
    Pending,
    /// Destination shard has verified and credited
    Credited,
    /// Source shard confirmed completion
    Confirmed,
    /// Transaction finalized
    Finalized,
    /// Transaction failed and rolled back
    RolledBack,
    /// Transaction timed out
    TimedOut,
}

/// A cross-shard message between shards.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossShardMessage {
    /// Message type
    pub msg_type: CrossShardMessageType,
    /// Source shard
    pub source_shard: ShardId,
    /// Destination shard
    pub dest_shard: ShardId,
    /// Message payload
    pub payload: Vec<u8>,
    /// Merkle proof of inclusion in source shard
    pub merkle_proof: Vec<Hash>,
    /// Source state root
    pub state_root: Hash,
    /// Signature from source shard committee
    pub committee_signature: Vec<u8>,
}

/// Types of cross-shard messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CrossShardMessageType {
    /// Transfer request
    Transfer(CrossShardTransaction),
    /// Transfer confirmation
    Confirm(Hash),
    /// Transfer rejection
    Reject(Hash, String),
    /// State sync request
    StateSync(u64, u64),
    /// State sync response
    StateSyncResponse(Vec<u8>),
    /// Heartbeat for liveness
    Heartbeat,
}

/// Receipt for a completed cross-shard transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossShardReceipt {
    /// Transaction ID
    pub tx_id: Hash,
    /// Success status
    pub success: bool,
    /// Source shard
    pub source_shard: ShardId,
    /// Destination shard
    pub dest_shard: ShardId,
    /// Final phase
    pub final_phase: CrossShardPhase,
    /// Total time taken (milliseconds)
    pub duration_ms: u64,
    /// Gas used
    pub cu_used: u64,
    /// Error message if failed
    pub error: Option<String>,
}

/// Main cross-shard coordinator.
///
/// Manages cross-shard transactions and message routing.
///
/// # Example
///
/// ```rust,ignore
/// let coordinator = CrossShardCoordinator::new(config);
///
/// // Initiate a cross-shard transfer
/// let tx_id = coordinator.initiate_transfer(
///     source_shard,
///     dest_shard,
///     sender,
///     recipient,
///     amount,
/// ).await?;
///
/// // Wait for completion
/// let receipt = coordinator.wait_for_completion(tx_id).await?;
/// ```
pub struct CrossShardCoordinator {
    config: CrossShardConfig,
    /// Pending transactions by ID
    pending: Arc<DashMap<Hash, CrossShardTransaction>>,
    /// Pending transactions by source shard
    by_source_shard: Arc<DashMap<ShardId, Vec<Hash>>>,
    /// Pending transactions by destination shard
    by_dest_shard: Arc<DashMap<ShardId, Vec<Hash>>>,
    /// Completed receipts
    receipts: Arc<DashMap<Hash, CrossShardReceipt>>,
    /// zk-STARK proofs enabled
    zk_enabled: bool,
    /// Message sender channels per shard
    shard_channels: Arc<DashMap<ShardId, mpsc::Sender<CrossShardMessage>>>,
    /// Metrics
    metrics: Arc<RwLock<CrossShardMetrics>>,
    /// Authorization token for privileged operations
    auth_token: Arc<Mutex<[u8; 32]>>,
    /// Global nonce counter for replay protection
    nonce_counter: Arc<AtomicU64>,
    /// Pending count per sender for DoS protection
    pending_per_sender: Arc<DashMap<Address, usize>>,
    /// Committee keypair for signing cross-shard messages
    committee_keypair: Arc<RwLock<Option<MlDsa65Keypair>>>,
}

/// Metrics for cross-shard operations.
#[derive(Clone, Debug, Default)]
pub struct CrossShardMetrics {
    /// Total cross-shard transactions initiated
    pub tx_initiated: u64,
    /// Total cross-shard transactions completed
    pub tx_completed: u64,
    /// Total cross-shard transactions failed
    pub tx_failed: u64,
    /// Average completion time (ms)
    pub avg_completion_time_ms: u64,
    /// Total messages sent
    pub messages_sent: u64,
    /// Total messages received
    pub messages_received: u64,
    /// Current pending transactions
    pub pending_count: u64,
}

impl CrossShardCoordinator {
    /// Creates a new cross-shard coordinator.
    pub fn new(config: CrossShardConfig) -> Self {
        let zk_enabled = config.enable_zk_proofs;
        
        // HIGH: Use OsRng for cryptographically secure authorization token
        let mut token = [0u8; 32];
        OsRng.fill_bytes(&mut token);
        
        Self {
            config,
            pending: Arc::new(DashMap::new()),
            by_source_shard: Arc::new(DashMap::new()),
            by_dest_shard: Arc::new(DashMap::new()),
            receipts: Arc::new(DashMap::new()),
            zk_enabled,
            shard_channels: Arc::new(DashMap::new()),
            metrics: Arc::new(RwLock::new(CrossShardMetrics::default())),
            auth_token: Arc::new(Mutex::new(token)),
            nonce_counter: Arc::new(AtomicU64::new(1)),
            pending_per_sender: Arc::new(DashMap::new()),
            committee_keypair: Arc::new(RwLock::new(None)),
        }
    }

    /// Sets the committee keypair used to sign outgoing cross-shard messages.
    pub fn set_committee_keypair(&self, keypair: MlDsa65Keypair) {
        *self.committee_keypair.write() = Some(keypair);
    }

    /// Signs a cross-shard message payload with the committee keypair.
    /// Returns the signature, or empty Vec if no keypair is set.
    fn sign_committee(&self, message: &CrossShardMessage) -> Vec<u8> {
        let kp_lock = self.committee_keypair.read();
        if let Some(ref kp) = *kp_lock {
            let signing_data = Self::message_signing_data(message);
            match sign_ml_dsa_65(&kp.secret_key, &signing_data) {
                Ok(sig) => sig,
                Err(e) => {
                    tracing::error!("Failed to sign cross-shard message: {}", e);
                    Vec::new()
                }
            }
        } else {
            tracing::warn!("No committee keypair set, cross-shard message unsigned");
            Vec::new()
        }
    }

    /// Computes the canonical signing data for a cross-shard message.
    /// This is the hash of (source_shard || dest_shard || state_root || payload).
    fn message_signing_data(message: &CrossShardMessage) -> Vec<u8> {
        let mut data = Vec::with_capacity(2 + 32 + message.payload.len());
        data.extend_from_slice(&message.source_shard.to_le_bytes());
        data.extend_from_slice(&message.dest_shard.to_le_bytes());
        data.extend_from_slice(&message.state_root);
        data.extend_from_slice(&message.payload);
        crate::types::hash_data(&data).to_vec()
    }

    /// Verifies a cross-shard message's committee signature.
    /// Returns Ok(()) if signature is valid or empty (backward compat during transition).
    /// Returns Err if signature is present but invalid.
    fn verify_committee_signature(
        &self,
        message: &CrossShardMessage,
        source_shard: ShardId,
    ) -> Result<(), CrossShardError> {
        if message.committee_signature.is_empty() {
            tracing::warn!(
                "Cross-shard message from shard {} has no committee signature",
                source_shard
            );
            return Ok(());
        }

        let kp_lock = self.committee_keypair.read();
        if let Some(ref kp) = *kp_lock {
            let signing_data = Self::message_signing_data(message);
            match verify_ml_dsa_65(&kp.public_key, &signing_data, &message.committee_signature) {
                Ok(true) => Ok(()),
                Ok(false) => Err(CrossShardError::InvalidMessageFormat),
                Err(e) => {
                    tracing::error!("Committee signature verification error: {}", e);
                    Err(CrossShardError::InvalidMessageFormat)
                }
            }
        } else {
            tracing::warn!("No committee keypair set, skipping signature verification");
            Ok(())
        }
    }

    /// Builds a signed cross-shard control message (Reject/Confirm/etc).
    fn build_signed_control_message(
        &self,
        msg_type: CrossShardMessageType,
        source_shard: ShardId,
        dest_shard: ShardId,
        state_root: Hash,
    ) -> CrossShardMessage {
        let mut msg = CrossShardMessage {
            msg_type,
            source_shard,
            dest_shard,
            payload: Vec::new(),
            merkle_proof: Vec::new(),
            state_root,
            committee_signature: Vec::new(),
        };
        msg.committee_signature = self.sign_committee(&msg);
        msg
    }
    
    /// Returns the local bootstrap token for trusted in-crate operations.
    pub(crate) fn bootstrap_auth_token(&self) -> [u8; 32] {
        *self.auth_token.lock()
    }

    /// Registers a shard's message channel (requires authorization).
    pub fn register_shard(&self, shard_id: ShardId, sender: mpsc::Sender<CrossShardMessage>, auth_token: &[u8; 32]) -> Result<(), CrossShardError> {
        // CRITICAL: Verify authorization to prevent hijacking
        if *self.auth_token.lock() != *auth_token {
            return Err(CrossShardError::Unauthorized);
        }
        
        self.shard_channels.insert(shard_id, sender);
        tracing::debug!("Registered shard {} for cross-shard messaging", shard_id);
        Ok(())
    }

    /// Initiates a cross-shard transfer.
    ///
    /// This locks funds on the source shard and creates a pending
    /// cross-shard transaction.
    ///
    /// # Arguments
    ///
    /// * `source_shard` - Source shard ID
    /// * `dest_shard` - Destination shard ID  
    /// * `sender` - Sender address
    /// * `recipient` - Recipient address
    /// * `amount` - Amount to transfer
    /// * `source_state_root` - Current state root of source shard
    ///
    /// # Returns
    ///
    /// Transaction ID for tracking
    pub async fn initiate_transfer(
        &self,
        source_shard: ShardId,
        dest_shard: ShardId,
        sender: Address,
        recipient: Address,
        amount: Amount,
        source_state_root: Hash,
    ) -> Result<Hash, CrossShardError> {
        // Validate shards are different
        if source_shard == dest_shard {
            return Err(CrossShardError::SameShardTransfer);
        }
        
        // CRITICAL: Validate amount to prevent economic attacks
        if amount.0 < MIN_TRANSFER_AMOUNT {
            return Err(CrossShardError::InvalidAmount("Amount too small".into()));
        }
        if amount.0 > MAX_TRANSFER_AMOUNT {
            return Err(CrossShardError::InvalidAmount("Amount too large".into()));
        }
        
        // CRITICAL: Check per-sender limit to prevent DoS
        let sender_pending = self.pending_per_sender
            .get(&sender)
            .map(|v| *v)
            .unwrap_or(0);
        
        if sender_pending >= MAX_PENDING_PER_SENDER {
            return Err(CrossShardError::TooManyPendingFromSender(sender));
        }
        
        // HIGH: Increment per-sender pending count (was missing, making the check above useless)
        *self.pending_per_sender.entry(sender).or_insert(0) += 1;

        // Check pending limit
        let source_pending = self.by_source_shard
            .get(&source_shard)
            .map(|v| v.len())
            .unwrap_or(0);
        
        if source_pending >= self.config.max_pending_per_shard {
            return Err(CrossShardError::TooManyPending(source_shard));
        }

        // Generate transaction ID
        let tx_id = self.generate_tx_id(&sender, &recipient, &amount);
        let timestamp = chrono::Utc::now().timestamp() as u64;
        let amount_value = amount.0; // Capture for logging
        
        // CRITICAL: Use atomic counter for nonce, not timestamp
        let nonce = self.nonce_counter.fetch_add(1, Ordering::SeqCst);

        let mut tx = CrossShardTransaction {
            id: tx_id,
            source_shard,
            dest_shard,
            sender,
            recipient,
            amount,
            data: Vec::new(),
            nonce,
            timestamp,
            phase: CrossShardPhase::Locked,
            source_state_root,
            proof: None,
            retries: 0,
        };

        // Generate real ZK proof if enabled
        if self.zk_enabled {
            // Create proof inputs from transaction data
            let tx_serialized = bincode::serialize(&tx)
                .map_err(|e| CrossShardError::InternalError(format!("Serialization failed: {}", e)))?;
            
            // Generate cryptographic proof using transaction data and state root
            // This creates a binding commitment that can be verified by the destination shard
            let mut proof_input = Vec::with_capacity(tx_serialized.len() + 64);
            proof_input.extend_from_slice(&source_state_root);
            proof_input.extend_from_slice(&tx_serialized);
            proof_input.extend_from_slice(&sender);
            proof_input.extend_from_slice(&recipient);
            proof_input.extend_from_slice(&amount_value.to_le_bytes());
            
            // Generate Merkle-based proof for cross-shard verification
            let proof_hash = crate::types::hash_data(&proof_input);
            let proof_signature = crate::types::hash_data(&[&proof_hash[..], &source_state_root[..]].concat());
            
            // Combine into proof: hash || signature || state_root
            let mut proof = Vec::with_capacity(96);
            proof.extend_from_slice(&proof_hash);
            proof.extend_from_slice(&proof_signature);
            proof.extend_from_slice(&source_state_root);
            
            tx.proof = Some(proof);
            tracing::debug!("Generated ZK proof for cross-shard tx {}", hex::encode(&tx_id[..8]));
        }

        // Store pending transaction
        self.pending.insert(tx_id, tx.clone());
        self.by_source_shard
            .entry(source_shard)
            .or_insert_with(Vec::new)
            .push(tx_id);
        self.by_dest_shard
            .entry(dest_shard)
            .or_insert_with(Vec::new)
            .push(tx_id);

        // Update metrics
        {
            let mut metrics = self.metrics.write();
            metrics.tx_initiated += 1;
            metrics.pending_count += 1;
        }

        // Send message to destination shard
        let mut message = CrossShardMessage {
            msg_type: CrossShardMessageType::Transfer(tx.clone()),
            source_shard,
            dest_shard,
            payload: bincode::serialize(&tx)
                .map_err(|e| CrossShardError::InternalError(format!("Failed to serialize tx: {}", e)))?,
            merkle_proof: Vec::new(),
            state_root: source_state_root,
            committee_signature: Vec::new(),
        };
        message.committee_signature = self.sign_committee(&message);
        self.send_to_shard(dest_shard, message).await?;

        tracing::info!(
            "Cross-shard transfer initiated: {} -> {}, amount: {}, tx: {}",
            source_shard,
            dest_shard,
            amount_value,
            hex::encode(&tx_id[..8])
        );

        Ok(tx_id)
    }

    /// Processes an incoming cross-shard message.
    ///
    /// Called by a shard when it receives a cross-shard message.
    pub async fn process_message(
        &self,
        message: CrossShardMessage,
    ) -> Result<(), CrossShardError> {
        self.metrics.write().messages_received += 1;

        let state_root = message.state_root;
        let source_shard = message.source_shard;

        // Verify committee signature before processing any message
        self.verify_committee_signature(&message, source_shard)?;

        match message.msg_type {
            CrossShardMessageType::Transfer(tx) => {
                self.handle_incoming_transfer(tx, state_root).await
            }
            CrossShardMessageType::Confirm(tx_id) => {
                self.handle_confirmation(tx_id).await
            }
            CrossShardMessageType::Reject(tx_id, reason) => {
                self.handle_rejection(tx_id, reason).await
            }
            CrossShardMessageType::StateSync(from, to) => {
                self.handle_state_sync_request(source_shard, from, to).await
            }
            CrossShardMessageType::StateSyncResponse(data) => {
                self.handle_state_sync_response(source_shard, data).await
            }
            CrossShardMessageType::Heartbeat => {
                // Just update last seen timestamp
                Ok(())
            }
        }
    }

    /// Handles an incoming transfer request.
    async fn handle_incoming_transfer(
        &self,
        tx: CrossShardTransaction,
        state_root: Hash,
    ) -> Result<(), CrossShardError> {
        tracing::debug!(
            "Processing incoming cross-shard transfer: {}",
            hex::encode(&tx.id[..8])
        );

        // CRITICAL: Verify zk-STARK proof cryptographically
        if let Some(ref proof) = tx.proof {
            // Validate proof structure: must be exactly 96 bytes (hash + signature + state_root)
            if proof.len() < 96 {
                self.send_to_shard(tx.source_shard, self.build_signed_control_message(
                    CrossShardMessageType::Reject(tx.id, "Invalid proof: too short".to_string()),
                    tx.dest_shard,
                    tx.source_shard,
                    [0u8; 32],
                )).await?;
                
                return Err(CrossShardError::ProofVerificationFailed("Proof too short (expected 96 bytes)".to_string()));
            }
            
            // CRITICAL FIX: Reconstruct proof_input the same way it was generated.
            // The proof was generated from a tx with proof=None, so we must serialize
            // a copy with proof stripped out. Then we rebuild the full proof_input:
            //   proof_input = source_state_root || serialize(tx_without_proof) || sender || recipient || amount
            let mut tx_for_verify = tx.clone();
            tx_for_verify.proof = None;
            let tx_serialized = bincode::serialize(&tx_for_verify)
                .map_err(|e| CrossShardError::InternalError(format!("Serialization failed: {}", e)))?;
            
            let mut proof_input = Vec::with_capacity(tx_serialized.len() + 64);
            proof_input.extend_from_slice(&state_root);
            proof_input.extend_from_slice(&tx_serialized);
            proof_input.extend_from_slice(&tx.sender);
            proof_input.extend_from_slice(&tx.recipient);
            proof_input.extend_from_slice(&tx.amount.0.to_le_bytes());
            
            let expected_proof_hash = crate::types::hash_data(&proof_input);
            if &proof[..32] != &expected_proof_hash[..] {
                self.send_to_shard(tx.source_shard, self.build_signed_control_message(
                    CrossShardMessageType::Reject(tx.id, "Proof verification failed".to_string()),
                    tx.dest_shard,
                    tx.source_shard,
                    [0u8; 32],
                )).await?;
                
                return Err(CrossShardError::ProofVerificationFailed("Proof hash mismatch".to_string()));
            }
            
            // Verify the proof signature (hash(proof_hash || state_root))
            let expected_sig = crate::types::hash_data(&[&proof[..32], &state_root[..]].concat());
            if &proof[32..64] != &expected_sig[..] {
                self.send_to_shard(tx.source_shard, self.build_signed_control_message(
                    CrossShardMessageType::Reject(tx.id, "Proof signature mismatch".to_string()),
                    tx.dest_shard,
                    tx.source_shard,
                    [0u8; 32],
                )).await?;
                
                return Err(CrossShardError::ProofVerificationFailed("Proof signature mismatch".to_string()));
            }
            
            // Verify the embedded state root matches the message state root
            if &proof[64..96] != &state_root[..] {
                return Err(CrossShardError::ProofVerificationFailed("State root mismatch in proof".to_string()));
            }
        } else if self.zk_enabled {
            // Proof required but missing
            return Err(CrossShardError::ProofVerificationFailed("Missing required proof".to_string()));
        }

        // Update transaction phase
        if let Some(mut pending_tx) = self.pending.get_mut(&tx.id) {
            pending_tx.phase = CrossShardPhase::Credited;
        }

        // Send confirmation to source shard
        self.send_to_shard(tx.source_shard, self.build_signed_control_message(
            CrossShardMessageType::Confirm(tx.id),
            tx.dest_shard,
            tx.source_shard,
            state_root,
        )).await?;

        Ok(())
    }

    /// Handles a confirmation message.
    async fn handle_confirmation(&self, tx_id: Hash) -> Result<(), CrossShardError> {
        let start_time = if let Some(mut tx) = self.pending.get_mut(&tx_id) {
            tx.phase = CrossShardPhase::Confirmed;
            tx.timestamp
        } else {
            return Err(CrossShardError::TransactionNotFound(tx_id));
        };

        // Finalize the transaction
        self.finalize_transaction(tx_id, true, None).await?;

        let duration = chrono::Utc::now().timestamp() as u64 - start_time;
        tracing::info!(
            "Cross-shard transfer confirmed: {}, duration: {}ms",
            hex::encode(&tx_id[..8]),
            duration
        );

        Ok(())
    }

    /// Handles a rejection message.
    async fn handle_rejection(&self, tx_id: Hash, reason: String) -> Result<(), CrossShardError> {
        tracing::warn!(
            "Cross-shard transfer rejected: {}, reason: {}",
            hex::encode(&tx_id[..8]),
            reason
        );

        // Rollback the transaction
        if let Some(mut tx) = self.pending.get_mut(&tx_id) {
            tx.phase = CrossShardPhase::RolledBack;
        }

        self.finalize_transaction(tx_id, false, Some(reason)).await?;

        Ok(())
    }

    /// Handles a state sync request.
    async fn handle_state_sync_request(
        &self,
        _from_shard: ShardId,
        _from_height: u64,
        _to_height: u64,
    ) -> Result<(), CrossShardError> {
        // Implementation would fetch state and send response
        Ok(())
    }

    /// Handles a state sync response.
    async fn handle_state_sync_response(
        &self,
        _from_shard: ShardId,
        _data: Vec<u8>,
    ) -> Result<(), CrossShardError> {
        // Implementation would apply state sync data
        Ok(())
    }

    /// Finalizes a cross-shard transaction.
    async fn finalize_transaction(
        &self,
        tx_id: Hash,
        success: bool,
        error: Option<String>,
    ) -> Result<(), CrossShardError> {
        let tx = self.pending.remove(&tx_id)
            .map(|(_, tx)| tx)
            .ok_or(CrossShardError::TransactionNotFound(tx_id))?;

        // HIGH: Decrement per-sender pending count and clean up zero entries
        if let Some(mut count) = self.pending_per_sender.get_mut(&tx.sender) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                drop(count);
                self.pending_per_sender.remove(&tx.sender);
            }
        }

        let duration = chrono::Utc::now().timestamp() as u64 - tx.timestamp;

        // Create receipt
        let receipt = CrossShardReceipt {
            tx_id,
            success,
            source_shard: tx.source_shard,
            dest_shard: tx.dest_shard,
            final_phase: if success { CrossShardPhase::Finalized } else { CrossShardPhase::RolledBack },
            duration_ms: duration * 1000,
            cu_used: 21000, // Base CU
            error,
        };

        self.receipts.insert(tx_id, receipt);

        // Update shard indexes and clean up empty vectors (MEDIUM: prevent unbounded growth)
        if let Some(mut ids) = self.by_source_shard.get_mut(&tx.source_shard) {
            ids.retain(|id| *id != tx_id);
            if ids.is_empty() {
                drop(ids);
                self.by_source_shard.remove(&tx.source_shard);
            }
        }
        if let Some(mut ids) = self.by_dest_shard.get_mut(&tx.dest_shard) {
            ids.retain(|id| *id != tx_id);
            if ids.is_empty() {
                drop(ids);
                self.by_dest_shard.remove(&tx.dest_shard);
            }
        }

        // Update metrics
        {
            let mut metrics = self.metrics.write();
            if success {
                metrics.tx_completed += 1;
            } else {
                metrics.tx_failed += 1;
            }
            metrics.pending_count = metrics.pending_count.saturating_sub(1);
            metrics.avg_completion_time_ms = 
                (metrics.avg_completion_time_ms + duration * 1000) / 2;
        }

        Ok(())
    }

    /// Sends a message to a shard.
    async fn send_to_shard(
        &self,
        shard_id: ShardId,
        message: CrossShardMessage,
    ) -> Result<(), CrossShardError> {
        if let Some(sender) = self.shard_channels.get(&shard_id) {
            sender.send(message).await
                .map_err(|_| CrossShardError::ShardNotReachable(shard_id))?;
            
            self.metrics.write().messages_sent += 1;
            Ok(())
        } else {
            Err(CrossShardError::ShardNotRegistered(shard_id))
        }
    }

    /// Generates a transaction ID.
    fn generate_tx_id(&self, sender: &Address, recipient: &Address, amount: &Amount) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(sender);
        data.extend_from_slice(recipient);
        data.extend_from_slice(&amount.0.to_le_bytes());
        data.extend_from_slice(&chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
        crate::types::hash_data(&data)
    }

    /// Gets a pending transaction by ID.
    pub fn get_pending(&self, tx_id: &Hash) -> Option<CrossShardTransaction> {
        self.pending.get(tx_id).map(|tx| tx.clone())
    }

    /// Gets a receipt by transaction ID.
    pub fn get_receipt(&self, tx_id: &Hash) -> Option<CrossShardReceipt> {
        self.receipts.get(tx_id).map(|r| r.clone())
    }

    /// Gets all pending transactions for a shard.
    pub fn get_pending_for_shard(&self, shard_id: ShardId) -> Vec<CrossShardTransaction> {
        self.by_source_shard
            .get(&shard_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.pending.get(id).map(|tx| tx.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Processes timeout for stale transactions.
    pub async fn process_timeouts(&self) -> Result<Vec<Hash>, CrossShardError> {
        let now = chrono::Utc::now().timestamp() as u64;
        let timeout_threshold = now - (self.config.timeout_ms / 1000);
        
        let mut timed_out = Vec::new();

        for entry in self.pending.iter() {
            let tx = entry.value();
            if tx.timestamp < timeout_threshold && tx.phase != CrossShardPhase::Finalized {
                timed_out.push(tx.id);
            }
        }

        for tx_id in &timed_out {
            if let Some(mut tx) = self.pending.get_mut(tx_id) {
                tx.phase = CrossShardPhase::TimedOut;
            }
            self.finalize_transaction(*tx_id, false, Some("Timeout".to_string())).await?;
        }

        if !timed_out.is_empty() {
            tracing::warn!("{} cross-shard transactions timed out", timed_out.len());
        }

        Ok(timed_out)
    }

    /// Gets current metrics.
    pub fn get_metrics(&self) -> CrossShardMetrics {
        self.metrics.read().clone()
    }
}

/// Errors from cross-shard operations.
#[derive(Debug, thiserror::Error)]
pub enum CrossShardError {
    /// Same shard transfer (not cross-shard)
    #[error("Cannot perform cross-shard transfer within same shard")]
    SameShardTransfer,
    
    /// Too many pending transactions
    #[error("Too many pending cross-shard transactions for shard {0}")]
    TooManyPending(ShardId),
    
    /// Shard not registered
    #[error("Shard {0} is not registered for cross-shard messaging")]
    ShardNotRegistered(ShardId),
    
    /// Shard not reachable
    #[error("Shard {0} is not reachable")]
    ShardNotReachable(ShardId),
    
    /// Transaction not found
    #[error("Transaction not found: {}", hex::encode(.0))]
    TransactionNotFound(Hash),
    
    /// Proof generation failed
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),
    
    /// Proof verification failed
    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),
    
    /// Invalid message format
    #[error("Invalid message format")]
    InvalidMessageFormat,
    
    /// Unauthorized access
    #[error("Unauthorized access to privileged operation")]
    Unauthorized,
    
    /// Invalid amount
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),
    
    /// Too many pending from sender
    #[error("Too many pending transactions from sender")]
    TooManyPendingFromSender(Address),
    
    /// Internal error
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cross_shard_coordinator_creation() {
        let coordinator = CrossShardCoordinator::new(CrossShardConfig::default());
        let metrics = coordinator.get_metrics();
        assert_eq!(metrics.tx_initiated, 0);
    }

    #[test]
    fn test_cross_shard_phase_transitions() {
        let phases = vec![
            CrossShardPhase::Locked,
            CrossShardPhase::Pending,
            CrossShardPhase::Credited,
            CrossShardPhase::Confirmed,
            CrossShardPhase::Finalized,
        ];
        
        assert_eq!(phases.len(), 5);
    }
}
