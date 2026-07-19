//! # Quantos Sidechain System
//!
//! This module implements Quantos's sidechain architecture, enabling
//! application-specific chains that inherit security from the main chain.
//!
//! ## Overview
//!
//! Sidechains in Quantos provide:
//! - **Shared Security**: Validators from L1 secure sidechains
//! - **Custom Runtimes**: Application-specific execution environments
//! - **Asset Bridging**: Secure cross-chain asset transfers
//! - **Independent Throughput**: Each sidechain has its own capacity
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      Quantos L1                             │
//! │  ┌─────────────────────────────────────────────────────┐   │
//! │  │              Sidechain Registry                      │   │
//! │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐            │   │
//! │  │  │ Chain A  │ │ Chain B  │ │ Chain C  │ ...        │   │
//! │  │  │ (DeFi)   │ │ (Gaming) │ │ (NFT)    │            │   │
//! │  │  └────┬─────┘ └────┬─────┘ └────┬─────┘            │   │
//! │  │       │            │            │                   │   │
//! │  │       └────────────┼────────────┘                   │   │
//! │  │                    │                                │   │
//! │  │          ┌─────────▼─────────┐                     │   │
//! │  │          │   Bridge Layer    │                     │   │
//! │  │          │  (Asset Locking)  │                     │   │
//! │  │          └───────────────────┘                     │   │
//! │  └─────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Security Model
//!
//! Sidechains use a **Proof of Stake Bridge** model:
//! 1. L1 validators stake on sidechain participation
//! 2. State commitments posted to L1 every epoch
//! 3. Fraud proofs enable challenges within dispute window
//! 4. Slashing for malicious sidechain operators

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use dashmap::DashMap;
use parking_lot::{RwLock, Mutex};
use serde::{Deserialize, Serialize};
use rand::RngCore;
use rand::rngs::OsRng;

use crate::types::{Address, Amount, Hash};

/// Maximum commitments to store per sidechain
const MAX_COMMITMENTS_PER_SIDECHAIN: usize = 10_000;
/// Maximum completed transfers to store
const MAX_COMPLETED_TRANSFERS: usize = 100_000;
/// Minimum registration stake required
const MIN_REGISTRATION_STAKE: u128 = 100_000_000_000_000_000_000; // 100 tokens
/// Minimum block time in ms
const MIN_BLOCK_TIME_MS: u64 = 100;
/// Maximum custom params length
const MAX_CUSTOM_PARAMS_LEN: usize = 4096;
/// HIGH: Maximum operators per sidechain to prevent memory exhaustion
const MAX_OPERATORS_PER_SIDECHAIN: usize = 200;
/// MEDIUM: Maximum sidechain name length
const MAX_SIDECHAIN_NAME_LEN: usize = 128;
/// HIGH: Maximum slash count before operator is deactivated
const MAX_SLASH_COUNT: u32 = 3;

/// Unique identifier for a sidechain.
pub type SidechainId = [u8; 8];

/// Configuration for a sidechain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SidechainConfig {
    /// Unique sidechain identifier
    pub id: SidechainId,
    
    /// Human-readable name
    pub name: String,
    
    /// Sidechain description
    pub description: String,
    
    /// Block time in milliseconds
    pub block_time_ms: u64,
    
    /// Maximum transactions per block
    pub max_tx_per_block: usize,
    
    /// Minimum stake required to operate
    pub min_operator_stake: Amount,
    
    /// Number of operators required
    pub required_operators: usize,
    
    /// Commitment interval (blocks between L1 checkpoints)
    pub commitment_interval: u64,
    
    /// Dispute window in L1 blocks
    pub dispute_window: u64,
    
    /// Whether the sidechain is currently active
    pub active: bool,
    
    /// Genesis timestamp
    pub genesis_timestamp: u64,
    
    /// Chain-specific parameters (JSON)
    pub custom_params: String,
}

impl Default for SidechainConfig {
    fn default() -> Self {
        Self {
            id: [0u8; 8],
            name: "Unnamed Sidechain".to_string(),
            description: String::new(),
            block_time_ms: 1000,
            max_tx_per_block: 10_000,
            min_operator_stake: Amount(1_000_000_000_000_000_000), // 1 token
            required_operators: 5,
            commitment_interval: 100,
            dispute_window: 1000,
            active: false,
            genesis_timestamp: 0,
            custom_params: "{}".to_string(),
        }
    }
}

/// Manages all registered sidechains.
///
/// The `SidechainRegistry` is the central component for sidechain
/// management on the Quantos L1.
///
/// # Example
///
/// ```rust,ignore
/// let registry = SidechainRegistry::new(1000);
///
/// // Register a new sidechain
/// let config = SidechainConfig {
///     name: "DeFi Chain".to_string(),
///     ..Default::default()
/// };
/// let id = registry.register(config, creator_address)?;
///
/// // Get sidechain info
/// let info = registry.get_sidechain(&id)?;
/// ```
pub struct SidechainRegistry {
    /// Maximum number of sidechains allowed
    max_sidechains: usize,
    
    /// Registered sidechains
    sidechains: Arc<DashMap<SidechainId, Sidechain>>,
    
    /// Sidechain operators (sidechain_id -> operators)
    operators: Arc<DashMap<SidechainId, Vec<SidechainOperator>>>,
    
    /// Bridge contract addresses
    bridges: Arc<DashMap<SidechainId, BridgeInfo>>,
    
    /// State commitments from sidechains
    commitments: Arc<DashMap<SidechainId, Vec<StateCommitment>>>,
    
    /// Authorization token for privileged operations
    auth_token: Arc<Mutex<[u8; 32]>>,
    
    /// Nonce counter for unique ID generation
    nonce_counter: Arc<AtomicU64>,
    
    /// Registration stakes (required for spam prevention)
    registration_stakes: Arc<DashMap<Address, Amount>>,
}

/// Represents a registered sidechain.
#[derive(Clone, Debug)]
pub struct Sidechain {
    /// Configuration
    pub config: SidechainConfig,
    
    /// Creator address
    pub creator: Address,
    
    /// Registration timestamp
    pub registered_at: u64,
    
    /// Current state root
    pub state_root: Hash,
    
    /// Latest block height on sidechain
    pub latest_height: u64,
    
    /// Total value locked (TVL) in the bridge
    pub total_locked: Amount,
    
    /// Number of active users
    pub active_users: u64,
}

/// A sidechain operator (validator).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SidechainOperator {
    /// Operator address
    pub address: Address,
    
    /// Stake amount
    pub stake: Amount,
    
    /// Operator public key for signing
    pub public_key: Vec<u8>,
    
    /// Whether currently active
    pub active: bool,
    
    /// Slash count
    pub slash_count: u32,
    
    /// Registration timestamp
    pub registered_at: u64,
}

/// Bridge information for a sidechain.
#[derive(Clone, Debug)]
pub struct BridgeInfo {
    /// Bridge contract address on L1
    pub l1_address: Address,
    
    /// Bridge contract address on sidechain
    pub sidechain_address: Address,
    
    /// Supported asset types
    pub supported_assets: Vec<AssetType>,
    
    /// Total value locked
    pub total_locked: Amount,
    
    /// Pending withdrawals count
    pub pending_withdrawals: u64,
}

/// Type of asset supported by the bridge.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AssetType {
    /// Native Quantos token
    Native,
    /// Fungible token
    Token { address: Address },
    /// Non-fungible token
    NFT { address: Address },
}

/// State commitment from a sidechain to L1.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateCommitment {
    /// Sidechain block height
    pub height: u64,
    
    /// State root hash
    pub state_root: Hash,
    
    /// Transaction root hash
    pub tx_root: Hash,
    
    /// Operator signatures
    pub signatures: Vec<OperatorSignature>,
    
    /// Timestamp
    pub timestamp: u64,
    
    /// L1 block where this was submitted
    pub l1_block: u64,
}

/// Signature from a sidechain operator.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorSignature {
    /// Operator address
    pub operator: Address,
    
    /// ML-DSA-65 signature
    pub signature: Vec<u8>,
}

impl SidechainRegistry {
    /// Creates a new sidechain registry.
    ///
    /// # Arguments
    ///
    /// * `max_sidechains` - Maximum number of sidechains allowed
    pub fn new(max_sidechains: usize) -> Self {
        // HIGH: Use OsRng for cryptographically secure authorization token
        let mut token = [0u8; 32];
        OsRng.fill_bytes(&mut token);
        
        Self {
            max_sidechains,
            sidechains: Arc::new(DashMap::new()),
            operators: Arc::new(DashMap::new()),
            bridges: Arc::new(DashMap::new()),
            commitments: Arc::new(DashMap::new()),
            auth_token: Arc::new(Mutex::new(token)),
            nonce_counter: Arc::new(AtomicU64::new(1)),
            registration_stakes: Arc::new(DashMap::new()),
        }
    }
    
    /// Returns the local bootstrap token for trusted in-crate operations.
    pub(crate) fn bootstrap_auth_token(&self) -> [u8; 32] {
        *self.auth_token.lock()
    }
    
    /// Deposits stake for sidechain registration
    pub fn deposit_registration_stake(&self, creator: Address, amount: Amount) {
        self.registration_stakes
            .entry(creator)
            .and_modify(|a| a.0 += amount.0)
            .or_insert(amount);
    }
    
    /// Registers a new sidechain.
    ///
    /// # Arguments
    ///
    /// * `config` - Sidechain configuration
    /// * `creator` - Address of the creator
    ///
    /// # Returns
    ///
    /// The sidechain ID if registration succeeds
    pub fn register(
        &self,
        mut config: SidechainConfig,
        creator: Address,
    ) -> Result<SidechainId, SidechainError> {
        // Check max sidechains
        if self.sidechains.len() >= self.max_sidechains {
            return Err(SidechainError::MaxSidechainsReached(self.max_sidechains));
        }
        
        // CRITICAL: Verify registration stake to prevent spam
        let stake = self.registration_stakes.get(&creator)
            .map(|s| s.0)
            .unwrap_or(0);
        if stake < MIN_REGISTRATION_STAKE {
            return Err(SidechainError::InsufficientRegistrationStake);
        }
        
        // MEDIUM: Validate sidechain name to prevent registry pollution
        if config.name.is_empty() {
            return Err(SidechainError::InvalidConfig("name cannot be empty".into()));
        }
        if config.name.len() > MAX_SIDECHAIN_NAME_LEN {
            return Err(SidechainError::InvalidConfig(
                format!("name too long ({} > {} bytes)", config.name.len(), MAX_SIDECHAIN_NAME_LEN)
            ));
        }
        if !config.name.chars().all(|c| c.is_alphanumeric() || c == ' ' || c == '-' || c == '_' || c == '.') {
            return Err(SidechainError::InvalidConfig(
                "name contains invalid characters (only alphanumeric, space, dash, underscore, dot allowed)".into()
            ));
        }
        
        // CRITICAL: Validate configuration parameters
        if config.block_time_ms < MIN_BLOCK_TIME_MS {
            return Err(SidechainError::InvalidConfig("block_time_ms too small".into()));
        }
        if config.max_tx_per_block == 0 {
            return Err(SidechainError::InvalidConfig("max_tx_per_block cannot be zero".into()));
        }
        if config.dispute_window == 0 {
            return Err(SidechainError::InvalidConfig("dispute_window cannot be zero".into()));
        }
        if config.required_operators == 0 {
            return Err(SidechainError::InvalidConfig("required_operators cannot be zero".into()));
        }
        if config.custom_params.len() > MAX_CUSTOM_PARAMS_LEN {
            return Err(SidechainError::InvalidConfig("custom_params too large".into()));
        }
        // Validate custom_params is valid JSON
        if !config.custom_params.is_empty() && serde_json::from_str::<serde_json::Value>(&config.custom_params).is_err() {
            return Err(SidechainError::InvalidConfig("custom_params is not valid JSON".into()));
        }
        
        // Generate unique ID with full hash
        let id = self.generate_id(&config.name, &creator);
        config.id = id;
        config.genesis_timestamp = chrono::Utc::now().timestamp() as u64;
        
        // Check if ID already exists
        if self.sidechains.contains_key(&id) {
            return Err(SidechainError::AlreadyExists(id));
        }
        
        let sidechain = Sidechain {
            config,
            creator,
            registered_at: chrono::Utc::now().timestamp() as u64,
            state_root: [0u8; 32],
            latest_height: 0,
            total_locked: Amount::zero(),
            active_users: 0,
        };
        
        self.sidechains.insert(id, sidechain);
        self.operators.insert(id, Vec::new());
        
        tracing::info!(
            "Registered new sidechain: {} ({})",
            hex::encode(&id),
            self.sidechains.get(&id).map(|s| s.config.name.clone()).unwrap_or_default()
        );
        
        Ok(id)
    }
    
    /// Generates a unique sidechain ID using atomic nonce.
    /// 
    /// MEDIUM: Uses OsRng for entropy and includes timestamp + nonce + random
    /// to minimize collision probability in the 8-byte ID space.
    fn generate_id(&self, name: &str, creator: &Address) -> SidechainId {
        let mut data = Vec::new();
        data.extend_from_slice(name.as_bytes());
        data.extend_from_slice(creator);
        // CRITICAL: Use atomic nonce instead of timestamp to prevent collisions
        let nonce = self.nonce_counter.fetch_add(1, Ordering::SeqCst);
        data.extend_from_slice(&nonce.to_le_bytes());
        // MEDIUM: Use OsRng for cryptographically secure random bytes
        let mut random_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut random_bytes);
        data.extend_from_slice(&random_bytes);
        // Include timestamp for additional uniqueness
        let ts = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        data.extend_from_slice(&ts.to_le_bytes());
        
        let hash = crate::types::hash_data(&data);
        let mut id = [0u8; 8];
        id.copy_from_slice(&hash[0..8]);
        id
    }
    
    /// Registers an operator for a sidechain.
    /// 
    /// # Arguments
    /// * `sidechain_id` - The sidechain to register for
    /// * `operator` - The operator to register
    /// * `caller` - The address calling this function (must be sidechain creator or operator itself)
    /// * `operator_signature` - Signature proving operator consent
    pub fn register_operator(
        &self,
        sidechain_id: &SidechainId,
        operator: SidechainOperator,
        caller: &Address,
        operator_signature: &[u8],
    ) -> Result<(), SidechainError> {
        let sidechain = self.sidechains.get(sidechain_id)
            .ok_or(SidechainError::NotFound(*sidechain_id))?;
        
        // CRITICAL FIX (u2): Only the sidechain creator can register operators.
        // Previously the operator could register themselves, breaking the intended
        // authorization model where the creator controls who becomes an operator.
        if caller != &sidechain.creator {
            return Err(SidechainError::Unauthorized);
        }
        
        // CRITICAL: Verify operator signed their consent to being registered
        if operator_signature.is_empty() || operator_signature.len() < 64 {
            return Err(SidechainError::InvalidSignature("Operator consent signature required".into()));
        }
        
        // Verify signature matches operator's public key
        let message = format!("register_operator:{}:{}", hex::encode(sidechain_id), hex::encode(&operator.address));
        match crate::crypto::verify_ml_dsa_65(&operator.public_key, message.as_bytes(), operator_signature) {
            Ok(true) => {},
            _ => return Err(SidechainError::InvalidSignature("Operator signature verification failed".into())),
        }
        
        // Check minimum stake
        if operator.stake.0 < sidechain.config.min_operator_stake.0 {
            return Err(SidechainError::InsufficientStake);
        }
        
        // Check operator not already registered
        if let Some(ops) = self.operators.get(sidechain_id) {
            if ops.iter().any(|o| o.address == operator.address) {
                return Err(SidechainError::OperatorAlreadyRegistered);
            }
            // HIGH (u3): Cap operator count to prevent memory exhaustion
            if ops.len() >= MAX_OPERATORS_PER_SIDECHAIN {
                return Err(SidechainError::MaxOperatorsReached);
            }
        }
        
        // Add operator
        self.operators
            .entry(*sidechain_id)
            .or_insert_with(Vec::new)
            .push(operator);
        
        // Activate sidechain if enough operators (with lock)
        drop(sidechain);
        self.check_activation(sidechain_id);
        
        Ok(())
    }
    
    /// Checks if a sidechain has enough operators to activate.
    /// Uses atomic operations to prevent race conditions.
    fn check_activation(&self, sidechain_id: &SidechainId) {
        // CRITICAL: Get exclusive lock on sidechain first to prevent race conditions
        if let Some(mut sidechain) = self.sidechains.get_mut(sidechain_id) {
            // Now get operators while holding the sidechain lock
            if let Some(operators) = self.operators.get(sidechain_id) {
                let active_count = operators.iter().filter(|o| o.active).count();
                
                if active_count >= sidechain.config.required_operators {
                    if !sidechain.config.active {
                        sidechain.config.active = true;
                        tracing::info!(
                            "Sidechain {} activated with {} operators",
                            hex::encode(sidechain_id),
                            active_count
                        );
                    }
                }
            }
        }
    }
    
    /// Submits a state commitment from a sidechain.
    pub fn submit_commitment(
        &self,
        sidechain_id: &SidechainId,
        commitment: StateCommitment,
    ) -> Result<(), SidechainError> {
        let mut sidechain = self.sidechains.get_mut(sidechain_id)
            .ok_or(SidechainError::NotFound(*sidechain_id))?;
        
        // Get operators
        let operators = self.operators.get(sidechain_id)
            .ok_or(SidechainError::NotFound(*sidechain_id))?;
        
        // HIGH (u6): Require minimum operators before accepting commitments.
        // With empty operator list, (0 * 2) / 3 + 1 = 1, allowing single-sig bypass.
        if operators.is_empty() {
            return Err(SidechainError::InsufficientOperators);
        }
        let active_operators = operators.iter().filter(|o| o.active).count();
        if active_operators < sidechain.config.required_operators {
            return Err(SidechainError::InsufficientOperators);
        }
        
        // Check signature count (use active operator count for threshold)
        let required_sigs = (active_operators * 2) / 3 + 1;
        if commitment.signatures.len() < required_sigs {
            return Err(SidechainError::InsufficientSignatures {
                required: required_sigs,
                got: commitment.signatures.len(),
            });
        }
        
        // CRITICAL: Verify each signature cryptographically
        let commitment_message = self.build_commitment_message(sidechain_id, &commitment);
        let mut valid_signatures = 0;
        
        for sig in &commitment.signatures {
            // Find the operator
            let operator = operators.iter()
                .find(|o| o.address == sig.operator && o.active);
            
            match operator {
                Some(op) => {
                    // Verify the signature using operator's public key
                    if sig.signature.len() < 64 {
                        tracing::warn!("Invalid signature length from operator {}", hex::encode(&sig.operator[..4]));
                        continue;
                    }
                    
                    match crate::crypto::verify_ml_dsa_65(&op.public_key, &commitment_message, &sig.signature) {
                        Ok(true) => valid_signatures += 1,
                        _ => tracing::warn!("Invalid signature from operator {}", hex::encode(&sig.operator[..4])),
                    }
                }
                None => {
                    tracing::warn!("Signature from unknown/inactive operator {}", hex::encode(&sig.operator[..4]));
                }
            }
        }
        
        // Check we have enough valid signatures
        if valid_signatures < required_sigs {
            return Err(SidechainError::InsufficientSignatures {
                required: required_sigs,
                got: valid_signatures,
            });
        }
        
        // Update sidechain state
        sidechain.state_root = commitment.state_root;
        sidechain.latest_height = commitment.height;
        
        // Store commitment with bounded storage
        {
            let mut commits = self.commitments
                .entry(*sidechain_id)
                .or_insert_with(Vec::new);
            
            // CRITICAL: Limit storage to prevent memory exhaustion
            if commits.len() >= MAX_COMMITMENTS_PER_SIDECHAIN {
                commits.remove(0);
            }
            commits.push(commitment);
        }
        
        Ok(())
    }
    
    /// Builds the message to sign for a commitment.
    /// 
    /// HIGH (u8): Now includes sidechain_id and l1_block to prevent replay attacks
    /// across sidechains or with old commitments.
    fn build_commitment_message(&self, sidechain_id: &SidechainId, commitment: &StateCommitment) -> Vec<u8> {
        let mut message = Vec::new();
        // HIGH: Include sidechain_id to prevent cross-sidechain replay
        message.extend_from_slice(sidechain_id);
        message.extend_from_slice(&commitment.height.to_le_bytes());
        message.extend_from_slice(&commitment.state_root);
        message.extend_from_slice(&commitment.tx_root);
        message.extend_from_slice(&commitment.timestamp.to_le_bytes());
        // HIGH: Include l1_block to prevent temporal replay
        message.extend_from_slice(&commitment.l1_block.to_le_bytes());
        message
    }
    
    /// HIGH (u7): Slashes an operator for malicious behavior.
    /// Increments slash_count and deactivates if threshold exceeded.
    pub fn slash_operator(
        &self,
        sidechain_id: &SidechainId,
        operator_address: &Address,
        auth_token: &[u8; 32],
        reason: &str,
    ) -> Result<(), SidechainError> {
        // Verify authorization
        if *self.auth_token.lock() != *auth_token {
            return Err(SidechainError::Unauthorized);
        }
        
        let mut operators = self.operators.get_mut(sidechain_id)
            .ok_or(SidechainError::NotFound(*sidechain_id))?;
        
        let operator = operators.iter_mut()
            .find(|o| &o.address == operator_address)
            .ok_or(SidechainError::OperatorNotFound)?;
        
        operator.slash_count += 1;
        tracing::warn!(
            "Operator {} slashed on sidechain {} (count: {}, reason: {})",
            hex::encode(&operator_address[..4]),
            hex::encode(sidechain_id),
            operator.slash_count,
            reason
        );
        
        // Deactivate if exceeds threshold
        if operator.slash_count >= MAX_SLASH_COUNT {
            operator.active = false;
            tracing::warn!(
                "Operator {} deactivated after {} slashes",
                hex::encode(&operator_address[..4]),
                operator.slash_count
            );
        }
        
        Ok(())
    }
    
    /// Gets a sidechain by ID.
    pub fn get_sidechain(&self, id: &SidechainId) -> Option<Sidechain> {
        self.sidechains.get(id).map(|s| s.clone())
    }
    
    /// Gets all registered sidechains.
    pub fn get_all_sidechains(&self) -> Vec<Sidechain> {
        self.sidechains.iter().map(|s| s.clone()).collect()
    }
    
    /// Gets operators for a sidechain.
    pub fn get_operators(&self, id: &SidechainId) -> Vec<SidechainOperator> {
        self.operators.get(id).map(|o| o.clone()).unwrap_or_default()
    }
    
    /// Gets the total number of registered sidechains.
    pub fn count(&self) -> usize {
        self.sidechains.len()
    }
    
    /// Gets the number of active sidechains.
    pub fn active_count(&self) -> usize {
        self.sidechains.iter().filter(|s| s.config.active).count()
    }
}

/// Bridge for transferring assets between L1 and sidechains.
///
/// The `SidechainBridge` manages asset locking on L1 and
/// corresponding minting on sidechains.
pub struct SidechainBridge {
    registry: Arc<SidechainRegistry>,
    
    /// Pending deposits (L1 -> Sidechain)
    pending_deposits: Arc<DashMap<Hash, PendingDeposit>>,
    
    /// Pending withdrawals (Sidechain -> L1)
    pending_withdrawals: Arc<DashMap<Hash, PendingWithdrawal>>,
    
    /// Completed transfers
    completed_transfers: Arc<RwLock<Vec<CompletedTransfer>>>,
    
    /// Locked assets per sidechain (escrow)
    locked_assets: Arc<DashMap<SidechainId, DashMap<Address, Amount>>>,
    
    /// Atomic nonce counter for transfer IDs
    transfer_nonce: Arc<AtomicU64>,
}

/// A pending deposit from L1 to a sidechain.
#[derive(Clone, Debug)]
pub struct PendingDeposit {
    /// Unique deposit ID
    pub id: Hash,
    
    /// Target sidechain
    pub sidechain_id: SidechainId,
    
    /// Sender on L1
    pub sender: Address,
    
    /// Recipient on sidechain
    pub recipient: Address,
    
    /// Amount to transfer
    pub amount: Amount,
    
    /// Asset type
    pub asset: AssetType,
    
    /// L1 transaction hash
    pub l1_tx_hash: Hash,
    
    /// Timestamp
    pub timestamp: u64,
    
    /// Status
    pub status: TransferStatus,
}

/// A pending withdrawal from sidechain to L1.
#[derive(Clone, Debug)]
pub struct PendingWithdrawal {
    /// Unique withdrawal ID
    pub id: Hash,
    
    /// Source sidechain
    pub sidechain_id: SidechainId,
    
    /// Sender on sidechain
    pub sender: Address,
    
    /// Recipient on L1
    pub recipient: Address,
    
    /// Amount to transfer
    pub amount: Amount,
    
    /// Asset type
    pub asset: AssetType,
    
    /// Sidechain transaction hash
    pub sidechain_tx_hash: Hash,
    
    /// Timestamp
    pub timestamp: u64,
    
    /// Status
    pub status: TransferStatus,
    
    /// Dispute deadline (L1 block number)
    pub dispute_deadline: u64,
}

/// Status of a cross-chain transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransferStatus {
    /// Pending confirmation
    Pending,
    /// Confirmed, waiting for dispute window
    Confirmed,
    /// Completed successfully
    Completed,
    /// Disputed
    Disputed,
    /// Failed
    Failed(String),
}

/// A completed cross-chain transfer.
#[derive(Clone, Debug)]
pub struct CompletedTransfer {
    /// Transfer ID
    pub id: Hash,
    
    /// Direction
    pub direction: TransferDirection,
    
    /// Amount
    pub amount: Amount,
    
    /// Completion timestamp
    pub completed_at: u64,
}

/// Direction of a cross-chain transfer.
#[derive(Clone, Debug)]
pub enum TransferDirection {
    /// L1 to sidechain
    Deposit { sidechain_id: SidechainId },
    /// Sidechain to L1
    Withdrawal { sidechain_id: SidechainId },
}

impl SidechainBridge {
    /// Creates a new sidechain bridge.
    pub fn new(registry: Arc<SidechainRegistry>) -> Self {
        Self {
            registry,
            pending_deposits: Arc::new(DashMap::new()),
            pending_withdrawals: Arc::new(DashMap::new()),
            completed_transfers: Arc::new(RwLock::new(Vec::new())),
            locked_assets: Arc::new(DashMap::new()),
            transfer_nonce: Arc::new(AtomicU64::new(1)),
        }
    }
    
    /// Locks assets in escrow (must be called before deposit)
    /// 
    /// HIGH (u4): Uses checked_add to prevent integer overflow in release builds.
    pub fn lock_assets(&self, sidechain_id: SidechainId, sender: Address, amount: Amount) -> Result<(), SidechainError> {
        let amount_value = amount.0;
        
        // HIGH: Use checked arithmetic to prevent overflow
        let sidechain_map = self.locked_assets
            .entry(sidechain_id)
            .or_insert_with(DashMap::new);
        
        let mut entry = sidechain_map.entry(sender).or_insert(Amount(0));
        entry.0 = entry.0.checked_add(amount_value)
            .ok_or(SidechainError::ArithmeticOverflow)?;
        
        tracing::info!("Locked {} assets for {} on sidechain {}", amount_value, hex::encode(&sender[..4]), hex::encode(&sidechain_id));
        Ok(())
    }
    
    /// Unlocks assets from escrow (for withdrawal completion)
    pub fn unlock_assets(&self, sidechain_id: SidechainId, recipient: Address, amount: Amount) -> Result<(), SidechainError> {
        let sidechain_assets = self.locked_assets.get(&sidechain_id)
            .ok_or(SidechainError::InsufficientLockedAssets)?;
        
        let mut locked = sidechain_assets.get_mut(&recipient)
            .ok_or(SidechainError::InsufficientLockedAssets)?;
        
        if locked.0 < amount.0 {
            return Err(SidechainError::InsufficientLockedAssets);
        }
        
        locked.0 -= amount.0;
        Ok(())
    }
    
    /// Initiates a deposit from L1 to a sidechain.
    ///
    /// This locks assets on L1 and creates a pending deposit
    /// that will be minted on the sidechain.
    pub fn initiate_deposit(
        &self,
        sidechain_id: SidechainId,
        sender: Address,
        recipient: Address,
        amount: Amount,
        asset: AssetType,
        l1_tx_hash: Hash,
    ) -> Result<Hash, SidechainError> {
        // Verify sidechain exists and is active
        let sidechain = self.registry.get_sidechain(&sidechain_id)
            .ok_or(SidechainError::NotFound(sidechain_id))?;
        
        if !sidechain.config.active {
            return Err(SidechainError::SidechainInactive(sidechain_id));
        }
        
        // CRITICAL: Verify assets are locked in escrow
        let sidechain_assets = self.locked_assets.get(&sidechain_id)
            .ok_or(SidechainError::AssetsNotLocked)?;
        
        let sender_locked = sidechain_assets.get(&sender)
            .map(|a| a.0)
            .unwrap_or(0);
        
        if sender_locked < amount.0 {
            return Err(SidechainError::InsufficientLockedAssets);
        }
        
        // Deduct from locked assets
        if let Some(mut locked) = sidechain_assets.get_mut(&sender) {
            locked.0 -= amount.0;
        }
        
        // Generate deposit ID with atomic nonce
        let id = self.generate_transfer_id(&sender, &recipient, &amount);
        let amount_value = amount.0;
        
        let deposit = PendingDeposit {
            id,
            sidechain_id,
            sender,
            recipient,
            amount,
            asset,
            l1_tx_hash,
            timestamp: chrono::Utc::now().timestamp() as u64,
            status: TransferStatus::Pending,
        };
        
        self.pending_deposits.insert(id, deposit);
        
        tracing::info!(
            "Deposit initiated: {} -> sidechain {}, amount: {}",
            hex::encode(&sender[..4]),
            hex::encode(&sidechain_id),
            amount_value
        );
        
        Ok(id)
    }
    
    /// Initiates a withdrawal from a sidechain to L1.
    pub fn initiate_withdrawal(
        &self,
        sidechain_id: SidechainId,
        sender: Address,
        recipient: Address,
        amount: Amount,
        asset: AssetType,
        sidechain_tx_hash: Hash,
        current_l1_block: u64,
    ) -> Result<Hash, SidechainError> {
        let sidechain = self.registry.get_sidechain(&sidechain_id)
            .ok_or(SidechainError::NotFound(sidechain_id))?;
        
        let id = self.generate_transfer_id(&sender, &recipient, &amount);
        
        // CRITICAL: Use checked arithmetic for dispute deadline
        let dispute_deadline = current_l1_block
            .checked_add(sidechain.config.dispute_window)
            .ok_or(SidechainError::ArithmeticOverflow)?;
        
        let withdrawal = PendingWithdrawal {
            id,
            sidechain_id,
            sender,
            recipient,
            amount,
            asset,
            sidechain_tx_hash,
            timestamp: chrono::Utc::now().timestamp() as u64,
            status: TransferStatus::Pending,
            dispute_deadline,
        };
        
        self.pending_withdrawals.insert(id, withdrawal);
        
        Ok(id)
    }
    
    /// Generates a transfer ID using atomic nonce (not timestamp).
    fn generate_transfer_id(&self, sender: &Address, recipient: &Address, amount: &Amount) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(sender);
        data.extend_from_slice(recipient);
        data.extend_from_slice(&amount.0.to_le_bytes());
        // CRITICAL: Use atomic nonce instead of timestamp to prevent collisions
        let nonce = self.transfer_nonce.fetch_add(1, Ordering::SeqCst);
        data.extend_from_slice(&nonce.to_le_bytes());
        // Use OsRng for cryptographically secure random bytes
        let mut random = [0u8; 16];
        OsRng.fill_bytes(&mut random);
        data.extend_from_slice(&random);
        crate::types::hash_data(&data)
    }
    
    /// Completes a deposit (called by sidechain operators).
    pub fn complete_deposit(&self, deposit_id: &Hash) -> Result<(), SidechainError> {
        if let Some((_, mut deposit)) = self.pending_deposits.remove(deposit_id) {
            deposit.status = TransferStatus::Completed;
            
            // CRITICAL: Bound completed transfers storage
            {
                let mut transfers = self.completed_transfers.write();
                if transfers.len() >= MAX_COMPLETED_TRANSFERS {
                    transfers.remove(0);
                }
                transfers.push(CompletedTransfer {
                    id: deposit.id,
                    direction: TransferDirection::Deposit { sidechain_id: deposit.sidechain_id },
                    amount: deposit.amount,
                    completed_at: chrono::Utc::now().timestamp() as u64,
                });
            }
            
            Ok(())
        } else {
            Err(SidechainError::TransferNotFound(*deposit_id))
        }
    }
    
    /// CRITICAL (u1): Fails a deposit and restores locked assets.
    /// 
    /// Without this, if a deposit fails on the sidechain side, the L1 assets
    /// deducted in initiate_deposit are permanently lost from escrow.
    pub fn fail_deposit(&self, deposit_id: &Hash) -> Result<(), SidechainError> {
        if let Some((_, mut deposit)) = self.pending_deposits.remove(deposit_id) {
            // Restore assets back to locked escrow
            let sidechain_id = deposit.sidechain_id;
            let sender = deposit.sender;
            let amount_value = deposit.amount.0;
            
            self.lock_assets(sidechain_id, sender, Amount(amount_value))?;
            
            deposit.status = TransferStatus::Failed("Deposit failed on sidechain".to_string());
            
            tracing::warn!(
                "Deposit {} failed, restored {} assets to escrow for {}",
                hex::encode(&deposit_id[..8]),
                amount_value,
                hex::encode(&sender[..4])
            );
            
            Ok(())
        } else {
            Err(SidechainError::TransferNotFound(*deposit_id))
        }
    }
    
    /// Finalizes a withdrawal after dispute window.
    /// 
    /// HIGH (u5): Fixed race condition — now checks dispute deadline BEFORE removing
    /// from the map, preventing TOCTOU where another thread could process the same
    /// withdrawal between remove and re-insert.
    pub fn finalize_withdrawal(&self, withdrawal_id: &Hash, current_l1_block: u64) -> Result<(), SidechainError> {
        // HIGH: Check dispute deadline BEFORE removing to prevent race condition
        {
            let withdrawal = self.pending_withdrawals.get(withdrawal_id)
                .ok_or(SidechainError::TransferNotFound(*withdrawal_id))?;
            if current_l1_block < withdrawal.dispute_deadline {
                return Err(SidechainError::DisputeWindowActive);
            }
        }
        
        // Now safe to remove — we know the dispute window has passed
        let (_, withdrawal) = self.pending_withdrawals.remove(withdrawal_id)
            .ok_or(SidechainError::TransferNotFound(*withdrawal_id))?;
        
        // CRITICAL: Actually unlock assets on L1
        let sidechain_id = withdrawal.sidechain_id;
        let recipient = withdrawal.recipient;
        let amount_to_unlock = Amount(withdrawal.amount.0);
        self.unlock_assets(sidechain_id, recipient, amount_to_unlock)?;
        
        // CRITICAL: Bound completed transfers storage
        {
            let mut transfers = self.completed_transfers.write();
            if transfers.len() >= MAX_COMPLETED_TRANSFERS {
                transfers.remove(0);
            }
            transfers.push(CompletedTransfer {
                id: withdrawal.id,
                direction: TransferDirection::Withdrawal { sidechain_id },
                amount: Amount(withdrawal.amount.0),
                completed_at: chrono::Utc::now().timestamp() as u64,
            });
        }
        
        Ok(())
    }
    
    /// Gets pending deposits for a sidechain.
    pub fn get_pending_deposits(&self, sidechain_id: &SidechainId) -> Vec<PendingDeposit> {
        self.pending_deposits.iter()
            .filter(|d| &d.sidechain_id == sidechain_id)
            .map(|d| d.clone())
            .collect()
    }
    
    /// Gets pending withdrawals for a sidechain.
    pub fn get_pending_withdrawals(&self, sidechain_id: &SidechainId) -> Vec<PendingWithdrawal> {
        self.pending_withdrawals.iter()
            .filter(|w| &w.sidechain_id == sidechain_id)
            .map(|w| w.clone())
            .collect()
    }
}

/// Errors from the sidechain system.
#[derive(Debug, thiserror::Error)]
pub enum SidechainError {
    /// Maximum sidechains reached
    #[error("Maximum sidechains ({0}) reached")]
    MaxSidechainsReached(usize),
    
    /// Sidechain already exists
    #[error("Sidechain already exists: {}", hex::encode(.0))]
    AlreadyExists(SidechainId),
    
    /// Sidechain not found
    #[error("Sidechain not found: {}", hex::encode(.0))]
    NotFound(SidechainId),
    
    /// Sidechain is inactive
    #[error("Sidechain is inactive: {}", hex::encode(.0))]
    SidechainInactive(SidechainId),
    
    /// Insufficient stake
    #[error("Insufficient stake for operator")]
    InsufficientStake,
    
    /// Insufficient signatures
    #[error("Insufficient signatures: required {required}, got {got}")]
    InsufficientSignatures { required: usize, got: usize },
    
    /// Transfer not found
    #[error("Transfer not found: {}", hex::encode(.0))]
    TransferNotFound(Hash),
    
    /// Dispute window still active
    #[error("Dispute window still active")]
    DisputeWindowActive,
    
    /// Unauthorized access
    #[error("Unauthorized access")]
    Unauthorized,
    
    /// Invalid signature
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    
    /// Operator already registered
    #[error("Operator already registered")]
    OperatorAlreadyRegistered,
    
    /// Maximum operators reached
    #[error("Maximum operators per sidechain reached")]
    MaxOperatorsReached,
    
    /// Insufficient operators
    #[error("Insufficient active operators for this operation")]
    InsufficientOperators,
    
    /// Operator not found
    #[error("Operator not found")]
    OperatorNotFound,
    
    /// Insufficient registration stake
    #[error("Insufficient registration stake (minimum 100 tokens required)")]
    InsufficientRegistrationStake,
    
    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    
    /// Assets not locked
    #[error("Assets not locked in escrow")]
    AssetsNotLocked,
    
    /// Insufficient locked assets
    #[error("Insufficient locked assets")]
    InsufficientLockedAssets,
    
    /// Arithmetic overflow
    #[error("Arithmetic overflow in calculation")]
    ArithmeticOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sidechain_registration() {
        let registry = SidechainRegistry::new(100);
        
        let config = SidechainConfig {
            name: "Test Chain".to_string(),
            ..Default::default()
        };
        
        let creator = [1u8; 32];
        let id = registry.register(config, creator).unwrap();
        
        assert!(registry.get_sidechain(&id).is_some());
        assert_eq!(registry.count(), 1);
    }
    
    #[test]
    fn test_max_sidechains() {
        let registry = SidechainRegistry::new(2);
        
        for i in 0..2 {
            let config = SidechainConfig {
                name: format!("Chain {}", i),
                ..Default::default()
            };
            registry.register(config, [i as u8; 32]).unwrap();
        }
        
        let config = SidechainConfig {
            name: "Too Many".to_string(),
            ..Default::default()
        };
        
        assert!(matches!(
            registry.register(config, [99u8; 32]),
            Err(SidechainError::MaxSidechainsReached(_))
        ));
    }
}
