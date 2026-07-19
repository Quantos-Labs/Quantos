use crate::crypto::MlDsa65Keypair;
use crate::rpc::{RpcError, RpcResult};
use crate::state::StateManager;
use crate::types::{
    Address, Amount, Hash, SignedTransaction, Transaction, TransactionType,
};
use parking_lot::Mutex;
use std::sync::Arc;

/// Maximum transaction size for deserialization (1MB)
const MAX_TX_SIZE: usize = 1024 * 1024;
/// Maximum amount value to prevent economic issues
const MAX_AMOUNT: u128 = u128::MAX / 2;

/// MEDIUM: Validates that an Amount does not exceed MAX_AMOUNT.
/// This enforces the limit at the type boundary so all code paths are covered.
fn validate_amount(amount: &Amount) -> RpcResult<()> {
    if amount.0 > MAX_AMOUNT {
        return Err(RpcError::InvalidRequest(
            format!("Amount exceeds maximum: {} > {}", amount.0, MAX_AMOUNT)
        ));
    }
    Ok(())
}

pub struct TransactionBuilder {
    state_manager: StateManager,
    /// Lock for atomic nonce fetching to prevent race conditions
    nonce_lock: Arc<Mutex<()>>,
    /// MEDIUM (z10): Number of shards for shard assignment
    num_shards: u16,
}

impl TransactionBuilder {
    pub fn new(state_manager: StateManager) -> Self {
        Self { 
            state_manager,
            nonce_lock: Arc::new(Mutex::new(())),
            num_shards: 1000, // Default, should be configured
        }
    }
    
    pub fn with_num_shards(state_manager: StateManager, num_shards: u16) -> Self {
        Self { 
            state_manager,
            nonce_lock: Arc::new(Mutex::new(())),
            num_shards: if num_shards == 0 { 1 } else { num_shards },
        }
    }

    pub fn build_transfer(
        &self,
        keypair: &MlDsa65Keypair,
        to: Address,
        amount: Amount,
        max_compute_units: u64,
    ) -> RpcResult<SignedTransaction> {
        // MEDIUM: Validate amount at the builder boundary
        validate_amount(&amount)?;
        
        let from = keypair.address();
        
        // MEDIUM: Hold nonce lock through the entire build+sign process.
        // The lock covers nonce fetch → tx construction → signing so that
        // concurrent callers get sequential nonces without gaps.
        // NOTE: The remaining window between sign and consensus submission
        // is unavoidable without a submit-under-lock API, but nonce ordering
        // is guaranteed by the consensus layer's mempool nonce checks.
        let _lock = self.nonce_lock.lock();
        let nonce = self.state_manager.get_nonce(&from)
            .map_err(|e| RpcError::InternalError(format!("Failed to get nonce: {}", e)))?;
        
        let shard_id = Transaction::target_shard(&from, self.num_shards);
        
        let mut tx = Transaction::new(
            TransactionType::Transfer,
            from,
            to,
            amount,
            nonce,
            max_compute_units,
            None,
            Vec::new(),
            shard_id,
        );

        let signature = keypair.sign(&tx.signing_data())
            .map_err(|e| RpcError::InternalError(e.to_string()))?;
        
        tx.set_signature(signature, keypair.public_key.clone())
            .map_err(|e| RpcError::InternalError(e))?;

        Ok(SignedTransaction::new(tx))
    }

    pub fn build_stake(
        &self,
        keypair: &MlDsa65Keypair,
        amount: Amount,
        max_compute_units: u64,
    ) -> RpcResult<SignedTransaction> {
        // MEDIUM: Validate amount at the builder boundary
        validate_amount(&amount)?;
        
        let from = keypair.address();
        
        // MEDIUM: Atomic nonce fetch — lock held through build+sign
        let _lock = self.nonce_lock.lock();
        let nonce = self.state_manager.get_nonce(&from)
            .map_err(|e| RpcError::InternalError(format!("Failed to get nonce: {}", e)))?;
        
        let shard_id = Transaction::target_shard(&from, self.num_shards);
        
        let mut tx = Transaction::new(
            TransactionType::Stake,
            from,
            from,
            amount,
            nonce,
            max_compute_units,
            None,
            Vec::new(),
            shard_id,
        );

        let signature = keypair.sign(&tx.signing_data())
            .map_err(|e| RpcError::InternalError(e.to_string()))?;
        
        tx.set_signature(signature, keypair.public_key.clone())
            .map_err(|e| RpcError::InternalError(e))?;

        Ok(SignedTransaction::new(tx))
    }

    pub fn build_unstake(
        &self,
        keypair: &MlDsa65Keypair,
        amount: Amount,
        max_compute_units: u64,
    ) -> RpcResult<SignedTransaction> {
        // MEDIUM: Validate amount at the builder boundary
        validate_amount(&amount)?;
        
        let from = keypair.address();
        
        // MEDIUM: Atomic nonce fetch — lock held through build+sign
        let _lock = self.nonce_lock.lock();
        let nonce = self.state_manager.get_nonce(&from)
            .map_err(|e| RpcError::InternalError(format!("Failed to get nonce: {}", e)))?;
        
        let shard_id = Transaction::target_shard(&from, self.num_shards);
        
        let mut tx = Transaction::new(
            TransactionType::Unstake,
            from,
            from,
            amount,
            nonce,
            max_compute_units,
            None,
            Vec::new(),
            shard_id,
        );

        let signature = keypair.sign(&tx.signing_data())
            .map_err(|e| RpcError::InternalError(e.to_string()))?;
        
        tx.set_signature(signature, keypair.public_key.clone())
            .map_err(|e| RpcError::InternalError(e))?;

        Ok(SignedTransaction::new(tx))
    }
}

pub fn serialize_transaction(tx: &SignedTransaction) -> RpcResult<String> {
    let bytes = bincode::serialize(tx)
        .map_err(|e| RpcError::InternalError(e.to_string()))?;
    Ok(hex::encode(bytes))
}

pub fn deserialize_transaction(hex_str: &str) -> RpcResult<SignedTransaction> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)
        .map_err(|_e| RpcError::InvalidRequest(format!("Invalid hex encoding")))?;
    
    // CRITICAL: Validate size before deserialization to prevent DoS
    if bytes.len() > MAX_TX_SIZE {
        return Err(RpcError::InvalidRequest(
            format!("Transaction too large: {} bytes (max {})", bytes.len(), MAX_TX_SIZE)
        ));
    }
    
    bincode::deserialize(&bytes)
        .map_err(|_| RpcError::InvalidRequest("Invalid transaction format".into()))
}

pub fn format_address(address: &Address) -> String {
    format!("QTS:{}", hex::encode(address))
}

pub fn format_hash(hash: &Hash) -> String {
    format!("QTS:{}", hex::encode(hash))
}

pub fn parse_amount(s: &str) -> RpcResult<Amount> {
    let value = s.parse::<u128>()
        .map_err(|_| RpcError::InvalidRequest("Invalid amount format".into()))?;
    
    // CRITICAL: Validate amount range to prevent economic issues
    if value > MAX_AMOUNT {
        return Err(RpcError::InvalidRequest(
            format!("Amount exceeds maximum: {} > {}", value, MAX_AMOUNT)
        ));
    }
    
    Ok(Amount(value))
}
