//! # Atomic Swap RPC API
//!
//! Production RPC endpoints for cross-shard atomic operations using CSAP.

use std::collections::HashSet;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::consensus::{QuantosConsensus, ShardOperation, AtomicStatus};
use crate::types::{Hash, ShardId, SignedTransaction};

/// Maximum valid shard ID (must match NodeConfig.num_shards upper bound)
const MAX_SHARD_ID: u16 = 10_000;

type RpcResult<T> = Result<T, RpcError>;

#[derive(Debug)]
pub struct RpcError {
    message: String,
}

impl RpcError {
    pub fn invalid_params(msg: &str) -> Self {
        Self { message: msg.to_string() }
    }
    
    pub fn internal_error_with_data(msg: &str, _data: serde_json::Value) -> Self {
        Self { message: msg.to_string() }
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for RpcError {}

/// Atomic swap RPC handler
pub struct AtomicSwapHandler {
    consensus: Arc<QuantosConsensus>,
}

impl AtomicSwapHandler {
    pub fn new(consensus: Arc<QuantosConsensus>) -> Self {
        Self { consensus }
    }

    /// Submits an atomic cross-shard operation
    ///
    /// Example request:
    /// ```json
    /// {
    ///   "operations": [
    ///     {
    ///       "shard_id": 0,
    ///       "transactions": [...],
    ///       "expected_state_root": "0x..."
    ///     },
    ///     {
    ///       "shard_id": 1,
    ///       "transactions": [...],
    ///       "expected_state_root": "0x..."
    ///     }
    ///   ]
    /// }
    /// ```
    pub async fn submit_atomic_operation(
        &self,
        request: AtomicOperationRequest,
    ) -> RpcResult<AtomicOperationResponse> {
        // Validate request
        if request.operations.is_empty() {
            return Err(RpcError::invalid_params("Operations cannot be empty"));
        }

        if request.operations.len() > 8 {
            return Err(RpcError::invalid_params("Too many operations (max 8)"));
        }

        // HIGH: Validate shard IDs are unique and within valid range
        let mut seen_shards: HashSet<ShardId> = HashSet::new();
        for op in &request.operations {
            if op.shard_id >= MAX_SHARD_ID {
                return Err(RpcError::invalid_params(
                    &format!("Invalid shard ID {}: must be < {}", op.shard_id, MAX_SHARD_ID)
                ));
            }
            if !seen_shards.insert(op.shard_id) {
                return Err(RpcError::invalid_params(
                    &format!("Duplicate shard ID {} in atomic operation", op.shard_id)
                ));
            }
            // HIGH: Validate each transaction in the operation
            if op.transactions.is_empty() {
                return Err(RpcError::invalid_params(
                    &format!("Shard {} has no transactions", op.shard_id)
                ));
            }
            for (i, tx) in op.transactions.iter().enumerate() {
                // Validate transaction has a signature
                if tx.transaction.signature.is_empty() {
                    return Err(RpcError::invalid_params(
                        &format!("Shard {} tx {}: missing signature", op.shard_id, i)
                    ));
                }
                // Validate transaction has a public key
                if tx.transaction.public_key.is_empty() {
                    return Err(RpcError::invalid_params(
                        &format!("Shard {} tx {}: missing public key", op.shard_id, i)
                    ));
                }
                // Verify the signature is valid
                let signing_data = tx.transaction.signing_data();
                match crate::crypto::verify_ml_dsa_65(
                    &tx.transaction.public_key,
                    &signing_data,
                    &tx.transaction.signature,
                ) {
                    Ok(true) => {},
                    Ok(false) => {
                        return Err(RpcError::invalid_params(
                            &format!("Shard {} tx {}: invalid signature", op.shard_id, i)
                        ));
                    }
                    Err(e) => {
                        return Err(RpcError::invalid_params(
                            &format!("Shard {} tx {}: signature verification error: {:?}", op.shard_id, i, e)
                        ));
                    }
                }
            }
        }

        // Convert to internal format
        let mut operations = Vec::new();
        for op in request.operations {
            let state_root = hex_to_hash(&op.expected_state_root)?;
            operations.push(ShardOperation {
                shard_id: op.shard_id,
                transactions: op.transactions,
                expected_state_root: state_root,
            });
        }

        // Execute atomic operation
        let result = self.consensus
            .execute_atomic_swap(operations)
            .await
            .map_err(|e| RpcError::internal_error_with_data(
                "Atomic operation failed",
                serde_json::to_value(e.to_string()).unwrap_or_else(|_| serde_json::Value::Null)
            ))?;

        Ok(AtomicOperationResponse {
            atomic_id: format!("0x{}", hex::encode(&result.atomic_id)),
            success: result.success,
            committed_shards: result.committed_shards,
        })
    }

    /// Gets the status of an atomic operation
    pub fn get_atomic_status(
        &self,
        atomic_id: String,
    ) -> RpcResult<AtomicStatusResponse> {
        let hash = hex_to_hash(&atomic_id)?;
        
        let status = self.consensus
            .get_atomic_status(&hash)
            .ok_or_else(|| RpcError::invalid_params("Atomic operation not found"))?;

        Ok(AtomicStatusResponse {
            atomic_id,
            status: match status {
                AtomicStatus::Preparing => "preparing".to_string(),
                AtomicStatus::Committing => "committing".to_string(),
                AtomicStatus::Committed => "committed".to_string(),
                AtomicStatus::RolledBack => "rolled_back".to_string(),
            },
        })
    }
}

/// Request for atomic operation
#[derive(Debug, Deserialize)]
pub struct AtomicOperationRequest {
    pub operations: Vec<ShardOperationRequest>,
}

#[derive(Debug, Deserialize)]
pub struct ShardOperationRequest {
    pub shard_id: ShardId,
    pub transactions: Vec<SignedTransaction>,
    pub expected_state_root: String,
}

/// Response for atomic operation
#[derive(Debug, Serialize)]
pub struct AtomicOperationResponse {
    pub atomic_id: String,
    pub success: bool,
    pub committed_shards: Vec<ShardId>,
}

/// Status response
#[derive(Debug, Serialize)]
pub struct AtomicStatusResponse {
    pub atomic_id: String,
    pub status: String,
}

fn hex_to_hash(hex: &str) -> RpcResult<Hash> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex)
        .map_err(|_| RpcError::invalid_params("Invalid hex string"))?;
    
    if bytes.len() != 32 {
        return Err(RpcError::invalid_params("Hash must be 32 bytes"));
    }
    
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}
