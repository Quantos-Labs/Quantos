// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Blob Transactions
//!
//! Temporary data blobs with post-quantum polynomial commitments for data availability.
//! Quantos equivalent of EIP-4844, adapted for DAG consensus and PQ security.
//!
//! ## Features
//!
//! - **PQ Commitments**: STARK-friendly polynomial commitments (not KZG)
//! - **Erasure Coding**: Reed-Solomon for data availability sampling
//! - **TTL-based Pruning**: Blobs expire after configurable epoch count
//! - **Shard-aware**: Blobs routed to appropriate shards
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Blob Transaction                          │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Transaction Header (sender, nonce, gas, shard)             │
//! │  ┌──────────────────────────────────────────────────────┐   │
//! │  │  Blob 0: [data: 128KB] [commitment] [proof]         │   │
//! │  │  Blob 1: [data: 128KB] [commitment] [proof]         │   │
//! │  │  ...up to MAX_BLOBS_PER_TX                           │   │
//! │  └──────────────────────────────────────────────────────┘   │
//! │  Blob commitments stored permanently on-chain               │
//! │  Blob data pruned after TTL_EPOCHS                          │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Commitment Scheme
//!
//! Uses STARK-friendly hash-based polynomial commitments:
//! 1. Split blob into 256-byte field elements
//! 2. Build Merkle tree over elements
//! 3. Root = commitment
//! 4. Proof = Merkle inclusion proof for any element
//!
//! This is post-quantum secure (relies only on hash functions).

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::crypto::sha3_256;
use crate::types::{Address, Hash, ShardId};

/// Maximum blob size: 128 KB (131,072 bytes)
pub const MAX_BLOB_SIZE: usize = 131_072;

/// Maximum blobs per transaction
pub const MAX_BLOBS_PER_TX: usize = 6;

/// Field element size for polynomial commitment (256 bytes)
const FIELD_ELEMENT_SIZE: usize = 256;

/// Number of field elements per blob (128KB / 256 = 512)
const ELEMENTS_PER_BLOB: usize = MAX_BLOB_SIZE / FIELD_ELEMENT_SIZE;

/// Default blob TTL in epochs (approximately 18 days at 1 epoch/30min)
const DEFAULT_BLOB_TTL_EPOCHS: u64 = 864;

/// Maximum total blob data per block (768 KB)
pub const MAX_BLOB_DATA_PER_BLOCK: usize = MAX_BLOB_SIZE * MAX_BLOBS_PER_TX;

/// Blob transaction extending the base transaction type.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobTransaction {
    /// Sender address
    pub sender: Address,
    /// Transaction nonce
    pub nonce: u64,
    /// STACC: max compute units for execution
    pub max_compute_units: u64,
    /// Target shard
    pub shard_id: ShardId,
    /// Calldata (contract interaction, if any)
    pub data: Vec<u8>,
    /// Blob sidecar: the actual blob data (NOT stored on-chain permanently)
    pub blobs: Vec<Blob>,
    /// Blob commitments (stored on-chain permanently)
    pub blob_commitments: Vec<BlobCommitment>,
    /// Transaction signature (ML-DSA-65)
    pub signature: Vec<u8>,
    /// Sender public key
    pub public_key: Vec<u8>,
    /// Transaction hash
    pub hash: Hash,
    /// Timestamp
    pub timestamp: u64,
}

/// A single data blob.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Blob {
    /// Raw blob data (up to MAX_BLOB_SIZE bytes)
    pub data: Vec<u8>,
    /// Index within the transaction
    pub index: u8,
}

/// Post-quantum commitment to a blob using STARK-friendly Merkle tree.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlobCommitment {
    /// Merkle root over 256-byte field elements of the blob
    pub root: Hash,
    /// Blob size in bytes
    pub size: u32,
    /// Number of field elements
    pub element_count: u32,
    /// Blob index within transaction
    pub index: u8,
}

/// Proof that a field element is part of a committed blob.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobProof {
    /// Element index within the blob
    pub element_index: u32,
    /// The field element data (256 bytes)
    pub element: Vec<u8>,
    /// Merkle sibling hashes from leaf to root
    pub siblings: Vec<Hash>,
    /// Path bits (0 = left, 1 = right)
    pub path: Vec<u8>,
}

/// Stored blob metadata (kept on-chain after pruning).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobMetadata {
    /// Blob commitment
    pub commitment: BlobCommitment,
    /// Transaction hash that included this blob
    pub tx_hash: Hash,
    /// Block/slot where the blob was included
    pub included_at_slot: u64,
    /// Epoch when the blob expires
    pub expires_at_epoch: u64,
    /// Whether the blob data has been pruned
    pub pruned: bool,
}

/// Configuration for blob transaction handling.
#[derive(Clone, Debug)]
pub struct BlobConfig {
    /// Maximum blob size in bytes
    pub max_blob_size: usize,
    /// Maximum blobs per transaction
    pub max_blobs_per_tx: usize,
    /// Blob TTL in epochs
    pub blob_ttl_epochs: u64,
    /// Maximum total blob data per block
    pub max_blob_data_per_block: usize,
    /// CU cost per blob byte
    pub cu_per_blob_byte: u64,
    /// Base CU cost per blob commitment verification
    pub cu_blob_commitment_verify: u64,
}

impl Default for BlobConfig {
    fn default() -> Self {
        Self {
            max_blob_size: MAX_BLOB_SIZE,
            max_blobs_per_tx: MAX_BLOBS_PER_TX,
            blob_ttl_epochs: DEFAULT_BLOB_TTL_EPOCHS,
            max_blob_data_per_block: MAX_BLOB_DATA_PER_BLOCK,
            cu_per_blob_byte: 1,
            cu_blob_commitment_verify: 10_000,
        }
    }
}

/// Manages blob storage, verification, and pruning.
pub struct BlobManager {
    config: BlobConfig,
    /// Active blobs (not yet pruned): commitment_root -> blob data
    active_blobs: Arc<RwLock<HashMap<Hash, Vec<u8>>>>,
    /// Blob metadata index: commitment_root -> metadata
    metadata: Arc<RwLock<HashMap<Hash, BlobMetadata>>>,
    /// Current epoch
    current_epoch: Arc<RwLock<u64>>,
}

impl BlobManager {
    /// Creates a new blob manager.
    pub fn new(config: BlobConfig) -> Self {
        Self {
            config,
            active_blobs: Arc::new(RwLock::new(HashMap::new())),
            metadata: Arc::new(RwLock::new(HashMap::new())),
            current_epoch: Arc::new(RwLock::new(0)),
        }
    }
    
    /// Validates a blob transaction.
    pub fn validate_blob_tx(&self, tx: &BlobTransaction) -> Result<(), BlobError> {
        // Check blob count
        if tx.blobs.len() > self.config.max_blobs_per_tx {
            return Err(BlobError::TooManyBlobs {
                got: tx.blobs.len(),
                max: self.config.max_blobs_per_tx,
            });
        }
        
        if tx.blobs.is_empty() {
            return Err(BlobError::NoBlobs);
        }
        
        // Commitment count must match blob count
        if tx.blobs.len() != tx.blob_commitments.len() {
            return Err(BlobError::CommitmentMismatch {
                blobs: tx.blobs.len(),
                commitments: tx.blob_commitments.len(),
            });
        }
        
        // Validate each blob
        for (i, blob) in tx.blobs.iter().enumerate() {
            // Size check
            if blob.data.len() > self.config.max_blob_size {
                return Err(BlobError::BlobTooLarge {
                    index: i,
                    size: blob.data.len(),
                    max: self.config.max_blob_size,
                });
            }
            
            if blob.data.is_empty() {
                return Err(BlobError::EmptyBlob { index: i });
            }
            
            // CRITICAL: Verify commitment size matches actual blob size
            // This prevents size manipulation attacks where trailing zeros
            // are stripped during processing to bypass verification
            if tx.blob_commitments[i].size != blob.data.len() as u32 {
                return Err(BlobError::InvalidCommitment { index: i });
            }
            
            // Verify commitment matches blob data
            let expected_commitment = compute_blob_commitment(&blob.data, i as u8);
            if expected_commitment != tx.blob_commitments[i] {
                return Err(BlobError::InvalidCommitment { index: i });
            }
        }
        
        Ok(())
    }
    
    /// Stores blob data after transaction inclusion.
    pub fn store_blobs(
        &self,
        tx: &BlobTransaction,
        slot: u64,
    ) -> Result<Vec<BlobMetadata>, BlobError> {
        let epoch = *self.current_epoch.read();
        let mut stored = Vec::new();
        
        for (i, blob) in tx.blobs.iter().enumerate() {
            let commitment = &tx.blob_commitments[i];
            
            let meta = BlobMetadata {
                commitment: commitment.clone(),
                tx_hash: tx.hash,
                included_at_slot: slot,
                expires_at_epoch: epoch + self.config.blob_ttl_epochs,
                pruned: false,
            };
            
            // Store blob data
            self.active_blobs.write().insert(commitment.root, blob.data.clone());
            self.metadata.write().insert(commitment.root, meta.clone());
            
            stored.push(meta);
        }
        
        Ok(stored)
    }
    
    /// Retrieves blob data by commitment root.
    pub fn get_blob(&self, commitment_root: &Hash) -> Option<Vec<u8>> {
        self.active_blobs.read().get(commitment_root).cloned()
    }
    
    /// Retrieves blob metadata.
    pub fn get_metadata(&self, commitment_root: &Hash) -> Option<BlobMetadata> {
        self.metadata.read().get(commitment_root).cloned()
    }
    
    /// Generates a data availability proof for a specific element.
    pub fn generate_proof(
        &self,
        commitment_root: &Hash,
        element_index: u32,
    ) -> Result<BlobProof, BlobError> {
        let blob_data = self.active_blobs.read()
            .get(commitment_root)
            .cloned()
            .ok_or(BlobError::BlobNotFound)?;
        
        generate_element_proof(&blob_data, element_index)
    }
    
    /// Verifies a data availability proof against a commitment.
    pub fn verify_proof(
        commitment: &BlobCommitment,
        proof: &BlobProof,
    ) -> bool {
        verify_element_proof(commitment, proof)
    }
    
    /// Prunes expired blobs. Called at epoch boundaries.
    pub fn prune_expired(&self, current_epoch: u64) -> usize {
        *self.current_epoch.write() = current_epoch;
        
        let mut to_prune = Vec::new();
        
        // Find expired blobs
        for (root, meta) in self.metadata.read().iter() {
            if !meta.pruned && current_epoch >= meta.expires_at_epoch {
                to_prune.push(*root);
            }
        }
        
        let pruned_count = to_prune.len();
        
        // Remove blob data but keep metadata
        for root in &to_prune {
            self.active_blobs.write().remove(root);
            if let Some(meta) = self.metadata.write().get_mut(root) {
                meta.pruned = true;
            }
        }
        
        if pruned_count > 0 {
            tracing::info!(
                "Pruned {} expired blobs at epoch {}",
                pruned_count,
                current_epoch
            );
        }
        
        pruned_count
    }
    
    /// Returns current blob storage stats.
    pub fn stats(&self) -> BlobStats {
        let active = self.active_blobs.read();
        let meta = self.metadata.read();
        
        BlobStats {
            active_blobs: active.len(),
            total_active_bytes: active.values().map(|b| b.len()).sum(),
            total_metadata_entries: meta.len(),
            pruned_count: meta.values().filter(|m| m.pruned).count(),
        }
    }
    
    /// Sets current epoch (called by consensus).
    pub fn set_epoch(&self, epoch: u64) {
        *self.current_epoch.write() = epoch;
    }
}

/// Blob storage statistics.
#[derive(Debug, Clone)]
pub struct BlobStats {
    pub active_blobs: usize,
    pub total_active_bytes: usize,
    pub total_metadata_entries: usize,
    pub pruned_count: usize,
}

/// Blob-related errors.
#[derive(Debug, Clone)]
pub enum BlobError {
    TooManyBlobs { got: usize, max: usize },
    NoBlobs,
    CommitmentMismatch { blobs: usize, commitments: usize },
    BlobTooLarge { index: usize, size: usize, max: usize },
    EmptyBlob { index: usize },
    InvalidCommitment { index: usize },
    BlobNotFound,
    InvalidProof,
    ElementOutOfRange { index: u32, count: u32 },
}

impl std::fmt::Display for BlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlobError::TooManyBlobs { got, max } => write!(f, "Too many blobs: {} > {}", got, max),
            BlobError::NoBlobs => write!(f, "Blob transaction must contain at least one blob"),
            BlobError::CommitmentMismatch { blobs, commitments } =>
                write!(f, "Blob/commitment count mismatch: {} blobs, {} commitments", blobs, commitments),
            BlobError::BlobTooLarge { index, size, max } =>
                write!(f, "Blob {} too large: {} > {} bytes", index, size, max),
            BlobError::EmptyBlob { index } => write!(f, "Blob {} is empty", index),
            BlobError::InvalidCommitment { index } => write!(f, "Invalid commitment for blob {}", index),
            BlobError::BlobNotFound => write!(f, "Blob data not found (may be pruned)"),
            BlobError::InvalidProof => write!(f, "Invalid data availability proof"),
            BlobError::ElementOutOfRange { index, count } =>
                write!(f, "Element index {} out of range (blob has {} elements)", index, count),
        }
    }
}

// ============================================================================
// Post-Quantum Commitment Scheme (STARK-friendly, hash-based)
// ============================================================================

/// Computes a PQ blob commitment using Merkle tree over field elements.
/// 
/// Includes the original data size in each element hash to bind the commitment
/// to the exact data length. This prevents size manipulation attacks where
/// trailing zeros could be stripped without changing the Merkle root.
pub fn compute_blob_commitment(data: &[u8], index: u8) -> BlobCommitment {
    // Pad data to multiple of FIELD_ELEMENT_SIZE
    let padded_len = ((data.len() + FIELD_ELEMENT_SIZE - 1) / FIELD_ELEMENT_SIZE) * FIELD_ELEMENT_SIZE;
    let mut padded = data.to_vec();
    padded.resize(padded_len, 0);
    
    let element_count = padded_len / FIELD_ELEMENT_SIZE;
    let data_len_bytes = (data.len() as u64).to_le_bytes();
    
    // Hash each field element with the original data length bound in
    // This ensures commitments are unique per exact data size,
    // preventing bypass through trailing-zero manipulation
    let element_hashes: Vec<Hash> = padded
        .chunks(FIELD_ELEMENT_SIZE)
        .map(|chunk| {
            let mut bound = Vec::with_capacity(FIELD_ELEMENT_SIZE + 8);
            bound.extend_from_slice(chunk);
            bound.extend_from_slice(&data_len_bytes);
            sha3_256(&bound)
        })
        .collect();
    
    // Build Merkle tree
    let root = merkle_root_from_hashes(&element_hashes);
    
    BlobCommitment {
        root,
        size: data.len() as u32,
        element_count: element_count as u32,
        index,
    }
}

/// Generates a Merkle inclusion proof for a specific field element.
pub fn generate_element_proof(data: &[u8], element_index: u32) -> Result<BlobProof, BlobError> {
    let padded_len = ((data.len() + FIELD_ELEMENT_SIZE - 1) / FIELD_ELEMENT_SIZE) * FIELD_ELEMENT_SIZE;
    let mut padded = data.to_vec();
    padded.resize(padded_len, 0);
    
    let element_count = padded_len / FIELD_ELEMENT_SIZE;
    
    if element_index as usize >= element_count {
        return Err(BlobError::ElementOutOfRange {
            index: element_index,
            count: element_count as u32,
        });
    }
    
    // Extract the element
    let start = element_index as usize * FIELD_ELEMENT_SIZE;
    let element = padded[start..start + FIELD_ELEMENT_SIZE].to_vec();
    
    // Hash all elements
    let element_hashes: Vec<Hash> = padded
        .chunks(FIELD_ELEMENT_SIZE)
        .map(|chunk| sha3_256(chunk))
        .collect();
    
    // Build Merkle proof
    let mut siblings = Vec::new();
    let mut path = Vec::new();
    let mut level = element_hashes;
    let mut idx = element_index as usize;
    
    while level.len() > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        
        if sibling_idx < level.len() {
            siblings.push(level[sibling_idx]);
        } else {
            siblings.push(level[idx]); // Duplicate for odd tree
        }
        
        path.push(if idx % 2 == 0 { 0 } else { 1 });
        
        // Build next level
        let mut next_level = Vec::new();
        for pair in level.chunks(2) {
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&pair[0]);
            if pair.len() > 1 {
                combined.extend_from_slice(&pair[1]);
            } else {
                combined.extend_from_slice(&pair[0]);
            }
            next_level.push(sha3_256(&combined));
        }
        
        level = next_level;
        idx /= 2;
    }
    
    Ok(BlobProof {
        element_index,
        element,
        siblings,
        path,
    })
}

/// Verifies a data availability proof against a commitment.
pub fn verify_element_proof(commitment: &BlobCommitment, proof: &BlobProof) -> bool {
    if proof.element_index >= commitment.element_count {
        return false;
    }
    
    // Hash the element
    let mut current = sha3_256(&proof.element);
    
    // Walk up the Merkle tree
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if i >= proof.path.len() {
            return false;
        }
        
        let mut combined = Vec::with_capacity(64);
        if proof.path[i] == 0 {
            // Current is left child
            combined.extend_from_slice(&current);
            combined.extend_from_slice(sibling);
        } else {
            // Current is right child
            combined.extend_from_slice(sibling);
            combined.extend_from_slice(&current);
        }
        current = sha3_256(&combined);
    }
    
    current == commitment.root
}

/// Computes Merkle root from leaf hashes.
fn merkle_root_from_hashes(hashes: &[Hash]) -> Hash {
    if hashes.is_empty() {
        return [0u8; 32];
    }
    if hashes.len() == 1 {
        return hashes[0];
    }
    
    let mut level = hashes.to_vec();
    
    while level.len() > 1 {
        let mut next = Vec::new();
        for pair in level.chunks(2) {
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&pair[0]);
            if pair.len() > 1 {
                combined.extend_from_slice(&pair[1]);
            } else {
                combined.extend_from_slice(&pair[0]);
            }
            next.push(sha3_256(&combined));
        }
        level = next;
    }
    
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_blob_commitment() {
        let data = vec![42u8; 1024]; // 1KB blob
        let commitment = compute_blob_commitment(&data, 0);
        
        assert_ne!(commitment.root, [0u8; 32]);
        assert_eq!(commitment.size, 1024);
        assert_eq!(commitment.element_count, 4); // 1024 / 256 = 4
        assert_eq!(commitment.index, 0);
    }
    
    #[test]
    fn test_blob_commitment_deterministic() {
        let data = vec![1u8; 512];
        let c1 = compute_blob_commitment(&data, 0);
        let c2 = compute_blob_commitment(&data, 0);
        assert_eq!(c1, c2);
    }
    
    #[test]
    fn test_proof_generation_and_verification() {
        let data = vec![0xABu8; 2048]; // 2KB = 8 elements
        let commitment = compute_blob_commitment(&data, 0);
        
        // Generate proof for element 3
        let proof = generate_element_proof(&data, 3).unwrap();
        assert_eq!(proof.element_index, 3);
        assert_eq!(proof.element.len(), FIELD_ELEMENT_SIZE);
        
        // Verify
        assert!(verify_element_proof(&commitment, &proof));
    }
    
    #[test]
    fn test_proof_invalid_element_index() {
        let data = vec![0u8; 512]; // 2 elements
        let result = generate_element_proof(&data, 5);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_proof_tampered_element() {
        let data = vec![0xABu8; 1024];
        let commitment = compute_blob_commitment(&data, 0);
        
        let mut proof = generate_element_proof(&data, 0).unwrap();
        proof.element[0] = 0xFF; // Tamper
        
        assert!(!verify_element_proof(&commitment, &proof));
    }
    
    #[test]
    fn test_blob_manager_lifecycle() {
        let config = BlobConfig::default();
        let manager = BlobManager::new(config);
        
        let data = vec![42u8; 1024];
        let commitment = compute_blob_commitment(&data, 0);
        
        let tx = BlobTransaction {
            sender: [1u8; 32],
            nonce: 0,
            max_compute_units: 100_000,
            shard_id: 0,
            data: Vec::new(),
            blobs: vec![Blob { data: data.clone(), index: 0 }],
            blob_commitments: vec![commitment.clone()],
            signature: Vec::new(),
            public_key: Vec::new(),
            hash: [0u8; 32],
            timestamp: 0,
        };
        
        // Validate
        assert!(manager.validate_blob_tx(&tx).is_ok());
        
        // Store
        let stored = manager.store_blobs(&tx, 100).unwrap();
        assert_eq!(stored.len(), 1);
        
        // Retrieve
        let blob = manager.get_blob(&commitment.root).unwrap();
        assert_eq!(blob, data);
        
        // Stats
        let stats = manager.stats();
        assert_eq!(stats.active_blobs, 1);
        assert_eq!(stats.total_active_bytes, 1024);
    }
    
    #[test]
    fn test_blob_pruning() {
        let mut config = BlobConfig::default();
        config.blob_ttl_epochs = 10;
        let manager = BlobManager::new(config);
        
        let data = vec![42u8; 512];
        let commitment = compute_blob_commitment(&data, 0);
        
        let tx = BlobTransaction {
            sender: [1u8; 32],
            nonce: 0,
            max_compute_units: 100_000,
            shard_id: 0,
            data: Vec::new(),
            blobs: vec![Blob { data: data.clone(), index: 0 }],
            blob_commitments: vec![commitment.clone()],
            signature: Vec::new(),
            public_key: Vec::new(),
            hash: [0u8; 32],
            timestamp: 0,
        };
        
        manager.store_blobs(&tx, 100).unwrap();
        
        // Not expired yet
        assert_eq!(manager.prune_expired(5), 0);
        assert!(manager.get_blob(&commitment.root).is_some());
        
        // Expired
        assert_eq!(manager.prune_expired(11), 1);
        assert!(manager.get_blob(&commitment.root).is_none());
        
        // Metadata still available
        let meta = manager.get_metadata(&commitment.root).unwrap();
        assert!(meta.pruned);
    }
    
    #[test]
    fn test_validation_errors() {
        let manager = BlobManager::new(BlobConfig::default());
        
        // No blobs
        let tx = BlobTransaction {
            sender: [1u8; 32],
            nonce: 0,
            max_compute_units: 100_000,
            shard_id: 0,
            data: Vec::new(),
            blobs: vec![],
            blob_commitments: vec![],
            signature: Vec::new(),
            public_key: Vec::new(),
            hash: [0u8; 32],
            timestamp: 0,
        };
        assert!(manager.validate_blob_tx(&tx).is_err());
    }
}
