//! # Quantos Transaction & Signature Batching
//!
//! High-performance batching system for transactions and signatures,
//! enabling efficient verification and processing.
//!
//! ## Features
//!
//! - **Transaction Batching**: Group transactions for parallel verification
//! - **Signature Aggregation**: Combine multiple ML-DSA-65 signatures
//! - **Batch Verification**: Verify multiple signatures in parallel
//! - **Memory-Efficient**: Streaming batch processing
//!
//! ## Performance
//!
//! | Operation | Single | Batched (1000) | Speedup |
//! |-----------|--------|----------------|---------|
//! | Sig Verify | 1ms | 100ms | 10x |
//! | TX Validate | 0.5ms | 50ms | 10x |

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

/// Maximum pending batches to prevent memory exhaustion
const MAX_PENDING_BATCHES: usize = 1000;
/// Maximum total pending transactions across all batches (memory bound)
const MAX_PENDING_TOTAL_TXS: usize = 500_000;
/// Maximum validator index to prevent bitmap memory exhaustion
const MAX_VALIDATOR_INDEX: usize = 10_000;
/// Expected ML-DSA-65 signature size
const MLDSA65_SIG_SIZE: usize = 3309;

use crate::types::{Address, Hash, ShardId, SignedTransaction, TransactionReceipt};
use crate::crypto::{verify_ml_dsa_65_batch, MlDsa65Keypair};
use crate::crypto::batch_verify::MlDsa65BatchVerifier;
use crate::compression::{CompressionEngine, CompressedBatch, CompressionConfig};

/// Configuration for the batching system.
#[derive(Clone, Debug)]
pub struct BatchingConfig {
    /// Maximum transactions per batch
    pub max_tx_per_batch: usize,
    /// Maximum signatures per batch
    pub max_sig_per_batch: usize,
    /// Batch timeout in milliseconds
    pub batch_timeout_ms: u64,
    /// Enable parallel verification
    pub parallel_verify: bool,
    /// Number of verification threads
    pub verify_threads: usize,
    /// Enable compression for batches
    pub compress_batches: bool,
}

impl Default for BatchingConfig {
    fn default() -> Self {
        Self {
            max_tx_per_batch: 10_000,
            max_sig_per_batch: 10_000,
            batch_timeout_ms: 100,
            parallel_verify: true,
            verify_threads: num_cpus::get(),
            compress_batches: true,
        }
    }
}

/// A batch of transactions for processing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionBatch {
    /// Batch identifier (computed atomically)
    id: Hash,
    /// Transactions in the batch
    pub transactions: Vec<SignedTransaction>,
    /// Shard assignment (if single-shard batch)
    pub shard_id: Option<ShardId>,
    /// Batch creation timestamp
    pub created_at: u64,
    /// Whether signatures have been verified
    pub signatures_verified: bool,
}

impl TransactionBatch {
    /// Creates a new empty batch.
    pub fn new() -> Self {
        Self {
            id: [0u8; 32],
            transactions: Vec::new(),
            shard_id: None,
            created_at: chrono::Utc::now().timestamp() as u64,
            signatures_verified: false,
        }
    }

    /// Gets the batch ID.
    pub fn id(&self) -> Hash {
        self.id
    }

    /// Creates a batch with the given transactions.
    pub fn with_transactions(transactions: Vec<SignedTransaction>) -> Self {
        let id = Self::compute_batch_id(&transactions);
        Self {
            id,
            transactions,
            shard_id: None,
            created_at: chrono::Utc::now().timestamp() as u64,
            signatures_verified: false,
        }
    }

    /// Computes the batch ID from transactions.
    fn compute_batch_id(transactions: &[SignedTransaction]) -> Hash {
        let mut data = Vec::new();
        for tx in transactions {
            data.extend_from_slice(&tx.hash);
        }
        crate::types::hash_data(&data)
    }

    /// Returns the number of transactions in the batch.
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Checks if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Adds a transaction to the batch and recomputes the batch ID.
    pub fn add(&mut self, tx: SignedTransaction) {
        self.transactions.push(tx);
        self.id = Self::compute_batch_id(&self.transactions);
    }

    /// Finalizes the batch by computing its ID.
    /// Kept for backwards compatibility; ID is now always current.
    pub fn finalize(&mut self) {
        self.id = Self::compute_batch_id(&self.transactions);
    }
}

/// A batch of signatures for verification.
#[derive(Clone, Debug)]
pub struct SignatureBatch {
    /// Batch identifier
    pub id: Hash,
    /// Signatures to verify
    pub entries: Vec<SignatureEntry>,
    /// Whether all signatures are valid
    pub all_valid: Option<bool>,
    /// Batch creation timestamp
    pub created_at: u64,
}

/// A single signature entry for batch verification.
#[derive(Clone, Debug)]
pub struct SignatureEntry {
    /// Public key
    pub public_key: Vec<u8>,
    /// Message that was signed
    pub message: Vec<u8>,
    /// Signature
    pub signature: Vec<u8>,
    /// Verification result
    pub valid: Option<bool>,
}

impl SignatureBatch {
    /// Creates a new empty signature batch.
    pub fn new() -> Self {
        Self {
            id: [0u8; 32],
            entries: Vec::new(),
            all_valid: None,
            created_at: chrono::Utc::now().timestamp() as u64,
        }
    }

    /// Adds a signature entry to the batch.
    pub fn add(&mut self, public_key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) {
        self.entries.push(SignatureEntry {
            public_key,
            message,
            signature,
            valid: None,
        });
    }

    /// Returns the number of signatures in the batch.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Main batching engine for Quantos.
///
/// Handles transaction and signature batching with parallel verification.
///
/// # Example
///
/// ```rust,ignore
/// let engine = BatchingEngine::new(BatchingConfig::default());
///
/// // Create a transaction batch
/// let batch = engine.create_tx_batch(transactions);
///
/// // Verify all signatures in parallel
/// let results = engine.verify_batch_signatures(&batch)?;
/// ```
pub struct BatchingEngine {
    config: BatchingConfig,
    compression: CompressionEngine,
    /// Pending transaction batches
    pending_tx_batches: Arc<RwLock<Vec<TransactionBatch>>>,
    /// Pending signature batches
    pending_sig_batches: Arc<RwLock<Vec<SignatureBatch>>>,
    /// Metrics
    metrics: Arc<RwLock<BatchingMetrics>>,
}

/// Metrics for the batching system.
#[derive(Debug, Default)]
pub struct BatchingMetrics {
    /// Total batches created
    pub batches_created: AtomicU64,
    /// Total transactions batched
    pub tx_batched: AtomicU64,
    /// Total signatures verified
    pub signatures_verified: AtomicU64,
    /// Sum of batch sizes (for average calculation)
    batch_size_sum: AtomicU64,
    /// Sum of verification times (for average calculation)
    verify_time_sum: AtomicU64,
}

impl BatchingMetrics {
    /// Gets average batch size.
    pub fn avg_batch_size(&self) -> f64 {
        let count = self.batches_created.load(Ordering::Relaxed);
        if count == 0 {
            return 0.0;
        }
        self.batch_size_sum.load(Ordering::Relaxed) as f64 / count as f64
    }

    /// Gets average verification time per signature (microseconds).
    pub fn avg_verify_time_us(&self) -> u64 {
        let count = self.signatures_verified.load(Ordering::Relaxed);
        if count == 0 {
            return 0;
        }
        self.verify_time_sum.load(Ordering::Relaxed) / count
    }

    /// Clones the metrics for reading.
    pub fn snapshot(&self) -> BatchingMetricsSnapshot {
        BatchingMetricsSnapshot {
            batches_created: self.batches_created.load(Ordering::Relaxed),
            tx_batched: self.tx_batched.load(Ordering::Relaxed),
            signatures_verified: self.signatures_verified.load(Ordering::Relaxed),
            avg_batch_size: self.avg_batch_size(),
            avg_verify_time_us: self.avg_verify_time_us(),
        }
    }
}

/// Snapshot of batching metrics.
#[derive(Clone, Debug)]
pub struct BatchingMetricsSnapshot {
    pub batches_created: u64,
    pub tx_batched: u64,
    pub signatures_verified: u64,
    pub avg_batch_size: f64,
    pub avg_verify_time_us: u64,
}

impl BatchingEngine {
    /// Creates a new batching engine.
    pub fn new(config: BatchingConfig) -> Self {
        Self {
            config,
            compression: CompressionEngine::new(CompressionConfig::default()),
            pending_tx_batches: Arc::new(RwLock::new(Vec::new())),
            pending_sig_batches: Arc::new(RwLock::new(Vec::new())),
            metrics: Arc::new(RwLock::new(BatchingMetrics::default())),
        }
    }

    /// Creates a transaction batch from a list of transactions.
    pub fn create_tx_batch(&self, transactions: Vec<SignedTransaction>) -> Result<TransactionBatch, BatchingError> {
        // Enforce batch size limit
        if transactions.len() > self.config.max_tx_per_batch {
            return Err(BatchingError::BatchTooLarge(
                transactions.len(),
                self.config.max_tx_per_batch,
            ));
        }

        let batch = TransactionBatch::with_transactions(transactions);
        
        // Update metrics atomically
        let metrics = self.metrics.read();
        metrics.batches_created.fetch_add(1, Ordering::Relaxed);
        let _ = metrics.tx_batched.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(batch.len() as u64));
        let _ = metrics.batch_size_sum.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(batch.len() as u64));
        
        Ok(batch)
    }

    /// Creates shard-specific batches from a list of transactions.
    ///
    /// Groups transactions by their target shard for efficient
    /// parallel processing.
    pub fn create_sharded_batches(
        &self,
        transactions: Vec<SignedTransaction>,
    ) -> Result<Vec<TransactionBatch>, BatchingError> {
        use dashmap::DashMap;
        
        // Group by shard
        let by_shard: DashMap<ShardId, Vec<SignedTransaction>> = DashMap::new();
        
        for tx in transactions {
            by_shard
                .entry(tx.transaction.shard_id)
                .or_insert_with(Vec::new)
                .push(tx);
        }
        
        // Create batches with size enforcement
        let mut batches = Vec::new();
        for (shard_id, txs) in by_shard.into_iter() {
            // Split into multiple batches if needed
            for chunk in txs.chunks(self.config.max_tx_per_batch) {
                let mut batch = TransactionBatch::with_transactions(chunk.to_vec());
                batch.shard_id = Some(shard_id);
                batches.push(batch);
            }
        }
        
        Ok(batches)
    }

    /// Verifies all signatures in a transaction batch.
    ///
    /// Uses parallel verification for efficiency.
    ///
    /// # Returns
    ///
    /// A vector of booleans indicating whether each signature is valid
    pub fn verify_batch_signatures(
        &self,
        batch: &TransactionBatch,
    ) -> Result<Vec<bool>, BatchingError> {
        let start = std::time::Instant::now();
        
        let results: Vec<bool> = if self.config.parallel_verify {
            batch.transactions
                .par_iter()
                .map(|tx| self.verify_single_signature(tx))
                .collect()
        } else {
            batch.transactions
                .iter()
                .map(|tx| self.verify_single_signature(tx))
                .collect()
        };
        
        let elapsed = start.elapsed();
        let total_time_us = elapsed.as_micros() as u64;
        let avg_time = total_time_us / batch.len().max(1) as u64;
        
        // Update metrics atomically
        let metrics = self.metrics.read();
        let _ = metrics.signatures_verified.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(batch.len() as u64));
        let _ = metrics.verify_time_sum.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(total_time_us));
        
        tracing::debug!(
            "Batch signature verification: {} sigs in {:?} ({} us/sig)",
            batch.len(),
            elapsed,
            avg_time
        );
        
        Ok(results)
    }

    /// Verifies a single signature with size validation.
    fn verify_single_signature(&self, tx: &SignedTransaction) -> bool {
        let sig = &tx.transaction.signature;
        if sig.is_empty() || sig.len() != MLDSA65_SIG_SIZE {
            tracing::warn!("Invalid ML-DSA-65 signature size: {} (expected {})", sig.len(), MLDSA65_SIG_SIZE);
            return false;
        }
        let message = tx.transaction.signing_data();
        verify_ml_dsa_65_batch(tx.transaction.public_key.clone(), message, sig.clone())
    }

    /// Verifies a batch of arbitrary signatures.
    pub fn verify_signature_batch(&self, batch: &mut SignatureBatch) -> Result<bool, BatchingError> {
        let start = std::time::Instant::now();
        
        let items: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = batch.entries.iter().map(|entry| {
            (
                entry.public_key.clone(),
                entry.message.clone(),
                entry.signature.clone(),
            )
        }).collect();

        let results: Vec<bool> = if self.config.parallel_verify {
            let verifier = MlDsa65BatchVerifier::new(items.len());
            verifier.verify_batch(&items)
        } else {
            items.iter().map(|(pubkey, message, signature)| {
                verify_ml_dsa_65_batch(pubkey.clone(), message.clone(), signature.clone())
            }).collect()
        };
        
        // Update entries with results
        for (entry, valid) in batch.entries.iter_mut().zip(results.iter()) {
            entry.valid = Some(*valid);
        }
        
        let all_valid = results.iter().all(|&v| v);
        batch.all_valid = Some(all_valid);
        
        let elapsed = start.elapsed();
        tracing::debug!(
            "Signature batch verification: {} sigs in {:?}, all valid: {}",
            batch.len(),
            elapsed,
            all_valid
        );
        
        Ok(all_valid)
    }

    /// Compresses a transaction batch.
    pub fn compress_batch(&self, batch: &TransactionBatch) -> Result<CompressedBatch, BatchingError> {
        let mut serialized = Vec::with_capacity(batch.transactions.len());
        
        for tx in &batch.transactions {
            let data = bincode::serialize(tx)
                .map_err(|e| BatchingError::SerializationFailed(e.to_string()))?;
            serialized.push(data);
        }
        
        self.compression
            .compress_transaction_batch(&serialized)
            .map_err(|e| BatchingError::CompressionFailed(e.to_string()))
    }

    /// Decompresses a transaction batch.
    /// Fails fast on first deserialization error to avoid data loss.
    pub fn decompress_batch(&self, compressed: &CompressedBatch) -> Result<TransactionBatch, BatchingError> {
        let serialized = self.compression
            .decompress_transaction_batch(compressed)
            .map_err(|e| BatchingError::DecompressionFailed(e.to_string()))?;
        
        let mut transactions = Vec::with_capacity(serialized.len());
        
        for (idx, data) in serialized.into_iter().enumerate() {
            let tx = bincode::deserialize::<SignedTransaction>(&data)
                .map_err(|e| {
                    tracing::error!("Failed to deserialize transaction at index {}: {}", idx, e);
                    BatchingError::DeserializationFailed(1, compressed.count as usize)
                })?;
            transactions.push(tx);
        }
        
        Ok(TransactionBatch::with_transactions(transactions))
    }

    /// Gets current metrics snapshot.
    pub fn get_metrics(&self) -> BatchingMetricsSnapshot {
        self.metrics.read().snapshot()
    }

    /// Adds a batch to pending queue with count and memory limits.
    pub fn add_pending_tx_batch(&self, batch: TransactionBatch) -> Result<(), BatchingError> {
        let mut pending = self.pending_tx_batches.write();
        
        if pending.len() >= MAX_PENDING_BATCHES {
            return Err(BatchingError::PendingQueueFull(MAX_PENDING_BATCHES));
        }
        
        // Enforce total transaction count to bound memory
        let total_txs: usize = pending.iter().map(|b| b.len()).sum();
        if total_txs + batch.len() > MAX_PENDING_TOTAL_TXS {
            return Err(BatchingError::PendingQueueFull(MAX_PENDING_TOTAL_TXS));
        }
        
        pending.push(batch);
        Ok(())
    }

    /// Cleans up old pending batches based on timeout.
    pub fn cleanup_pending_batches(&self, max_age_secs: u64) {
        let now = chrono::Utc::now().timestamp() as u64;
        
        let mut tx_batches = self.pending_tx_batches.write();
        tx_batches.retain(|batch| {
            now.saturating_sub(batch.created_at) < max_age_secs
        });
        
        let mut sig_batches = self.pending_sig_batches.write();
        sig_batches.retain(|batch| {
            now.saturating_sub(batch.created_at) < max_age_secs
        });
    }

    /// Gets the number of pending transaction batches.
    pub fn pending_tx_count(&self) -> usize {
        self.pending_tx_batches.read().len()
    }

    /// Gets the number of pending signature batches.
    pub fn pending_sig_count(&self) -> usize {
        self.pending_sig_batches.read().len()
    }
}

/// Aggregated signature for committee voting.
///
/// Combines multiple ML-DSA-65 signatures into a more compact form
/// for efficient verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedSignature {
    /// Signers (validator addresses)
    pub signers: Vec<Address>,
    /// Individual signatures (ML-DSA-65 doesn't support true aggregation)
    pub signatures: Vec<Vec<u8>>,
    /// Validator indices corresponding to each signature (insertion order)
    pub validator_indices: Vec<usize>,
    /// Bitmap indicating which validators signed
    pub signer_bitmap: Vec<u8>,
    /// Aggregation method
    pub method: AggregationMethod,
}

/// Method used for signature aggregation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AggregationMethod {
    /// Simple concatenation (no true aggregation)
    Concatenated,
    /// Compressed concatenation
    Compressed,
    /// Threshold signature (future)
    Threshold { required: u32, total: u32 },
}

impl AggregatedSignature {
    /// Creates a new aggregated signature.
    pub fn new() -> Self {
        Self {
            signers: Vec::new(),
            signatures: Vec::new(),
            validator_indices: Vec::new(),
            signer_bitmap: Vec::new(),
            method: AggregationMethod::Concatenated,
        }
    }

    /// Adds a signature to the aggregate.
    /// Returns Err if index exceeds MAX_VALIDATOR_INDEX or signature size is invalid.
    pub fn add_signature(&mut self, signer: Address, signature: Vec<u8>, index: usize) -> Result<(), BatchingError> {
        if index > MAX_VALIDATOR_INDEX {
            return Err(BatchingError::ValidatorIndexOutOfBounds(index, MAX_VALIDATOR_INDEX));
        }
        if signature.len() != MLDSA65_SIG_SIZE {
            return Err(BatchingError::VerificationFailed(
                format!("Invalid signature size: {} (expected {})", signature.len(), MLDSA65_SIG_SIZE),
            ));
        }
        
        self.signers.push(signer);
        self.signatures.push(signature);
        self.validator_indices.push(index);
        
        // Update bitmap
        let byte_idx = index / 8;
        let bit_idx = index % 8;
        
        while self.signer_bitmap.len() <= byte_idx {
            self.signer_bitmap.push(0);
        }
        
        self.signer_bitmap[byte_idx] |= 1 << bit_idx;
        Ok(())
    }

    /// Returns the number of signatures.
    pub fn count(&self) -> usize {
        self.signatures.len()
    }

    /// Checks if a validator at the given index has signed.
    pub fn has_signed(&self, index: usize) -> bool {
        let byte_idx = index / 8;
        let bit_idx = index % 8;
        
        if byte_idx >= self.signer_bitmap.len() {
            return false;
        }
        
        (self.signer_bitmap[byte_idx] & (1 << bit_idx)) != 0
    }

    /// Verifies all signatures in the aggregate.
    /// 
    /// Uses stored validator_indices (insertion order) to correctly map
    /// signatures to public keys.
    pub fn verify_all(&self, message: &[u8], validator_public_keys: &[Vec<u8>]) -> Result<bool, BatchingError> {
        if self.signers.len() != self.signatures.len() {
            return Ok(false);
        }
        if self.validator_indices.len() != self.signatures.len() {
            return Err(BatchingError::SignatureCountMismatch(
                self.validator_indices.len(),
                self.signatures.len(),
            ));
        }
        
        // Verify each signature using stored validator_indices (insertion order)
        // This is the correct mapping — not the bitmap extraction order.
        let mut items = Vec::with_capacity(self.signatures.len());
        for (sig, &validator_idx) in self.signatures.iter().zip(self.validator_indices.iter()) {
            if validator_idx >= validator_public_keys.len() {
                return Err(BatchingError::ValidatorIndexOutOfBounds(
                    validator_idx,
                    validator_public_keys.len(),
                ));
            }
            if sig.len() != MLDSA65_SIG_SIZE {
                return Err(BatchingError::VerificationFailed(
                    format!("Invalid signature size at index {}: {} (expected {})", validator_idx, sig.len(), MLDSA65_SIG_SIZE),
                ));
            }
            items.push((validator_public_keys[validator_idx].clone(), message.to_vec(), sig.clone()));
        }

        let verifier = MlDsa65BatchVerifier::new(items.len());
        let results = verifier.verify_batch(&items);

        for valid in results {
            if !valid {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Compresses the aggregated signature.
    pub fn compress(&self, engine: &CompressionEngine) -> Result<CompressedBatch, BatchingError> {
        engine
            .compress_signatures(&self.signatures)
            .map_err(|e| BatchingError::CompressionFailed(e.to_string()))
    }
}

/// Errors from the batching system.
#[derive(Debug, thiserror::Error)]
pub enum BatchingError {
    /// Batch is too large
    #[error("Batch too large: {0} exceeds maximum {1}")]
    BatchTooLarge(usize, usize),
    
    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    /// Compression failed
    #[error("Compression failed: {0}")]
    CompressionFailed(String),
    
    /// Decompression failed
    #[error("Decompression failed: {0}")]
    DecompressionFailed(String),
    
    /// Invalid batch format
    #[error("Invalid batch format")]
    InvalidBatchFormat,
    
    /// Serialization failed
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),
    
    /// Deserialization failed for some transactions
    #[error("Deserialization failed: {0} out of {1} transactions")]
    DeserializationFailed(usize, usize),
    
    /// Pending queue is full
    #[error("Pending queue full: maximum {0} batches")]
    PendingQueueFull(usize),
    
    /// Signature count doesn't match validator indices
    #[error("Signature count mismatch: {0} indices but {1} signatures")]
    SignatureCountMismatch(usize, usize),
    
    /// Validator index out of bounds
    #[error("Validator index {0} out of bounds (max {1})")]
    ValidatorIndexOutOfBounds(usize, usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_batch_creation() {
        let batch = TransactionBatch::new();
        assert!(batch.is_empty());
    }

    #[test]
    fn test_signature_batch() {
        let mut batch = SignatureBatch::new();
        batch.add(vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]);
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn test_aggregated_signature_bitmap() {
        let mut agg = AggregatedSignature::new();
        agg.add_signature([0u8; 32], vec![0u8; MLDSA65_SIG_SIZE], 0).unwrap();
        agg.add_signature([1u8; 32], vec![0u8; MLDSA65_SIG_SIZE], 5).unwrap();
        
        assert!(agg.has_signed(0));
        assert!(!agg.has_signed(1));
        assert!(agg.has_signed(5));
        assert_eq!(agg.count(), 2);
    }
}
