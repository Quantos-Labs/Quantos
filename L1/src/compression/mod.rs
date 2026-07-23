// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Quantos Compression Engine
//!
//! High-performance compression for transactions, signatures, and network messages.
//!
//! ## Compression Algorithms
//!
//! | Algorithm | Use Case | Ratio | Speed |
//! |-----------|----------|-------|-------|
//! | **LZ4** | Real-time TX compression | ~2x | Very Fast |
//! | **Zstd** | Storage & checkpoints | ~4x | Fast |
//! | **Snappy** | Network messages | ~1.5x | Fastest |
//!
//! ## Features
//!
//! - **Adaptive Compression**: Automatically selects best algorithm
//! - **Batch Compression**: Compress multiple items together for better ratio
//! - **Streaming**: Support for streaming compression/decompression
//! - **Dictionary Training**: Pre-trained dictionaries for TX patterns

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Maximum decompressed size to prevent decompression bombs (256 MB)
const MAX_DECOMPRESSED_SIZE: usize = 256 * 1024 * 1024;

/// Maximum batch size to prevent unbounded allocation (128 MB)
const MAX_BATCH_SIZE: usize = 128 * 1024 * 1024;

/// Maximum number of items in a batch
const MAX_BATCH_ITEMS: usize = 100_000;

/// Maximum global in-flight decompression memory (512 MB)
const MAX_INFLIGHT_MEMORY: usize = 512 * 1024 * 1024;

/// Maximum size for a single item in a batch (16 MB)
const MAX_SINGLE_ITEM_SIZE: usize = 16 * 1024 * 1024;

/// Valid zstd compression level range
const ZSTD_LEVEL_MIN: i32 = 1;
const ZSTD_LEVEL_MAX: i32 = 22;

/// Global tracker for in-flight decompression memory
static INFLIGHT_MEMORY: AtomicUsize = AtomicUsize::new(0);

/// Compression algorithm selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionAlgorithm {
    /// No compression
    None,
    /// LZ4 - fastest, good for real-time
    Lz4,
    /// Zstandard - best ratio, good for storage
    Zstd,
    /// Snappy - balanced speed/ratio
    Snappy,
}

impl Default for CompressionAlgorithm {
    fn default() -> Self {
        Self::Lz4
    }
}

/// Configuration for the compression engine.
#[derive(Clone, Debug)]
pub struct CompressionConfig {
    /// Default algorithm for transactions
    pub tx_algorithm: CompressionAlgorithm,
    /// Default algorithm for signatures
    pub sig_algorithm: CompressionAlgorithm,
    /// Default algorithm for network messages
    pub network_algorithm: CompressionAlgorithm,
    /// Default algorithm for storage
    pub storage_algorithm: CompressionAlgorithm,
    /// Zstd compression level (clamped to 1-22, default 3)
    pub zstd_level: i32,
    /// Minimum size to compress (bytes)
    pub min_compress_size: usize,
    /// Enable adaptive algorithm selection
    pub adaptive: bool,
}

impl CompressionConfig {
    /// Clamps zstd_level to the valid range.
    fn validated(mut self) -> Self {
        self.zstd_level = self.zstd_level.clamp(ZSTD_LEVEL_MIN, ZSTD_LEVEL_MAX);
        self
    }
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            tx_algorithm: CompressionAlgorithm::Lz4,
            sig_algorithm: CompressionAlgorithm::Lz4,
            network_algorithm: CompressionAlgorithm::Snappy,
            storage_algorithm: CompressionAlgorithm::Zstd,
            zstd_level: 3,
            min_compress_size: 64,
            adaptive: true,
        }
    }
}

/// Main compression engine for Quantos.
///
/// Provides compression/decompression for all data types with
/// automatic algorithm selection and batch processing.
///
/// # Example
///
/// ```rust,ignore
/// let engine = CompressionEngine::new(CompressionConfig::default());
///
/// // Compress a transaction
/// let compressed = engine.compress_transaction(&tx_bytes)?;
///
/// // Decompress
/// let original = engine.decompress(&compressed)?;
/// ```
pub struct CompressionEngine {
    config: CompressionConfig,
    /// Pre-trained dictionary for transaction compression
    tx_dictionary: Option<Vec<u8>>,
    /// Pre-trained dictionary for signature compression  
    sig_dictionary: Option<Vec<u8>>,
    /// Total bytes compressed
    bytes_compressed: AtomicU64,
    /// Total bytes decompressed
    bytes_decompressed: AtomicU64,
    /// Number of compression operations
    compress_count: AtomicU64,
    /// Number of decompression operations
    decompress_count: AtomicU64,
}

impl CompressionEngine {
    /// Creates a new compression engine.
    pub fn new(config: CompressionConfig) -> Self {
        let config = config.validated();
        Self {
            config,
            tx_dictionary: None,
            sig_dictionary: None,
            bytes_compressed: AtomicU64::new(0),
            bytes_decompressed: AtomicU64::new(0),
            compress_count: AtomicU64::new(0),
            decompress_count: AtomicU64::new(0),
        }
    }

    /// Compresses data using the specified algorithm.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to compress
    /// * `algorithm` - Compression algorithm to use
    ///
    /// # Returns
    ///
    /// Compressed data with a header indicating the algorithm used
    pub fn compress(&self, data: &[u8], algorithm: CompressionAlgorithm) -> Result<Vec<u8>, CompressionError> {
        // Validate input size
        if data.len() > MAX_DECOMPRESSED_SIZE {
            return Err(CompressionError::DataTooLarge);
        }

        // Skip compression for small data
        if data.len() < self.config.min_compress_size {
            self.compress_count.fetch_add(1, Ordering::Relaxed);
            return Ok(self.wrap_uncompressed(data));
        }

        let compressed = match algorithm {
            CompressionAlgorithm::None => self.wrap_uncompressed(data),
            CompressionAlgorithm::Lz4 => self.compress_lz4(data)?,
            CompressionAlgorithm::Zstd => self.compress_zstd(data)?,
            CompressionAlgorithm::Snappy => self.compress_snappy(data)?,
        };

        // Update statistics (saturating to prevent overflow)
        let _ = self.bytes_compressed.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(data.len() as u64));
        let _ = self.compress_count.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1));

        // Only use compressed if it's actually smaller
        if compressed.len() >= data.len() + 5 {
            Ok(self.wrap_uncompressed(data))
        } else {
            Ok(compressed)
        }
    }

    /// Decompresses data, auto-detecting the algorithm from the header.
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        if data.len() < 5 {
            return Err(CompressionError::InvalidHeader);
        }

        // Read header
        let algorithm = match data[0] {
            0x00 => CompressionAlgorithm::None,
            0x01 => CompressionAlgorithm::Lz4,
            0x02 => CompressionAlgorithm::Zstd,
            0x03 => CompressionAlgorithm::Snappy,
            _ => return Err(CompressionError::InvalidHeader),
        };

        let original_size = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
        
        // Validate original_size to prevent decompression bombs
        if original_size > MAX_DECOMPRESSED_SIZE {
            return Err(CompressionError::DecompressionBomb);
        }
        
        // Enforce global in-flight memory quota to prevent concurrent exhaustion
        let prev = INFLIGHT_MEMORY.fetch_add(original_size, Ordering::AcqRel);
        if prev + original_size > MAX_INFLIGHT_MEMORY {
            INFLIGHT_MEMORY.fetch_sub(original_size, Ordering::AcqRel);
            return Err(CompressionError::MemoryQuotaExceeded);
        }
        
        let compressed_data = &data[5..];

        let result = match algorithm {
            CompressionAlgorithm::None => {
                // Validate uncompressed data size matches header
                if compressed_data.len() != original_size {
                    INFLIGHT_MEMORY.fetch_sub(original_size, Ordering::AcqRel);
                    return Err(CompressionError::InvalidHeader);
                }
                if compressed_data.is_empty() {
                    INFLIGHT_MEMORY.fetch_sub(original_size, Ordering::AcqRel);
                    return Ok(Vec::new());
                }
                Ok(compressed_data.to_vec())
            },
            CompressionAlgorithm::Lz4 => self.decompress_lz4(compressed_data, original_size),
            CompressionAlgorithm::Zstd => self.decompress_zstd(compressed_data, original_size),
            CompressionAlgorithm::Snappy => self.decompress_snappy(compressed_data, original_size),
        };
        
        // Release in-flight memory quota regardless of outcome
        INFLIGHT_MEMORY.fetch_sub(original_size, Ordering::AcqRel);
        
        let result = result?;

        // Update statistics (saturating to prevent overflow)
        let _ = self.bytes_decompressed.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(result.len() as u64));
        let _ = self.decompress_count.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1));

        Ok(result)
    }

    /// Compresses a transaction.
    pub fn compress_transaction(&self, tx_data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        self.compress(tx_data, self.config.tx_algorithm)
    }

    /// Compresses a batch of transactions together for better ratio.
    ///
    /// Batch compression achieves better ratios by exploiting
    /// similarities between transactions (common addresses, etc.)
    pub fn compress_transaction_batch(&self, transactions: &[Vec<u8>]) -> Result<CompressedBatch, CompressionError> {
        if transactions.is_empty() {
            return Ok(CompressedBatch::empty());
        }

        // Validate batch limits
        if transactions.len() > MAX_BATCH_ITEMS {
            return Err(CompressionError::BatchTooLarge);
        }

        // Calculate total size with overflow checking
        let mut total_size: usize = 0;
        for tx in transactions {
            total_size = total_size.checked_add(4)
                .and_then(|s| s.checked_add(tx.len()))
                .ok_or(CompressionError::BatchTooLarge)?;
            
            if total_size > MAX_BATCH_SIZE {
                return Err(CompressionError::BatchTooLarge);
            }
        }

        // Concatenate all transactions with length prefixes
        let mut combined = Vec::with_capacity(total_size);
        
        for tx in transactions {
            combined.extend_from_slice(&(tx.len() as u32).to_le_bytes());
            combined.extend_from_slice(tx);
        }

        let original_size = combined.len();
        let compressed = self.compress(&combined, self.config.tx_algorithm)?;
        let compressed_size = compressed.len();

        Ok(CompressedBatch {
            data: compressed,
            count: transactions.len() as u32,
            original_size: original_size as u64,
            compressed_size: compressed_size as u64,
            algorithm: self.config.tx_algorithm,
        })
    }

    /// Decompresses a batch of transactions.
    pub fn decompress_transaction_batch(&self, batch: &CompressedBatch) -> Result<Vec<Vec<u8>>, CompressionError> {
        // Validate count field
        if batch.count as usize > MAX_BATCH_ITEMS {
            return Err(CompressionError::InvalidBatchFormat);
        }

        let decompressed = self.decompress(&batch.data)?;
        
        let mut transactions = Vec::with_capacity(batch.count as usize);
        let mut offset: usize = 0;
        
        while offset < decompressed.len() {
            // Check if we have enough space for length prefix
            let next_offset = offset.checked_add(4)
                .ok_or(CompressionError::InvalidBatchFormat)?;
            
            if next_offset > decompressed.len() {
                break;
            }
            
            let tx_len = u32::from_le_bytes([
                decompressed[offset],
                decompressed[offset + 1],
                decompressed[offset + 2],
                decompressed[offset + 3],
            ]) as usize;
            
            // Cap individual item size to prevent malicious length prefixes
            if tx_len > MAX_SINGLE_ITEM_SIZE {
                return Err(CompressionError::InvalidBatchFormat);
            }
            
            offset = next_offset;
            
            // Check for overflow and bounds
            let end_offset = offset.checked_add(tx_len)
                .ok_or(CompressionError::InvalidBatchFormat)?;
            
            if end_offset > decompressed.len() {
                return Err(CompressionError::InvalidBatchFormat);
            }
            
            transactions.push(decompressed[offset..end_offset].to_vec());
            offset = end_offset;
        }
        
        // Validate that count matches actual items
        if transactions.len() != batch.count as usize {
            return Err(CompressionError::CountMismatch);
        }
        
        Ok(transactions)
    }

    /// Compresses signatures.
    pub fn compress_signatures(&self, signatures: &[Vec<u8>]) -> Result<CompressedBatch, CompressionError> {
        if signatures.is_empty() {
            return Ok(CompressedBatch::empty());
        }

        // Validate batch limits
        if signatures.len() > MAX_BATCH_ITEMS {
            return Err(CompressionError::BatchTooLarge);
        }

        // Calculate total size with overflow checking
        let mut total_size: usize = 0;
        for sig in signatures {
            total_size = total_size.checked_add(4)
                .and_then(|s| s.checked_add(sig.len()))
                .ok_or(CompressionError::BatchTooLarge)?;
            
            if total_size > MAX_BATCH_SIZE {
                return Err(CompressionError::BatchTooLarge);
            }
        }

        // Use u32 for signature lengths to avoid truncation
        let mut combined = Vec::with_capacity(total_size);
        
        for sig in signatures {
            combined.extend_from_slice(&(sig.len() as u32).to_le_bytes());
            combined.extend_from_slice(sig);
        }

        let original_size = combined.len();
        let compressed = self.compress(&combined, self.config.sig_algorithm)?;
        let compressed_size = compressed.len();

        Ok(CompressedBatch {
            data: compressed,
            count: signatures.len() as u32,
            original_size: original_size as u64,
            compressed_size: compressed_size as u64,
            algorithm: self.config.sig_algorithm,
        })
    }

    /// Decompresses signatures.
    pub fn decompress_signatures(&self, batch: &CompressedBatch) -> Result<Vec<Vec<u8>>, CompressionError> {
        // Validate count field
        if batch.count as usize > MAX_BATCH_ITEMS {
            return Err(CompressionError::InvalidBatchFormat);
        }

        let decompressed = self.decompress(&batch.data)?;
        
        let mut signatures = Vec::with_capacity(batch.count as usize);
        let mut offset: usize = 0;
        
        while offset < decompressed.len() {
            // Check if we have enough space for length prefix (now u32)
            let next_offset = offset.checked_add(4)
                .ok_or(CompressionError::InvalidBatchFormat)?;
            
            if next_offset > decompressed.len() {
                break;
            }
            
            let sig_len = u32::from_le_bytes([
                decompressed[offset],
                decompressed[offset + 1],
                decompressed[offset + 2],
                decompressed[offset + 3],
            ]) as usize;
            
            // Cap individual item size to prevent malicious length prefixes
            if sig_len > MAX_SINGLE_ITEM_SIZE {
                return Err(CompressionError::InvalidBatchFormat);
            }
            
            offset = next_offset;
            
            // Check for overflow and bounds
            let end_offset = offset.checked_add(sig_len)
                .ok_or(CompressionError::InvalidBatchFormat)?;
            
            if end_offset > decompressed.len() {
                return Err(CompressionError::InvalidBatchFormat);
            }
            
            signatures.push(decompressed[offset..end_offset].to_vec());
            offset = end_offset;
        }
        
        // Validate that count matches actual items
        if signatures.len() != batch.count as usize {
            return Err(CompressionError::CountMismatch);
        }
        
        Ok(signatures)
    }

    /// Compresses a network message.
    pub fn compress_network_message(&self, message: &[u8]) -> Result<Vec<u8>, CompressionError> {
        self.compress(message, self.config.network_algorithm)
    }

    /// Compresses data for storage.
    pub fn compress_for_storage(&self, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        self.compress(data, self.config.storage_algorithm)
    }

    /// Wraps uncompressed data with a header.
    /// Returns empty vec header for empty input to avoid wasting 5 bytes.
    fn wrap_uncompressed(&self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            let mut result = Vec::with_capacity(5);
            result.push(0x00);
            result.extend_from_slice(&0u32.to_le_bytes());
            return result;
        }
        let mut result = Vec::with_capacity(5 + data.len());
        result.push(0x00); // Algorithm: None
        result.extend_from_slice(&(data.len() as u32).to_le_bytes());
        result.extend_from_slice(data);
        result
    }

    /// Compresses using LZ4.
    fn compress_lz4(&self, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        let compressed = lz4_flex::compress_prepend_size(data);
        
        let mut result = Vec::with_capacity(compressed.len() + 5);
        result.push(0x01); // Algorithm: LZ4
        result.extend_from_slice(&(data.len() as u32).to_le_bytes());
        result.extend_from_slice(&compressed);
        
        Ok(result)
    }

    /// Decompresses LZ4.
    fn decompress_lz4(&self, data: &[u8], expected_size: usize) -> Result<Vec<u8>, CompressionError> {
        let result = lz4_flex::decompress_size_prepended(data)
            .map_err(|_| CompressionError::DecompressionFailed("LZ4 decompression failed".into()))?;
        
        // Validate decompressed size matches expected
        if result.len() != expected_size {
            return Err(CompressionError::SizeMismatch);
        }
        
        Ok(result)
    }

    /// Compresses using Zstd.
    fn compress_zstd(&self, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        let level = self.config.zstd_level.clamp(ZSTD_LEVEL_MIN, ZSTD_LEVEL_MAX);
        let compressed = zstd::encode_all(data, level)
            .map_err(|_| CompressionError::CompressionFailed("Zstd compression failed".into()))?;
        
        let mut result = Vec::with_capacity(compressed.len() + 5);
        result.push(0x02); // Algorithm: Zstd
        result.extend_from_slice(&(data.len() as u32).to_le_bytes());
        result.extend_from_slice(&compressed);
        
        Ok(result)
    }

    /// Decompresses Zstd.
    fn decompress_zstd(&self, data: &[u8], expected_size: usize) -> Result<Vec<u8>, CompressionError> {
        let result = zstd::decode_all(data)
            .map_err(|_| CompressionError::DecompressionFailed("Zstd decompression failed".into()))?;
        
        // Validate decompressed size matches expected
        if result.len() != expected_size {
            return Err(CompressionError::SizeMismatch);
        }
        
        Ok(result)
    }

    /// Compresses using Snappy.
    fn compress_snappy(&self, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        let mut encoder = snap::raw::Encoder::new();
        let compressed = encoder.compress_vec(data)
            .map_err(|_| CompressionError::CompressionFailed("Snappy compression failed".into()))?;
        
        let mut result = Vec::with_capacity(compressed.len() + 5);
        result.push(0x03); // Algorithm: Snappy
        result.extend_from_slice(&(data.len() as u32).to_le_bytes());
        result.extend_from_slice(&compressed);
        
        Ok(result)
    }

    /// Decompresses Snappy.
    fn decompress_snappy(&self, data: &[u8], expected_size: usize) -> Result<Vec<u8>, CompressionError> {
        let mut decoder = snap::raw::Decoder::new();
        let result = decoder.decompress_vec(data)
            .map_err(|_| CompressionError::DecompressionFailed("Snappy decompression failed".into()))?;
        
        // Validate decompressed size matches expected
        if result.len() != expected_size {
            return Err(CompressionError::SizeMismatch);
        }
        
        Ok(result)
    }

    /// Selects the best algorithm based on data characteristics.
    pub fn select_algorithm(&self, data: &[u8], priority: CompressionPriority) -> CompressionAlgorithm {
        if !self.config.adaptive {
            return match priority {
                CompressionPriority::Speed => CompressionAlgorithm::Lz4,
                CompressionPriority::Ratio => CompressionAlgorithm::Zstd,
                CompressionPriority::Balanced => CompressionAlgorithm::Snappy,
            };
        }

        // Small data: skip compression
        if data.len() < self.config.min_compress_size {
            return CompressionAlgorithm::None;
        }

        // Large data: use Zstd for best ratio
        if data.len() > 10000 {
            return CompressionAlgorithm::Zstd;
        }

        // Default based on priority
        match priority {
            CompressionPriority::Speed => CompressionAlgorithm::Lz4,
            CompressionPriority::Ratio => CompressionAlgorithm::Zstd,
            CompressionPriority::Balanced => CompressionAlgorithm::Snappy,
        }
    }

    /// Gets compression statistics.
    pub fn get_stats(&self) -> CompressionStats {
        CompressionStats {
            bytes_compressed: self.bytes_compressed.load(Ordering::Relaxed),
            bytes_decompressed: self.bytes_decompressed.load(Ordering::Relaxed),
            compress_count: self.compress_count.load(Ordering::Relaxed),
            decompress_count: self.decompress_count.load(Ordering::Relaxed),
        }
    }
}

/// A compressed batch of items.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompressedBatch {
    /// Compressed data
    pub data: Vec<u8>,
    /// Number of items in the batch
    pub count: u32,
    /// Original uncompressed size
    pub original_size: u64,
    /// Compressed size
    pub compressed_size: u64,
    /// Algorithm used
    pub algorithm: CompressionAlgorithm,
}

impl CompressedBatch {
    /// Creates an empty batch.
    pub fn empty() -> Self {
        Self {
            data: Vec::new(),
            count: 0,
            original_size: 0,
            compressed_size: 0,
            algorithm: CompressionAlgorithm::None,
        }
    }

    /// Returns the compression ratio.
    pub fn ratio(&self) -> f64 {
        if self.compressed_size == 0 {
            return 1.0;
        }
        self.original_size as f64 / self.compressed_size as f64
    }

    /// Returns the space savings percentage.
    pub fn savings_percent(&self) -> f64 {
        if self.original_size == 0 {
            return 0.0;
        }
        (1.0 - (self.compressed_size as f64 / self.original_size as f64)) * 100.0
    }
}

/// Compression priority for algorithm selection.
#[derive(Clone, Copy, Debug)]
pub enum CompressionPriority {
    /// Prioritize speed over ratio
    Speed,
    /// Prioritize ratio over speed
    Ratio,
    /// Balance speed and ratio
    Balanced,
}

/// Compression statistics.
#[derive(Clone, Debug, Default)]
pub struct CompressionStats {
    /// Total bytes compressed
    pub bytes_compressed: u64,
    /// Total bytes decompressed
    pub bytes_decompressed: u64,
    /// Number of compression operations
    pub compress_count: u64,
    /// Number of decompression operations
    pub decompress_count: u64,
}

impl CompressionStats {
    /// Calculates average compression ratio.
    pub fn avg_compression_ratio(&self) -> f64 {
        if self.bytes_compressed == 0 {
            return 1.0;
        }
        self.bytes_compressed as f64 / self.bytes_decompressed.max(1) as f64
    }
}

/// Errors from the compression system.
#[derive(Debug, thiserror::Error)]
pub enum CompressionError {
    /// Invalid compression header
    #[error("Invalid compression header")]
    InvalidHeader,
    
    /// Compression failed
    #[error("Compression failed: {0}")]
    CompressionFailed(String),
    
    /// Decompression failed
    #[error("Decompression failed: {0}")]
    DecompressionFailed(String),
    
    /// Invalid batch format
    #[error("Invalid batch format")]
    InvalidBatchFormat,
    
    /// Decompression bomb detected (size too large)
    #[error("Decompression bomb: size exceeds maximum allowed")]
    DecompressionBomb,
    
    /// Data too large to compress
    #[error("Data exceeds maximum size limit")]
    DataTooLarge,
    
    /// Batch too large
    #[error("Batch exceeds maximum size or item limit")]
    BatchTooLarge,
    
    /// Decompressed size doesn't match expected
    #[error("Decompressed size mismatch")]
    SizeMismatch,
    
    /// Count field doesn't match actual items
    #[error("Batch count mismatch")]
    CountMismatch,
    
    /// Global decompression memory quota exceeded
    #[error("Decompression memory quota exceeded")]
    MemoryQuotaExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lz4_roundtrip() {
        let engine = CompressionEngine::new(CompressionConfig::default());
        let data = b"Hello, Quantos! This is a test message for compression.".repeat(10);
        
        let compressed = engine.compress(&data, CompressionAlgorithm::Lz4).unwrap();
        let decompressed = engine.decompress(&compressed).unwrap();
        
        assert_eq!(data.to_vec(), decompressed);
        assert!(compressed.len() < data.len());
    }

    #[test]
    fn test_zstd_roundtrip() {
        let engine = CompressionEngine::new(CompressionConfig::default());
        let data = b"Hello, Quantos! This is a test message for compression.".repeat(10);
        
        let compressed = engine.compress(&data, CompressionAlgorithm::Zstd).unwrap();
        let decompressed = engine.decompress(&compressed).unwrap();
        
        assert_eq!(data.to_vec(), decompressed);
    }

    #[test]
    fn test_batch_compression() {
        let engine = CompressionEngine::new(CompressionConfig::default());
        let transactions: Vec<Vec<u8>> = (0..10)
            .map(|i| format!("Transaction {}: data data data", i).into_bytes())
            .collect();
        
        let batch = engine.compress_transaction_batch(&transactions).unwrap();
        let decompressed = engine.decompress_transaction_batch(&batch).unwrap();
        
        assert_eq!(transactions, decompressed);
        assert!(batch.ratio() > 1.0);
    }
}
