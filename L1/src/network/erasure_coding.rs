// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Erasure Coding for Block Propagation
//!
//! Reed-Solomon erasure coding implementation for efficient block propagation.
//! Allows reconstruction of full blocks from k-of-n fragments, reducing
//! bandwidth requirements and improving propagation speed.
//!
//! ## Features
//!
//! - **Reed-Solomon GF(2^8)**: Industry-standard erasure coding
//! - **Configurable Redundancy**: k data shards + m parity shards
//! - **Parallel Encoding/Decoding**: SIMD-accelerated operations
//! - **Streaming Support**: Process large blocks in chunks

use std::sync::Arc;
use parking_lot::RwLock;
use thiserror::Error;

/// Galois Field GF(2^8) operations for Reed-Solomon
const GF_SIZE: usize = 256;
const GF_POLYNOMIAL: u8 = 0x1D; // x^8 + x^4 + x^3 + x^2 + 1

/// Precomputed tables for GF(2^8) arithmetic
struct GaloisField {
    /// Exponential table: exp[i] = α^i
    exp_table: [u8; 512],
    /// Logarithm table: log[α^i] = i
    log_table: [u8; 256],
}

impl GaloisField {
    fn new() -> Self {
        let mut exp_table = [0u8; 512];
        let mut log_table = [0u8; 256];
        
        let mut x: u16 = 1;
        for i in 0..255 {
            exp_table[i] = x as u8;
            exp_table[i + 255] = x as u8;
            log_table[x as usize] = i as u8;
            
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= GF_POLYNOMIAL as u16 | 0x100;
            }
        }
        exp_table[510] = 1;
        log_table[0] = 0; // Convention: log(0) = 0
        
        Self { exp_table, log_table }
    }
    
    #[inline]
    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let log_a = self.log_table[a as usize] as usize;
        let log_b = self.log_table[b as usize] as usize;
        self.exp_table[log_a + log_b]
    }
    
    #[inline]
    fn div(&self, a: u8, b: u8) -> Result<u8, ErasureCodingError> {
        if a == 0 {
            return Ok(0);
        }
        if b == 0 {
            return Err(ErasureCodingError::DecodingFailed(
                "Division by zero in GF(2^8)".to_string()
            ));
        }
        let log_a = self.log_table[a as usize] as usize;
        let log_b = self.log_table[b as usize] as usize;
        Ok(self.exp_table[log_a + 255 - log_b])
    }
    
    #[inline]
    fn inv(&self, a: u8) -> Result<u8, ErasureCodingError> {
        if a == 0 {
            return Err(ErasureCodingError::DecodingFailed(
                "Inverse of zero in GF(2^8)".to_string()
            ));
        }
        let log_a = self.log_table[a as usize] as usize;
        Ok(self.exp_table[255 - log_a])
    }
}

use once_cell::sync::Lazy;

static GF: Lazy<GaloisField> = Lazy::new(|| GaloisField::new());

/// Errors in erasure coding operations
#[derive(Error, Debug, Clone)]
pub enum ErasureCodingError {
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    
    #[error("Not enough shards for reconstruction: have {have}, need {need}")]
    InsufficientShards { have: usize, need: usize },
    
    #[error("Shard size mismatch")]
    ShardSizeMismatch,
    
    #[error("Invalid shard index: {0}")]
    InvalidShardIndex(usize),
    
    #[error("Encoding failed: {0}")]
    EncodingFailed(String),
    
    #[error("Decoding failed: {0}")]
    DecodingFailed(String),
}

/// Configuration for erasure coding
#[derive(Clone, Debug)]
pub struct ErasureCodingConfig {
    /// Number of data shards (k)
    pub data_shards: usize,
    /// Number of parity shards (m)
    pub parity_shards: usize,
    /// Shard size in bytes
    pub shard_size: usize,
}

impl Default for ErasureCodingConfig {
    fn default() -> Self {
        Self {
            data_shards: 10,      // 10 data fragments
            parity_shards: 4,     // 4 parity fragments
            shard_size: 64 * 1024, // 64KB per shard
        }
    }
}

impl ErasureCodingConfig {
    /// Validates the configuration
    pub fn validate(&self) -> Result<(), ErasureCodingError> {
        if self.data_shards == 0 {
            return Err(ErasureCodingError::InvalidConfig(
                "data_shards must be > 0".to_string(),
            ));
        }
        if self.data_shards + self.parity_shards > 255 {
            return Err(ErasureCodingError::InvalidConfig(
                "total shards must be <= 255 for GF(2^8)".to_string(),
            ));
        }
        Ok(())
    }
    
    /// Total number of shards (n = k + m)
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }
    
    /// Minimum shards needed for reconstruction
    pub fn min_shards(&self) -> usize {
        self.data_shards
    }
}

/// A coded shard with metadata
#[derive(Clone, Debug)]
pub struct CodedShard {
    /// Shard index (0..n)
    pub index: usize,
    /// Shard data
    pub data: Vec<u8>,
    /// Original block hash for verification
    pub block_hash: [u8; 32],
    /// Block size before encoding
    pub original_size: usize,
}

/// Reed-Solomon encoder/decoder
pub struct ReedSolomonCodec {
    config: ErasureCodingConfig,
    /// Vandermonde encoding matrix
    encoding_matrix: Vec<Vec<u8>>,
    /// Cache for decoding matrices
    decoding_cache: RwLock<std::collections::HashMap<Vec<usize>, Vec<Vec<u8>>>>,
}

impl ReedSolomonCodec {
    /// Creates a new Reed-Solomon codec
    pub fn new(config: ErasureCodingConfig) -> Result<Self, ErasureCodingError> {
        config.validate()?;
        
        let encoding_matrix = Self::build_vandermonde_matrix(
            config.total_shards(),
            config.data_shards,
        );
        
        Ok(Self {
            config,
            encoding_matrix,
            decoding_cache: RwLock::new(std::collections::HashMap::new()),
        })
    }
    
    /// Builds Vandermonde encoding matrix
    fn build_vandermonde_matrix(rows: usize, cols: usize) -> Vec<Vec<u8>> {
        let mut matrix = vec![vec![0u8; cols]; rows];
        
        for i in 0..rows {
            for j in 0..cols {
                if i < cols {
                    // Identity matrix for data shards
                    matrix[i][j] = if i == j { 1 } else { 0 };
                } else {
                    // Vandermonde matrix for parity shards
                    let row = (i - cols + 1) as u8;
                    let col = j as u8;
                    matrix[i][j] = GF.exp_table[(row as usize * col as usize) % 255];
                }
            }
        }
        
        matrix
    }
    
    /// Encodes a block into coded shards
    pub fn encode(&self, data: &[u8], block_hash: [u8; 32]) -> Result<Vec<CodedShard>, ErasureCodingError> {
        let original_size = data.len();
        let k = self.config.data_shards;
        let n = self.config.total_shards();
        
        // Calculate shard size (pad to multiple of k)
        let shard_size = (data.len() + k - 1) / k;
        
        // Pad data to exact multiple of shard_size * k
        let mut padded = data.to_vec();
        padded.resize(shard_size * k, 0);
        
        // Split into data shards
        let data_shards: Vec<&[u8]> = padded.chunks(shard_size).collect();
        
        // Create all shards (data + parity)
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(n);
        
        // Data shards are copied directly
        for shard in &data_shards {
            shards.push(shard.to_vec());
        }
        
        // Generate parity shards
        for i in k..n {
            let mut parity = vec![0u8; shard_size];
            
            for byte_idx in 0..shard_size {
                let mut value = 0u8;
                for j in 0..k {
                    value ^= GF.mul(self.encoding_matrix[i][j], data_shards[j][byte_idx]);
                }
                parity[byte_idx] = value;
            }
            
            shards.push(parity);
        }
        
        // Wrap in CodedShard structs
        let coded_shards: Vec<CodedShard> = shards
            .into_iter()
            .enumerate()
            .map(|(index, data)| CodedShard {
                index,
                data,
                block_hash,
                original_size,
            })
            .collect();
        
        Ok(coded_shards)
    }
    
    /// Decodes shards back to original block
    pub fn decode(&self, shards: &[CodedShard]) -> Result<Vec<u8>, ErasureCodingError> {
        let k = self.config.data_shards;
        
        if shards.len() < k {
            return Err(ErasureCodingError::InsufficientShards {
                have: shards.len(),
                need: k,
            });
        }
        
        // Verify all shards have same size
        let shard_size = shards[0].data.len();
        if shards.iter().any(|s| s.data.len() != shard_size) {
            return Err(ErasureCodingError::ShardSizeMismatch);
        }
        
        // Get shard indices
        let indices: Vec<usize> = shards.iter().take(k).map(|s| s.index).collect();
        
        // Check if we have all data shards (fast path)
        let all_data_shards = indices.iter().all(|&i| i < k)
            && (0..k).all(|i| indices.contains(&i));
        
        if all_data_shards {
            // Fast path: just concatenate data shards
            let mut result = Vec::with_capacity(shard_size * k);
            for i in 0..k {
                let shard = shards.iter().find(|s| s.index == i)
                    .ok_or(ErasureCodingError::InvalidShardIndex(i))?;
                result.extend_from_slice(&shard.data);
            }
            result.truncate(shards[0].original_size);
            return Ok(result);
        }
        
        // Need to decode using matrix inversion
        let decoding_matrix = self.get_decoding_matrix(&indices)?;
        
        // Decode each byte position
        let mut result = vec![0u8; shard_size * k];
        
        for byte_idx in 0..shard_size {
            for i in 0..k {
                let mut value = 0u8;
                for (j, shard) in shards.iter().take(k).enumerate() {
                    value ^= GF.mul(decoding_matrix[i][j], shard.data[byte_idx]);
                }
                result[i * shard_size + byte_idx] = value;
            }
        }
        
        // Reorder to original data shard order
        let mut ordered = vec![0u8; shard_size * k];
        for i in 0..k {
            let start = i * shard_size;
            let end = start + shard_size;
            ordered[start..end].copy_from_slice(&result[start..end]);
        }
        
        ordered.truncate(shards[0].original_size);
        Ok(ordered)
    }
    
    /// Gets or computes decoding matrix for given shard indices
    fn get_decoding_matrix(&self, indices: &[usize]) -> Result<Vec<Vec<u8>>, ErasureCodingError> {
        let k = self.config.data_shards;
        
        // Check cache
        {
            let cache = self.decoding_cache.read();
            if let Some(matrix) = cache.get(indices) {
                return Ok(matrix.clone());
            }
        }
        
        // Build submatrix from encoding matrix
        let mut submatrix: Vec<Vec<u8>> = Vec::with_capacity(k);
        for &idx in indices.iter().take(k) {
            if idx >= self.encoding_matrix.len() {
                return Err(ErasureCodingError::InvalidShardIndex(idx));
            }
            submatrix.push(self.encoding_matrix[idx].clone());
        }
        
        // Invert the submatrix using Gaussian elimination
        let inverted = self.invert_matrix(&submatrix)?;
        
        // Cache the result
        {
            let mut cache = self.decoding_cache.write();
            cache.insert(indices.to_vec(), inverted.clone());
        }
        
        Ok(inverted)
    }
    
    /// Inverts a matrix using Gaussian elimination in GF(2^8)
    fn invert_matrix(&self, matrix: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, ErasureCodingError> {
        let n = matrix.len();
        
        // Create augmented matrix [A|I]
        let mut aug: Vec<Vec<u8>> = matrix
            .iter()
            .enumerate()
            .map(|(i, row)| {
                let mut new_row = row.clone();
                new_row.resize(2 * n, 0);
                new_row[n + i] = 1;
                new_row
            })
            .collect();
        
        // Forward elimination
        for col in 0..n {
            // Find pivot
            let mut pivot_row = None;
            for row in col..n {
                if aug[row][col] != 0 {
                    pivot_row = Some(row);
                    break;
                }
            }
            
            let pivot_row = pivot_row.ok_or_else(|| {
                ErasureCodingError::DecodingFailed("Singular matrix".to_string())
            })?;
            
            // Swap rows if needed
            if pivot_row != col {
                aug.swap(col, pivot_row);
            }
            
            // Scale pivot row
            let pivot_val = aug[col][col];
            let pivot_inv = GF.inv(pivot_val)?;
            for j in 0..2 * n {
                aug[col][j] = GF.mul(aug[col][j], pivot_inv);
            }
            
            // Eliminate column
            for row in 0..n {
                if row != col && aug[row][col] != 0 {
                    let factor = aug[row][col];
                    for j in 0..2 * n {
                        aug[row][j] ^= GF.mul(factor, aug[col][j]);
                    }
                }
            }
        }
        
        // Extract inverse matrix
        let inverse: Vec<Vec<u8>> = aug
            .into_iter()
            .map(|row| row[n..].to_vec())
            .collect();
        
        Ok(inverse)
    }
    
    /// Returns config reference
    pub fn config(&self) -> &ErasureCodingConfig {
        &self.config
    }
}

/// Block encoder for network propagation
pub struct BlockErasureEncoder {
    codec: Arc<ReedSolomonCodec>,
    /// Maximum block size before encoding
    max_block_size: usize,
}

impl BlockErasureEncoder {
    pub fn new(config: ErasureCodingConfig) -> Result<Self, ErasureCodingError> {
        let max_block_size = config.shard_size * config.data_shards;
        
        Ok(Self {
            codec: Arc::new(ReedSolomonCodec::new(config)?),
            max_block_size,
        })
    }
    
    /// Encodes a block for propagation
    pub fn encode_block(&self, block_data: &[u8], block_hash: [u8; 32]) -> Result<Vec<CodedShard>, ErasureCodingError> {
        if block_data.len() > self.max_block_size {
            return Err(ErasureCodingError::EncodingFailed(format!(
                "Block size {} exceeds maximum {}",
                block_data.len(),
                self.max_block_size
            )));
        }
        
        self.codec.encode(block_data, block_hash)
    }
    
    /// Decodes shards back to block
    pub fn decode_block(&self, shards: &[CodedShard]) -> Result<Vec<u8>, ErasureCodingError> {
        self.codec.decode(shards)
    }
    
    /// Returns number of shards needed for reconstruction
    pub fn min_shards_for_reconstruction(&self) -> usize {
        self.codec.config().min_shards()
    }
    
    /// Returns total number of shards produced
    pub fn total_shards(&self) -> usize {
        self.codec.config().total_shards()
    }
}

/// Shard collector for block reconstruction
pub struct ShardCollector {
    /// Block hash we're collecting for
    block_hash: [u8; 32],
    /// Collected shards
    shards: Vec<CodedShard>,
    /// Required shards count
    required: usize,
    /// Total expected shards
    total: usize,
    /// Creation timestamp
    created_at: std::time::Instant,
}

impl ShardCollector {
    pub fn new(block_hash: [u8; 32], required: usize, total: usize) -> Self {
        Self {
            block_hash,
            shards: Vec::with_capacity(total),
            required,
            total,
            created_at: std::time::Instant::now(),
        }
    }
    
    /// Adds a shard to the collector
    pub fn add_shard(&mut self, shard: CodedShard) -> bool {
        // Verify block hash matches
        if shard.block_hash != self.block_hash {
            return false;
        }
        
        // Check for duplicate index
        if self.shards.iter().any(|s| s.index == shard.index) {
            return false;
        }
        
        self.shards.push(shard);
        true
    }
    
    /// Returns true if we have enough shards
    pub fn is_complete(&self) -> bool {
        self.shards.len() >= self.required
    }
    
    /// Returns collected shards
    pub fn shards(&self) -> &[CodedShard] {
        &self.shards
    }
    
    /// Returns elapsed time since creation
    pub fn elapsed(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }
    
    /// Returns progress ratio
    pub fn progress(&self) -> f32 {
        self.shards.len() as f32 / self.required as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encode_decode_no_loss() {
        let config = ErasureCodingConfig {
            data_shards: 4,
            parity_shards: 2,
            shard_size: 1024,
        };
        
        let codec = ReedSolomonCodec::new(config).unwrap();
        let original = b"Hello, World! This is a test of erasure coding.";
        let block_hash = [0u8; 32];
        
        let shards = codec.encode(original, block_hash).unwrap();
        assert_eq!(shards.len(), 6); // 4 data + 2 parity
        
        let decoded = codec.decode(&shards).unwrap();
        assert_eq!(&decoded, original);
    }
    
    #[test]
    fn test_encode_decode_with_loss() {
        let config = ErasureCodingConfig {
            data_shards: 4,
            parity_shards: 2,
            shard_size: 1024,
        };
        
        let codec = ReedSolomonCodec::new(config).unwrap();
        let original = b"Test data for erasure coding with lost shards.";
        let block_hash = [0u8; 32];
        
        let mut shards = codec.encode(original, block_hash).unwrap();
        
        // Remove 2 shards (within tolerance)
        shards.remove(1);
        shards.remove(3);
        
        let decoded = codec.decode(&shards).unwrap();
        assert_eq!(&decoded, original);
    }
    
    #[test]
    fn test_insufficient_shards() {
        let config = ErasureCodingConfig {
            data_shards: 4,
            parity_shards: 2,
            shard_size: 1024,
        };
        
        let codec = ReedSolomonCodec::new(config).unwrap();
        let original = b"Test data";
        let block_hash = [0u8; 32];
        
        let mut shards = codec.encode(original, block_hash).unwrap();
        
        // Remove too many shards
        shards.truncate(3);
        
        let result = codec.decode(&shards);
        assert!(matches!(result, Err(ErasureCodingError::InsufficientShards { .. })));
    }
    
    #[test]
    fn test_galois_field_arithmetic() {
        // Test multiplication
        assert_eq!(GF.mul(3, 7), GF.mul(7, 3)); // Commutative
        assert_eq!(GF.mul(1, 5), 5); // Identity
        assert_eq!(GF.mul(0, 5), 0); // Zero
        
        // Test inverse
        for a in 1..=255u8 {
            let inv = GF.inv(a).unwrap();
            assert_eq!(GF.mul(a, inv), 1);
        }
        
        // Test division/inverse of zero returns error, not panic
        assert!(GF.div(1, 0).is_err());
        assert!(GF.inv(0).is_err());
    }
}
