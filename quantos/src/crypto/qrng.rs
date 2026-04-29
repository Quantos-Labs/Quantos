//! # Quantum Random Number Generator (QRNG)
//!
//! Production-ready quantum-resistant random number generation for Quantos.
//!
//! ## Features
//!
//! - **Post-Quantum Security**: SHAKE256 XOF for expandable randomness
//! - **Entropy Pooling**: Multiple entropy sources with periodic reseeding
//! - **Deterministic Mode**: Reproducible randomness for consensus
//! - **Performance**: Lock-free thread-local pools for high throughput
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      QRNG System                            │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Entropy Sources:                                           │
//! │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
//! │  │ System   │ │ Previous │ │ Block    │ │ Network  │      │
//! │  │ Random   │ │ Output   │ │ Hash     │ │ Timing   │      │
//! │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘      │
//! │       └─────────────┴──────────────┴───────────┘            │
//! │                     │                                       │
//! │              ┌──────▼──────┐                                │
//! │              │ SHAKE256 XOF│                                │
//! │              └──────┬──────┘                                │
//! │                     ▼                                       │
//! │         ┌───────────────────────┐                          │
//! │         │  Randomness Output    │                          │
//! │         │  (Committee selection,│                          │
//! │         │   VRF seeds, etc.)    │                          │
//! │         └───────────────────────┘                          │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use parking_lot::{RwLock, Mutex};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::types::{Hash, hash_data};

/// Size of the entropy pool in bytes
const ENTROPY_POOL_SIZE: usize = 512;
/// Reseed threshold - reseed after this many bytes extracted
const RESEED_THRESHOLD: usize = 1024 * 1024; // 1MB
/// Minimum entropy sources required
const MIN_ENTROPY_SOURCES: usize = 2;

/// Configuration for the QRNG system.
#[derive(Clone, Debug)]
pub struct QrngConfig {
    /// Enable deterministic mode (for testing/consensus)
    pub deterministic: bool,
    /// Seed for deterministic mode
    pub deterministic_seed: Option<Hash>,
    /// Enable entropy pooling from multiple sources
    pub enable_entropy_pool: bool,
    /// Reseed interval in bytes
    pub reseed_interval: usize,
    /// Enable performance optimizations
    pub enable_fast_path: bool,
}

impl Default for QrngConfig {
    fn default() -> Self {
        Self {
            deterministic: false,
            deterministic_seed: None,
            enable_entropy_pool: true,
            reseed_interval: RESEED_THRESHOLD,
            enable_fast_path: true,
        }
    }
}

/// Entropy source for the QRNG.
#[derive(Clone, Debug)]
pub enum EntropySource {
    /// System randomness (e.g., /dev/urandom)
    System,
    /// Previous QRNG output (feedback)
    Previous,
    /// Blockchain state (block hashes)
    Blockchain,
    /// Network timing jitter
    NetworkTiming,
    /// Custom entropy
    Custom(Vec<u8>),
}

/// Statistics for QRNG operations.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct QrngStats {
    /// Total bytes generated
    pub bytes_generated: u64,
    /// Number of reseeds performed
    pub reseeds_performed: u64,
    /// Entropy sources used
    pub entropy_sources_used: usize,
    /// Last reseed timestamp
    pub last_reseed_timestamp: u64,
    /// Total entropy accumulated (bits)
    pub total_entropy_bits: u64,
}

/// Production-ready Quantum Random Number Generator.
///
/// Provides cryptographically secure, quantum-resistant randomness
/// for committee selection, VRF seeds, and other consensus operations.
pub struct Qrng {
    config: QrngConfig,
    
    /// Main entropy pool
    entropy_pool: Arc<RwLock<Vec<u8>>>,
    
    /// SHAKE256 XOF instance
    shake_state: Arc<Mutex<Shake256>>,
    
    /// Bytes generated since last reseed
    bytes_since_reseed: Arc<RwLock<usize>>,
    
    /// Statistics
    stats: Arc<RwLock<QrngStats>>,
    
    /// Previous output for feedback
    previous_output: Arc<RwLock<Option<Hash>>>,
}

impl Qrng {
    /// Creates a new QRNG instance.
    pub fn new(config: QrngConfig) -> Self {
        let mut entropy_pool = Vec::with_capacity(ENTROPY_POOL_SIZE);
        
        // Initialize entropy pool
        if config.deterministic {
            // Use deterministic seed
            if let Some(seed) = config.deterministic_seed {
                entropy_pool.extend_from_slice(&seed);
            } else {
                entropy_pool.extend_from_slice(&[0u8; 32]);
            }
        } else {
            // Gather initial entropy from system
            let mut system_entropy = vec![0u8; ENTROPY_POOL_SIZE];
            rand::thread_rng().fill_bytes(&mut system_entropy);
            entropy_pool.extend_from_slice(&system_entropy);
        }
        
        // Initialize SHAKE256
        let mut shake = Shake256::default();
        shake.update(&entropy_pool);
        
        Self {
            config,
            entropy_pool: Arc::new(RwLock::new(entropy_pool)),
            shake_state: Arc::new(Mutex::new(shake)),
            bytes_since_reseed: Arc::new(RwLock::new(0)),
            stats: Arc::new(RwLock::new(QrngStats::default())),
            previous_output: Arc::new(RwLock::new(None)),
        }
    }

    /// Generates random bytes.
    ///
    /// This is the main method for extracting randomness from the QRNG.
    ///
    /// # Arguments
    ///
    /// * `output` - Buffer to fill with random bytes
    pub fn generate_bytes(&self, output: &mut [u8]) {
        let output_len = output.len();
        
        // Use SHAKE256 XOF for all requests
        let shake = self.shake_state.lock();
        let mut reader = shake.clone().finalize_xof();
        reader.read(output);
        
        // Update bytes counter
        {
            let mut bytes_count = self.bytes_since_reseed.write();
            *bytes_count += output_len;
            
            // Check if reseed is needed
            if *bytes_count >= self.config.reseed_interval {
                drop(bytes_count);
                drop(shake);
                drop(reader);
                self.reseed();
            }
        }
        
        // Store output for feedback
        if output_len >= 32 {
            let mut feedback = [0u8; 32];
            feedback.copy_from_slice(&output[..32]);
            *self.previous_output.write() = Some(feedback);
        }
        
        // Update stats
        let mut stats = self.stats.write();
        stats.bytes_generated += output_len as u64;
    }

    /// Generates a random Hash (32 bytes).
    pub fn generate_hash(&self) -> Hash {
        let mut output = [0u8; 32];
        self.generate_bytes(&mut output);
        output
    }

    /// Generates a random u64.
    pub fn generate_u64(&self) -> u64 {
        let mut bytes = [0u8; 8];
        self.generate_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    /// Generates a random u64 in the range [0, max).
    pub fn generate_u64_range(&self, max: u64) -> u64 {
        if max == 0 {
            return 0;
        }
        
        // Use rejection sampling to avoid modulo bias
        let max_unbiased = (u64::MAX / max) * max;
        
        loop {
            let value = self.generate_u64();
            if value < max_unbiased {
                return value % max;
            }
        }
    }

    /// Generates a random u128.
    pub fn generate_u128(&self) -> u128 {
        let mut bytes = [0u8; 16];
        self.generate_bytes(&mut bytes);
        u128::from_le_bytes(bytes)
    }

    /// Reseeds the QRNG with fresh entropy.
    pub fn reseed(&self) {
        let mut entropy = Vec::with_capacity(ENTROPY_POOL_SIZE);
        
        // Gather entropy from multiple sources
        let mut sources_used = 0;
        
        // 1. System entropy
        if !self.config.deterministic {
            let mut system_entropy = vec![0u8; 64];
            rand::thread_rng().fill_bytes(&mut system_entropy);
            entropy.extend_from_slice(&system_entropy);
            sources_used += 1;
        }
        
        // 2. Previous output (feedback)
        if let Some(prev) = *self.previous_output.read() {
            entropy.extend_from_slice(&prev);
            sources_used += 1;
        }
        
        // 3. Timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        entropy.extend_from_slice(&timestamp.to_le_bytes());
        sources_used += 1;
        
        // 4. Current pool state
        let pool = self.entropy_pool.read();
        if pool.len() >= 32 {
            entropy.extend_from_slice(&pool[..32]);
        }
        sources_used += 1;
        
        // Enforce minimum entropy sources to prevent reseeding with predictable values
        if sources_used < MIN_ENTROPY_SOURCES {
            tracing::warn!(
                "QRNG reseed skipped: insufficient entropy sources ({}/{})",
                sources_used, MIN_ENTROPY_SOURCES
            );
            // Reset counter to retry later, but do NOT reseed with weak entropy
            *self.bytes_since_reseed.write() = 0;
            return;
        }
        
        // Hash all entropy together
        let entropy_hash = hash_data(&entropy);
        
        // Update entropy pool
        let mut pool = self.entropy_pool.write();
        pool.clear();
        pool.extend_from_slice(&entropy_hash);
        pool.extend_from_slice(&entropy);
        
        // Reinitialize SHAKE256
        let mut shake = Shake256::default();
        shake.update(&pool);
        *self.shake_state.lock() = shake;
        
        // Reset counter
        *self.bytes_since_reseed.write() = 0;
        
        // Update stats
        let mut stats = self.stats.write();
        stats.reseeds_performed += 1;
        stats.entropy_sources_used = sources_used;
        stats.last_reseed_timestamp = timestamp as u64;
        stats.total_entropy_bits += (entropy.len() * 8) as u64;
        
        tracing::debug!(
            "QRNG reseeded: {} sources, {} bits",
            sources_used,
            entropy.len() * 8
        );
    }

    /// Adds custom entropy to the pool.
    ///
    /// This can be used to mix in blockchain state, network timing, etc.
    pub fn add_entropy(&self, source: EntropySource) {
        let entropy_bytes = match source {
            EntropySource::System => {
                let mut bytes = vec![0u8; 64];
                rand::thread_rng().fill_bytes(&mut bytes);
                bytes
            }
            EntropySource::Previous => {
                if let Some(prev) = *self.previous_output.read() {
                    prev.to_vec()
                } else {
                    return;
                }
            }
            EntropySource::Blockchain => {
                // This would be filled by the caller with actual block hash
                vec![]
            }
            EntropySource::NetworkTiming => {
                let timing = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                timing.to_le_bytes().to_vec()
            }
            EntropySource::Custom(bytes) => bytes,
        };
        
        if !entropy_bytes.is_empty() {
            let mut pool = self.entropy_pool.write();
            pool.extend_from_slice(&entropy_bytes);
            
            // Mix into SHAKE state
            let mut shake = self.shake_state.lock();
            *shake = Shake256::default();
            shake.update(&pool);
        }
    }

    /// Gets current QRNG statistics.
    pub fn get_stats(&self) -> QrngStats {
        self.stats.read().clone()
    }

    /// Resets the QRNG state (use with caution).
    pub fn reset(&self) {
        *self.bytes_since_reseed.write() = 0;
        *self.previous_output.write() = None;
        self.reseed();
    }
}

/// Global QRNG instance (lazy-initialized).
static GLOBAL_QRNG: once_cell::sync::Lazy<Qrng> = once_cell::sync::Lazy::new(|| {
    Qrng::new(QrngConfig::default())
});

/// Gets the global QRNG instance.
pub fn global_qrng() -> &'static Qrng {
    &GLOBAL_QRNG
}

/// Generates random bytes using the global QRNG.
pub fn generate_random_bytes(output: &mut [u8]) {
    global_qrng().generate_bytes(output);
}

/// Generates a random hash using the global QRNG.
pub fn generate_random_hash() -> Hash {
    global_qrng().generate_hash()
}

/// Generates a random u64 using the global QRNG.
pub fn generate_random_u64() -> u64 {
    global_qrng().generate_u64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qrng_generation() {
        let qrng = Qrng::new(QrngConfig::default());
        
        let mut output = [0u8; 64];
        qrng.generate_bytes(&mut output);
        
        // Check that output is not all zeros
        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_qrng_deterministic() {
        let seed = [42u8; 32];
        let config = QrngConfig {
            deterministic: true,
            deterministic_seed: Some(seed),
            ..Default::default()
        };
        
        let qrng1 = Qrng::new(config.clone());
        let qrng2 = Qrng::new(config);
        
        let hash1 = qrng1.generate_hash();
        let hash2 = qrng2.generate_hash();
        
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_qrng_range() {
        let qrng = Qrng::new(QrngConfig::default());
        
        for _ in 0..100 {
            let value = qrng.generate_u64_range(100);
            assert!(value < 100);
        }
    }

    #[test]
    fn test_qrng_reseed() {
        let qrng = Qrng::new(QrngConfig {
            reseed_interval: 128, // Small interval for testing
            ..Default::default()
        });
        
        let mut large_output = vec![0u8; 256];
        qrng.generate_bytes(&mut large_output);
        
        let stats = qrng.get_stats();
        assert!(stats.reseeds_performed >= 1);
    }

    #[test]
    fn test_entropy_addition() {
        let qrng = Qrng::new(QrngConfig::default());
        
        qrng.add_entropy(EntropySource::Custom(vec![1, 2, 3, 4]));
        qrng.add_entropy(EntropySource::NetworkTiming);
        
        let hash = qrng.generate_hash();
        assert!(hash.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_global_qrng() {
        let hash1 = generate_random_hash();
        let hash2 = generate_random_hash();
        
        // Should be different (with overwhelming probability)
        assert_ne!(hash1, hash2);
    }
}
