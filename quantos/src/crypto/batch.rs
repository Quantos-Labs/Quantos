//! # Batch Signature Verification
//!
//! Parallel signature verification using Rayon for massive throughput.

use rayon::prelude::*;
use dashmap::DashMap;
use std::sync::Arc;

use crate::crypto::{verify_dilithium, CryptoResult};
use crate::types::Hash;

/// Signature verification cache to avoid re-verifying known signatures.
pub struct SignatureCache {
    /// Cache of verified signatures: hash(pubkey || message || signature) -> is_valid
    cache: Arc<DashMap<Hash, bool>>,
    /// Maximum cache size
    max_size: usize,
}

impl SignatureCache {
    /// Creates a new signature cache.
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Arc::new(DashMap::with_capacity(max_size)),
            max_size,
        }
    }

    /// Computes cache key for a signature verification.
    /// Uses domain separation and length prefixing to prevent collision attacks.
    fn cache_key(public_key: &[u8], message: &[u8], signature: &[u8]) -> Hash {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        
        // Domain separation to prevent cross-protocol attacks
        hasher.update(b"QUANTOS_SIG_CACHE_V1");
        
        // Length-prefix each component to prevent collision attacks
        hasher.update(&(public_key.len() as u64).to_le_bytes());
        hasher.update(public_key);
        
        hasher.update(&(message.len() as u64).to_le_bytes());
        hasher.update(message);
        
        hasher.update(&(signature.len() as u64).to_le_bytes());
        hasher.update(signature);
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Verifies a signature with caching.
    pub fn verify_cached(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> CryptoResult<bool> {
        let key = Self::cache_key(public_key, message, signature);

        // Check cache first
        if let Some(result) = self.cache.get(&key) {
            return Ok(*result);
        }

        // Verify and cache
        let result = verify_dilithium(public_key, message, signature)?;

        // Evict if cache is full (simple LRU approximation)
        if self.cache.len() >= self.max_size {
            // Remove ~25% of entries to amortize eviction cost
            let to_remove: Vec<_> = self.cache
                .iter()
                .take(self.max_size / 4)
                .map(|e| *e.key())
                .collect();
            for k in to_remove {
                self.cache.remove(&k);
            }
        }

        self.cache.insert(key, result);
        Ok(result)
    }

    /// Cache hit rate for monitoring.
    pub fn size(&self) -> usize {
        self.cache.len()
    }

    /// Clears the cache.
    pub fn clear(&self) {
        self.cache.clear();
    }
}

/// Batch signature verification request.
#[derive(Clone)]
pub struct VerificationRequest {
    pub public_key: Vec<u8>,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Batch signature verification result.
#[derive(Clone)]
pub struct VerificationResult {
    pub index: usize,
    pub valid: bool,
    pub error: Option<String>,
}

/// Verifies multiple signatures in parallel using Rayon.
pub fn batch_verify_signatures(requests: &[VerificationRequest]) -> Vec<VerificationResult> {
    requests
        .par_iter()
        .enumerate()
        .map(|(index, req)| {
            match verify_dilithium(&req.public_key, &req.message, &req.signature) {
                Ok(valid) => VerificationResult {
                    index,
                    valid,
                    error: None,
                },
                Err(e) => VerificationResult {
                    index,
                    valid: false,
                    error: Some(e.to_string()),
                },
            }
        })
        .collect()
}

/// Verifies multiple signatures in parallel with caching.
pub fn batch_verify_cached(
    cache: &SignatureCache,
    requests: &[VerificationRequest],
) -> Vec<VerificationResult> {
    requests
        .par_iter()
        .enumerate()
        .map(|(index, req)| {
            match cache.verify_cached(&req.public_key, &req.message, &req.signature) {
                Ok(valid) => VerificationResult {
                    index,
                    valid,
                    error: None,
                },
                Err(e) => VerificationResult {
                    index,
                    valid: false,
                    error: Some(e.to_string()),
                },
            }
        })
        .collect()
}

/// Batch verifier with built-in caching and parallelism.
pub struct BatchVerifier {
    cache: SignatureCache,
    /// Number of parallel workers (defaults to CPU count)
    num_workers: usize,
}

impl BatchVerifier {
    /// Creates a new batch verifier.
    pub fn new(cache_size: usize) -> Self {
        Self {
            cache: SignatureCache::new(cache_size),
            num_workers: num_cpus::get(),
        }
    }

    /// Verifies a batch of signatures.
    pub fn verify_batch(&self, requests: &[VerificationRequest]) -> Vec<VerificationResult> {
        batch_verify_cached(&self.cache, requests)
    }

    /// Verifies a single signature (with caching).
    pub fn verify_single(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> CryptoResult<bool> {
        self.cache.verify_cached(public_key, message, signature)
    }

    /// Returns cache statistics.
    pub fn cache_size(&self) -> usize {
        self.cache.size()
    }

    /// Clears the verification cache.
    pub fn clear_cache(&self) {
        self.cache.clear();
    }
}

impl Default for BatchVerifier {
    fn default() -> Self {
        // 100K cache entries by default to prevent memory exhaustion
        Self::new(100_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::DilithiumKeypair;

    #[test]
    fn test_batch_verification() {
        let keypair = DilithiumKeypair::generate().unwrap();
        let messages: Vec<Vec<u8>> = (0..10).map(|i| format!("message_{}", i).into_bytes()).collect();
        
        let requests: Vec<VerificationRequest> = messages
            .iter()
            .map(|msg| {
                let sig = keypair.sign(msg).unwrap();
                VerificationRequest {
                    public_key: keypair.public_key.clone(),
                    message: msg.clone(),
                    signature: sig,
                }
            })
            .collect();

        let results = batch_verify_signatures(&requests);
        assert_eq!(results.len(), 10);
        assert!(results.iter().all(|r| r.valid));
    }

    #[test]
    fn test_signature_cache() {
        let cache = SignatureCache::new(1000);
        let keypair = DilithiumKeypair::generate().unwrap();
        let message = b"test message";
        let signature = keypair.sign(message).unwrap();

        // First verification - cache miss
        let result1 = cache.verify_cached(&keypair.public_key, message, &signature).unwrap();
        assert!(result1);
        assert_eq!(cache.size(), 1);

        // Second verification - cache hit
        let result2 = cache.verify_cached(&keypair.public_key, message, &signature).unwrap();
        assert!(result2);
        assert_eq!(cache.size(), 1); // No new entry
    }

    #[test]
    fn test_batch_verifier() {
        let verifier = BatchVerifier::new(1000);
        let keypair = DilithiumKeypair::generate().unwrap();
        let message = b"test";
        let signature = keypair.sign(message).unwrap();

        let result = verifier.verify_single(&keypair.public_key, message, &signature).unwrap();
        assert!(result);
        assert_eq!(verifier.cache_size(), 1);
    }
}
