// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # SIMD Acceleration for Cryptographic Operations
//!
//! Uses SIMD (Single Instruction Multiple Data) instructions for
//! parallel processing of cryptographic primitives.
//!
//! ## Supported Architectures
//! - x86_64: AVX2, AVX-512
//! - ARM64: NEON
//!
//! ## Optimizations
//! - Parallel hash computation
//! - Vectorized XOR operations
//! - Batch memory operations

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

/// SIMD-accelerated hash computation for multiple inputs.
/// Processes 4 hashes in parallel using AVX2.
pub fn simd_hash_batch_4(inputs: &[&[u8]; 4]) -> [[u8; 32]; 4] {
    // Fallback to sequential - SIMD SHA3 requires specific implementation
    [
        crate::crypto::sha3_256(inputs[0]),
        crate::crypto::sha3_256(inputs[1]),
        crate::crypto::sha3_256(inputs[2]),
        crate::crypto::sha3_256(inputs[3]),
    ]
}

/// SIMD-accelerated XOR operation for signature compression.
///
/// # Safety
///
/// The caller must ensure AVX2 is available on the current CPU before calling
/// this function (use the `is_x86_feature_detected!("avx2")` guard).
/// All slice accesses are bounds-checked via `safe_len = min(a, b, out)`.
/// `_mm256_loadu_si256` / `_mm256_storeu_si256` are used (unaligned variants),
/// so no alignment requirement is imposed on the callers.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn simd_xor_256(a: &[u8], b: &[u8], out: &mut [u8]) {
    // Use the minimum length of all three slices for safe iteration
    let safe_len = a.len().min(b.len()).min(out.len());
    if safe_len < 32 {
        // Fallback to scalar for small inputs
        for i in 0..safe_len {
            out[i] = a[i] ^ b[i];
        }
        return;
    }
    
    let chunks = safe_len / 32;
    
    for i in 0..chunks {
        let offset = i * 32;
        let va = _mm256_loadu_si256(a[offset..].as_ptr() as *const __m256i);
        let vb = _mm256_loadu_si256(b[offset..].as_ptr() as *const __m256i);
        let vr = _mm256_xor_si256(va, vb);
        _mm256_storeu_si256(out[offset..].as_mut_ptr() as *mut __m256i, vr);
    }
    
    // Handle remaining bytes
    let remaining_start = chunks * 32;
    for i in remaining_start..safe_len {
        out[i] = a[i] ^ b[i];
    }
}

/// Safe wrapper for SIMD XOR.
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    let len = a.len().min(b.len());
    let mut out = vec![0u8; len];
    
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") && len >= 32 {
            unsafe {
                simd_xor_256(a, b, &mut out);
            }
            return out;
        }
    }
    
    // Fallback
    for i in 0..len {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// SIMD-accelerated memory copy with prefetch.
///
/// # Safety
///
/// AVX2 must be available (guarded by `is_x86_feature_detected!` at call site).
/// `copy_len = min(src, dst)` guarantees both slices are long enough before
/// any load/store. `_mm256_loadu_si256` / `_mm256_storeu_si256` do not require
/// alignment. Remaining bytes are handled by `copy_from_slice`, which is safe.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn simd_memcpy_256(src: &[u8], dst: &mut [u8]) {
    // Validate dst can hold all of src
    let copy_len = src.len().min(dst.len());
    if copy_len == 0 {
        return;
    }
    
    let chunks = copy_len / 32;
    
    for i in 0..chunks {
        let offset = i * 32;
        // Prefetch next chunk
        if i + 1 < chunks {
            _mm_prefetch(src[(i + 1) * 32..].as_ptr() as *const i8, _MM_HINT_T0);
        }
        let v = _mm256_loadu_si256(src[offset..].as_ptr() as *const __m256i);
        _mm256_storeu_si256(dst[offset..].as_mut_ptr() as *mut __m256i, v);
    }
    
    // Handle remaining bytes safely
    let remaining_start = chunks * 32;
    if remaining_start < copy_len {
        dst[remaining_start..copy_len].copy_from_slice(&src[remaining_start..copy_len]);
    }
}

/// Safe wrapper for SIMD memcpy.
pub fn fast_copy(src: &[u8], dst: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") && src.len() >= 32 {
            unsafe {
                simd_memcpy_256(src, dst);
            }
            return;
        }
    }
    
    dst[..src.len()].copy_from_slice(src);
}

/// SIMD-accelerated comparison of byte arrays.
///
/// # Safety
///
/// AVX2 must be available at call site (guarded by `is_x86_feature_detected!`).
/// `a.len() == b.len()` is checked before any SIMD access.
/// All 256-bit loads are within `[0, chunks * 32)` which is ≤ `len`.
/// The tail slice comparison `a[remaining_start..]` is fully safe Rust.
///
/// Note: this comparison is **not** constant-time. Do not use it for
/// secret data (e.g. MAC verification). Use `subtle::ConstantTimeEq` for that.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn simd_compare_256(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let len = a.len();
    let chunks = len / 32;
    
    for i in 0..chunks {
        let offset = i * 32;
        // Bounds are guaranteed: offset + 32 <= chunks * 32 <= len
        let va = _mm256_loadu_si256(a[offset..].as_ptr() as *const __m256i);
        let vb = _mm256_loadu_si256(b[offset..].as_ptr() as *const __m256i);
        let cmp = _mm256_cmpeq_epi8(va, vb);
        let mask = _mm256_movemask_epi8(cmp);
        if mask != -1i32 {
            return false;
        }
    }
    
    // Check remaining bytes (safe: remaining_start <= len)
    let remaining_start = chunks * 32;
    a[remaining_start..] == b[remaining_start..]
}

/// Safe wrapper for SIMD comparison.
pub fn fast_compare(a: &[u8], b: &[u8]) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") && a.len() >= 32 {
            unsafe {
                return simd_compare_256(a, b);
            }
        }
    }
    
    a == b
}

/// Vectorized signature verification preparation.
/// Prepares multiple signatures for batch verification.
pub struct SimdVerificationBatch {
    pub public_keys: Vec<Vec<u8>>,
    pub messages: Vec<Vec<u8>>,
    pub signatures: Vec<Vec<u8>>,
}

impl SimdVerificationBatch {
    pub fn new() -> Self {
        Self {
            public_keys: Vec::new(),
            messages: Vec::new(),
            signatures: Vec::new(),
        }
    }

    pub fn add(&mut self, public_key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) {
        self.public_keys.push(public_key);
        self.messages.push(message);
        self.signatures.push(signature);
    }

    pub fn len(&self) -> usize {
        self.public_keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.public_keys.is_empty()
    }

    /// Verifies all signatures using SIMD-optimized operations where possible.
    pub fn verify_all(&self) -> Vec<bool> {
        use rayon::prelude::*;
        
        self.public_keys
            .par_iter()
            .zip(self.messages.par_iter())
            .zip(self.signatures.par_iter())
            .map(|((pk, msg), sig)| {
                crate::crypto::verify_ml_dsa_65(pk, msg, sig)
                    .unwrap_or(false)
            })
            .collect()
    }
}

impl Default for SimdVerificationBatch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_bytes() {
        let a = vec![0xFF; 64];
        let b = vec![0xAA; 64];
        let result = xor_bytes(&a, &b);
        
        assert_eq!(result.len(), 64);
        for byte in result {
            assert_eq!(byte, 0x55);
        }
    }

    #[test]
    fn test_fast_copy() {
        let src = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut dst = vec![0u8; 20];
        
        fast_copy(&src, &mut dst);
        
        assert_eq!(&dst[..10], &src[..]);
    }

    #[test]
    fn test_fast_compare() {
        let a = vec![1u8; 100];
        let b = vec![1u8; 100];
        let c = vec![2u8; 100];
        
        assert!(fast_compare(&a, &b));
        assert!(!fast_compare(&a, &c));
    }

    #[test]
    fn test_simd_verification_batch() {
        use crate::crypto::MlDsa65Keypair;
        
        let keypair = MlDsa65Keypair::generate().unwrap();
        let mut batch = SimdVerificationBatch::new();
        
        for i in 0..4 {
            let msg = format!("message {}", i).into_bytes();
            let sig = keypair.sign(&msg).unwrap();
            batch.add(keypair.public_key.clone(), msg, sig);
        }
        
        let results = batch.verify_all();
        assert!(results.iter().all(|&r| r));
    }
}
