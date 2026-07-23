// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Pre-computed Tables for Cryptographic Acceleration
//!
//! Pre-computes expensive cryptographic values at startup to accelerate
//! runtime operations.
//!
//! ## Pre-computed Values
//! - NTT (Number Theoretic Transform) tables for ML-DSA-65
//! - Hash lookup tables
//! - Address derivation cache
//! - Modular arithmetic tables

use once_cell::sync::Lazy;
use dashmap::DashMap;
use lru::LruCache;
use std::sync::Mutex;
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::PublicKey as _PQPublicKeyTrait;

use crate::types::{Address, Hash, hash_data};
use sha3::{Digest, Sha3_256};

/// Signature verification cache: maps SHA3(pubkey|message|sig) -> bool
pub struct VerifyCache {
    cache: Mutex<LruCache<Vec<u8>, bool>>,
}

impl VerifyCache {
    pub fn new(capacity: usize) -> Self {
        use std::num::NonZeroUsize;
        let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1).unwrap());
        Self { cache: Mutex::new(LruCache::new(cap)) }
    }

    /// Get cached result or compute and store it.
    pub fn get_or_compute<F: FnOnce() -> bool>(&self, key: &[u8], compute: F) -> bool {
        let mut cache = self.cache.lock().unwrap();
        if let Some(v) = cache.get(key) {
            return *v;
        }

        let res = compute();
        cache.put(key.to_vec(), res);
        res
    }

    pub fn size(&self) -> usize { self.cache.lock().unwrap().len() }
}

/// Global verification cache instance (LRU, bounded by entries).
pub static VERIFY_CACHE: Lazy<VerifyCache> = Lazy::new(|| VerifyCache::new(200_000));

/// Parsed public key cache to avoid repeated `PublicKey::from_bytes` allocations.
pub struct PublicKeyCache {
    cache: Mutex<LruCache<Vec<u8>, mldsa65::PublicKey>>,
}

impl PublicKeyCache {
    pub fn new(capacity: usize) -> Self {
        use std::num::NonZeroUsize;
        let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1).unwrap());
        Self { cache: Mutex::new(LruCache::new(cap)) }
    }

    /// Get parsed public key by bytes, or parse and insert.
    pub fn get_or_parse(&self, key: &[u8]) -> Option<mldsa65::PublicKey> {
        let mut cache = self.cache.lock().unwrap();
        if let Some(pk) = cache.get(key) {
            return Some(pk.clone());
        }

        match mldsa65::PublicKey::from_bytes(key) {
            Ok(parsed) => {
                cache.put(key.to_vec(), parsed.clone());
                Some(parsed)
            }
            Err(_) => None,
        }
    }

    pub fn size(&self) -> usize { self.cache.lock().unwrap().len() }
}

pub static PUBLIC_KEY_CACHE: Lazy<PublicKeyCache> = Lazy::new(|| PublicKeyCache::new(50_000));

/// ML-DSA-65 modulus q = 8380417
pub const MLDSA_Q: i32 = 8380417;
/// ML-DSA-65 N = 256
pub const MLDSA_N: usize = 256;

/// Pre-computed NTT roots of unity for ML-DSA-65.
/// These values accelerate polynomial multiplication.
pub static NTT_ROOTS: Lazy<[i32; MLDSA_N]> = Lazy::new(|| {
    let mut roots = [0i32; MLDSA_N];
    let primitive_root = 1753; // Primitive 512th root of unity mod q
    
    let mut power = 1i64;
    for i in 0..MLDSA_N {
        roots[i] = power as i32;
        power = (power * primitive_root as i64) % MLDSA_Q as i64;
    }
    
    roots
});

/// Pre-computed inverse NTT roots.
pub static NTT_ROOTS_INV: Lazy<[i32; MLDSA_N]> = Lazy::new(|| {
    let mut roots_inv = [0i32; MLDSA_N];
    let inv_root = mod_inverse(1753, MLDSA_Q);
    
    let mut power = 1i64;
    for i in 0..MLDSA_N {
        roots_inv[i] = power as i32;
        power = (power * inv_root as i64) % MLDSA_Q as i64;
    }
    
    roots_inv
});

/// Pre-computed Montgomery reduction constants.
pub static MONTGOMERY_R: Lazy<i64> = Lazy::new(|| {
    1i64 << 32
});

pub static MONTGOMERY_R_INV: Lazy<i32> = Lazy::new(|| {
    mod_inverse((*MONTGOMERY_R % MLDSA_Q as i64) as i32, MLDSA_Q)
});

/// Computes modular inverse using extended Euclidean algorithm.
fn mod_inverse(a: i32, m: i32) -> i32 {
    let mut t = 0i64;
    let mut newt = 1i64;
    let mut r = m as i64;
    let mut newr = a as i64;
    
    while newr != 0 {
        let quotient = r / newr;
        (t, newt) = (newt, t - quotient * newt);
        (r, newr) = (newr, r - quotient * newr);
    }
    
    if t < 0 {
        t += m as i64;
    }
    
    t as i32
}

/// SHA3 round constants (pre-computed).
pub static KECCAK_RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// Keccak rotation offsets (pre-computed).
pub static KECCAK_ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Keccak pi lane indices (pre-computed).
pub static KECCAK_PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// Address derivation cache for frequently accessed addresses.
pub struct AddressCache {
    cache: DashMap<Vec<u8>, Address>,
    max_size: usize,
}

impl AddressCache {
    /// Creates a new address cache.
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: DashMap::with_capacity(max_size),
            max_size,
        }
    }

    /// Gets or computes address from public key.
    pub fn get_or_compute(&self, public_key: &[u8]) -> Address {
        if let Some(addr) = self.cache.get(public_key) {
            return *addr;
        }

        let address = hash_data(public_key);

        // Evict if full
        if self.cache.len() >= self.max_size {
            if let Some(key) = self.cache.iter().next().map(|e| e.key().clone()) {
                self.cache.remove(&key);
            }
        }

        self.cache.insert(public_key.to_vec(), address);
        address
    }

    /// Cache size.
    pub fn size(&self) -> usize {
        self.cache.len()
    }

    /// Clears the cache.
    pub fn clear(&self) {
        self.cache.clear();
    }
}

/// Global address cache.
pub static ADDRESS_CACHE: Lazy<AddressCache> = Lazy::new(|| {
    AddressCache::new(100_000)
});

/// Hash result cache for repeated hash operations.
pub struct HashCache {
    cache: DashMap<Vec<u8>, Hash>,
    max_size: usize,
}

impl HashCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: DashMap::with_capacity(max_size),
            max_size,
        }
    }

    /// Gets or computes hash.
    pub fn get_or_compute(&self, data: &[u8]) -> Hash {
        // Only cache for larger inputs where hashing is expensive
        if data.len() < 64 {
            return hash_data(data);
        }

        if let Some(hash) = self.cache.get(data) {
            return *hash;
        }

        let hash = hash_data(data);

        if self.cache.len() >= self.max_size {
            if let Some(key) = self.cache.iter().next().map(|e| e.key().clone()) {
                self.cache.remove(&key);
            }
        }

        self.cache.insert(data.to_vec(), hash);
        hash
    }

    pub fn size(&self) -> usize {
        self.cache.len()
    }

    pub fn clear(&self) {
        self.cache.clear();
    }
}

/// Global hash cache.
pub static HASH_CACHE: Lazy<HashCache> = Lazy::new(|| {
    HashCache::new(50_000)
});

/// Byte multiplication lookup table for GF(2^8).
/// Used in various cryptographic operations.
pub static GF256_MUL_TABLE: Lazy<[[u8; 256]; 256]> = Lazy::new(|| {
    let mut table = [[0u8; 256]; 256];
    
    for a in 0..256 {
        for b in 0..256 {
            table[a][b] = gf256_mul(a as u8, b as u8);
        }
    }
    
    table
});

/// GF(2^8) multiplication.
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let hi_bit = a & 0x80;
        a <<= 1;
        if hi_bit != 0 {
            a ^= 0x1B; // AES irreducible polynomial
        }
        b >>= 1;
    }
    
    result
}

/// Pre-computed Barrett reduction constants for common moduli.
pub struct BarrettConstants {
    pub modulus: u64,
    pub mu: u64, // floor(2^k / modulus)
    pub k: u32,
}

impl BarrettConstants {
    pub fn new(modulus: u64) -> Self {
        let k = 64u32;
        let mu = ((1u128 << k) / modulus as u128) as u64;
        Self { modulus, mu, k }
    }

    /// Performs Barrett reduction: a mod n.
    pub fn reduce(&self, a: u64) -> u64 {
        let q = ((a as u128 * self.mu as u128) >> self.k) as u64;
        let r = a - q * self.modulus;
        if r >= self.modulus {
            r - self.modulus
        } else {
            r
        }
    }
}

/// Pre-computed Barrett constants for ML-DSA-65.
pub static BARRETT_MLDSA65: Lazy<BarrettConstants> = Lazy::new(|| {
    BarrettConstants::new(MLDSA_Q as u64)
});

/// Accelerated NTT using pre-computed tables.
pub fn fast_ntt(poly: &mut [i32; MLDSA_N]) {
    let mut k = 0usize;
    let mut len = 128;
    
    while len >= 1 {
        let mut start = 0;
        while start < MLDSA_N {
            let zeta = NTT_ROOTS[k];
            k += 1;
            
            for j in start..start + len {
                let t = montgomery_reduce(zeta as i64 * poly[j + len] as i64);
                poly[j + len] = poly[j] - t;
                poly[j] = poly[j] + t;
            }
            
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Montgomery reduction.
fn montgomery_reduce(a: i64) -> i32 {
    let t = (a as i32).wrapping_mul(-58728449); // -q^-1 mod 2^32
    let t = a + (t as i64) * (MLDSA_Q as i64);
    (t >> 32) as i32
}

/// Accelerated inverse NTT.
pub fn fast_ntt_inv(poly: &mut [i32; MLDSA_N]) {
    let mut k = MLDSA_N - 1;
    let mut len = 1;
    
    while len < MLDSA_N {
        let mut start = 0;
        while start < MLDSA_N {
            let zeta = NTT_ROOTS_INV[k];
            k = k.wrapping_sub(1);
            
            for j in start..start + len {
                let t = poly[j];
                poly[j] = t + poly[j + len];
                poly[j + len] = montgomery_reduce(zeta as i64 * (t - poly[j + len]) as i64);
            }
            
            start += 2 * len;
        }
        len <<= 1;
    }
    
    // Final scaling
    let f = 41978; // 256^-1 mod q in Montgomery form
    for coeff in poly.iter_mut() {
        *coeff = montgomery_reduce(f as i64 * *coeff as i64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_roots_initialized() {
        assert_eq!(NTT_ROOTS[0], 1);
        assert!(NTT_ROOTS[1] != 0);
    }

    #[test]
    fn test_address_cache() {
        let pubkey = vec![1u8; 1952];
        
        let addr1 = ADDRESS_CACHE.get_or_compute(&pubkey);
        let addr2 = ADDRESS_CACHE.get_or_compute(&pubkey);
        
        assert_eq!(addr1, addr2);
        assert!(ADDRESS_CACHE.size() >= 1);
    }

    #[test]
    fn test_hash_cache() {
        let data = vec![42u8; 1000];
        
        let hash1 = HASH_CACHE.get_or_compute(&data);
        let hash2 = HASH_CACHE.get_or_compute(&data);
        
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_barrett_reduction() {
        let constants = BarrettConstants::new(MLDSA_Q as u64);
        
        let a = 1234567890u64;
        let result = constants.reduce(a);
        
        assert_eq!(result, a % MLDSA_Q as u64);
    }

    #[test]
    fn test_gf256_mul() {
        assert_eq!(GF256_MUL_TABLE[2][3], gf256_mul(2, 3));
        assert_eq!(GF256_MUL_TABLE[0][100], 0);
        assert_eq!(GF256_MUL_TABLE[1][50], 50);
    }

    #[test]
    fn test_mod_inverse() {
        let inv = mod_inverse(17, MLDSA_Q);
        let product = (17i64 * inv as i64) % MLDSA_Q as i64;
        assert_eq!(product, 1);
    }
}
