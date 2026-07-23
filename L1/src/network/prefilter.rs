// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use once_cell::sync::Lazy;
use parking_lot::RwLock;
use sha3::{Digest, Sha3_256};

/// Stateless prefilter to reject obvious garbage before expensive verify.
pub struct Prefilter {
    /// Small rotating bloom-like bitset for duplicate suppression
    bits: Vec<u64>,
    size_bits: usize,
}

impl Prefilter {
    pub fn new(size_bits: usize) -> Self {
        Self { bits: vec![0u64; (size_bits + 63) / 64], size_bits }
    }

    fn hash64(&self, data: &[u8]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        data.hash(&mut h);
        h.finish()
    }

    fn insert_hash(&mut self, h: u64) {
        let idx = (h as usize) % self.size_bits;
        self.bits[idx / 64] |= 1 << (idx % 64);
    }

    fn contains_hash(&self, h: u64) -> bool {
        let idx = (h as usize) % self.size_bits;
        (self.bits[idx / 64] & (1 << (idx % 64))) != 0
    }

    /// Basic entropy test: count distinct bytes
    fn entropy_ok(data: &[u8]) -> bool {
        if data.len() < 8 { return false; }
        let mut seen = [false; 256];
        let mut distinct = 0usize;
        for &b in data.iter().take(64) {
            let idx = b as usize;
            if !seen[idx] {
                seen[idx] = true;
                distinct += 1;
                if distinct >= 8 { return true; }
            }
        }
        false
    }

    /// Check a transaction payload bytes conservatively.
    pub fn check_transaction_bytes(&mut self, payload: &[u8]) -> Result<(), String> {
        // Size limits: reject trivially tiny or enormous payloads
        if payload.len() < 64 { return Err("payload too small".to_string()); }
        if payload.len() > 256 * 1024 { return Err("payload too large".to_string()); }

        // Quick hash duplicate suppression
        let mut h = Sha3_256::new();
        h.update(payload);
        let sum = h.finalize();
        let short = u64::from_le_bytes([sum[0], sum[1], sum[2], sum[3], sum[4], sum[5], sum[6], sum[7]]);

        if self.contains_hash(short) {
            return Err("duplicate or repeated payload".to_string());
        }

        // Entropy check on first bytes to reject all-zero / low-entropy garbage
        if !Self::entropy_ok(payload) {
            return Err("low entropy payload".to_string());
        }

        // pass: record
        self.insert_hash(short);
        Ok(())
    }
}

pub static PREFILTER: Lazy<RwLock<Prefilter>> = Lazy::new(|| RwLock::new(Prefilter::new(65536)));

/// Convenience wrapper used by networking/mempool
pub fn prefilter_tx_bytes(payload: &[u8]) -> Result<(), String> {
    PREFILTER.write().check_transaction_bytes(payload)
}
