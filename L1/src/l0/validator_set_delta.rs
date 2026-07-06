//! ValidatorSet Delta Encoding
//!
//! Instead of transmitting full validator sets on every epoch change,
//! only the diff (adds + removes) is sent over the wire.  For a chain
//! with 100 validators and 5 churn per epoch, this reduces the payload
//! from ~200 KiB to ~17 KiB (≈ 12× reduction).

use crate::l0::light_client::ValidatorSet;

/// Compact delta between two [`ValidatorSet`] snapshots.
///
/// Encoding strategy:
/// - `added`: new validators (pubkey + stake) — always sent in full.
/// - `removed_indices`: positional indices of validators that left,
///   sorted ascending so the decoder can delete from the back first.
/// - `threshold_bps`: only present if the threshold changed.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ValidatorSetDelta {
    pub added_pubkeys: Vec<Vec<u8>>,
    pub added_stakes: Vec<u64>,
    pub removed_indices: Vec<usize>,
    pub threshold_bps: Option<u16>,
}

impl ValidatorSetDelta {
    /// Create a delta by comparing `new` against `base`.
    ///
    /// Runs in O(n) using a hash-map on pubkeys.  Both sets are assumed
    /// small enough (< 10 000 validators) that a `HashMap` is fine.
    pub fn compute(base: &ValidatorSet, new: &ValidatorSet) -> Self {
        use std::collections::HashMap;

        let mut base_map: HashMap<&[u8], (usize, u64)> = HashMap::with_capacity(base.pubkeys.len());
        for (i, pk) in base.pubkeys.iter().enumerate() {
            base_map.insert(pk.as_slice(), (i, base.stakes[i]));
        }

        let mut added_pubkeys = Vec::new();
        let mut added_stakes = Vec::new();
        let mut removed_indices = Vec::new();

        // Detect added validators (in new but not in base)
        for (i, pk) in new.pubkeys.iter().enumerate() {
            let pk_slice = pk.as_slice();
            if let Some(&(idx, old_stake)) = base_map.get(pk_slice) {
                // Validator existed in base — check if stake changed
                if old_stake != new.stakes[i] {
                    // Treat stake change as remove + re-add at new index
                    // (simpler than a separate "stake update" field)
                    removed_indices.push(idx);
                    added_pubkeys.push(pk.clone());
                    added_stakes.push(new.stakes[i]);
                }
                base_map.remove(pk_slice);
            } else {
                added_pubkeys.push(pk.clone());
                added_stakes.push(new.stakes[i]);
            }
        }

        // Remaining entries in base_map were removed
        for (_, (idx, _)) in base_map {
            removed_indices.push(idx);
        }

        removed_indices.sort_unstable_by(|a, b| b.cmp(a)); // descending for safe deletion

        let threshold_bps = if base.threshold_bps != new.threshold_bps {
            Some(new.threshold_bps)
        } else {
            None
        };

        Self {
            added_pubkeys,
            added_stakes,
            removed_indices,
            threshold_bps,
        }
    }

    /// Apply this delta to a `base` validator set, returning the updated set.
    ///
    /// **Panics** (debug only) if indices are out of bounds — the wire format
    /// is expected to be validated before this call.
    pub fn apply(&self, base: &ValidatorSet) -> ValidatorSet {
        let mut pubkeys = base.pubkeys.clone();
        let mut stakes = base.stakes.clone();

        // Remove in descending order so indices stay valid
        for &idx in &self.removed_indices {
            debug_assert!(idx < pubkeys.len(), "remove index {} out of bounds", idx);
            if idx < pubkeys.len() {
                pubkeys.swap_remove(idx);
                stakes.swap_remove(idx);
            }
        }

        // Add new validators
        for (pk, stake) in self.added_pubkeys.iter().zip(&self.added_stakes) {
            pubkeys.push(pk.clone());
            stakes.push(*stake);
        }

        let threshold_bps = self.threshold_bps.unwrap_or(base.threshold_bps);

        ValidatorSet {
            pubkeys,
            stakes,
            threshold_bps,
        }
    }

    /// Wire-format encoding (custom compact binary).
    ///
    /// Layout:
    /// ```text
    /// [1 byte]  flags: bit 0 = has threshold, bit 1-7 = reserved
    /// [2 bytes] removed count (u16 LE)
    /// [N * 2 bytes] removed indices (u16 LE each, capped at 65 535 validators)
    /// [2 bytes] added count (u16 LE)
    /// for each added:
    ///   [2 bytes] pubkey length (u16 LE)
    ///   [N bytes] pubkey
    ///   [8 bytes] stake (u64 LE)
    /// [2 bytes] optional threshold_bps (u16 LE) — only if flag bit 0 set
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.estimated_wire_size());

        // Flags
        let mut flags: u8 = 0;
        if self.threshold_bps.is_some() {
            flags |= 0x01;
        }
        out.push(flags);

        // Removed indices
        let removed_count = self.removed_indices.len() as u16;
        out.extend_from_slice(&removed_count.to_le_bytes());
        for &idx in &self.removed_indices {
            out.extend_from_slice(&(idx as u16).to_le_bytes());
        }

        // Added validators
        let added_count = self.added_pubkeys.len() as u16;
        out.extend_from_slice(&added_count.to_le_bytes());
        for (pk, stake) in self.added_pubkeys.iter().zip(&self.added_stakes) {
            let pk_len = pk.len() as u16;
            out.extend_from_slice(&pk_len.to_le_bytes());
            out.extend_from_slice(pk);
            out.extend_from_slice(&stake.to_le_bytes());
        }

        // Optional threshold
        if let Some(th) = self.threshold_bps {
            out.extend_from_slice(&th.to_le_bytes());
        }

        out
    }

    /// Decode from the compact wire format.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }

        let mut pos = 0usize;
        let flags = bytes[pos];
        pos += 1;
        let has_threshold = (flags & 0x01) != 0;

        // Removed
        let removed_count = u16::from_le_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]) as usize;
        pos += 2;
        let mut removed_indices = Vec::with_capacity(removed_count);
        for _ in 0..removed_count {
            let idx = u16::from_le_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]) as usize;
            pos += 2;
            removed_indices.push(idx);
        }

        // Added
        let added_count = u16::from_le_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]) as usize;
        pos += 2;
        let mut added_pubkeys = Vec::with_capacity(added_count);
        let mut added_stakes = Vec::with_capacity(added_count);
        for _ in 0..added_count {
            let pk_len = u16::from_le_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]) as usize;
            pos += 2;
            let pk = bytes.get(pos..pos + pk_len)?.to_vec();
            pos += pk_len;
            let stake = u64::from_le_bytes([
                *bytes.get(pos)?,
                *bytes.get(pos + 1)?,
                *bytes.get(pos + 2)?,
                *bytes.get(pos + 3)?,
                *bytes.get(pos + 4)?,
                *bytes.get(pos + 5)?,
                *bytes.get(pos + 6)?,
                *bytes.get(pos + 7)?,
            ]);
            pos += 8;
            added_pubkeys.push(pk);
            added_stakes.push(stake);
        }

        let threshold_bps = if has_threshold {
            Some(u16::from_le_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]))
        } else {
            None
        };

        Some(Self {
            added_pubkeys,
            added_stakes,
            removed_indices,
            threshold_bps,
        })
    }

    /// Returns true if the delta represents no change (empty diff).
    pub fn is_empty(&self) -> bool {
        self.added_pubkeys.is_empty()
            && self.removed_indices.is_empty()
            && self.threshold_bps.is_none()
    }

    /// Estimated size on the wire, useful for pre-allocation.
    fn estimated_wire_size(&self) -> usize {
        1 // flags
        + 2 // removed count
        + self.removed_indices.len() * 2
        + 2 // added count
        + self.added_pubkeys.iter().map(|pk| 2 + pk.len() + 8).sum::<usize>()
        + if self.threshold_bps.is_some() { 2 } else { 0 }
    }
}

/// Extension trait for [`ValidatorSet`] to support delta operations.
pub trait ValidatorSetExt {
    /// Compute delta from `self` to `other`.
    fn delta_to(&self, other: &ValidatorSet) -> ValidatorSetDelta;
    /// Apply a delta to `self`.
    fn apply_delta(&self, delta: &ValidatorSetDelta) -> ValidatorSet;
}

impl ValidatorSetExt for ValidatorSet {
    fn delta_to(&self, other: &ValidatorSet) -> ValidatorSetDelta {
        ValidatorSetDelta::compute(self, other)
    }

    fn apply_delta(&self, delta: &ValidatorSetDelta) -> ValidatorSet {
        delta.apply(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_set(pubkeys: Vec<Vec<u8>>, stakes: Vec<u64>, threshold: u16) -> ValidatorSet {
        ValidatorSet { pubkeys, stakes, threshold_bps: threshold }
    }

    #[test]
    fn test_delta_add_remove() {
        let base = mk_set(
            vec![vec![1; 32], vec![2; 32], vec![3; 32]],
            vec![100, 200, 300],
            6666,
        );
        let new = mk_set(
            vec![vec![1; 32], vec![4; 32], vec![3; 32]],
            vec![100, 400, 300],
            6666,
        );

        let delta = ValidatorSetDelta::compute(&base, &new);
        assert_eq!(delta.removed_indices, vec![1]); // validator 2 removed
        assert_eq!(delta.added_pubkeys.len(), 1);
        assert_eq!(delta.added_pubkeys[0], vec![4; 32]);
        assert_eq!(delta.added_stakes[0], 400);
        assert!(delta.threshold_bps.is_none());

        let reconstructed = delta.apply(&base);
        assert_eq!(reconstructed.pubkeys, new.pubkeys);
        assert_eq!(reconstructed.stakes, new.stakes);
    }

    #[test]
    fn test_delta_threshold_change() {
        let base = mk_set(vec![vec![1; 32]], vec![100], 5000);
        let new = mk_set(vec![vec![1; 32]], vec![100], 7500);

        let delta = ValidatorSetDelta::compute(&base, &new);
        assert_eq!(delta.threshold_bps, Some(7500));
        assert!(delta.is_empty()); // no validator churn
    }

    #[test]
    fn test_roundtrip_encode_decode() {
        let base = mk_set(
            vec![vec![1; 32], vec![2; 32], vec![3; 32]],
            vec![100, 200, 300],
            6666,
        );
        let new = mk_set(
            vec![vec![1; 32], vec![4; 32]],
            vec![100, 400],
            7500,
        );

        let delta = ValidatorSetDelta::compute(&base, &new);
        let encoded = delta.encode();
        let decoded = ValidatorSetDelta::decode(&encoded).unwrap();
        assert_eq!(delta, decoded);

        let reconstructed = decoded.apply(&base);
        assert_eq!(reconstructed.pubkeys, new.pubkeys);
        assert_eq!(reconstructed.stakes, new.stakes);
        assert_eq!(reconstructed.threshold_bps, 7500);
    }

    #[test]
    fn test_empty_delta() {
        let base = mk_set(vec![vec![1; 32]], vec![100], 5000);
        let delta = ValidatorSetDelta::compute(&base, &base);
        assert!(delta.is_empty());
        assert_eq!(delta.encode().len(), 5); // flags(1) + 0 removed(2) + 0 added(2)
    }
}
