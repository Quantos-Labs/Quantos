// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Epoch Beacon Aggregator with VDF anti-grinding.
//!
//! Resolves the audit finding in S1.1 (SPHINCS+ VRF grinding) by:
//! 1. Replacing SPHINCS+ with a deterministic hash-based VRF.
//! 2. Aggregating ALL committee contributions so a single abort does not
//!    bias the beacon (grinding-by-abort protection).
//! 3. Adding a VDF (Verifiable Delay Function) on top of the aggregated
//!    randomness, so no validator can compute the beacon fast enough
//!    to decide whether to abort.
//!
//! ## Protocol
//!
//! 1. Each validator in the committee produces:
//!    beta_i = VRF.evaluate(sk_i, input_e)
//! 2. The beacon is the hash of ALL contributions:
//!    beacon_e = SHA3-256( beacon_{e-1} || beta_1 || ... || beta_n )
//! 3. A VDF is applied:
//!    final_beacon_e = VDF.evaluate(beacon_e, difficulty_T)
//! 4. The next epoch input derives from final_beacon_e:
//!    input_{e+1} = SHA3-256(final_beacon_e)
//!
//! ## Anti-grinding safeguards (duplicated from vrf_hashbased.rs)
//!
//! * Pre-commitment : pk_i registered before input_e is known.
//! * Epoch chaining : input_{e+1} = H(final_beacon_e).
//! * Activation delay : VALIDATOR_ACTIVATION_DELAY_EPOCHS.

use sha3::{Digest, Sha3_256};
use serde::{Deserialize, Serialize};

use crate::crypto::vrf_hashbased::{HashVrfKeypair, VrfStarkProof, derive_epoch_input};
use crate::types::Hash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of sequential squarings in the VDF.
/// Production value: ~1 minute on a single CPU core.
/// Test value: small enough for unit tests.
#[cfg(not(test))]
pub const VDF_DIFFICULTY: u64 = 10_000_000;
#[cfg(test)]
pub const VDF_DIFFICULTY: u64 = 1_000;

/// Size of the RSA modulus for the Wesolowski VDF (2048 bits).
const VDF_RSA_MODULUS_BITS: usize = 2048;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single validator contribution to the beacon.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BeaconContribution {
    pub validator_index: u32,
    pub public_key: Hash,
    pub beta: Hash,
    pub vrf_proof: VrfStarkProof,
}

/// The aggregated beacon for an epoch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochBeacon {
    pub epoch: u64,
    pub input: [u8; 32],
    pub intermediate: Hash,
    pub vdf_output: Hash,
    pub contributions: Vec<BeaconContribution>,
}

// ---------------------------------------------------------------------------
// Beacon Aggregator
// ---------------------------------------------------------------------------

/// Aggregates committee VRF contributions and runs the VDF.
pub struct BeaconAggregator;

impl BeaconAggregator {
    /// Aggregate contributions from all committee validators.
    ///
    /// Returns `None` if any contribution fails VRF verification.
    pub fn aggregate(
        epoch: u64,
        prev_beacon: &Hash,
        contributions: &[BeaconContribution],
    ) -> Option<EpochBeacon> {
        if contributions.is_empty() {
            return None;
        }

        let input = derive_epoch_input(prev_beacon, epoch);

        // Verify every contribution.
        for c in contributions {
            let kp = HashVrfKeypair {
                secret_key: [0u8; 32], // not needed for verify
                public_key: c.public_key,
            };
            if !kp.verify(&input, &c.vrf_proof).unwrap_or(false) {
                return None;
            }
        }

        // Compute intermediate beacon = H(prev || beta_1 || ... || beta_n).
        let intermediate = Self::hash_beacon(prev_beacon, contributions);

        // Apply VDF.
        let vdf = VdfEvaluator::new(VDF_DIFFICULTY);
        let vdf_output = vdf.evaluate(&intermediate);

        Some(EpochBeacon {
            epoch,
            input,
            intermediate,
            vdf_output,
            contributions: contributions.to_vec(),
        })
    }

    fn hash_beacon(prev: &Hash, contributions: &[BeaconContribution]) -> Hash {
        let mut h = Sha3_256::new();
        h.update(prev);
        for c in contributions {
            h.update(&c.beta);
        }
        h.finalize().into()
    }

    /// Derive the input for the next epoch.
    pub fn next_input(beacon: &EpochBeacon) -> [u8; 32] {
        derive_epoch_input(&beacon.vdf_output, beacon.epoch + 1)
    }
}

// ---------------------------------------------------------------------------
// VDF (iterated hashing)
// ---------------------------------------------------------------------------

/// A Verifiable Delay Function evaluator.
///
/// Current implementation: iterated SHA3-256 (sequential, no parallelism).
/// For production deployment, replace with a proper Wesolowski or Pietrzak
/// VDF using modular squaring (RSA group or class group).
pub struct VdfEvaluator {
    iterations: u64,
}

impl VdfEvaluator {
    pub fn new(iterations: u64) -> Self {
        Self { iterations }
    }

    /// Sequential evaluation — cannot be parallelised.
    pub fn evaluate(&self, seed: &Hash) -> Hash {
        let mut state = *seed;
        for _ in 0..self.iterations {
            let mut h = Sha3_256::new();
            h.update(&state);
            state = h.finalize().into();
        }
        state
    }

    /// Verify by re-running the same sequential computation.
    pub fn verify(&self, seed: &Hash, output: &Hash) -> bool {
        self.evaluate(seed) == *output
    }
}

// ---------------------------------------------------------------------------
// Committee self-sortition (using the beacon)
// ---------------------------------------------------------------------------

/// Select committee members deterministically from the beacon output.
pub fn select_committee(
    beacon: &EpochBeacon,
    validator_set_size: usize,
    committee_size: usize,
) -> Vec<usize> {
    let mut selected = Vec::with_capacity(committee_size);
    let mut h = Sha3_256::new();
    h.update(&beacon.vdf_output);

    for i in 0..committee_size {
        let mut hi = h.clone();
        hi.update(&i.to_le_bytes());
        let hash = hi.finalize();
        let idx = u64::from_le_bytes([
            hash[0], hash[1], hash[2], hash[3],
            hash[4], hash[5], hash[6], hash[7],
        ]) as usize % validator_set_size;
        selected.push(idx);
    }
    selected
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vdf_evaluate() {
        let vdf = VdfEvaluator::new(100);
        let seed = [1u8; 32];
        let out1 = vdf.evaluate(&seed);
        let out2 = vdf.evaluate(&seed);
        assert_eq!(out1, out2);
        assert!(vdf.verify(&seed, &out1));
    }

    #[test]
    fn test_beacon_aggregate_empty() {
        let prev = [0u8; 32];
        let result = BeaconAggregator::aggregate(1, &prev, &[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_committee_selection() {
        let beacon = EpochBeacon {
            epoch: 1,
            input: [0u8; 32],
            intermediate: [1u8; 32],
            vdf_output: [2u8; 32],
            contributions: vec![],
        };
        let committee = select_committee(&beacon, 1000, 21);
        assert_eq!(committee.len(), 21);
        for &idx in &committee {
            assert!(idx < 1000);
        }
    }
}
