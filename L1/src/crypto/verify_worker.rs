// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use crate::crypto::verify_ml_dsa_65;

/// Verify a single ML-DSA-65 signature.
///
/// Previously routed through a single-threaded channel worker that collected
/// requests into batches with a 5ms timeout. This serialized all verification
/// calls and added latency. Now calls `verify_ml_dsa_65` directly, which uses
/// an LRU cache (`VERIFY_CACHE`) and can run on any thread / rayon worker.
pub fn verify_ml_dsa_65_batch(pubkey: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
    verify_ml_dsa_65(&pubkey, &message, &signature).unwrap_or(false)
}
