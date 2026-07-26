// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use rayon::prelude::*;
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

/// Verify a batch of ML-DSA-65 signatures in parallel.
///
/// ML-DSA-65 itself does not define a native "batch verification" primitive,
/// but we can exploit the now lock-free `verify_ml_dsa_65` / `VERIFY_CACHE`
/// path to run many independent verifications across all rayon workers
/// concurrently. This amortizes thread-pool scheduling overhead compared to
/// calling the single-tx wrapper once per transaction.
pub fn verify_ml_dsa_65_parallel_batch(items: &[(Vec<u8>, Vec<u8>, Vec<u8>)]) -> Vec<bool> {
    items
        .par_iter()
        .map(|(pubkey, message, signature)| {
            verify_ml_dsa_65(pubkey, message, signature).unwrap_or(false)
        })
        .collect()
}
