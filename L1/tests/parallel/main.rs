// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Comprehensive tests for the Parallel Execution module

use quantos::parallel::*;
use quantos::types::*;

// ══════════════════════════════════════════════════════════
//  Parallel Config
// ══════════════════════════════════════════════════════════

#[test]
fn test_parallel_config_defaults() {
    let config = ParallelConfig::default();
    assert!(config.workers_per_shard > 0);
    assert!(config.batch_size > 0);
    assert!(config.queue_capacity > 0);
}

#[test]
fn test_parallel_config_custom() {
    let mut config = ParallelConfig::default();
    config.workers_per_shard = 8;
    config.batch_size = 500;
    assert_eq!(config.workers_per_shard, 8);
    assert_eq!(config.batch_size, 500);
}

// ══════════════════════════════════════════════════════════
//  Shard Metrics
// ══════════════════════════════════════════════════════════

#[test]
fn test_shard_metrics_default() {
    let metrics = ShardMetrics::default();
    assert_eq!(metrics.tx_processed, 0);
    assert_eq!(metrics.tx_failed, 0);
}

#[test]
fn test_total_metrics_default() {
    let total = TotalMetrics::default();
    assert_eq!(total.tx_processed, 0);
}

// ══════════════════════════════════════════════════════════
//  Signature Verification
// ══════════════════════════════════════════════════════════

#[test]
fn test_sig_verify_result_valid() {
    let result = SigVerifyResult::Valid;
    assert!(result.is_valid());
    assert!(!result.is_error());
}

#[test]
fn test_sig_verify_result_invalid() {
    let result = SigVerifyResult::Invalid;
    assert!(!result.is_valid());
    assert!(!result.is_error());
}

#[test]
fn test_sig_verify_result_error() {
    let result = SigVerifyResult::Error("test".to_string());
    assert!(!result.is_valid());
    assert!(result.is_error());
}

#[test]
fn test_verify_signatures_batch_empty() {
    let results = verify_signatures_batch(&[]);
    assert!(results.is_empty());
}

#[test]
fn test_verify_signatures_batch_unsigned() {
    let tx = make_simple_tx([1u8; 32], [2u8; 32]);
    let results = verify_signatures_batch(&[tx]);
    // Unsigned tx should fail verification
    assert_eq!(results.len(), 1);
    assert!(!results[0].is_valid());
}

// ══════════════════════════════════════════════════════════
//  Parallel Error
// ══════════════════════════════════════════════════════════

#[test]
fn test_parallel_error_display() {
    let err = ParallelError::QueueFull(5);
    let msg = format!("{}", err);
    assert!(msg.contains("5"));
}

// ── Helper ───────────────────────────────────────────────

fn make_simple_tx(from: Address, to: Address) -> SignedTransaction {
    let tx = Transaction::new(
        TransactionType::Transfer,
        from,
        to,
        Amount(100),
        0,
        21000,
        0,
        Vec::new(),
        0,
    );
    SignedTransaction::new(tx)
}
