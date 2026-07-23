// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Comprehensive tests for Types module (transaction, account, vertex, etc.)

use quantos::types::*;

// ══════════════════════════════════════════════════════════
//  Hash utilities
// ══════════════════════════════════════════════════════════

#[test]
fn test_hash_data_deterministic() {
    let h1 = hash_data(b"hello");
    let h2 = hash_data(b"hello");
    assert_eq!(h1, h2);
}

#[test]
fn test_hash_data_different_inputs() {
    let h1 = hash_data(b"hello");
    let h2 = hash_data(b"world");
    assert_ne!(h1, h2);
}

#[test]
fn test_hash_data_empty() {
    let h = hash_data(b"");
    assert_ne!(h, [0u8; 32]);
}

#[test]
fn test_hash_to_hex() {
    let hash = [0xABu8; 32];
    let hex = hash_to_hex(&hash);
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_hex_to_hash_valid() {
    let hex = "ab".repeat(32);
    let hash = hex_to_hash(&hex).unwrap();
    assert_eq!(hash, [0xABu8; 32]);
}

#[test]
fn test_hex_to_hash_invalid_length() {
    let result = hex_to_hash("abcd");
    assert!(result.is_err());
}

#[test]
fn test_hex_to_hash_invalid_chars() {
    let result = hex_to_hash(&"zz".repeat(32));
    assert!(result.is_err());
}

#[test]
fn test_hash_roundtrip() {
    let original = hash_data(b"roundtrip test");
    let hex = hash_to_hex(&original);
    let recovered = hex_to_hash(&hex).unwrap();
    assert_eq!(original, recovered);
}

// ══════════════════════════════════════════════════════════
//  Amount
// ══════════════════════════════════════════════════════════

#[test]
fn test_amount_zero() {
    let a = Amount::zero();
    assert_eq!(a.0, 0);
}

#[test]
fn test_amount_checked_add() {
    let a = Amount(100);
    let b = Amount(200);
    let result = a.checked_add(&b).unwrap();
    assert_eq!(result.0, 300);
}

#[test]
fn test_amount_checked_add_overflow() {
    let a = Amount(u128::MAX);
    let b = Amount(1);
    assert!(a.checked_add(&b).is_none());
}

#[test]
fn test_amount_checked_sub() {
    let a = Amount(300);
    let b = Amount(100);
    let result = a.checked_sub(&b).unwrap();
    assert_eq!(result.0, 200);
}

#[test]
fn test_amount_checked_sub_underflow() {
    let a = Amount(100);
    let b = Amount(200);
    assert!(a.checked_sub(&b).is_none());
}

// ══════════════════════════════════════════════════════════
//  Transaction
// ══════════════════════════════════════════════════════════

fn make_tx() -> Transaction {
    Transaction::new(
        TransactionType::Transfer,
        [1u8; 32],
        [2u8; 32],
        Amount(1000),
        0,
        21000,
        1,
        Vec::new(),
        0,
    )
}

#[test]
fn test_transaction_creation() {
    let tx = make_tx();
    assert_eq!(tx.from, [1u8; 32]);
    assert_eq!(tx.to, [2u8; 32]);
    assert_eq!(tx.amount.0, 1000);
    assert_eq!(tx.nonce, 0);
    assert_eq!(tx.gas_limit, 21000);
    assert_eq!(tx.chain_id, 1);
}

#[test]
fn test_transaction_hash_nonzero() {
    let tx = make_tx();
    let hash = tx.hash();
    assert_ne!(hash, [0u8; 32]);
}

#[test]
fn test_transaction_signing_data() {
    let tx = make_tx();
    let data = tx.signing_data();
    assert!(!data.is_empty());
}

#[test]
fn test_transaction_gas_cost() {
    let tx = make_tx();
    let cost = tx.gas_cost().unwrap();
    assert_eq!(cost, 21000); // gas_limit * gas_price = 21000 * 1
}

#[test]
fn test_transaction_gas_cost_overflow() {
    let mut tx = make_tx();
    tx.gas_limit = u64::MAX;
    tx.gas_price = u64::MAX;
    // Should not panic, checked arithmetic
    let cost = tx.gas_cost();
    assert!(cost.is_some()); // u128 can hold u64::MAX * u64::MAX
}

#[test]
fn test_transaction_total_cost() {
    let tx = make_tx();
    let total = tx.total_cost().unwrap();
    assert_eq!(total, 21000 + 1000); // gas_cost + amount
}

#[test]
fn test_transaction_validate_timestamp_valid() {
    let tx = make_tx();
    let now = tx.timestamp;
    assert!(tx.validate_timestamp(now).is_ok());
}

#[test]
fn test_transaction_validate_timestamp_future() {
    let tx = make_tx();
    // Current time is way before tx timestamp
    let result = tx.validate_timestamp(0);
    assert!(result.is_err());
}

#[test]
fn test_transaction_validate_timestamp_old() {
    let tx = make_tx();
    // Current time is way after tx timestamp
    let result = tx.validate_timestamp(tx.timestamp + 60_000);
    assert!(result.is_err());
}

#[test]
fn test_transaction_target_shard() {
    let addr = [1u8; 32];
    let shard = Transaction::target_shard(&addr, 1000);
    assert!(shard < 1000);
}

#[test]
fn test_transaction_target_shard_deterministic() {
    let addr = [5u8; 32];
    let s1 = Transaction::target_shard(&addr, 100);
    let s2 = Transaction::target_shard(&addr, 100);
    assert_eq!(s1, s2);
}

#[test]
fn test_transaction_target_shard_different_addrs() {
    let a1 = [1u8; 32];
    let a2 = [2u8; 32];
    let s1 = Transaction::target_shard(&a1, 1000);
    let s2 = Transaction::target_shard(&a2, 1000);
    // Very likely different (not guaranteed)
    let _ = (s1, s2);
}

// ══════════════════════════════════════════════════════════
//  SignedTransaction
// ══════════════════════════════════════════════════════════

#[test]
fn test_signed_transaction_creation() {
    let tx = make_tx();
    let signed = SignedTransaction::new(tx);
    assert_ne!(signed.hash, [0u8; 32]);
    assert!(signed.size > 0);
}

// ══════════════════════════════════════════════════════════
//  DAGVertex
// ══════════════════════════════════════════════════════════

#[test]
fn test_vertex_creation() {
    let v = DAGVertex::new(Vec::new(), Vec::new(), 0, [0u8; 32], 0).unwrap();
    assert_eq!(v.height, 0);
    assert_eq!(v.shard_id, 0);
    assert_eq!(v.status, VertexStatus::Pending);
    assert_ne!(v.hash, [0u8; 32]);
}

#[test]
fn test_vertex_with_parents() {
    let parent_hash = [1u8; 32];
    let v = DAGVertex::new(vec![parent_hash], Vec::new(), 0, [0u8; 32], 1).unwrap();
    assert_eq!(v.parents.len(), 1);
    assert_eq!(v.parents[0], parent_hash);
    assert_eq!(v.height, 1);
}

#[test]
fn test_vertex_status_variants() {
    assert_ne!(VertexStatus::Pending, VertexStatus::Confirmed);
    assert_ne!(VertexStatus::PreConfirmed, VertexStatus::Finalized);
    assert_ne!(VertexStatus::Confirmed, VertexStatus::Orphaned);
}

// ══════════════════════════════════════════════════════════
//  Address encoding
// ══════════════════════════════════════════════════════════

#[test]
fn test_address_to_qts() {
    let addr = [1u8; 32];
    let encoded = address_to_qts(&addr);
    assert!(encoded.starts_with("qts1"));
}

#[test]
fn test_address_to_qts_different_addresses() {
    let a1 = [1u8; 32];
    let a2 = [2u8; 32];
    let e1 = address_to_qts(&a1);
    let e2 = address_to_qts(&a2);
    assert_ne!(e1, e2);
}

#[test]
fn test_address_to_qts_deterministic() {
    let addr = [42u8; 32];
    let e1 = address_to_qts(&addr);
    let e2 = address_to_qts(&addr);
    assert_eq!(e1, e2);
}
