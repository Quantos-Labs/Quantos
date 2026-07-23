// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Comprehensive tests for the State module

use quantos::state::*;
use quantos::types::*;
use quantos::storage::Storage;
use tempfile::tempdir;

// ── Helpers ──────────────────────────────────────────────

fn setup_state_manager() -> (StateManager, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let storage = Storage::new(dir.path()).unwrap();
    let manager = StateManager::new(storage);
    (manager, dir)
}

// ══════════════════════════════════════════════════════════
//  State Manager
// ══════════════════════════════════════════════════════════

#[test]
fn test_state_manager_creation() {
    let (_manager, _dir) = setup_state_manager();
}

#[test]
fn test_state_manager_get_account_nonexistent() {
    let (manager, _dir) = setup_state_manager();
    let result = manager.get_account(&[99u8; 32]);
    // Returns default account for nonexistent addresses
    assert!(result.is_ok());
}

#[test]
fn test_state_manager_get_balance() {
    let (manager, _dir) = setup_state_manager();
    let result = manager.get_balance(&[1u8; 32]);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().0, 0);
}

#[test]
fn test_state_manager_get_nonce() {
    let (manager, _dir) = setup_state_manager();
    let result = manager.get_nonce(&[1u8; 32]);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

#[test]
fn test_state_manager_state_root() {
    let (manager, _dir) = setup_state_manager();
    let root = manager.state_root();
    // Initial state root should exist
    let _ = root;
}

#[test]
fn test_state_manager_auth_token() {
    let (manager, _dir) = setup_state_manager();
    let token = manager.get_auth_token();
    assert_ne!(token, [0u8; 32]);
}

#[test]
fn test_state_manager_set_balance() {
    let (manager, _dir) = setup_state_manager();
    let addr = [1u8; 32];
    let auth = manager.get_auth_token();
    
    manager.set_balance(&addr, Amount(10_000), &auth).unwrap();
    let balance = manager.get_balance(&addr).unwrap();
    assert_eq!(balance.0, 10_000);
}

// ══════════════════════════════════════════════════════════
//  State Rent
// ══════════════════════════════════════════════════════════

#[test]
fn test_rent_config_defaults() {
    let config = RentConfig::default();
    assert!(config.lamports_per_byte_epoch > 0);
    assert!(config.exemption_threshold_years > 0.0);
    assert!(config.slots_per_epoch > 0);
}

#[test]
fn test_storage_account_creation() {
    let sa = StorageAccount::new([1u8; 32], 1024, Amount(1_000_000), 0);
    assert_eq!(sa.data_size, 1024);
    assert_eq!(sa.balance.0, 1_000_000);
}

// ══════════════════════════════════════════════════════════
//  Flat Storage
// ══════════════════════════════════════════════════════════

#[test]
fn test_flat_storage_config_defaults() {
    let config = FlatStorageConfig::default();
    let _ = config;
}

#[test]
fn test_flat_account_state_creation() {
    let state = FlatAccountState::new([1u8; 32]);
    assert_eq!(state.balance.0, 0);
    assert_eq!(state.nonce, 0);
    assert!(!state.is_hot);
}

#[test]
fn test_flat_account_state_hash() {
    let s1 = FlatAccountState::new([1u8; 32]);
    let s2 = FlatAccountState::new([2u8; 32]);
    assert_ne!(s1.state_hash(), s2.state_hash());
}

#[test]
fn test_state_delta_creation() {
    let delta = StateDelta::new(0, [0u8; 32]);
    assert!(delta.is_empty());
    assert_eq!(delta.block_number, 0);
}

// ══════════════════════════════════════════════════════════
//  State Compression
// ══════════════════════════════════════════════════════════

#[test]
fn test_temporal_aggregator_creation() {
    let aggregator = TemporalAggregator::new(10);
    let result = aggregator.get_aggregated(0);
    assert!(result.is_none());
}

#[test]
fn test_semantic_diff_encoder_creation() {
    let _encoder = SemanticDiffEncoder::new();
}

// ══════════════════════════════════════════════════════════
//  STM (Software Transactional Memory)
// ══════════════════════════════════════════════════════════

#[test]
fn test_stm_transaction_creation() {
    let tx = StmTransaction::new(1);
    assert_eq!(tx.read_set_size(), 0);
    assert_eq!(tx.write_set_size(), 0);
}

#[test]
fn test_stm_transaction_read_write() {
    let mut tx = StmTransaction::new(1);
    tx.record_read(b"key1".to_vec(), 0);
    tx.record_write(b"key2".to_vec(), b"value2".to_vec());
    assert_eq!(tx.read_set_size(), 1);
    assert_eq!(tx.write_set_size(), 1);
}

#[test]
fn test_stm_manager_creation() {
    let _stm = StmManager::new(3);
}
