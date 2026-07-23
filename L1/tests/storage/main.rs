// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Comprehensive tests for the Storage module (storage/rocks.rs)

use quantos::storage::Storage;
use quantos::types::*;
use tempfile::tempdir;

// ── Helpers ──────────────────────────────────────────────

fn setup_storage() -> (Storage, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let storage = Storage::new(dir.path()).unwrap();
    (storage, dir)
}

fn make_account(addr: Address, balance: u128, nonce: u64) -> Account {
    let mut account = Account::with_balance(addr, Amount(balance));
    account.nonce = nonce;
    account
}

fn make_signed_tx(from: Address, to: Address, amount: u128, nonce: u64) -> SignedTransaction {
    let tx = Transaction::new(
        TransactionType::Transfer,
        from,
        to,
        Amount(amount),
        nonce,
        21000,
        0,
        Vec::new(),
        0,
    );
    SignedTransaction::new(tx)
}

// ── Basic storage operations ─────────────────────────────

#[test]
fn test_storage_creation() {
    let (_storage, _dir) = setup_storage();
}

#[test]
fn test_account_put_get() {
    let (storage, _dir) = setup_storage();
    let addr = [1u8; 32];
    let account = make_account(addr, 1000, 0);

    storage.put_account(&account).unwrap();
    let fetched = storage.get_account(&addr).unwrap().unwrap();
    assert_eq!(fetched.balance.0, 1000);
    assert_eq!(fetched.nonce, 0);
}

#[test]
fn test_account_not_found() {
    let (storage, _dir) = setup_storage();
    let addr = [99u8; 32];
    let result = storage.get_account(&addr).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_account_update() {
    let (storage, _dir) = setup_storage();
    let addr = [1u8; 32];

    let account = make_account(addr, 1000, 0);
    storage.put_account(&account).unwrap();

    let updated = make_account(addr, 2000, 1);
    storage.put_account(&updated).unwrap();

    let fetched = storage.get_account(&addr).unwrap().unwrap();
    assert_eq!(fetched.balance.0, 2000);
    assert_eq!(fetched.nonce, 1);
}

// ── Vertex storage ───────────────────────────────────────

#[test]
fn test_vertex_put_get() {
    let (storage, _dir) = setup_storage();
    let vertex = DAGVertex::new(Vec::new(), Vec::new(), 0, [0u8; 32], 0).unwrap();

    storage.put_vertex(&vertex).unwrap();
    let fetched = storage.get_vertex(&vertex.hash).unwrap().unwrap();
    assert_eq!(fetched.hash, vertex.hash);
    assert_eq!(fetched.height, 0);
}

#[test]
fn test_vertex_not_found() {
    let (storage, _dir) = setup_storage();
    let hash = [42u8; 32];
    let result = storage.get_vertex(&hash).unwrap();
    assert!(result.is_none());
}

// ── Transaction storage ──────────────────────────────────

#[test]
fn test_transaction_put_get() {
    let (storage, _dir) = setup_storage();
    let tx = make_signed_tx([1u8; 32], [2u8; 32], 100, 0);

    storage.put_transaction(&tx).unwrap();
    let fetched = storage.get_transaction(&tx.hash).unwrap().unwrap();
    assert_eq!(fetched.hash, tx.hash);
}

#[test]
fn test_transaction_not_found() {
    let (storage, _dir) = setup_storage();
    let hash = [42u8; 32];
    let result = storage.get_transaction(&hash).unwrap();
    assert!(result.is_none());
}

// ── Contract storage ─────────────────────────────────────

#[test]
fn test_contract_storage_put_get() {
    let (storage, _dir) = setup_storage();
    let addr = [1u8; 32];
    let mut writes = std::collections::HashMap::new();
    writes.insert(b"key1".to_vec(), b"value1".to_vec());
    writes.insert(b"key2".to_vec(), b"value2".to_vec());

    storage.update_contract_storage(&addr, &writes, &[]).unwrap();

    let loaded = storage.get_contract_storage(&addr).unwrap();
    assert_eq!(loaded.get(&b"key1".to_vec()), Some(&b"value1".to_vec()));
    assert_eq!(loaded.get(&b"key2".to_vec()), Some(&b"value2".to_vec()));
}

#[test]
fn test_contract_storage_delete() {
    let (storage, _dir) = setup_storage();
    let addr = [1u8; 32];
    let mut writes = std::collections::HashMap::new();
    writes.insert(b"key1".to_vec(), b"value1".to_vec());
    storage.update_contract_storage(&addr, &writes, &[]).unwrap();

    // Delete key1
    let deletes = vec![b"key1".to_vec()];
    storage.update_contract_storage(&addr, &std::collections::HashMap::new(), &deletes).unwrap();

    let loaded = storage.get_contract_storage(&addr).unwrap();
    assert!(loaded.get(&b"key1".to_vec()).is_none());
}

#[test]
fn test_contract_storage_empty() {
    let (storage, _dir) = setup_storage();
    let addr = [99u8; 32];
    let loaded = storage.get_contract_storage(&addr).unwrap();
    assert!(loaded.is_empty());
}

// ── Multiple accounts ────────────────────────────────────

#[test]
fn test_multiple_accounts() {
    let (storage, _dir) = setup_storage();

    for i in 0u8..10 {
        let addr = [i; 32];
        let account = make_account(addr, (i as u128) * 1000, i as u64);
        storage.put_account(&account).unwrap();
    }

    for i in 0u8..10 {
        let addr = [i; 32];
        let fetched = storage.get_account(&addr).unwrap().unwrap();
        assert_eq!(fetched.balance.0, (i as u128) * 1000);
    }
}

// ── Auth token ───────────────────────────────────────────

#[test]
fn test_auth_token_not_zero() {
    let (storage, _dir) = setup_storage();
    let token = storage.get_auth_token();
    assert_ne!(token, [0u8; 32]);
}

#[test]
fn test_auth_token_consistent() {
    let (storage, _dir) = setup_storage();
    let t1 = storage.get_auth_token();
    let t2 = storage.get_auth_token();
    assert_eq!(t1, t2);
}
