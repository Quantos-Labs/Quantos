//! Comprehensive tests for the Mempool module

use quantos::crypto::MlDsa65Keypair;
use quantos::mempool::*;
use quantos::state::StateManager;
use quantos::storage::Storage;
use quantos::types::*;
use tempfile::tempdir;

// ── Helpers ──────────────────────────────────────────────

fn setup_mempool() -> (Mempool, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let storage = Storage::new(dir.path()).unwrap();
    let state_manager = StateManager::new(storage);
    let pool = Mempool::new(state_manager, 10_000);
    (pool, dir)
}

fn make_signed_tx(nonce: u64) -> (SignedTransaction, MlDsa65Keypair) {
    let keypair = MlDsa65Keypair::generate().unwrap();
    let from = keypair.address();
    let mut tx = Transaction::new(
        TransactionType::Transfer,
        from,
        [2u8; 32],
        Amount(100),
        nonce,
        21000,
        1,
        Vec::new(),
        0,
    );
    let sig = keypair.sign(&tx.signing_data()).unwrap();
    tx.set_signature(sig, keypair.public_key.clone()).unwrap();
    (SignedTransaction::new(tx), keypair)
}

// ══════════════════════════════════════════════════════════
//  Basic Operations
// ══════════════════════════════════════════════════════════

#[test]
fn test_mempool_creation() {
    let (_pool, _dir) = setup_mempool();
}

#[test]
fn test_mempool_add_transaction() {
    let (pool, _dir) = setup_mempool();
    let (tx, _kp) = make_signed_tx(0);
    let result = pool.add_transaction(tx);
    assert!(result.is_ok());
}

#[test]
fn test_mempool_add_and_get() {
    let (pool, _dir) = setup_mempool();
    let (tx, _kp) = make_signed_tx(0);
    let hash = tx.hash;
    pool.add_transaction(tx).unwrap();

    let fetched = pool.get_transaction(&hash);
    assert!(fetched.is_some());
}

#[test]
fn test_mempool_remove_transaction() {
    let (pool, _dir) = setup_mempool();
    let (tx, _kp) = make_signed_tx(0);
    let hash = tx.hash;
    pool.add_transaction(tx).unwrap();
    pool.remove_transaction(&hash);

    let fetched = pool.get_transaction(&hash);
    assert!(fetched.is_none());
}

#[test]
fn test_mempool_pending_count() {
    let (pool, _dir) = setup_mempool();
    assert_eq!(pool.pending_count(), 0);

    let (tx1, _) = make_signed_tx(0);
    pool.add_transaction(tx1).unwrap();
    assert_eq!(pool.pending_count(), 1);

    let (tx2, _) = make_signed_tx(0);
    pool.add_transaction(tx2).unwrap();
    assert_eq!(pool.pending_count(), 2);
}

#[test]
fn test_mempool_duplicate_rejected() {
    let (pool, _dir) = setup_mempool();
    let (tx, _kp) = make_signed_tx(0);
    pool.add_transaction(tx.clone()).unwrap();
    let result = pool.add_transaction(tx);
    assert!(result.is_err());
}

#[test]
fn test_mempool_clear() {
    let (pool, _dir) = setup_mempool();
    let (tx1, _) = make_signed_tx(0);
    let (tx2, _) = make_signed_tx(0);
    pool.add_transaction(tx1).unwrap();
    pool.add_transaction(tx2).unwrap();
    assert_eq!(pool.pending_count(), 2);

    pool.clear();
    assert_eq!(pool.pending_count(), 0);
}

// ══════════════════════════════════════════════════════════
//  Prune
// ══════════════════════════════════════════════════════════

#[test]
fn test_mempool_prune_confirmed() {
    let (pool, _dir) = setup_mempool();
    let (tx, _kp) = make_signed_tx(0);
    let hash = tx.hash;
    pool.add_transaction(tx).unwrap();
    assert_eq!(pool.pending_count(), 1);

    pool.prune_confirmed(&[hash]);
    assert_eq!(pool.pending_count(), 0);
}

// ══════════════════════════════════════════════════════════
//  MempoolError
// ══════════════════════════════════════════════════════════

#[test]
fn test_mempool_error_display() {
    let err = MempoolError::DuplicateTransaction;
    let msg = format!("{}", err);
    assert!(msg.contains("already exists"));
}

// ══════════════════════════════════════════════════════════
//  Routing Metrics
// ══════════════════════════════════════════════════════════

#[test]
fn test_routing_metrics_default() {
    let _metrics = RoutingMetrics::default();
    // Fields are private, just verify construction works
}
