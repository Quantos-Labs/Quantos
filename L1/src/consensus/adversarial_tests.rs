// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Adversarial Consensus Tests (§13)
//!
//! Tests verifying consensus safety under Byzantine conditions:
//! - Equivocation (double voting for different blocks)
//! - Duplicate votes ignored (no double-counting)
//! - Insufficient quorum → no commit
//! - Pipeline overflow / resource exhaustion
//! - Conflicting QCs at same slot detected
//! - Leader timeout → view change triggered
//! - Fast path failure → standard fallback
//! - Total order violation detection
//! - Bullshark commit rule under adversarial DAG
//! - BFT threshold boundary verification

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use crate::consensus::{
    ConsensusError, CommitteeManager,
    pipelining::{PipelinedConsensus, PipelineVote, PipelineConfig},
    optimistic_responsiveness::{
        OptimisticConsensus, OptimisticConfig, FastVote,
        StandardVote, VotePhase, ResponsivenessMode,
    },
    view_change::{ViewChangeManager, ViewChangeConfig, ViewChangeMessage, ViewChangeReason, NewViewMessage},
    safety_model::{
        SafetyChecker, QuorumCertificate as SafetyQC,
        quorum_threshold, max_byzantine, min_honest,
        BullsharkCommitRule,
    },
};
use crate::types::{Address, Hash, ShardId};
use crate::storage::Storage;

fn addr(s: u8) -> Address { [s; 32] }
fn hash(s: u8) -> Hash { [s; 32] }

fn mk_vote(bh: Hash, v: u64, vr: Address, st: u64) -> PipelineVote {
    PipelineVote { block_hash: bh, view: v, voter: vr, stake: st, signature: vec![0u8; 64] }
}

fn mk_fast(ph: Hash, r: u64, vr: Address, st: u64) -> FastVote {
    FastVote { proposal_hash: ph, round: r, voter: vr, stake: st, signature: vec![0u8; 64], received_at: Instant::now() }
}

fn mk_std(ph: Hash, r: u64, p: VotePhase, vr: Address, st: u64) -> StandardVote {
    StandardVote { proposal_hash: ph, round: r, phase: p, voter: vr, stake: st, signature: vec![0u8; 64] }
}

fn mk_sqc(vh: Hash, s: u64, sh: ShardId, sigs: Vec<(Address, Vec<u8>)>, st: u128) -> SafetyQC {
    SafetyQC { vertex_hash: vh, slot: s, shard_id: sh, signers: sigs.into_iter().collect(), total_stake: st, created_at: Instant::now() }
}

static TEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn temp_storage() -> Storage {
    let n = TEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "quantos_adv_test_{}_{}_{}",
        std::process::id(),
        n,
        nanos
    ));
    Storage::new(&dir).expect("failed to create temp storage for test")
}

/// Sets up a CommitteeManager with 21 registered validators (1000 stake each,
/// total_stake = 21000) and a rotated committee for epoch 0 / committee 0.
fn setup_committee_manager() -> Arc<CommitteeManager> {
    let cm = Arc::new(CommitteeManager::new(temp_storage(), 1, 21));
    for i in 0..21u8 {
        let v = crate::types::Validator::new(
            addr(100 + i),
            vec![0xAB; 32],
            crate::types::Amount(1000),
            vec![0xCD; 32],
        ).unwrap();
        cm.add_validator(v).unwrap();
    }
    cm.rotate_committees(0, 0, &hash(1)).unwrap();
    cm
}

// ── 1. Equivocation: same validator votes for 2 different blocks ────────

#[tokio::test]
async fn adv_equivocation_rejected() {
    let (tx, _) = mpsc::channel(100);
    let cfg = PipelineConfig { quorum_threshold: 3, total_stake: 5, ..Default::default() };
    let c = PipelinedConsensus::new(addr(1), cfg, tx);
    let blk = c.propose(vec![1], hash(42)).unwrap();
    c.on_vote(mk_vote(blk.hash, 0, addr(10), 1)).unwrap();
    let err = c.on_vote(mk_vote(hash(99), 0, addr(10), 1));
    assert!(err.is_err(), "Equivocation must be rejected");
    match err.err().unwrap() {
        ConsensusError::InvalidVote(m) => assert!(m.contains("wrong block"), "{}", m),
        o => panic!("Expected InvalidVote, got: {}", o),
    }
}

// ── 2. Duplicate vote: not double-counted ────────────────────────────────

#[tokio::test]
async fn adv_duplicate_vote_not_double_counted() {
    let (tx, _) = mpsc::channel(100);
    let cfg = PipelineConfig { quorum_threshold: 2, total_stake: 3, ..Default::default() };
    let c = PipelinedConsensus::new(addr(1), cfg, tx);
    let blk = c.propose(vec![1], hash(42)).unwrap();
    c.on_vote(mk_vote(blk.hash, 0, addr(10), 1)).unwrap();
    let dup = c.on_vote(mk_vote(blk.hash, 0, addr(10), 1)).unwrap();
    assert!(dup.is_none(), "Duplicate must not produce QC");
    let qc = c.on_vote(mk_vote(blk.hash, 0, addr(20), 1)).unwrap();
    assert!(qc.is_some(), "Quorum with 2 distinct validators");
    assert_eq!(qc.unwrap().total_stake, 2, "Stake must be 2 not 3");
}

// ── 3. Insufficient quorum → no commit ──────────────────────────────────

#[tokio::test]
async fn adv_insufficient_quorum_no_commit() {
    let (tx, mut rx) = mpsc::channel(100);
    let cfg = PipelineConfig { quorum_threshold: 5, total_stake: 7, ..Default::default() };
    let c = PipelinedConsensus::new(addr(1), cfg, tx);
    let blk = c.propose(vec![1], hash(42)).unwrap();
    for i in 0..3u8 {
        c.on_vote(mk_vote(blk.hash, 0, addr(10 + i), 1)).unwrap();
    }
    assert!(rx.try_recv().is_err(), "Must NOT commit with 3 < 5 quorum");
}

// ── 4. Pipeline overflow attack ──────────────────────────────────────────

#[tokio::test]
async fn adv_pipeline_overflow_rejected() {
    let (tx, _) = mpsc::channel(100);
    let cfg = PipelineConfig { max_pipeline_depth: 2, quorum_threshold: 1, total_stake: 1, ..Default::default() };
    let c = PipelinedConsensus::new(addr(1), cfg, tx);
    c.propose(vec![1], hash(1)).unwrap();
    c.advance_view();
    c.propose(vec![2], hash(2)).unwrap();
    c.advance_view();
    let result = c.propose(vec![3], hash(3));
    assert!(result.is_err(), "Pipeline overflow must be rejected");
    match result.err().unwrap() {
        ConsensusError::ResourceExhausted(m) => assert!(m.contains("Pipeline"), "{}", m),
        o => panic!("Expected ResourceExhausted, got: {}", o),
    }
}

// ── 5. View change on leader timeout ─────────────────────────────────────

#[test]
fn adv_view_change_on_timeout() {
    let (tx, _rx) = mpsc::channel(10);
    let cfg = ViewChangeConfig {
        view_timeout: Duration::from_millis(1),
        heartbeat_interval: Duration::from_millis(1),
        max_missed_heartbeats: 1,
        quorum_threshold: 2,
        total_stake: 3,
        vc_timeout: Duration::from_millis(10),
    };
    let mgr = ViewChangeManager::new([1u8; 32], 1, cfg, tx);
    std::thread::sleep(Duration::from_millis(10));
    let timeout_reason = mgr.check_timeout();
    assert!(timeout_reason.is_some(), "Timeout should be detected after heartbeat interval");
}

// ── 6. View change with insufficient quorum → no certificate ─────────────

#[test]
fn adv_view_change_insufficient_quorum_no_cert() {
    let (tx, _rx) = mpsc::channel(10);
    let cfg = ViewChangeConfig {
        quorum_threshold: 5,
        total_stake: 7,
        ..Default::default()
    };
    let mgr = ViewChangeManager::new([1u8; 32], 1, cfg, tx);

    for i in 0..2u8 {
        let msg = ViewChangeMessage::new(
            2, addr(10 + i), 1, None, ViewChangeReason::LeaderTimeout,
        );
        let result = mgr.on_view_change_message(msg).unwrap();
        assert!(result.is_none(), "No cert with 2 < 5 quorum");
    }
}

// ── 7. Equivocation reported → blame certificate created ─────────────────

#[test]
fn adv_equivocation_blame_created() {
    let (tx, _rx) = mpsc::channel(10);
    let cfg = ViewChangeConfig::default();
    let mgr = ViewChangeManager::new([1u8; 32], 1, cfg, tx);

    let result = mgr.report_equivocation(1, addr(42), vec![0xAA; 32], vec![0xBB; 32]);
    assert!(result.is_ok(), "report_equivocation should succeed");
}

// ── 8. Optimistic fast path failure → fallback ───────────────────────────

#[tokio::test]
async fn adv_fast_path_failure_falls_back() {
    let (tx, _rx) = mpsc::channel(10);
    let cfg = OptimisticConfig {
        quorum_threshold: 3,
        fast_quorum_threshold: 5,
        total_stake: 7,
        fast_path_timeout: Duration::from_millis(1),
        ..Default::default()
    };
    let oc = OptimisticConsensus::new(addr(1), cfg, tx);
    oc.propose(hash(42), hash(43)).unwrap();

    // Submit only 3 fast votes (below fast_quorum_threshold of 5)
    for i in 0..3u8 {
        let _ = oc.on_fast_vote(mk_fast(hash(42), 0, addr(10 + i), 1));
    }

    // Wait for fast timeout to elapse
    tokio::time::sleep(Duration::from_millis(5)).await;

    // The deadline is only checked lazily on the next incoming vote, so we
    // submit one more (distinct) vote to trigger the fallback to standard.
    let _ = oc.on_fast_vote(mk_fast(hash(42), 0, addr(20), 1));

    let mode = oc.mode();
    assert!(
        mode != ResponsivenessMode::Optimistic,
        "Must fall back from optimistic after insufficient fast votes"
    );
}

// ── 9. Safety checker detects conflicting QCs ────────────────────────────

#[test]
fn adv_safety_conflicting_qc_detected() {
    let cm = setup_committee_manager();
    let checker = SafetyChecker::new(cm);

    let shard = 0u16;
    let slot = 1u64;

    let qc_a = mk_sqc(hash(1), slot, shard, vec![(addr(10), vec![0xAA; 64])], 15000);
    let result_a = checker.verify_agreement(shard, slot, &qc_a);
    assert!(result_a.is_ok(), "First QC should be accepted");

    let qc_b = mk_sqc(hash(2), slot, shard, vec![(addr(20), vec![0xBB; 64])], 15000);
    let result_b = checker.verify_agreement(shard, slot, &qc_b);
    assert!(result_b.is_err(), "Conflicting QC must be detected");
}

// ── 10. Safety checker: insufficient stake rejected ──────────────────────

#[test]
fn adv_safety_insufficient_stake_rejected() {
    let cm = setup_committee_manager();
    let checker = SafetyChecker::new(cm);

    let shard = 0u16;
    let slot = 1u64;

    let qc = mk_sqc(hash(1), slot, shard, vec![(addr(10), vec![0xAA; 64])], 100);
    let result = checker.verify_agreement(shard, slot, &qc);
    assert!(result.is_err(), "QC with insufficient stake must be rejected");
}

// ── 11. Total order violation detected ───────────────────────────────────

#[test]
fn adv_total_order_violation_detected() {
    let cm = Arc::new(CommitteeManager::new(temp_storage(), 1, 21));
    let checker = SafetyChecker::new(cm);

    let shard = 0u16;
    checker.record_commit(shard, hash(10), 5);
    let result = checker.verify_total_order(shard, 3, hash(20), &[hash(10)]);
    assert!(result.is_err(), "Parent slot >= child slot must be detected");
}

// ── 12. Equivocation detection in safety checker ─────────────────────────

#[test]
fn adv_equivocation_detected_and_recorded() {
    let cm = Arc::new(CommitteeManager::new(temp_storage(), 1, 21));
    let checker = SafetyChecker::new(cm);

    let shard = 0u16;
    let slot = 1u64;

    let qc_a = mk_sqc(hash(1), slot, shard, vec![(addr(10), vec![0xAA; 64])], 15000);
    let qc_b = mk_sqc(hash(2), slot, shard, vec![(addr(10), vec![0xBB; 64])], 15000);

    checker.detect_equivocation(addr(10), qc_a, qc_b);

    let proofs = checker.drain_equivocations();
    assert_eq!(proofs.len(), 1, "One equivocation proof should be recorded");
    assert_eq!(proofs[0].validator, addr(10));
}

// ── 13. Bullshark: no commit without wave QC ─────────────────────────────

#[test]
fn adv_bullshark_no_commit_without_wave_qc() {
    let rule = BullsharkCommitRule::new();
    let shard = 0u16;
    rule.register_vertex(hash(1), 0, &[]);
    assert!(!rule.should_commit(shard, hash(1), 0), "Must not commit without wave QC");
}

// ── 14. Bullshark: commit with proper wave QC ────────────────────────────

#[test]
fn adv_bullshark_commit_with_wave_qc() {
    let rule = BullsharkCommitRule::new();
    let shard = 0u16;
    rule.register_vertex(hash(1), 0, &[]);
    rule.register_vertex(hash(2), 1, &[hash(1)]);
    rule.register_vertex(hash(3), 2, &[hash(2)]);
    rule.register_qc(shard, 2, hash(3));
    assert!(rule.should_commit(shard, hash(1), 0), "Anchor must commit with wave QC");
}

// ── 15. BFT threshold boundary tests ──────────────────────────────────────

#[test]
fn adv_bft_threshold_boundaries() {
    assert_eq!(max_byzantine(3), 0);
    assert_eq!(quorum_threshold(3), 3);
    assert_eq!(max_byzantine(4), 1);
    assert_eq!(quorum_threshold(4), 3);
    assert_eq!(max_byzantine(7), 2);
    assert_eq!(quorum_threshold(7), 5);
    assert_eq!(max_byzantine(10), 3);
    assert_eq!(quorum_threshold(10), 7);
    assert_eq!(max_byzantine(21), 6);
    assert_eq!(quorum_threshold(21), 15);
    assert_eq!(max_byzantine(100), 33);
    assert_eq!(quorum_threshold(100), 67);
    assert_eq!(min_honest(21), 15);
    assert_eq!(min_honest(100), 67);
}

// ── 16. Standard path works when fast path fails ─────────────────────────

#[tokio::test]
async fn adv_standard_path_after_fast_failure() {
    let (tx, mut rx) = mpsc::channel(10);
    let cfg = OptimisticConfig {
        quorum_threshold: 3,
        fast_quorum_threshold: 5,
        total_stake: 7,
        fast_path_timeout: Duration::from_millis(1),
        ..Default::default()
    };
    let oc = OptimisticConsensus::new(addr(1), cfg, tx);
    oc.propose(hash(42), hash(43)).unwrap();

    // Fail the fast path: insufficient fast votes + timeout elapses.
    let _ = oc.on_fast_vote(mk_fast(hash(42), 0, addr(10), 1));
    tokio::time::sleep(Duration::from_millis(5)).await;
    let _ = oc.on_fast_vote(mk_fast(hash(42), 0, addr(11), 1));
    assert_eq!(oc.mode(), ResponsivenessMode::Standard, "Must have switched to standard mode");

    // Standard path should still be able to commit via Commit-phase quorum.
    for i in 0..3u8 {
        let _ = oc.on_standard_vote(mk_std(hash(42), 0, VotePhase::Commit, addr(20 + i), 1));
    }
    assert!(rx.try_recv().is_ok(), "Standard path must commit once quorum reached");
}

// ── 17. Old view change messages ignored ─────────────────────────────────

#[test]
fn adv_old_view_change_ignored() {
    let (tx, _rx) = mpsc::channel(10);
    let cfg = ViewChangeConfig { quorum_threshold: 1, total_stake: 1, ..Default::default() };
    let mgr = ViewChangeManager::new([1u8; 32], 1, cfg, tx);

    // Advance genuinely to view 2 via quorum + on_new_view.
    let msg = ViewChangeMessage::new(2, addr(10), 1, None, ViewChangeReason::LeaderTimeout);
    let cert = mgr.on_view_change_message(msg).unwrap().expect("quorum of 1 should form cert");
    mgr.set_leader(2, addr(1));
    mgr.on_new_view(NewViewMessage {
        view: 2,
        leader: addr(1),
        vc_cert: cert,
        high_qc: None,
        first_proposal: None,
        signature: vec![0u8; 64],
    }).unwrap();
    assert_eq!(mgr.current_view(), 2, "View should have advanced to 2");

    // Now an old message for view 1 (<= current_view 2) must be ignored.
    let old_msg = ViewChangeMessage::new(1, addr(20), 1, None, ViewChangeReason::LeaderTimeout);
    let result = mgr.on_view_change_message(old_msg).unwrap();
    assert!(result.is_none(), "Old view change messages must be ignored");
}
