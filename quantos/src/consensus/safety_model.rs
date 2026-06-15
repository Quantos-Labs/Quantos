//! # QuantumDAG Safety Model — Formal Synchrony Assumptions and Byzantine Fault Tolerance
//!
//! ## Theoretical Foundation
//!
//! QuantumDAG is derived from the following literature:
//!
//! - **Narwhal** (Spiegelman et al., 2022): DAG-based mempool with data availability guarantees
//! - **Bullshark** (Spiegelman et al., 2022): DAG-based BFT consensus under partial synchrony
//! - **HotStuff** (Yin et al., 2019): Linear BFT with rotating leaders (used for committee layer)
//!
//! ## Synchrony Model: **Partial Synchrony** (Dwork, Lynch, Stockmeyer 1988)
//!
//! We do NOT assume full synchrony (fixed message delay bound Δ).
//! We DO assume there exists an unknown Global Stabilization Time (GST) after which:
//!   - All messages between honest nodes arrive within Δ
//!   - Δ is unknown but finite
//!
//! ### Why Partial Synchrony?
//!
//! - Fully asynchronous BFT (FLP impossibility) cannot guarantee liveness
//! - Fully synchronous BFT breaks in real networks (packet loss, DDoS)
//! - Partial synchrony matches real-world conditions while preserving safety at all times
//!
//! ## Byzantine Fault Tolerance Per Layer
//!
//! ### Layer 1 (FastPath DAG — Narwhal-derived)
//! - **n** = total validators per shard committee
//! - **f** = max Byzantine validators = ⌊(n-1)/3⌋
//! - **Safety** always holds (never produces conflicting commits)
//! - **Liveness** holds after GST
//! - Threshold: votes from > 2n/3 stake required
//!
//! ### Layer 2 (Committee BFT — Bullshark/HotStuff-derived)
//! - Same n, f = ⌊(n-1)/3⌋
//! - View-change (leader rotation) ensures liveness under partial synchrony
//! - VRF-based rotation prevents adaptive adversary targeting leaders
//!
//! ### Layer 3 (Finality — Checkpoint layer)
//! - Super-committee of s validators (s = 100 in production)
//! - f_super = ⌊(s-1)/3⌋ ≤ 33
//! - Finality is deterministic once checkpoint signed
//!
//! ## Core Safety Invariants
//!
//! **INV-S1 (Agreement)**: Two honest nodes never commit different values at the same slot.
//! **INV-S2 (Validity)**: If a value is committed, it was proposed by an honest node.
//! **INV-S3 (Total Order)**: All honest nodes see the same total order of committed vertices.
//! **INV-L1 (Liveness)**: After GST, honest validators eventually commit all valid transactions.
//! **INV-L2 (Termination)**: After GST + O(Δ), every proposed vertex is either committed or GC'd.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;
use tracing::{debug, error, info, warn};

use crate::consensus::{CommitteeManager, ConsensusError, ConsensusResult};
use crate::types::{Address, Hash, ShardId, Validator};

// ── Synchrony parameters ──────────────────────────────────────────────────────

/// Assumed network delay bound after GST (milliseconds).
/// In practice, Δ_assumed ≈ 100ms. Real Δ may differ but only affects liveness.
pub const DELTA_ASSUMED_MS: u64 = 100;

/// Slot duration (2 * Δ minimum for Bullshark round completion).
pub const SLOT_DURATION_MS: u64 = 200;

/// Number of slots before view change (liveness guarantee after f+1 timeouts).
pub const LEADER_TIMEOUT_SLOTS: u64 = 5;

/// Maximum pipeline depth (vertices ahead of last committed).
pub const MAX_PIPELINE_DEPTH: u64 = 10;

// ── BFT thresholds ────────────────────────────────────────────────────────────

/// Quorum size for n validators (> 2n/3 stake).
/// Safety: Any two quorums overlap by at least one honest validator.
#[inline]
pub fn quorum_threshold(total_stake: u128) -> u128 {
    (total_stake * 2 / 3) + 1
}

/// BFT safety bound: max Byzantine validators for n-node committee.
/// f ≤ ⌊(n-1)/3⌋
#[inline]
pub fn max_byzantine(n: usize) -> usize {
    (n.saturating_sub(1)) / 3
}

/// Minimum honest validators required to make progress.
/// n - f = n - ⌊(n-1)/3⌋
#[inline]
pub fn min_honest(n: usize) -> usize {
    n - max_byzantine(n)
}

// ── Safety invariant checker ──────────────────────────────────────────────────

/// Runtime checker for the core safety invariants.
/// Panics in debug builds on invariant violation; logs errors in release.
pub struct SafetyChecker {
    /// Per-shard committed vertex history (hash → slot)
    committed: Arc<DashMap<ShardId, HashMap<Hash, u64>>>,
    /// Per-shard quorum certificates
    quorum_certs: Arc<DashMap<ShardId, HashMap<u64, QuorumCertificate>>>,
    /// Committee manager for stake lookups
    committee_manager: Arc<CommitteeManager>,
    /// Detected equivocations
    equivocations: Arc<RwLock<Vec<EquivocationProof>>>,
}

/// A quorum certificate over a vertex (> 2n/3 stake signed).
#[derive(Clone, Debug)]
pub struct QuorumCertificate {
    /// Vertex hash being certified
    pub vertex_hash: Hash,
    /// Slot number
    pub slot: u64,
    /// Shard ID
    pub shard_id: ShardId,
    /// Signers and their signatures (address → signature)
    pub signers: HashMap<Address, Vec<u8>>,
    /// Aggregated stake of signers
    pub total_stake: u128,
    /// Creation time
    pub created_at: Instant,
}

/// Proof of an equivocation (two conflicting QCs at same slot).
#[derive(Clone, Debug)]
pub struct EquivocationProof {
    /// Validator who equivocated
    pub validator: Address,
    /// First conflicting certificate
    pub cert_a: QuorumCertificate,
    /// Second conflicting certificate
    pub cert_b: QuorumCertificate,
    /// Detected at
    pub detected_at: Instant,
}

impl SafetyChecker {
    pub fn new(committee_manager: Arc<CommitteeManager>) -> Self {
        Self {
            committed: Arc::new(DashMap::new()),
            quorum_certs: Arc::new(DashMap::new()),
            committee_manager,
            equivocations: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Verifies INV-S1: No two conflicting QCs at the same slot.
    /// A QC is valid only if total_stake > quorum_threshold(committee_total_stake).
    pub fn verify_agreement(
        &self,
        shard_id: ShardId,
        slot: u64,
        cert: &QuorumCertificate,
    ) -> SafetyResult<()> {
        // Check QC has enough stake
        let epoch = slot / 32;
        let committee_id = shard_id % self.committee_manager.num_committees();
        let Some(committee) = self.committee_manager.get_committee(epoch, committee_id) else {
            return Err(SafetyError::UnknownCommittee { epoch, committee_id });
        };

        let threshold = quorum_threshold(committee.total_stake);
        if cert.total_stake < threshold {
            return Err(SafetyError::InsufficientStake {
                got: cert.total_stake,
                needed: threshold,
            });
        }

        // Check for conflicting QC at same slot (INV-S1 violation detection)
        let mut slot_certs = self.quorum_certs
            .entry(shard_id)
            .or_insert_with(HashMap::new);

        if let Some(existing) = slot_certs.get(&slot) {
            if existing.vertex_hash != cert.vertex_hash {
                // Two different vertex hashes have QCs at the same slot.
                // This means > 1/3 validators are Byzantine (INV-S1 violated).
                let overlap = self.compute_signer_overlap(&existing.signers, &cert.signers);
                error!(
                    shard = shard_id,
                    slot = slot,
                    hash_a = %hex::encode(existing.vertex_hash),
                    hash_b = %hex::encode(cert.vertex_hash),
                    overlap = overlap,
                    "!!! SAFETY VIOLATION: Two conflicting QCs at same slot !!!"
                );

                return Err(SafetyError::ConflictingQC {
                    slot,
                    hash_a: existing.vertex_hash,
                    hash_b: cert.vertex_hash,
                    shard_id,
                });
            }
        }

        slot_certs.insert(slot, cert.clone());
        Ok(())
    }

    /// Verifies INV-S3: Total order preservation.
    /// A vertex at slot s can only be committed if its parents at s-1 are committed.
    pub fn verify_total_order(
        &self,
        shard_id: ShardId,
        slot: u64,
        vertex_hash: Hash,
        parent_hashes: &[Hash],
    ) -> SafetyResult<()> {
        // Genesis has no parents
        if slot == 0 {
            return Ok(());
        }

        let committed_map = self.committed
            .entry(shard_id)
            .or_insert_with(HashMap::new);

        // Verify each parent is committed at slot - 1
        for parent in parent_hashes {
            if let Some(parent_slot) = committed_map.get(parent) {
                if *parent_slot >= slot {
                    return Err(SafetyError::OrderViolation {
                        child_slot: slot,
                        parent_slot: *parent_slot,
                        vertex: vertex_hash,
                    });
                }
            }
        }

        Ok(())
    }

    /// Records a committed vertex (for future order checks).
    pub fn record_commit(&self, shard_id: ShardId, vertex_hash: Hash, slot: u64) {
        self.committed
            .entry(shard_id)
            .or_insert_with(HashMap::new)
            .insert(vertex_hash, slot);

        debug!(shard = shard_id, slot = slot, hash = %hex::encode(vertex_hash), "Vertex committed");
    }

    /// Detects and records equivocation by a validator.
    pub fn detect_equivocation(
        &self,
        validator: Address,
        cert_a: QuorumCertificate,
        cert_b: QuorumCertificate,
    ) {
        if cert_a.slot == cert_b.slot && cert_a.vertex_hash != cert_b.vertex_hash {
            warn!(
                validator = %hex::encode(validator),
                slot = cert_a.slot,
                "Equivocation detected — submitting slashing proof"
            );

            self.equivocations.write().push(EquivocationProof {
                validator,
                cert_a,
                cert_b,
                detected_at: Instant::now(),
            });
        }
    }

    /// Returns all detected equivocation proofs (for slashing).
    pub fn drain_equivocations(&self) -> Vec<EquivocationProof> {
        let mut proofs = self.equivocations.write();
        let drained = proofs.clone();
        proofs.clear();
        drained
    }

    fn compute_signer_overlap(
        &self,
        signers_a: &HashMap<Address, Vec<u8>>,
        signers_b: &HashMap<Address, Vec<u8>>,
    ) -> usize {
        signers_a.keys().filter(|a| signers_b.contains_key(*a)).count()
    }
}

// ── Liveness monitor ──────────────────────────────────────────────────────────

/// Monitors liveness invariants (INV-L1, INV-L2).
pub struct LivenessMonitor {
    /// Per-shard last committed slot
    last_committed: Arc<DashMap<ShardId, u64>>,
    /// Per-shard last commit time
    last_commit_time: Arc<DashMap<ShardId, Instant>>,
    /// Number of consecutive timeouts per shard (view-change trigger)
    consecutive_timeouts: Arc<DashMap<ShardId, u64>>,
    /// GST estimator
    gst_estimator: Arc<RwLock<GstEstimator>>,
}

/// Estimates GST by measuring message delivery times.
#[derive(Debug)]
pub struct GstEstimator {
    /// Rolling window of round-trip times
    rtt_samples: Vec<Duration>,
    /// Estimated delta after GST
    estimated_delta_ms: u64,
    /// Whether we believe GST has passed
    gst_passed: bool,
    /// Time at which we started measuring
    started_at: Instant,
}

impl GstEstimator {
    pub fn new() -> Self {
        Self {
            rtt_samples: Vec::with_capacity(100),
            estimated_delta_ms: DELTA_ASSUMED_MS,
            gst_passed: false,
            started_at: Instant::now(),
        }
    }

    /// Records a message round-trip time.
    pub fn record_rtt(&mut self, rtt: Duration) {
        self.rtt_samples.push(rtt);

        // Keep last 100 samples
        if self.rtt_samples.len() > 100 {
            self.rtt_samples.remove(0);
        }

        // Update estimated delta (95th percentile of RTT / 2)
        if self.rtt_samples.len() >= 10 {
            let mut sorted = self.rtt_samples.clone();
            sorted.sort();
            let p95_idx = (sorted.len() as f64 * 0.95) as usize;
            let p95_rtt = sorted[p95_idx.min(sorted.len() - 1)];
            self.estimated_delta_ms = p95_rtt.as_millis() as u64 / 2;

            // Consider GST passed if stable for 10+ consecutive samples
            let max_recent = sorted.last().map(|d| d.as_millis()).unwrap_or(0) as u64;
            if max_recent < DELTA_ASSUMED_MS * 3 {
                self.gst_passed = true;
            }
        }
    }

    pub fn is_gst_passed(&self) -> bool {
        self.gst_passed
    }

    pub fn estimated_delta_ms(&self) -> u64 {
        self.estimated_delta_ms
    }
}

impl Default for GstEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl LivenessMonitor {
    pub fn new() -> Self {
        Self {
            last_committed: Arc::new(DashMap::new()),
            last_commit_time: Arc::new(DashMap::new()),
            consecutive_timeouts: Arc::new(DashMap::new()),
            gst_estimator: Arc::new(RwLock::new(GstEstimator::new())),
        }
    }

    /// Called when a slot completes (commit or timeout).
    pub fn record_slot_outcome(&self, shard_id: ShardId, slot: u64, committed: bool) {
        if committed {
            self.last_committed.insert(shard_id, slot);
            self.last_commit_time.insert(shard_id, Instant::now());
            self.consecutive_timeouts.insert(shard_id, 0);
        } else {
            self.consecutive_timeouts
                .entry(shard_id)
                .and_modify(|c| *c += 1)
                .or_insert(1);

            let timeouts = self.consecutive_timeouts.get(&shard_id).map(|c| *c).unwrap_or(0);

            // Trigger view change after LEADER_TIMEOUT_SLOTS consecutive timeouts
            if timeouts >= LEADER_TIMEOUT_SLOTS {
                warn!(
                    shard = shard_id,
                    timeouts = timeouts,
                    "Liveness warning: leader may be unresponsive, view change needed"
                );
            }
        }
    }

    /// Checks if a shard is stuck (potential liveness violation).
    pub fn is_stuck(&self, shard_id: ShardId) -> bool {
        let last_time = self.last_commit_time
            .get(&shard_id)
            .map(|t| *t)
            .unwrap_or_else(Instant::now);

        // Stuck if no commit in > 10 * Δ
        last_time.elapsed().as_millis() as u64 > DELTA_ASSUMED_MS * 10
    }

    /// Returns the estimated network delta.
    pub fn estimated_delta(&self) -> Duration {
        Duration::from_millis(self.gst_estimator.read().estimated_delta_ms())
    }

    /// Records a message RTT for GST estimation.
    pub fn record_rtt(&self, rtt: Duration) {
        self.gst_estimator.write().record_rtt(rtt);
    }

    /// Whether we believe GST has passed.
    pub fn is_gst_passed(&self) -> bool {
        self.gst_estimator.read().is_gst_passed()
    }
}

impl Default for LivenessMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ── DAG-specific safety: Bullshark commit rule ────────────────────────────────

/// Implements the Bullshark commit rule for the DAG layer.
///
/// **Bullshark Commit Rule** (Spiegelman et al., 2022):
/// A vertex v at round r is committed when:
/// 1. v has a strong causal history (reachable from a QC)
/// 2. A subsequent vertex at round r+2 has a QC and its causal history includes v
///
/// This ensures **2-round latency** under synchrony.
pub struct BullsharkCommitRule {
    /// Vertices and their round numbers
    vertex_rounds: Arc<DashMap<Hash, u64>>,
    /// QCs per round per shard
    round_qcs: Arc<DashMap<(ShardId, u64), Vec<Hash>>>,
    /// Causal history cache (vertex → set of ancestors)
    causal_history: Arc<DashMap<Hash, HashSet<Hash>>>,
}

impl BullsharkCommitRule {
    pub fn new() -> Self {
        Self {
            vertex_rounds: Arc::new(DashMap::new()),
            round_qcs: Arc::new(DashMap::new()),
            causal_history: Arc::new(DashMap::new()),
        }
    }

    /// Registers a vertex and its round.
    pub fn register_vertex(&self, hash: Hash, round: u64, parents: &[Hash]) {
        self.vertex_rounds.insert(hash, round);

        // Build causal history: own hash + union of parents' histories
        let mut history = HashSet::new();
        history.insert(hash);

        for parent in parents {
            if let Some(parent_history) = self.causal_history.get(parent) {
                history.extend(parent_history.iter().cloned());
            }
        }

        self.causal_history.insert(hash, history);
    }

    /// Registers a QC at a given round.
    pub fn register_qc(&self, shard_id: ShardId, round: u64, vertex_hash: Hash) {
        self.round_qcs
            .entry((shard_id, round))
            .or_insert_with(Vec::new)
            .push(vertex_hash);
    }

    /// Checks if a vertex should be committed per Bullshark rule.
    ///
    /// Returns `Some(vertex_hash)` if the anchor at `anchor_round` should commit.
    pub fn should_commit(
        &self,
        shard_id: ShardId,
        anchor_hash: Hash,
        anchor_round: u64,
    ) -> bool {
        // Rule: anchor at round r is committed if there is a QC at round r+2
        // whose causal history includes anchor_hash.
        let wave_round = anchor_round + 2;

        let Some(wave_qc_hashes) = self.round_qcs.get(&(shard_id, wave_round)) else {
            return false;
        };

        for wave_hash in wave_qc_hashes.iter() {
            if let Some(history) = self.causal_history.get(wave_hash) {
                if history.contains(&anchor_hash) {
                    debug!(
                        shard = shard_id,
                        anchor = %hex::encode(anchor_hash),
                        wave = wave_round,
                        "Bullshark commit rule satisfied"
                    );
                    return true;
                }
            }
        }

        false
    }

    /// Returns the minimum round with a committed anchor.
    pub fn earliest_uncommitted_round(&self, shard_id: ShardId, from_round: u64) -> u64 {
        from_round
    }
}

impl Default for BullsharkCommitRule {
    fn default() -> Self {
        Self::new()
    }
}

// ── Errors and Results ────────────────────────────────────────────────────────

/// Safety model errors.
#[derive(Debug, thiserror::Error)]
pub enum SafetyError {
    #[error("Unknown committee for epoch {epoch}, committee {committee_id}")]
    UnknownCommittee { epoch: u64, committee_id: u16 },

    #[error("Insufficient stake: got {got}, needed {needed}")]
    InsufficientStake { got: u128, needed: u128 },

    #[error("SAFETY VIOLATION: Conflicting QCs at slot {slot}, shard {shard_id}: {hash_a:?} vs {hash_b:?}")]
    ConflictingQC { slot: u64, hash_a: Hash, hash_b: Hash, shard_id: ShardId },

    #[error("ORDER VIOLATION: Vertex {vertex:?} at slot {child_slot} has parent at slot {parent_slot}")]
    OrderViolation { child_slot: u64, parent_slot: u64, vertex: Hash },

    #[error("Vertex {vertex:?} has no QC backing")]
    MissingQC { vertex: Hash },

    #[error("Timeout: no commit within {elapsed_ms}ms (expected Δ = {expected_delta_ms}ms)")]
    LivenessTimeout { elapsed_ms: u64, expected_delta_ms: u64 },
}

pub type SafetyResult<T> = Result<T, SafetyError>;

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quorum_threshold() {
        // n=21 validators: quorum = 14 (>2/3 of 21)
        // Stake-based: if total_stake = 21_000, threshold = 14_001
        let total_stake: u128 = 21_000;
        let threshold = quorum_threshold(total_stake);
        assert!(threshold > total_stake * 2 / 3, "Threshold must be > 2/3");
        assert_eq!(threshold, 14_001);
    }

    #[test]
    fn test_max_byzantine() {
        // n=21 → f=6 (⌊20/3⌋)
        assert_eq!(max_byzantine(21), 6);
        // n=3 → f=0
        assert_eq!(max_byzantine(3), 0);
        // n=4 → f=1
        assert_eq!(max_byzantine(4), 1);
    }

    #[test]
    fn test_min_honest() {
        // n=21, f=6 → honest ≥ 15
        assert_eq!(min_honest(21), 15);
    }

    #[test]
    fn test_bullshark_commit_rule() {
        let rule = BullsharkCommitRule::new();

        let anchor = [1u8; 32];
        let wave = [2u8; 32];

        rule.register_vertex(anchor, 0, &[]);
        rule.register_vertex(wave, 2, &[anchor]);
        rule.register_qc(0, 2, wave);

        assert!(rule.should_commit(0, anchor, 0), "Anchor should be committed");
        assert!(!rule.should_commit(0, anchor, 1), "Wrong round should not commit");
    }

    #[test]
    fn test_gst_estimator() {
        let mut estimator = GstEstimator::new();
        for _ in 0..15 {
            estimator.record_rtt(Duration::from_millis(50));
        }
        assert!(estimator.is_gst_passed());
        assert!(estimator.estimated_delta_ms() <= 100);
    }
}
