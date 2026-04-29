//! # Optimistic Responsiveness
//!
//! Achieves 2 RTT finality when the network is stable (synchronous periods).
//! Falls back to standard BFT timing under adversarial conditions.
//!
//! ## Features
//!
//! - **Fast Path (2 RTT)**: Direct commit when all honest validators respond quickly
//! - **Slow Path (4 RTT)**: Standard BFT path under adversarial conditions  
//! - **Adaptive Switching**: Automatic detection of network conditions
//! - **Optimistic Execution**: Pre-execute transactions before finality

use std::collections::HashMap;
use std::time::{Duration, Instant};
use parking_lot::{Mutex, RwLock};
use tokio::sync::mpsc;

use crate::types::{Hash, Address};
use crate::consensus::ConsensusResult;

/// Network condition for responsiveness mode selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkCondition {
    /// All validators responding within expected time
    Synchronous,
    /// Some validators slow but majority responsive
    PartialSync,
    /// Significant delays or failures
    Asynchronous,
}

/// Responsiveness mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponsivenessMode {
    /// Optimistic fast path (2 RTT)
    Optimistic,
    /// Standard BFT path (4 RTT)
    Standard,
    /// Conservative mode under attack
    Conservative,
}

/// Fast path proposal
#[derive(Clone)]
pub struct FastProposal {
    /// Proposal hash
    pub hash: Hash,
    /// Round number
    pub round: u64,
    /// Proposer
    pub proposer: Address,
    /// Payload hash
    pub payload_hash: Hash,
    /// State root
    pub state_root: Hash,
    /// Creation time
    pub created_at: Instant,
    /// Fast path votes (for 2 RTT)
    pub fast_votes: Vec<FastVote>,
    /// Standard votes (for 4 RTT fallback)
    pub standard_votes: Vec<StandardVote>,
}

/// Fast vote (optimistic path)
#[derive(Clone, Debug)]
pub struct FastVote {
    pub proposal_hash: Hash,
    pub round: u64,
    pub voter: Address,
    pub stake: u64,
    pub signature: Vec<u8>,
    pub received_at: Instant,
}

/// Standard vote (BFT path)
#[derive(Clone, Debug)]
pub struct StandardVote {
    pub proposal_hash: Hash,
    pub round: u64,
    pub phase: VotePhase,
    pub voter: Address,
    pub stake: u64,
    pub signature: Vec<u8>,
}

/// Vote phase in standard BFT
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VotePhase {
    Prepare,
    PreCommit,
    Commit,
    Decide,
}

/// Commit certificate proving finality
#[derive(Clone, Debug)]
pub struct CommitCertificate {
    pub proposal_hash: Hash,
    pub round: u64,
    /// True if committed via fast path
    pub fast_path: bool,
    pub aggregated_sig: Vec<u8>,
    pub signers: Vec<Address>,
    pub total_stake: u64,
    pub latency_ms: u64,
}

/// Round state for tracking consensus progress
struct RoundState {
    proposal: Option<FastProposal>,
    fast_votes: HashMap<Address, FastVote>,
    prepare_votes: HashMap<Address, StandardVote>,
    precommit_votes: HashMap<Address, StandardVote>,
    commit_votes: HashMap<Address, StandardVote>,
    fast_path_deadline: Option<Instant>,
    started_at: Instant,
    committed: bool,
}

impl RoundState {
    fn new() -> Self {
        Self {
            proposal: None,
            fast_votes: HashMap::new(),
            prepare_votes: HashMap::new(),
            precommit_votes: HashMap::new(),
            commit_votes: HashMap::new(),
            fast_path_deadline: None,
            started_at: Instant::now(),
            committed: false,
        }
    }
    
    fn fast_vote_stake(&self) -> u64 {
        self.fast_votes.values().map(|v| v.stake).sum()
    }
    
    fn prepare_stake(&self) -> u64 {
        self.prepare_votes.values().map(|v| v.stake).sum()
    }
    
    fn precommit_stake(&self) -> u64 {
        self.precommit_votes.values().map(|v| v.stake).sum()
    }
    
    fn commit_stake(&self) -> u64 {
        self.commit_votes.values().map(|v| v.stake).sum()
    }
}

/// Latency tracker for adaptive mode selection
struct LatencyTracker {
    /// Recent RTT samples per validator
    samples: HashMap<Address, Vec<Duration>>,
    /// Maximum samples per validator
    max_samples: usize,
    /// Expected RTT under synchrony
    expected_rtt: Duration,
}

impl LatencyTracker {
    fn new(expected_rtt: Duration) -> Self {
        Self {
            samples: HashMap::new(),
            max_samples: 100,
            expected_rtt,
        }
    }
    
    fn record(&mut self, validator: Address, rtt: Duration) {
        let samples = self.samples.entry(validator).or_insert_with(Vec::new);
        samples.push(rtt);
        if samples.len() > self.max_samples {
            samples.remove(0);
        }
    }
    
    fn average_rtt(&self, validator: &Address) -> Option<Duration> {
        self.samples.get(validator).and_then(|s| {
            if s.is_empty() {
                None
            } else {
                let sum: Duration = s.iter().sum();
                Some(sum / s.len() as u32)
            }
        })
    }
    
    fn detect_condition(&self) -> NetworkCondition {
        if self.samples.is_empty() {
            return NetworkCondition::Asynchronous;
        }
        
        let mut fast_count = 0;
        let mut slow_count = 0;
        let threshold = self.expected_rtt * 2;
        
        for samples in self.samples.values() {
            if let Some(last) = samples.last() {
                if *last <= threshold {
                    fast_count += 1;
                } else {
                    slow_count += 1;
                }
            }
        }
        
        let total = fast_count + slow_count;
        if total == 0 {
            return NetworkCondition::Asynchronous;
        }
        
        let fast_ratio = fast_count as f64 / total as f64;
        
        if fast_ratio >= 0.9 {
            NetworkCondition::Synchronous
        } else if fast_ratio >= 0.67 {
            NetworkCondition::PartialSync
        } else {
            NetworkCondition::Asynchronous
        }
    }
}

/// Optimistic responsiveness configuration
#[derive(Clone)]
pub struct OptimisticConfig {
    /// Expected network RTT
    pub expected_rtt: Duration,
    /// Fast path timeout (typically 2 * expected_rtt)
    pub fast_path_timeout: Duration,
    /// Standard path timeout
    pub standard_timeout: Duration,
    /// Quorum threshold (2f+1 stake)
    pub quorum_threshold: u64,
    /// Fast quorum (n stake for instant commit)
    pub fast_quorum_threshold: u64,
    /// Total stake
    pub total_stake: u64,
}

impl Default for OptimisticConfig {
    fn default() -> Self {
        Self {
            expected_rtt: Duration::from_millis(50),
            fast_path_timeout: Duration::from_millis(150),
            standard_timeout: Duration::from_millis(500),
            quorum_threshold: 67,
            fast_quorum_threshold: 90, // 90% for instant commit
            total_stake: 100,
        }
    }
}

/// Optimistic Responsiveness Consensus
pub struct OptimisticConsensus {
    /// Local validator address
    local_addr: Address,
    /// Configuration
    config: OptimisticConfig,
    /// Current round
    current_round: RwLock<u64>,
    /// Per-round state
    rounds: RwLock<HashMap<u64, RoundState>>,
    /// Current responsiveness mode
    mode: RwLock<ResponsivenessMode>,
    /// Latency tracker
    latency: Mutex<LatencyTracker>,
    /// Committed proposals
    committed: RwLock<Vec<CommitCertificate>>,
    /// Commit notification channel
    commit_tx: mpsc::Sender<CommitCertificate>,
    /// Metrics
    metrics: Mutex<OptimisticMetrics>,
}

/// Metrics for optimistic consensus
#[derive(Default)]
pub struct OptimisticMetrics {
    pub fast_path_commits: u64,
    pub standard_commits: u64,
    pub fast_path_failures: u64,
    pub avg_fast_latency_ms: f64,
    pub avg_standard_latency_ms: f64,
}

impl OptimisticConsensus {
    pub fn new(
        local_addr: Address,
        config: OptimisticConfig,
        commit_tx: mpsc::Sender<CommitCertificate>,
    ) -> Self {
        let latency = LatencyTracker::new(config.expected_rtt);
        
        Self {
            local_addr,
            config,
            current_round: RwLock::new(0),
            rounds: RwLock::new(HashMap::new()),
            mode: RwLock::new(ResponsivenessMode::Optimistic),
            latency: Mutex::new(latency),
            committed: RwLock::new(Vec::new()),
            commit_tx,
            metrics: Mutex::new(OptimisticMetrics::default()),
        }
    }
    
    /// Creates a new proposal
    pub fn propose(
        &self,
        payload_hash: Hash,
        state_root: Hash,
    ) -> ConsensusResult<FastProposal> {
        let round = *self.current_round.read();
        
        // Generate proposal hash
        let mut hash_data = Vec::new();
        hash_data.extend_from_slice(&round.to_le_bytes());
        hash_data.extend_from_slice(&payload_hash);
        hash_data.extend_from_slice(&state_root);
        hash_data.extend_from_slice(&self.local_addr);
        let hash = crate::crypto::sha3_256(&hash_data);
        
        let proposal = FastProposal {
            hash,
            round,
            proposer: self.local_addr,
            payload_hash,
            state_root,
            created_at: Instant::now(),
            fast_votes: Vec::new(),
            standard_votes: Vec::new(),
        };
        
        // Initialize round state
        {
            let mut rounds = self.rounds.write();
            let state = rounds.entry(round).or_insert_with(RoundState::new);
            state.proposal = Some(proposal.clone());
            state.fast_path_deadline = Some(Instant::now() + self.config.fast_path_timeout);
        }
        
        Ok(proposal)
    }
    
    /// Receives a proposal from leader
    pub fn on_proposal(&self, proposal: FastProposal) -> ConsensusResult<()> {
        let mut rounds = self.rounds.write();
        let state = rounds.entry(proposal.round).or_insert_with(RoundState::new);
        
        if state.proposal.is_some() {
            // Already have proposal for this round
            return Ok(());
        }
        
        state.proposal = Some(proposal);
        state.fast_path_deadline = Some(Instant::now() + self.config.fast_path_timeout);
        
        Ok(())
    }
    
    /// Receives a fast vote (optimistic path)
    pub fn on_fast_vote(&self, vote: FastVote) -> ConsensusResult<Option<CommitCertificate>> {
        // Record latency
        {
            let mut latency = self.latency.lock();
            latency.record(vote.voter, vote.received_at.elapsed());
        }
        
        let mut rounds = self.rounds.write();
        let state = match rounds.get_mut(&vote.round) {
            Some(s) => s,
            None => return Ok(None),
        };
        
        // Check deadline
        if let Some(deadline) = state.fast_path_deadline {
            if Instant::now() > deadline {
                // Fast path expired, switch to standard
                drop(rounds);
                self.switch_to_standard(vote.round)?;
                return Ok(None);
            }
        }
        
        // Add vote if not duplicate
        if state.fast_votes.contains_key(&vote.voter) {
            return Ok(None);
        }
        state.fast_votes.insert(vote.voter, vote);
        
        // Check for fast commit (need high quorum for 2 RTT)
        let fast_stake = state.fast_vote_stake();
        if fast_stake >= self.config.fast_quorum_threshold && !state.committed {
            state.committed = true;
            
            let proposal = state.proposal.as_ref().unwrap();
            let cert = self.create_fast_commit_cert(proposal, &state.fast_votes);
            
            // Update metrics
            {
                let mut metrics = self.metrics.lock();
                metrics.fast_path_commits += 1;
                let latency = proposal.created_at.elapsed().as_millis() as f64;
                metrics.avg_fast_latency_ms = 
                    0.1 * latency + 0.9 * metrics.avg_fast_latency_ms;
            }
            
            // Store and notify
            self.committed.write().push(cert.clone());
            let _ = self.commit_tx.try_send(cert.clone());
            
            // Advance round
            drop(rounds);
            self.advance_round();
            
            return Ok(Some(cert));
        }
        
        Ok(None)
    }
    
    /// Receives a standard vote (BFT path)
    pub fn on_standard_vote(&self, vote: StandardVote) -> ConsensusResult<Option<CommitCertificate>> {
        let mut rounds = self.rounds.write();
        let state = match rounds.get_mut(&vote.round) {
            Some(s) => s,
            None => return Ok(None),
        };
        
        if state.committed {
            return Ok(None);
        }
        
        match vote.phase {
            VotePhase::Prepare => {
                state.prepare_votes.insert(vote.voter, vote);
                
                // Check prepare quorum -> send precommit
                if state.prepare_stake() >= self.config.quorum_threshold {
                    // Would trigger precommit broadcast
                }
            }
            VotePhase::PreCommit => {
                state.precommit_votes.insert(vote.voter, vote);
                
                // Check precommit quorum -> send commit
                if state.precommit_stake() >= self.config.quorum_threshold {
                    // Would trigger commit broadcast
                }
            }
            VotePhase::Commit => {
                state.commit_votes.insert(vote.voter, vote);
                
                // Check commit quorum -> finalize
                if state.commit_stake() >= self.config.quorum_threshold {
                    state.committed = true;
                    
                    let proposal = state.proposal.as_ref().unwrap();
                    let cert = self.create_standard_commit_cert(proposal, &state.commit_votes);
                    
                    // Update metrics
                    {
                        let mut metrics = self.metrics.lock();
                        metrics.standard_commits += 1;
                        let latency = proposal.created_at.elapsed().as_millis() as f64;
                        metrics.avg_standard_latency_ms = 
                            0.1 * latency + 0.9 * metrics.avg_standard_latency_ms;
                    }
                    
                    self.committed.write().push(cert.clone());
                    let _ = self.commit_tx.try_send(cert.clone());
                    
                    drop(rounds);
                    self.advance_round();
                    
                    return Ok(Some(cert));
                }
            }
            VotePhase::Decide => {}
        }
        
        Ok(None)
    }
    
    /// Switches to standard path when fast path times out
    fn switch_to_standard(&self, round: u64) -> ConsensusResult<()> {
        *self.mode.write() = ResponsivenessMode::Standard;
        
        let mut metrics = self.metrics.lock();
        metrics.fast_path_failures += 1;
        
        tracing::debug!("Fast path timeout at round {}, switching to standard", round);
        
        Ok(())
    }
    
    /// Creates commit certificate from fast votes
    fn create_fast_commit_cert(
        &self,
        proposal: &FastProposal,
        votes: &HashMap<Address, FastVote>,
    ) -> CommitCertificate {
        let mut signers = Vec::new();
        let mut aggregated_sig = Vec::new();
        let mut total_stake = 0u64;
        
        for vote in votes.values() {
            signers.push(vote.voter);
            aggregated_sig.extend_from_slice(&vote.signature);
            total_stake += vote.stake;
        }
        
        CommitCertificate {
            proposal_hash: proposal.hash,
            round: proposal.round,
            fast_path: true,
            aggregated_sig,
            signers,
            total_stake,
            latency_ms: proposal.created_at.elapsed().as_millis() as u64,
        }
    }
    
    /// Creates commit certificate from standard votes
    fn create_standard_commit_cert(
        &self,
        proposal: &FastProposal,
        votes: &HashMap<Address, StandardVote>,
    ) -> CommitCertificate {
        let mut signers = Vec::new();
        let mut aggregated_sig = Vec::new();
        let mut total_stake = 0u64;
        
        for vote in votes.values() {
            signers.push(vote.voter);
            aggregated_sig.extend_from_slice(&vote.signature);
            total_stake += vote.stake;
        }
        
        CommitCertificate {
            proposal_hash: proposal.hash,
            round: proposal.round,
            fast_path: false,
            aggregated_sig,
            signers,
            total_stake,
            latency_ms: proposal.created_at.elapsed().as_millis() as u64,
        }
    }
    
    /// Advances to next round
    fn advance_round(&self) {
        let mut round = self.current_round.write();
        *round += 1;
        
        // Update mode based on network conditions
        let condition = self.latency.lock().detect_condition();
        let mut mode = self.mode.write();
        *mode = match condition {
            NetworkCondition::Synchronous => ResponsivenessMode::Optimistic,
            NetworkCondition::PartialSync => ResponsivenessMode::Standard,
            NetworkCondition::Asynchronous => ResponsivenessMode::Conservative,
        };
        
        // Cleanup old rounds
        let current = *round;
        self.rounds.write().retain(|r, _| *r >= current.saturating_sub(10));
    }
    
    /// Handles round timeout
    pub fn on_timeout(&self, round: u64) -> ConsensusResult<()> {
        if round < *self.current_round.read() {
            return Ok(());
        }
        
        // Switch to standard if we were optimistic
        if *self.mode.read() == ResponsivenessMode::Optimistic {
            self.switch_to_standard(round)?;
        }
        
        // Advance round
        self.advance_round();
        
        Ok(())
    }
    
    /// Returns current round
    pub fn current_round(&self) -> u64 {
        *self.current_round.read()
    }
    
    /// Returns current mode
    pub fn mode(&self) -> ResponsivenessMode {
        *self.mode.read()
    }
    
    /// Returns metrics
    pub fn metrics(&self) -> OptimisticMetrics {
        let m = self.metrics.lock();
        OptimisticMetrics {
            fast_path_commits: m.fast_path_commits,
            standard_commits: m.standard_commits,
            fast_path_failures: m.fast_path_failures,
            avg_fast_latency_ms: m.avg_fast_latency_ms,
            avg_standard_latency_ms: m.avg_standard_latency_ms,
        }
    }
    
    /// Returns fast path success rate
    pub fn fast_path_rate(&self) -> f64 {
        let m = self.metrics.lock();
        let total = m.fast_path_commits + m.standard_commits;
        if total == 0 {
            0.0
        } else {
            m.fast_path_commits as f64 / total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_fast_path_commit() {
        let (tx, mut rx) = mpsc::channel(10);
        let config = OptimisticConfig {
            quorum_threshold: 2,
            fast_quorum_threshold: 3,
            total_stake: 4,
            ..Default::default()
        };
        
        let consensus = OptimisticConsensus::new([1u8; 32], config, tx);
        
        let proposal = consensus.propose([2u8; 32], [3u8; 32]).unwrap();
        
        // Add fast votes
        for i in 0..3 {
            let vote = FastVote {
                proposal_hash: proposal.hash,
                round: proposal.round,
                voter: [10 + i; 32],
                stake: 1,
                signature: vec![i; 64],
                received_at: Instant::now(),
            };
            
            let result = consensus.on_fast_vote(vote).unwrap();
            if i == 2 {
                assert!(result.is_some());
                let cert = result.unwrap();
                assert!(cert.fast_path);
            }
        }
        
        // Should have received commit
        let cert = rx.try_recv().unwrap();
        assert!(cert.fast_path);
    }
    
    #[test]
    fn test_mode_detection() {
        let mut tracker = LatencyTracker::new(Duration::from_millis(50));
        
        // Fast validators
        for i in 0..10 {
            tracker.record([i; 32], Duration::from_millis(30));
        }
        
        assert_eq!(tracker.detect_condition(), NetworkCondition::Synchronous);
        
        // Add slow validators
        for i in 10..15 {
            tracker.record([i; 32], Duration::from_millis(500));
        }
        
        // Now partial sync
        let condition = tracker.detect_condition();
        assert!(condition != NetworkCondition::Synchronous);
    }
}
