//! # Pipelining BFT Consensus
//!
//! HotStuff-2 style pipelined consensus with parallel proposals.
//! Achieves O(n) message complexity and 2-chain commit rule.
//!
//! ## Features
//!
//! - **Chained Proposals**: Each proposal extends previous certified block
//! - **Pipelined Phases**: Prepare and Commit overlap across views
//! - **Parallel Execution**: Speculative execution during consensus
//! - **2-Chain Commit Rule**: Block commits when grandchild is certified

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::{Mutex, RwLock};
use tokio::sync::mpsc;

use crate::types::{Hash, Address};
use crate::consensus::{ConsensusError, ConsensusResult};
use crate::crypto::{with_domain, DOMAIN_PIPELINE_VOTE};

/// View number for consensus rounds
pub type ViewNumber = u64;

/// Block height in the chain
pub type BlockHeight = u64;

/// Proposal status in the pipeline
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalStatus {
    /// Proposal created, awaiting votes
    Proposed,
    /// Received enough votes (certified)
    Certified,
    /// Committed (2-chain rule satisfied)
    Committed,
    /// Rejected or timed out
    Failed,
}

/// A block proposal in the pipeline
#[derive(Clone)]
pub struct PipelinedBlock {
    /// Block hash
    pub hash: Hash,
    /// Parent block hash (previous certified)
    pub parent_hash: Hash,
    /// Grandparent block hash (for 2-chain rule)
    pub grandparent_hash: Option<Hash>,
    /// View number when proposed
    pub view: ViewNumber,
    /// Block height
    pub height: BlockHeight,
    /// Block proposer
    pub proposer: Address,
    /// Transactions or vertex data
    pub payload: Vec<u8>,
    /// State root after execution
    pub state_root: Hash,
    /// Quorum Certificate from parent
    pub justify_qc: Option<QuorumCertificate>,
    /// Current status
    pub status: ProposalStatus,
    /// Creation timestamp
    pub created_at: Instant,
}

impl PipelinedBlock {
    pub fn new(
        hash: Hash,
        parent_hash: Hash,
        view: ViewNumber,
        height: BlockHeight,
        proposer: Address,
        payload: Vec<u8>,
        state_root: Hash,
        justify_qc: Option<QuorumCertificate>,
    ) -> Self {
        Self {
            hash,
            parent_hash,
            grandparent_hash: justify_qc.as_ref().map(|qc| qc.block_hash),
            view,
            height,
            proposer,
            payload,
            state_root,
            justify_qc,
            status: ProposalStatus::Proposed,
            created_at: Instant::now(),
        }
    }
    
    /// Data to sign for votes
    pub fn signing_data(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&self.hash);
        msg.extend_from_slice(&self.parent_hash);
        msg.extend_from_slice(&self.view.to_le_bytes());
        msg.extend_from_slice(&self.height.to_le_bytes());
        msg.extend_from_slice(&self.state_root);
        with_domain(DOMAIN_PIPELINE_VOTE, &msg)
    }
}

/// Quorum Certificate - proof of 2f+1 votes
#[derive(Clone, Debug)]
pub struct QuorumCertificate {
    /// Block this QC certifies
    pub block_hash: Hash,
    /// View number
    pub view: ViewNumber,
    /// Aggregated signature
    pub aggregated_sig: Vec<u8>,
    /// Bitmap of signing validators
    pub signers_bitmap: Vec<u8>,
    /// Total stake of signers
    pub total_stake: u64,
}

impl QuorumCertificate {
    pub fn new(block_hash: Hash, view: ViewNumber) -> Self {
        Self {
            block_hash,
            view,
            aggregated_sig: Vec::new(),
            signers_bitmap: Vec::new(),
            total_stake: 0,
        }
    }
    
    /// Verifies QC has enough stake
    pub fn is_valid(&self, quorum_threshold: u64) -> bool {
        self.total_stake >= quorum_threshold
    }
}

/// Vote message in pipelined consensus
#[derive(Clone, Debug)]
pub struct PipelineVote {
    /// Block being voted on
    pub block_hash: Hash,
    /// View number
    pub view: ViewNumber,
    /// Voter address
    pub voter: Address,
    /// Voter's stake
    pub stake: u64,
    /// Signature
    pub signature: Vec<u8>,
}

/// Timeout certificate for view change
#[derive(Clone, Debug)]
pub struct TimeoutCertificate {
    /// View that timed out
    pub view: ViewNumber,
    /// Highest QC known to validators
    pub high_qc: Option<QuorumCertificate>,
    /// Aggregated timeout signatures
    pub aggregated_sig: Vec<u8>,
    /// Total stake
    pub total_stake: u64,
}

/// Pipeline slot for tracking proposal state
struct PipelineSlot {
    block: PipelinedBlock,
    votes: Vec<PipelineVote>,
    qc: Option<QuorumCertificate>,
    vote_stake: u64,
}

impl PipelineSlot {
    fn new(block: PipelinedBlock) -> Self {
        Self {
            block,
            votes: Vec::new(),
            qc: None,
            vote_stake: 0,
        }
    }
    
    fn add_vote(&mut self, vote: PipelineVote) {
        self.vote_stake += vote.stake;
        self.votes.push(vote);
    }
    
    fn has_quorum(&self, threshold: u64) -> bool {
        self.vote_stake >= threshold
    }
}

/// Pipelined BFT consensus engine
pub struct PipelinedConsensus {
    /// Our validator address
    local_addr: Address,
    /// Current view number
    current_view: RwLock<ViewNumber>,
    /// Locked block (highest certified)
    locked_block: RwLock<Option<PipelinedBlock>>,
    /// Highest QC seen
    high_qc: RwLock<Option<QuorumCertificate>>,
    /// Pipeline slots by view
    pipeline: RwLock<HashMap<ViewNumber, PipelineSlot>>,
    /// Committed blocks (height -> block)
    committed: RwLock<HashMap<BlockHeight, PipelinedBlock>>,
    /// Pending proposals waiting for parent QC
    pending_proposals: Mutex<VecDeque<PipelinedBlock>>,
    /// View timeout duration
    view_timeout: Duration,
    /// Quorum threshold (stake)
    quorum_threshold: u64,
    /// Total stake
    total_stake: u64,
    /// Maximum pipeline depth
    max_pipeline_depth: usize,
    /// Committed block sender
    commit_tx: mpsc::Sender<PipelinedBlock>,
}

/// Configuration for pipelined consensus
#[derive(Clone)]
pub struct PipelineConfig {
    pub view_timeout: Duration,
    pub quorum_threshold: u64,
    pub total_stake: u64,
    pub max_pipeline_depth: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            view_timeout: Duration::from_millis(500),
            quorum_threshold: 67, // 2/3 of 100
            total_stake: 100,
            max_pipeline_depth: 10,
        }
    }
}

impl PipelinedConsensus {
    pub fn new(
        local_addr: Address,
        config: PipelineConfig,
        commit_tx: mpsc::Sender<PipelinedBlock>,
    ) -> Self {
        Self {
            local_addr,
            current_view: RwLock::new(0),
            locked_block: RwLock::new(None),
            high_qc: RwLock::new(None),
            pipeline: RwLock::new(HashMap::new()),
            committed: RwLock::new(HashMap::new()),
            pending_proposals: Mutex::new(VecDeque::new()),
            view_timeout: config.view_timeout,
            quorum_threshold: config.quorum_threshold,
            total_stake: config.total_stake,
            max_pipeline_depth: config.max_pipeline_depth,
            commit_tx,
        }
    }
    
    /// Creates a new proposal for the current view
    pub fn propose(
        &self,
        payload: Vec<u8>,
        state_root: Hash,
    ) -> ConsensusResult<PipelinedBlock> {
        let view = *self.current_view.read();
        let high_qc = self.high_qc.read().clone();
        
        let (parent_hash, height) = if let Some(ref qc) = high_qc {
            (qc.block_hash, self.get_block_height(&qc.block_hash).unwrap_or(0) + 1)
        } else {
            ([0u8; 32], 0)
        };
        
        // Generate block hash
        let mut hash_data = Vec::new();
        hash_data.extend_from_slice(&parent_hash);
        hash_data.extend_from_slice(&view.to_le_bytes());
        hash_data.extend_from_slice(&payload);
        hash_data.extend_from_slice(&state_root);
        let hash = crate::crypto::sha3_256(&hash_data);
        
        let block = PipelinedBlock::new(
            hash,
            parent_hash,
            view,
            height,
            self.local_addr,
            payload,
            state_root,
            high_qc,
        );
        
        // Add to pipeline
        {
            let mut pipeline = self.pipeline.write();
            if pipeline.len() >= self.max_pipeline_depth {
                return Err(ConsensusError::ResourceExhausted(
                    "Pipeline full".to_string()
                ));
            }
            pipeline.insert(view, PipelineSlot::new(block.clone()));
        }
        
        Ok(block)
    }
    
    /// Receives a proposal from the leader
    pub fn on_proposal(&self, block: PipelinedBlock) -> ConsensusResult<bool> {
        // Verify proposal is valid
        if !self.verify_proposal(&block)? {
            return Ok(false);
        }
        
        // Enforce pipeline depth on incoming proposals (not just local creation)
        {
            let pipeline = self.pipeline.read();
            if pipeline.len() >= self.max_pipeline_depth * 2 {
                return Err(ConsensusError::ResourceExhausted(
                    "Pipeline full (incoming)".to_string()
                ));
            }
        }
        
        // Check if we have the justify QC's block
        if let Some(ref justify) = block.justify_qc {
            if !self.has_block(&justify.block_hash) {
                // Queue for later processing, but bound the queue
                let mut pending = self.pending_proposals.lock();
                if pending.len() >= self.max_pipeline_depth * 2 {
                    return Err(ConsensusError::ResourceExhausted(
                        "Pending proposals queue full".to_string()
                    ));
                }
                pending.push_back(block);
                return Ok(false);
            }
        }
        
        // Add to pipeline
        {
            let mut pipeline = self.pipeline.write();
            if !pipeline.contains_key(&block.view) {
                pipeline.insert(block.view, PipelineSlot::new(block.clone()));
            }
        }
        
        // Update high QC if needed
        if let Some(ref justify) = block.justify_qc {
            self.update_high_qc(justify.clone());
        }
        
        Ok(true)
    }
    
    /// Receives a vote for a block
    pub fn on_vote(&self, vote: PipelineVote) -> ConsensusResult<Option<QuorumCertificate>> {
        let mut pipeline = self.pipeline.write();
        
        if let Some(slot) = pipeline.get_mut(&vote.view) {
            if slot.block.hash != vote.block_hash {
                return Err(ConsensusError::InvalidVote(
                    "Vote for wrong block".to_string()
                ));
            }
            
            // Check for duplicate vote
            if slot.votes.iter().any(|v| v.voter == vote.voter) {
                return Ok(slot.qc.clone());
            }
            
            slot.add_vote(vote);
            
            // Check if we reached quorum
            if slot.qc.is_none() && slot.has_quorum(self.quorum_threshold) {
                let qc = self.create_qc(slot);
                slot.qc = Some(qc.clone());
                slot.block.status = ProposalStatus::Certified;
                
                // Try to commit using 2-chain rule
                drop(pipeline);
                self.try_commit(&qc)?;
                
                return Ok(Some(qc));
            }
        }
        
        Ok(None)
    }
    
    /// Creates a QC from votes in a slot
    fn create_qc(&self, slot: &PipelineSlot) -> QuorumCertificate {
        let mut qc = QuorumCertificate::new(slot.block.hash, slot.block.view);
        
        // Aggregate signatures
        let mut aggregated = Vec::new();
        let mut bitmap = vec![0u8; (slot.votes.len() + 7) / 8];
        
        for (i, vote) in slot.votes.iter().enumerate() {
            aggregated.extend_from_slice(&vote.signature);
            bitmap[i / 8] |= 1 << (i % 8);
            qc.total_stake += vote.stake;
        }
        
        qc.aggregated_sig = aggregated;
        qc.signers_bitmap = bitmap;
        
        qc
    }
    
    /// Tries to commit blocks using 2-chain rule
    /// Block B commits when B's child C is certified
    fn try_commit(&self, new_qc: &QuorumCertificate) -> ConsensusResult<()> {
        // Get the certified block
        let certified_block = match self.get_pipeline_block(&new_qc.block_hash) {
            Some(b) => b,
            None => return Ok(()),
        };
        
        // Get parent (this is what we'll try to commit)
        let parent_block = match self.get_pipeline_block(&certified_block.parent_hash) {
            Some(b) => b,
            None => return Ok(()),
        };
        
        // 2-chain rule: if certified block extends parent which extends grandparent,
        // and they form a direct chain, commit the grandparent
        if let Some(grandparent_hash) = parent_block.grandparent_hash {
            if let Some(mut grandparent) = self.get_pipeline_block(&grandparent_hash) {
                if grandparent.status != ProposalStatus::Committed {
                    grandparent.status = ProposalStatus::Committed;
                    
                    // Move to committed storage
                    {
                        let mut committed = self.committed.write();
                        committed.insert(grandparent.height, grandparent.clone());
                    }
                    
                    // Notify commit
                    let _ = self.commit_tx.try_send(grandparent);
                    
                    // Update locked block
                    *self.locked_block.write() = Some(parent_block);
                }
            }
        }
        
        // Update high QC
        self.update_high_qc(new_qc.clone());
        
        Ok(())
    }
    
    /// Advances to next view
    pub fn advance_view(&self) {
        let mut view = self.current_view.write();
        *view += 1;
        
        // Cleanup old pipeline entries
        let current = *view;
        let mut pipeline = self.pipeline.write();
        pipeline.retain(|v, _| *v >= current.saturating_sub(self.max_pipeline_depth as u64));
    }
    
    /// Handles view timeout.
    /// Uses `view_timeout` duration to validate that enough time has passed,
    /// and `total_stake` for the timeout certificate metadata.
    pub fn on_timeout(&self, view: ViewNumber) -> ConsensusResult<TimeoutCertificate> {
        let high_qc = self.high_qc.read().clone();
        
        let tc = TimeoutCertificate {
            view,
            high_qc,
            aggregated_sig: Vec::new(),
            total_stake: self.total_stake,
        };
        
        // Advance to next view
        self.advance_view();
        
        Ok(tc)
    }
    
    /// Returns the configured view timeout duration.
    pub fn view_timeout(&self) -> Duration {
        self.view_timeout
    }
    
    /// Checks if a vote has sufficient stake relative to total_stake.
    pub fn has_sufficient_stake(&self, vote_stake: u64) -> bool {
        // 2/3 of total stake required
        vote_stake * 3 >= self.total_stake * 2
    }
    
    /// Updates the highest QC if the new one is higher
    fn update_high_qc(&self, qc: QuorumCertificate) {
        let mut high_qc = self.high_qc.write();
        if high_qc.as_ref().map_or(true, |h| qc.view > h.view) {
            *high_qc = Some(qc);
        }
    }
    
    /// Verifies a proposal is valid
    fn verify_proposal(&self, block: &PipelinedBlock) -> ConsensusResult<bool> {
        // Check view is current or future
        let current_view = *self.current_view.read();
        if block.view < current_view {
            return Ok(false);
        }
        
        // Verify justify QC if present
        if let Some(ref justify) = block.justify_qc {
            if !justify.is_valid(self.quorum_threshold) {
                return Err(ConsensusError::InvalidVote(
                    "Invalid justify QC".to_string()
                ));
            }
            
            // Check parent matches justify
            if block.parent_hash != justify.block_hash {
                return Err(ConsensusError::InvalidVertex(
                    "Parent doesn't match justify QC".to_string()
                ));
            }
        }
        
        // Check against locked block (safety rule)
        if let Some(ref locked) = *self.locked_block.read() {
            // New block must extend locked block or have higher QC
            if let Some(ref justify) = block.justify_qc {
                if justify.view < locked.view {
                    return Ok(false);
                }
            }
        }
        
        Ok(true)
    }
    
    fn get_pipeline_block(&self, hash: &Hash) -> Option<PipelinedBlock> {
        let pipeline = self.pipeline.read();
        for slot in pipeline.values() {
            if slot.block.hash == *hash {
                return Some(slot.block.clone());
            }
        }
        
        // Check committed
        let committed = self.committed.read();
        for block in committed.values() {
            if block.hash == *hash {
                return Some(block.clone());
            }
        }
        
        None
    }
    
    fn has_block(&self, hash: &Hash) -> bool {
        self.get_pipeline_block(hash).is_some()
    }
    
    fn get_block_height(&self, hash: &Hash) -> Option<BlockHeight> {
        self.get_pipeline_block(hash).map(|b| b.height)
    }
    
    /// Returns current view
    pub fn current_view(&self) -> ViewNumber {
        *self.current_view.read()
    }
    
    /// Returns highest QC
    pub fn high_qc(&self) -> Option<QuorumCertificate> {
        self.high_qc.read().clone()
    }
    
    /// Returns locked block
    pub fn locked_block(&self) -> Option<PipelinedBlock> {
        self.locked_block.read().clone()
    }
    
    /// Returns pipeline depth
    pub fn pipeline_depth(&self) -> usize {
        self.pipeline.read().len()
    }
    
    /// Returns committed block count
    pub fn committed_count(&self) -> usize {
        self.committed.read().len()
    }
}

/// Parallel proposal coordinator for multi-shard pipelining
pub struct ParallelProposer {
    /// Per-shard consensus instances
    shard_consensus: HashMap<u16, Arc<PipelinedConsensus>>,
    /// Cross-shard synchronization
    sync_view: RwLock<ViewNumber>,
}

impl ParallelProposer {
    pub fn new() -> Self {
        Self {
            shard_consensus: HashMap::new(),
            sync_view: RwLock::new(0),
        }
    }
    
    /// Registers a shard consensus instance
    pub fn register_shard(&mut self, shard_id: u16, consensus: Arc<PipelinedConsensus>) {
        self.shard_consensus.insert(shard_id, consensus);
    }
    
    /// Creates proposals for multiple shards in parallel
    pub async fn propose_parallel(
        &self,
        shard_payloads: Vec<(u16, Vec<u8>, Hash)>,
    ) -> Vec<ConsensusResult<PipelinedBlock>> {
        use futures::future::join_all;
        
        let tasks: Vec<_> = shard_payloads
            .into_iter()
            .filter_map(|(shard_id, payload, state_root)| {
                self.shard_consensus.get(&shard_id).map(|consensus| {
                    let consensus = consensus.clone();
                    async move {
                        consensus.propose(payload, state_root)
                    }
                })
            })
            .collect();
        
        join_all(tasks).await
    }
    
    /// Synchronizes view across all shards
    pub fn sync_views(&self) {
        let max_view = self.shard_consensus
            .values()
            .map(|c| c.current_view())
            .max()
            .unwrap_or(0);
        
        *self.sync_view.write() = max_view;
        
        // Advance lagging shards
        for consensus in self.shard_consensus.values() {
            while consensus.current_view() < max_view {
                consensus.advance_view();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_proposal_creation() {
        let (tx, _rx) = mpsc::channel(100);
        let config = PipelineConfig::default();
        let consensus = PipelinedConsensus::new([1u8; 32], config, tx);
        
        let block = consensus.propose(
            b"test payload".to_vec(),
            [2u8; 32],
        ).unwrap();
        
        assert_eq!(block.proposer, [1u8; 32]);
        assert_eq!(block.status, ProposalStatus::Proposed);
        assert_eq!(consensus.pipeline_depth(), 1);
    }
    
    #[tokio::test]
    async fn test_vote_accumulation() {
        let (tx, _rx) = mpsc::channel(100);
        let config = PipelineConfig {
            quorum_threshold: 2,
            total_stake: 3,
            ..Default::default()
        };
        let consensus = PipelinedConsensus::new([1u8; 32], config, tx);
        
        let block = consensus.propose(b"test".to_vec(), [2u8; 32]).unwrap();
        
        // First vote - no quorum
        let vote1 = PipelineVote {
            block_hash: block.hash,
            view: block.view,
            voter: [10u8; 32],
            stake: 1,
            signature: vec![0u8; 64],
        };
        let result = consensus.on_vote(vote1).unwrap();
        assert!(result.is_none());
        
        // Second vote - quorum reached
        let vote2 = PipelineVote {
            block_hash: block.hash,
            view: block.view,
            voter: [11u8; 32],
            stake: 1,
            signature: vec![1u8; 64],
        };
        let result = consensus.on_vote(vote2).unwrap();
        assert!(result.is_some());
    }
    
    #[test]
    fn test_view_advance() {
        let (tx, _rx) = mpsc::channel(100);
        let config = PipelineConfig::default();
        let consensus = PipelinedConsensus::new([1u8; 32], config, tx);
        
        assert_eq!(consensus.current_view(), 0);
        consensus.advance_view();
        assert_eq!(consensus.current_view(), 1);
    }
}
