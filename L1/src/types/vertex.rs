use serde::{Deserialize, Serialize};
use crate::types::{Address, Hash, ShardId, SignedTransaction, hash_data};
use crate::crypto::{verify_ml_dsa_65_batch, with_domain, DOMAIN_VERTEX, DOMAIN_COMMITTEE_VOTE};

/// Maximum transactions per vertex
const MAX_TRANSACTIONS_PER_VERTEX: usize = 10000;
/// Maximum committee votes per vertex
const MAX_VOTES_PER_VERTEX: usize = 1000;
/// Maximum timestamp drift (5 minutes in seconds)
const MAX_TIMESTAMP_DRIFT: u64 = 5 * 60;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum VertexStatus {
    Pending,
    PreConfirmed,
    Confirmed,
    Finalized,
    Orphaned,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DAGVertex {
    pub hash: Hash,
    pub parents: Vec<Hash>,
    pub transactions: Vec<SignedTransaction>,
    pub timestamp: u64,
    pub shard_id: ShardId,
    pub creator: Address,
    pub signature: Vec<u8>,
    pub weight: u64,
    pub height: u64,
    pub status: VertexStatus,
    pub committee_votes: Vec<CommitteeVote>,
    pub state_root: Hash,
}

impl DAGVertex {
    pub fn new(
        parents: Vec<Hash>,
        transactions: Vec<SignedTransaction>,
        shard_id: ShardId,
        creator: Address,
        height: u64,
    ) -> Result<Self, String> {
        // CRITICAL: Validate transaction count
        if transactions.len() > MAX_TRANSACTIONS_PER_VERTEX {
            return Err(format!("Too many transactions: {} > {}", transactions.len(), MAX_TRANSACTIONS_PER_VERTEX));
        }
        let timestamp = chrono::Utc::now().timestamp() as u64;
        let mut vertex = Self {
            hash: [0u8; 32],
            parents,
            transactions,
            timestamp,
            shard_id,
            creator,
            signature: Vec::new(),
            weight: 0,
            height,
            status: VertexStatus::Pending,
            committee_votes: Vec::new(),
            state_root: [0u8; 32],
        };
        vertex.hash = vertex.compute_hash();
        Ok(vertex)
    }

    pub fn compute_hash(&self) -> Hash {
        let mut data = Vec::new();
        
        for parent in &self.parents {
            data.extend_from_slice(parent);
        }
        
        for tx in &self.transactions {
            data.extend_from_slice(&tx.hash);
        }
        
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&self.shard_id.to_le_bytes());
        data.extend_from_slice(&self.creator);
        data.extend_from_slice(&self.height.to_le_bytes());
        
        hash_data(&data)
    }

    pub fn signing_data(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&self.hash);
        msg.extend_from_slice(&self.state_root);
        with_domain(DOMAIN_VERTEX, &msg)
    }

    pub fn set_signature(&mut self, signature: Vec<u8>, public_key: &[u8]) -> Result<(), String> {
        // CRITICAL: Verify signature before accepting
        let signing_data = self.signing_data();
        if verify_ml_dsa_65_batch(public_key.to_vec(), signing_data, signature.clone()) {
            self.signature = signature;
            Ok(())
        } else {
            Err("Invalid vertex signature".to_string())
        }
    }
    
    pub fn validate_timestamp(&self, current_time: u64) -> Result<(), String> {
        if self.timestamp > current_time + MAX_TIMESTAMP_DRIFT {
            return Err("Vertex timestamp too far in future".to_string());
        }
        if current_time > self.timestamp + MAX_TIMESTAMP_DRIFT {
            return Err("Vertex timestamp too old".to_string());
        }
        Ok(())
    }

    pub fn set_state_root(&mut self, state_root: Hash) {
        self.state_root = state_root;
    }

    pub fn add_vote(&mut self, vote: CommitteeVote) -> Result<(), String> {
        // CRITICAL: Prevent unbounded vector growth
        if self.committee_votes.len() >= MAX_VOTES_PER_VERTEX {
            return Err(format!("Maximum votes reached: {}", MAX_VOTES_PER_VERTEX));
        }
        self.committee_votes.push(vote);
        self.update_weight();
        Ok(())
    }

    /// HIGH (z4): Use saturating arithmetic to prevent overflow
    fn update_weight(&mut self) {
        self.weight = self.committee_votes.iter()
            .filter(|v| v.approve)
            .map(|v| v.stake_weight)
            .fold(0u64, |acc, w| acc.saturating_add(w));
    }

    /// HIGH (z4): Use saturating arithmetic to prevent overflow
    pub fn has_quorum(&self, threshold: u64) -> bool {
        let approve_weight: u64 = self.committee_votes.iter()
            .filter(|v| v.approve)
            .map(|v| v.stake_weight)
            .fold(0u64, |acc, w| acc.saturating_add(w));
        approve_weight >= threshold
    }

    pub fn tx_count(&self) -> usize {
        self.transactions.len()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitteeVote {
    pub validator: Address,
    pub vertex_hash: Hash,
    pub approve: bool,
    pub stake_weight: u64,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

impl CommitteeVote {
    pub fn new(
        validator: Address,
        vertex_hash: Hash,
        approve: bool,
        stake_weight: u64,
    ) -> Self {
        Self {
            validator,
            vertex_hash,
            approve,
            stake_weight,
            signature: Vec::new(),
            timestamp: chrono::Utc::now().timestamp() as u64,
        }
    }

    pub fn signing_data(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&self.validator);
        msg.extend_from_slice(&self.vertex_hash);
        msg.push(self.approve as u8);
        msg.extend_from_slice(&self.stake_weight.to_le_bytes());
        msg.extend_from_slice(&self.timestamp.to_le_bytes());
        with_domain(DOMAIN_COMMITTEE_VOTE, &msg)
    }

    pub fn set_signature(&mut self, signature: Vec<u8>, public_key: &[u8]) -> Result<(), String> {
        // CRITICAL: Verify signature before accepting
        let signing_data = self.signing_data();
        if verify_ml_dsa_65_batch(public_key.to_vec(), signing_data, signature.clone()) {
            self.signature = signature;
            Ok(())
        } else {
            Err("Invalid vote signature".to_string())
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedSignature {
    pub vertex_hash: Hash,
    pub committee_id: u16,
    pub validators: Vec<Address>,
    pub aggregated_sig: Vec<u8>,
    pub bitmap: Vec<u8>,
    pub total_stake: u64,
}

impl AggregatedSignature {
    pub fn new(vertex_hash: Hash, committee_id: u16) -> Self {
        Self {
            vertex_hash,
            committee_id,
            validators: Vec::new(),
            aggregated_sig: Vec::new(),
            bitmap: Vec::new(),
            total_stake: 0,
        }
    }
}
