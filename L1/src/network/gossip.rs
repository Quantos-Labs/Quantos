// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use serde::{Deserialize, Serialize};
use crate::types::{CommitteeVote, DAGVertex, Hash, SignedTransaction, Checkpoint};
use parking_lot::Mutex;

/// Maximum hops in propagation path to prevent memory exhaustion
const MAX_PROPAGATION_HOPS: usize = 32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GossipMessage {
    Transaction(TransactionGossip),
    Vertex(VertexGossip),
    Vote(VoteGossip),
    Checkpoint(CheckpointGossip),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionGossip {
    pub transaction: SignedTransaction,
    pub first_seen: u64,
}

impl TransactionGossip {
    pub fn new(transaction: SignedTransaction) -> Self {
        Self {
            transaction,
            first_seen: chrono::Utc::now().timestamp_millis() as u64,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct VertexGossip {
    pub vertex: DAGVertex,
    pub propagation_path: Vec<[u8; 32]>,
}

/// Custom deserializer that enforces MAX_PROPAGATION_HOPS on propagation_path
impl<'de> Deserialize<'de> for VertexGossip {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawVertexGossip {
            vertex: DAGVertex,
            propagation_path: Vec<[u8; 32]>,
        }
        
        let raw = RawVertexGossip::deserialize(deserializer)?;
        
        // CRITICAL: Reject messages with propagation_path exceeding the limit
        // to prevent memory exhaustion from malicious payloads
        if raw.propagation_path.len() > MAX_PROPAGATION_HOPS {
            return Err(serde::de::Error::custom(format!(
                "propagation_path length {} exceeds maximum {}",
                raw.propagation_path.len(),
                MAX_PROPAGATION_HOPS
            )));
        }
        
        Ok(VertexGossip {
            vertex: raw.vertex,
            propagation_path: raw.propagation_path,
        })
    }
}

#[derive(Debug)]
pub enum GossipError {
    PropagationPathTooLong,
}

impl VertexGossip {
    pub fn new(vertex: DAGVertex) -> Self {
        Self {
            vertex,
            propagation_path: Vec::new(),
        }
    }

    pub fn add_hop(&mut self, peer_id: [u8; 32]) -> Result<(), GossipError> {
        // CRITICAL: Limit propagation path to prevent memory exhaustion
        if self.propagation_path.len() >= MAX_PROPAGATION_HOPS {
            return Err(GossipError::PropagationPathTooLong);
        }
        self.propagation_path.push(peer_id);
        Ok(())
    }
    
    /// Validates the propagation path length
    pub fn validate(&self) -> bool {
        self.propagation_path.len() <= MAX_PROPAGATION_HOPS
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteGossip {
    pub vote: CommitteeVote,
    pub committee_id: u16,
    pub epoch: u64,
}

impl VoteGossip {
    pub fn new(vote: CommitteeVote, committee_id: u16, epoch: u64) -> Self {
        Self {
            vote,
            committee_id,
            epoch,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointGossip {
    pub checkpoint: Checkpoint,
    pub signatures: Vec<crate::types::ValidatorSignature>,
}

impl CheckpointGossip {
    pub fn new(checkpoint: Checkpoint) -> Self {
        Self {
            checkpoint,
            signatures: Vec::new(),
        }
    }
}

pub const TOPIC_TRANSACTIONS: &str = "/quantos/tx/1.0.0";
pub const TOPIC_VERTICES: &str = "/quantos/vertex/1.0.0";
pub const TOPIC_VOTES: &str = "/quantos/vote/1.0.0";
pub const TOPIC_CHECKPOINTS: &str = "/quantos/checkpoint/1.0.0";

pub fn shard_topic(shard_id: u16) -> String {
    format!("/quantos/shard/{}/1.0.0", shard_id)
}

pub fn committee_topic(committee_id: u16) -> String {
    format!("/quantos/committee/{}/1.0.0", committee_id)
}

pub struct MessageValidator {
    max_message_size: usize,
    max_tx_per_second: u32,
    seen_messages: dashmap::DashMap<Hash, u64>,
    /// Lock for atomic deduplication check-and-insert
    dedup_lock: Mutex<()>,
}

impl MessageValidator {
    pub fn new(max_message_size: usize, max_tx_per_second: u32) -> Self {
        Self {
            max_message_size,
            max_tx_per_second,
            seen_messages: dashmap::DashMap::new(),
            dedup_lock: Mutex::new(()),
        }
    }

    pub fn validate_message(&self, data: &[u8]) -> bool {
        if data.len() > self.max_message_size {
            return false;
        }
        true
    }

    pub fn is_duplicate(&self, hash: &Hash) -> bool {
        // CRITICAL: Atomic check-and-insert to prevent race condition
        let _lock = self.dedup_lock.lock();
        
        let now = chrono::Utc::now().timestamp() as u64;
        
        if let Some(seen_at) = self.seen_messages.get(hash) {
            if now - *seen_at < 60 {
                return true;
            }
        }
        
        self.seen_messages.insert(*hash, now);
        false
    }

    pub fn cleanup_old_messages(&self) {
        // CRITICAL: Hold the dedup lock during cleanup to prevent race condition
        // where a message is removed from seen_messages between the check and
        // insert in is_duplicate, causing duplicate processing
        let _lock = self.dedup_lock.lock();
        
        let now = chrono::Utc::now().timestamp() as u64;
        self.seen_messages.retain(|_, seen_at| now - *seen_at < 300);
        
        // Hard cap: if cache is still too large after TTL cleanup, evict oldest
        const MAX_DEDUP_ENTRIES: usize = 500_000;
        if self.seen_messages.len() > MAX_DEDUP_ENTRIES {
            let excess = self.seen_messages.len() - MAX_DEDUP_ENTRIES;
            let mut entries: Vec<(Hash, u64)> = self.seen_messages.iter()
                .map(|e| (*e.key(), *e.value()))
                .collect();
            entries.sort_by_key(|(_, ts)| *ts);
            for (hash, _) in entries.into_iter().take(excess) {
                self.seen_messages.remove(&hash);
            }
        }
    }
}
