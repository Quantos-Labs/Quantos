use std::collections::{VecDeque, HashSet};
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::warn;

/// Maximum sync requests to prevent memory exhaustion
const MAX_SYNC_REQUESTS: usize = 1000;
/// Maximum slot range per sync to prevent DoS
const MAX_SLOT_RANGE: u64 = 100_000;

use crate::consensus::QuantosConsensus;
use crate::network::{NetworkResult, NetworkError, SyncRequest, SyncResponse};
use crate::types::{Checkpoint, Hash, ShardId};

pub struct ChainSyncer {
    consensus: QuantosConsensus,
    sync_state: Arc<RwLock<SyncState>>,
    pending_requests: Arc<RwLock<VecDeque<SyncRequest>>>,
}

#[derive(Clone, Debug)]
pub struct SyncState {
    pub syncing: bool,
    pub current_slot: u64,
    pub target_slot: u64,
    pub synced_shards: Vec<ShardId>,
    pub progress: f64,
}

impl Default for SyncState {
    fn default() -> Self {
        Self {
            syncing: false,
            current_slot: 0,
            target_slot: 0,
            synced_shards: Vec::new(),
            progress: 0.0,
        }
    }
}

impl ChainSyncer {
    pub fn new(consensus: QuantosConsensus) -> Self {
        Self {
            consensus,
            sync_state: Arc::new(RwLock::new(SyncState::default())),
            pending_requests: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    pub async fn start_sync(&self, target_slot: u64) -> NetworkResult<()> {
        let current_slot = self.consensus.current_slot();
        
        if target_slot <= current_slot {
            return Ok(());
        }
        
        // CRITICAL: Validate slot range to prevent DoS
        let slot_range = target_slot.saturating_sub(current_slot);
        if slot_range > MAX_SLOT_RANGE {
            warn!("Sync range too large: {} slots, capping to {}", slot_range, MAX_SLOT_RANGE);
            return Err(NetworkError::InvalidMessage(
                format!("Sync range exceeds maximum: {} > {}", slot_range, MAX_SLOT_RANGE)
            ));
        }

        {
            let mut state = self.sync_state.write();
            state.syncing = true;
            state.current_slot = current_slot;
            state.target_slot = target_slot;
            state.progress = 0.0;
        }

        tracing::info!("Starting sync from slot {} to {}", current_slot, target_slot);

        let batch_size = 100u64;
        let mut from_slot = current_slot;

        while from_slot < target_slot {
            // CRITICAL: Check total queue size across ALL calls, not just this call's count
            let current_queue_len = self.pending_requests.read().len();
            if current_queue_len >= MAX_SYNC_REQUESTS {
                warn!("Sync request queue full: {} pending (max {})", current_queue_len, MAX_SYNC_REQUESTS);
                break;
            }
            
            let to_slot = std::cmp::min(from_slot + batch_size, target_slot);
            
            let request = SyncRequest {
                from_slot,
                to_slot,
                shard_id: None,
                batch_size: 100,
            };

            self.pending_requests.write().push_back(request);
            from_slot = to_slot;
        }

        Ok(())
    }

    pub async fn handle_sync_response(&self, response: SyncResponse) -> NetworkResult<()> {
        for vertex in response.vertices {
            self.consensus.receive_vertex(vertex).await
                .map_err(|e| NetworkError::InvalidMessage(e.to_string()))?;
        }

        let mut state = self.sync_state.write();
        if state.target_slot > 0 {
            state.progress = (state.current_slot as f64 / state.target_slot as f64) * 100.0;
        }

        if state.current_slot >= state.target_slot {
            state.syncing = false;
            tracing::info!("Sync completed at slot {}", state.current_slot);
        }

        Ok(())
    }

    pub fn create_sync_response(&self, request: &SyncRequest) -> SyncResponse {
        let vertices = Vec::new();
        
        SyncResponse {
            vertices,
            checkpoint: None,
            has_more: false,
            next_slot: request.to_slot,
        }
    }

    pub fn sync_state(&self) -> SyncState {
        self.sync_state.read().clone()
    }

    pub fn is_syncing(&self) -> bool {
        self.sync_state.read().syncing
    }

    pub fn sync_progress(&self) -> f64 {
        self.sync_state.read().progress
    }

    pub fn next_sync_request(&self) -> Option<SyncRequest> {
        self.pending_requests.write().pop_front()
    }
}

pub struct VertexDownloader {
    pending_downloads: Arc<RwLock<HashSet<Hash>>>,
    max_concurrent: usize,
}

impl VertexDownloader {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            pending_downloads: Arc::new(RwLock::new(HashSet::new())),
            max_concurrent,
        }
    }

    pub fn request_vertex(&self, hash: Hash) {
        let mut pending = self.pending_downloads.write();
        // OPTIMIZATION: O(1) lookup with HashSet instead of O(n) Vec::contains
        if pending.len() < self.max_concurrent * 10 {
            pending.insert(hash);
        }
    }

    pub fn request_vertices(&self, hashes: Vec<Hash>) {
        for hash in hashes {
            self.request_vertex(hash);
        }
    }

    pub fn get_pending_downloads(&self, limit: usize) -> Vec<Hash> {
        let mut pending = self.pending_downloads.write();
        let count = std::cmp::min(limit, pending.len());
        // OPTIMIZATION: Collect first, then remove in bulk — avoids O(n) per-element
        // removal during iteration which caused O(n*limit) total cost
        let batch: Vec<Hash> = pending.iter().take(count).copied().collect();
        for h in &batch {
            pending.remove(h);
        }
        batch
    }

    pub fn mark_downloaded(&self, hash: &Hash) {
        self.pending_downloads.write().remove(hash);
    }

    pub fn pending_count(&self) -> usize {
        self.pending_downloads.read().len()
    }
}

pub struct CheckpointSyncer {
    latest_known: Arc<RwLock<Option<Checkpoint>>>,
}

impl CheckpointSyncer {
    pub fn new() -> Self {
        Self {
            latest_known: Arc::new(RwLock::new(None)),
        }
    }

    pub fn update_latest(&self, checkpoint: Checkpoint) {
        let mut latest = self.latest_known.write();
        if latest.as_ref().map(|c| c.slot).unwrap_or(0) < checkpoint.slot {
            *latest = Some(checkpoint);
        }
    }

    pub fn latest_checkpoint(&self) -> Option<Checkpoint> {
        self.latest_known.read().clone()
    }

    pub fn needs_sync(&self, local_slot: u64) -> bool {
        self.latest_known.read()
            .as_ref()
            .map(|c| c.slot > local_slot + 100)
            .unwrap_or(false)
    }
}

impl Default for CheckpointSyncer {
    fn default() -> Self {
        Self::new()
    }
}
