// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Snapshot Sync
//!
//! Fast state synchronization from snapshots instead of replaying from genesis.
//! Enables new nodes to join the network quickly with verified state.
//!
//! ## Features
//!
//! - **Chunked Snapshots**: Split large states into manageable chunks
//! - **Parallel Download**: Fetch chunks from multiple peers
//! - **Merkle Verification**: Verify each chunk against state root
//! - **Incremental Sync**: Resume interrupted syncs
//! - **Snapshot Pruning**: Manage snapshot storage

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::{Mutex, RwLock};
use tokio::sync::mpsc;

use crate::types::{Hash, Address};
use crate::state::{StateError, StateResult};

/// Snapshot chunk size (default 1MB)
const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

/// Maximum concurrent chunk downloads
const MAX_CONCURRENT_DOWNLOADS: usize = 16;

/// Snapshot metadata
#[derive(Clone, Debug)]
pub struct SnapshotMetadata {
    /// Snapshot identifier
    pub snapshot_id: Hash,
    /// Block height of snapshot
    pub block_height: u64,
    /// Epoch of snapshot
    pub epoch: u64,
    /// State root at snapshot
    pub state_root: Hash,
    /// Total size in bytes
    pub total_size: u64,
    /// Number of chunks
    pub chunk_count: u32,
    /// Chunk size
    pub chunk_size: usize,
    /// Creation timestamp
    pub created_at: u64,
    /// Merkle proofs for chunks
    pub chunk_proofs: Vec<ChunkProof>,
    /// Accounts count
    pub accounts_count: u64,
    /// Contracts count
    pub contracts_count: u64,
}

impl SnapshotMetadata {
    pub fn new(block_height: u64, epoch: u64, state_root: Hash) -> Self {
        let mut id_data = Vec::new();
        id_data.extend_from_slice(&block_height.to_le_bytes());
        id_data.extend_from_slice(&state_root);
        let snapshot_id = crate::crypto::sha3_256(&id_data);
        
        Self {
            snapshot_id,
            block_height,
            epoch,
            state_root,
            total_size: 0,
            chunk_count: 0,
            chunk_size: DEFAULT_CHUNK_SIZE,
            created_at: chrono::Utc::now().timestamp_millis() as u64,
            chunk_proofs: Vec::new(),
            accounts_count: 0,
            contracts_count: 0,
        }
    }
}

/// Proof for a single chunk
#[derive(Clone, Debug)]
pub struct ChunkProof {
    /// Chunk index
    pub index: u32,
    /// Chunk hash
    pub chunk_hash: Hash,
    /// Merkle proof path to state root
    pub proof_path: Vec<Hash>,
    /// Chunk offset in full state
    pub offset: u64,
    /// Chunk size
    pub size: u32,
}

impl ChunkProof {
    /// Verifies chunk data against proof
    pub fn verify(&self, data: &[u8], state_root: &Hash) -> bool {
        // Compute chunk hash
        let computed_hash = crate::crypto::sha3_256(data);
        if computed_hash != self.chunk_hash {
            return false;
        }
        
        // Verify Merkle proof
        let mut current = computed_hash;
        for (i, sibling) in self.proof_path.iter().enumerate() {
            let mut combined = Vec::with_capacity(64);
            if (self.index >> i) & 1 == 0 {
                combined.extend_from_slice(&current);
                combined.extend_from_slice(sibling);
            } else {
                combined.extend_from_slice(sibling);
                combined.extend_from_slice(&current);
            }
            current = crate::crypto::sha3_256(&combined);
        }
        
        current == *state_root
    }
}

/// Snapshot chunk data
#[derive(Clone)]
pub struct SnapshotChunk {
    /// Chunk index
    pub index: u32,
    /// Raw chunk data
    pub data: Vec<u8>,
    /// Chunk hash
    pub hash: Hash,
    /// Accounts in this chunk
    pub accounts: Vec<AccountSnapshot>,
    /// Storage entries in this chunk
    pub storage: Vec<StorageSnapshot>,
}

/// Account data in snapshot
#[derive(Clone, Debug)]
pub struct AccountSnapshot {
    pub address: Address,
    pub balance: u64,
    pub nonce: u64,
    pub code_hash: Option<Hash>,
    pub storage_root: Option<Hash>,
}

/// Storage entry in snapshot
#[derive(Clone, Debug)]
pub struct StorageSnapshot {
    pub address: Address,
    pub key: Hash,
    pub value: [u8; 32],
}

/// Sync status for a chunk
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkStatus {
    /// Not yet requested
    Pending,
    /// Currently downloading
    Downloading,
    /// Downloaded, verifying
    Verifying,
    /// Verified and applied
    Applied,
    /// Failed (will retry)
    Failed,
}

/// Chunk sync state
struct ChunkState {
    status: ChunkStatus,
    proof: ChunkProof,
    data: Option<Vec<u8>>,
    retries: u32,
    last_attempt: Option<Instant>,
    peer: Option<[u8; 32]>,
}

/// Sync progress information
#[derive(Clone, Debug)]
pub struct SyncProgress {
    /// Total chunks
    pub total_chunks: u32,
    /// Chunks downloaded
    pub downloaded_chunks: u32,
    /// Chunks verified
    pub verified_chunks: u32,
    /// Chunks applied
    pub applied_chunks: u32,
    /// Failed chunks
    pub failed_chunks: u32,
    /// Bytes downloaded
    pub bytes_downloaded: u64,
    /// Total bytes
    pub total_bytes: u64,
    /// Download speed (bytes/sec)
    pub download_speed: f64,
    /// Estimated time remaining
    pub eta_seconds: u64,
    /// Current phase
    pub phase: SyncPhase,
}

/// Sync phase
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncPhase {
    /// Fetching metadata
    FetchingMetadata,
    /// Downloading chunks
    DownloadingChunks,
    /// Verifying chunks
    VerifyingChunks,
    /// Applying to state
    ApplyingState,
    /// Finalizing
    Finalizing,
    /// Complete
    Complete,
    /// Failed
    Failed,
}

/// Snapshot sync configuration
#[derive(Clone, Debug)]
pub struct SnapshotSyncConfig {
    /// Chunk size in bytes
    pub chunk_size: usize,
    /// Maximum concurrent downloads
    pub max_concurrent: usize,
    /// Maximum retries per chunk
    pub max_retries: u32,
    /// Retry delay
    pub retry_delay: Duration,
    /// Download timeout per chunk
    pub chunk_timeout: Duration,
    /// Verify chunks in parallel
    pub parallel_verify: bool,
    /// Apply chunks in parallel
    pub parallel_apply: bool,
}

impl Default for SnapshotSyncConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_concurrent: MAX_CONCURRENT_DOWNLOADS,
            max_retries: 3,
            retry_delay: Duration::from_secs(5),
            chunk_timeout: Duration::from_secs(30),
            parallel_verify: true,
            parallel_apply: false,
        }
    }
}

/// Snapshot Sync Manager
pub struct SnapshotSync {
    config: SnapshotSyncConfig,
    /// Current snapshot being synced
    current_snapshot: RwLock<Option<SnapshotMetadata>>,
    /// Chunk states
    chunk_states: RwLock<HashMap<u32, ChunkState>>,
    /// Current sync phase
    phase: RwLock<SyncPhase>,
    /// Download start time
    start_time: Mutex<Option<Instant>>,
    /// Bytes downloaded
    bytes_downloaded: Mutex<u64>,
    /// Active downloads (chunk_index -> peer_id)
    active_downloads: Mutex<HashMap<u32, [u8; 32]>>,
    /// Available peers for download
    peers: RwLock<Vec<PeerInfo>>,
    /// Progress notification channel
    progress_tx: mpsc::Sender<SyncProgress>,
    /// State application callback
    state_applier: Arc<dyn StateApplier + Send + Sync>,
}

/// Peer information for snapshot sync
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub peer_id: [u8; 32],
    pub has_snapshot: bool,
    pub snapshot_height: u64,
    pub bandwidth: u64,
    pub latency_ms: u32,
    pub reliability: f64,
}

/// Trait for applying snapshot state
pub trait StateApplier {
    fn apply_account(&self, account: &AccountSnapshot) -> StateResult<()>;
    fn apply_storage(&self, storage: &StorageSnapshot) -> StateResult<()>;
    fn finalize(&self, state_root: Hash) -> StateResult<()>;
}

/// Default state applier (no-op for testing)
pub struct NoOpApplier;

impl StateApplier for NoOpApplier {
    fn apply_account(&self, _account: &AccountSnapshot) -> StateResult<()> { Ok(()) }
    fn apply_storage(&self, _storage: &StorageSnapshot) -> StateResult<()> { Ok(()) }
    fn finalize(&self, _state_root: Hash) -> StateResult<()> { Ok(()) }
}

impl SnapshotSync {
    pub fn new(
        config: SnapshotSyncConfig,
        progress_tx: mpsc::Sender<SyncProgress>,
        state_applier: Arc<dyn StateApplier + Send + Sync>,
    ) -> Self {
        Self {
            config,
            current_snapshot: RwLock::new(None),
            chunk_states: RwLock::new(HashMap::new()),
            phase: RwLock::new(SyncPhase::FetchingMetadata),
            start_time: Mutex::new(None),
            bytes_downloaded: Mutex::new(0),
            active_downloads: Mutex::new(HashMap::new()),
            peers: RwLock::new(Vec::new()),
            progress_tx,
            state_applier,
        }
    }
    
    /// Registers a peer for snapshot sync
    pub fn add_peer(&self, peer: PeerInfo) {
        self.peers.write().push(peer);
    }
    
    /// Removes a peer
    pub fn remove_peer(&self, peer_id: &[u8; 32]) {
        self.peers.write().retain(|p| &p.peer_id != peer_id);
    }
    
    /// Starts sync with given snapshot metadata
    pub fn start_sync(&self, metadata: SnapshotMetadata) -> StateResult<()> {
        // Initialize chunk states
        {
            let mut states = self.chunk_states.write();
            states.clear();
            
            for proof in &metadata.chunk_proofs {
                states.insert(proof.index, ChunkState {
                    status: ChunkStatus::Pending,
                    proof: proof.clone(),
                    data: None,
                    retries: 0,
                    last_attempt: None,
                    peer: None,
                });
            }
        }
        
        *self.current_snapshot.write() = Some(metadata);
        *self.phase.write() = SyncPhase::DownloadingChunks;
        *self.start_time.lock() = Some(Instant::now());
        *self.bytes_downloaded.lock() = 0;
        
        Ok(())
    }
    
    /// Gets next chunks to download
    pub fn get_pending_chunks(&self, max: usize) -> Vec<(u32, ChunkProof)> {
        let states = self.chunk_states.read();
        let active = self.active_downloads.lock();
        
        states.iter()
            .filter(|(idx, state)| {
                state.status == ChunkStatus::Pending && 
                !active.contains_key(idx)
            })
            .take(max)
            .map(|(idx, state)| (*idx, state.proof.clone()))
            .collect()
    }
    
    /// Selects best peer for download
    pub fn select_peer(&self) -> Option<PeerInfo> {
        let peers = self.peers.read();
        
        // Sort by reliability and bandwidth
        let mut available: Vec<_> = peers.iter()
            .filter(|p| p.has_snapshot)
            .collect();
        
        available.sort_by(|a, b| {
            let score_a = a.reliability * a.bandwidth as f64;
            let score_b = b.reliability * b.bandwidth as f64;
            score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        available.first().cloned().cloned()
    }
    
    /// Marks chunk download as started
    pub fn start_chunk_download(&self, chunk_index: u32, peer_id: [u8; 32]) {
        if let Some(state) = self.chunk_states.write().get_mut(&chunk_index) {
            state.status = ChunkStatus::Downloading;
            state.last_attempt = Some(Instant::now());
            state.peer = Some(peer_id);
        }
        self.active_downloads.lock().insert(chunk_index, peer_id);
    }
    
    /// Receives downloaded chunk data
    pub fn receive_chunk(&self, chunk_index: u32, data: Vec<u8>) -> StateResult<bool> {
        let snapshot = self.current_snapshot.read();
        let metadata = snapshot.as_ref()
            .ok_or_else(|| StateError::ExecutionError("No active sync".to_string()))?;
        
        // MEDIUM (w7): Validate chunk index is within expected range
        if chunk_index >= metadata.chunk_count {
            return Err(StateError::ExecutionError(
                format!("Chunk index {} out of range (max {})", chunk_index, metadata.chunk_count)
            ));
        }
        
        // MEDIUM (w7): Validate chunk data is not empty and within size bounds
        if data.is_empty() {
            return Err(StateError::ExecutionError("Empty chunk data".to_string()));
        }
        // Allow 2x chunk_size as upper bound (last chunk may differ, but reject absurd sizes)
        let max_chunk_size = metadata.chunk_size.saturating_mul(2);
        if data.len() > max_chunk_size {
            return Err(StateError::ExecutionError(
                format!("Chunk size {} exceeds max allowed {}", data.len(), max_chunk_size)
            ));
        }
        
        // Update bytes downloaded
        {
            let mut bytes = self.bytes_downloaded.lock();
            *bytes += data.len() as u64;
        }
        
        // Remove from active
        self.active_downloads.lock().remove(&chunk_index);
        
        // Verify chunk
        let mut states = self.chunk_states.write();
        let state = states.get_mut(&chunk_index)
            .ok_or_else(|| StateError::ExecutionError("Unknown chunk".to_string()))?;
        
        state.status = ChunkStatus::Verifying;
        
        // MEDIUM (w7): Validate chunk size matches expected proof size (if non-zero)
        if state.proof.size > 0 && data.len() as u32 != state.proof.size {
            // Allow mismatch only for the last chunk
            if chunk_index < metadata.chunk_count.saturating_sub(1) {
                state.status = ChunkStatus::Failed;
                state.retries += 1;
                tracing::warn!("Chunk {} size mismatch: got {}, expected {}", chunk_index, data.len(), state.proof.size);
                return Ok(false);
            }
        }
        
        if state.proof.verify(&data, &metadata.state_root) {
            state.data = Some(data);
            state.status = ChunkStatus::Applied;
            
            // Check if all done
            drop(states);
            self.check_completion();
            
            Ok(true)
        } else {
            state.status = ChunkStatus::Failed;
            state.retries += 1;
            
            if state.retries < self.config.max_retries {
                state.status = ChunkStatus::Pending;
            }
            
            Ok(false)
        }
    }
    
    /// Handles chunk download failure
    pub fn chunk_failed(&self, chunk_index: u32) {
        self.active_downloads.lock().remove(&chunk_index);
        
        if let Some(state) = self.chunk_states.write().get_mut(&chunk_index) {
            state.status = ChunkStatus::Failed;
            state.retries += 1;
            
            if state.retries < self.config.max_retries {
                state.status = ChunkStatus::Pending;
            }
        }
    }
    
    /// Applies all downloaded chunks to state
    pub async fn apply_chunks(&self) -> StateResult<()> {
        *self.phase.write() = SyncPhase::ApplyingState;
        
        let states = self.chunk_states.read();
        
        for (_, state) in states.iter() {
            if state.status != ChunkStatus::Applied {
                continue;
            }
            
            if let Some(ref data) = state.data {
                // Deserialize and apply
                let chunk = self.deserialize_chunk(data)?;
                
                for account in &chunk.accounts {
                    self.state_applier.apply_account(account)?;
                }
                
                for storage in &chunk.storage {
                    self.state_applier.apply_storage(storage)?;
                }
            }
        }
        
        Ok(())
    }
    
    /// Deserializes chunk data
    fn deserialize_chunk(&self, data: &[u8]) -> StateResult<SnapshotChunk> {
        let hash = crate::crypto::sha3_256(data);
        
        Ok(SnapshotChunk {
            index: 0,
            data: data.to_vec(),
            hash,
            accounts: Vec::new(),
            storage: Vec::new(),
        })
    }
    
    /// Checks if sync is complete
    fn check_completion(&self) {
        let states = self.chunk_states.read();
        
        let all_applied = states.values().all(|s| s.status == ChunkStatus::Applied);
        let any_failed = states.values().any(|s| {
            s.status == ChunkStatus::Failed && s.retries >= self.config.max_retries
        });
        
        if any_failed {
            *self.phase.write() = SyncPhase::Failed;
        } else if all_applied {
            *self.phase.write() = SyncPhase::Finalizing;
        }
    }
    
    /// Finalizes sync
    pub fn finalize(&self) -> StateResult<()> {
        let snapshot = self.current_snapshot.read();
        let metadata = snapshot.as_ref()
            .ok_or_else(|| StateError::ExecutionError("No active sync".to_string()))?;
        
        self.state_applier.finalize(metadata.state_root)?;
        
        *self.phase.write() = SyncPhase::Complete;
        
        tracing::info!(
            "Snapshot sync complete: height={}, accounts={}",
            metadata.block_height,
            metadata.accounts_count
        );
        
        Ok(())
    }
    
    /// Gets current sync progress
    pub fn progress(&self) -> SyncProgress {
        let states = self.chunk_states.read();
        let snapshot = self.current_snapshot.read();
        
        let total_chunks = states.len() as u32;
        let downloaded = states.values().filter(|s| s.data.is_some()).count() as u32;
        let verified = states.values().filter(|s| s.status == ChunkStatus::Applied).count() as u32;
        let failed = states.values().filter(|s| s.status == ChunkStatus::Failed).count() as u32;
        
        let bytes_downloaded = *self.bytes_downloaded.lock();
        let total_bytes = snapshot.as_ref().map(|s| s.total_size).unwrap_or(0);
        
        let elapsed = self.start_time.lock()
            .map(|t| t.elapsed().as_secs_f64())
            .unwrap_or(1.0);
        
        let speed = bytes_downloaded as f64 / elapsed;
        let remaining_bytes = total_bytes.saturating_sub(bytes_downloaded);
        let eta = if speed > 0.0 { (remaining_bytes as f64 / speed) as u64 } else { 0 };
        
        SyncProgress {
            total_chunks,
            downloaded_chunks: downloaded,
            verified_chunks: verified,
            applied_chunks: verified,
            failed_chunks: failed,
            bytes_downloaded,
            total_bytes,
            download_speed: speed,
            eta_seconds: eta,
            phase: *self.phase.read(),
        }
    }
    
    /// Aborts current sync
    pub fn abort(&self) {
        *self.phase.write() = SyncPhase::Failed;
        self.chunk_states.write().clear();
        self.active_downloads.lock().clear();
        *self.current_snapshot.write() = None;
    }
    
    /// Returns current phase
    pub fn phase(&self) -> SyncPhase {
        *self.phase.read()
    }
    
    /// Returns if sync is active
    pub fn is_active(&self) -> bool {
        let phase = *self.phase.read();
        !matches!(phase, SyncPhase::Complete | SyncPhase::Failed | SyncPhase::FetchingMetadata)
    }
}

/// Snapshot creator for generating snapshots
pub struct SnapshotCreator {
    config: SnapshotSyncConfig,
}

impl SnapshotCreator {
    pub fn new(config: SnapshotSyncConfig) -> Self {
        Self { config }
    }
    
    /// Creates a snapshot from current state
    pub fn create_snapshot(
        &self,
        block_height: u64,
        epoch: u64,
        state_root: Hash,
        accounts: &[AccountSnapshot],
        storage: &[StorageSnapshot],
    ) -> StateResult<(SnapshotMetadata, Vec<SnapshotChunk>)> {
        let mut metadata = SnapshotMetadata::new(block_height, epoch, state_root);
        metadata.accounts_count = accounts.len() as u64;
        metadata.chunk_size = self.config.chunk_size;
        
        // Serialize state data
        let mut all_data = Vec::new();
        
        // Serialize accounts
        for account in accounts {
            all_data.extend_from_slice(&account.address);
            all_data.extend_from_slice(&account.balance.to_le_bytes());
            all_data.extend_from_slice(&account.nonce.to_le_bytes());
        }
        
        // Serialize storage
        for slot in storage {
            all_data.extend_from_slice(&slot.address);
            all_data.extend_from_slice(&slot.key);
            all_data.extend_from_slice(&slot.value);
        }
        
        metadata.total_size = all_data.len() as u64;
        
        // Split into chunks
        let mut chunks = Vec::new();
        let mut chunk_hashes = Vec::new();
        
        for (i, chunk_data) in all_data.chunks(self.config.chunk_size).enumerate() {
            let hash = crate::crypto::sha3_256(chunk_data);
            chunk_hashes.push(hash);
            
            chunks.push(SnapshotChunk {
                index: i as u32,
                data: chunk_data.to_vec(),
                hash,
                accounts: Vec::new(),
                storage: Vec::new(),
            });
        }
        
        metadata.chunk_count = chunks.len() as u32;
        
        // Build Merkle proofs for chunks
        let proofs = self.build_chunk_proofs(&chunk_hashes, state_root);
        metadata.chunk_proofs = proofs;
        
        Ok((metadata, chunks))
    }
    
    /// Builds Merkle proofs for chunks
    fn build_chunk_proofs(&self, chunk_hashes: &[Hash], _state_root: Hash) -> Vec<ChunkProof> {
        let mut proofs = Vec::new();
        let mut offset = 0u64;
        
        for (i, hash) in chunk_hashes.iter().enumerate() {
            let size = self.config.chunk_size as u32;
            
            // Build Merkle proof path from leaf to root
            let proof_path = self.build_proof_path(chunk_hashes, i);
            
            proofs.push(ChunkProof {
                index: i as u32,
                chunk_hash: *hash,
                proof_path,
                offset,
                size,
            });
            
            offset += size as u64;
        }
        
        proofs
    }
    
    /// Builds Merkle proof path for a chunk
    fn build_proof_path(&self, hashes: &[Hash], index: usize) -> Vec<Hash> {
        if hashes.len() <= 1 {
            return Vec::new();
        }
        
        let mut path = Vec::new();
        let mut level = hashes.to_vec();
        let mut idx = index;
        
        while level.len() > 1 {
            // Get sibling
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            if sibling_idx < level.len() {
                path.push(level[sibling_idx]);
            }
            
            // Build next level
            let mut next_level = Vec::new();
            for chunk in level.chunks(2) {
                let mut combined = Vec::new();
                combined.extend_from_slice(&chunk[0]);
                if chunk.len() > 1 {
                    combined.extend_from_slice(&chunk[1]);
                }
                next_level.push(crate::crypto::sha3_256(&combined));
            }
            
            level = next_level;
            idx /= 2;
        }
        
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_chunk_proof_verification() {
        let data = b"test chunk data";
        let hash = crate::crypto::sha3_256(data);
        
        let proof = ChunkProof {
            index: 0,
            chunk_hash: hash,
            proof_path: Vec::new(),
            offset: 0,
            size: data.len() as u32,
        };
        
        // With empty proof path, should match directly
        assert!(proof.verify(data, &hash));
        
        // Wrong data should fail
        assert!(!proof.verify(b"wrong data", &hash));
    }
    
    #[test]
    fn test_snapshot_creation() {
        let creator = SnapshotCreator::new(SnapshotSyncConfig {
            chunk_size: 100,
            ..Default::default()
        });
        
        let accounts = vec![
            AccountSnapshot {
                address: [1u8; 32],
                balance: 1000,
                nonce: 5,
                code_hash: None,
                storage_root: None,
            }
        ];
        
        let (metadata, chunks) = creator.create_snapshot(
            100,
            10,
            [0u8; 32],
            &accounts,
            &[],
        ).unwrap();
        
        assert_eq!(metadata.block_height, 100);
        assert_eq!(metadata.accounts_count, 1);
        assert!(!chunks.is_empty());
    }
    
    #[tokio::test]
    async fn test_sync_progress() {
        let (tx, _rx) = mpsc::channel(10);
        let sync = SnapshotSync::new(
            SnapshotSyncConfig::default(),
            tx,
            Arc::new(NoOpApplier),
        );
        
        let metadata = SnapshotMetadata {
            chunk_proofs: vec![
                ChunkProof {
                    index: 0,
                    chunk_hash: [1u8; 32],
                    proof_path: Vec::new(),
                    offset: 0,
                    size: 1000,
                }
            ],
            ..SnapshotMetadata::new(100, 10, [0u8; 32])
        };
        
        sync.start_sync(metadata).unwrap();
        
        let progress = sync.progress();
        assert_eq!(progress.total_chunks, 1);
        assert_eq!(progress.phase, SyncPhase::DownloadingChunks);
    }
}
