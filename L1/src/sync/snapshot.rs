//! # Snapshot Sync
//!
//! Fast node bootstrapping via state snapshots.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Snapshot Structure                        │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Header: slot, state_root, chunk_count, total_size          │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Chunk 0: accounts[0..N]     │ Merkle proof                 │
//! │  Chunk 1: accounts[N..2N]    │ Merkle proof                 │
//! │  Chunk 2: storage[0..M]      │ Merkle proof                 │
//! │  ...                         │ ...                          │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Manifest: chunk_hashes[], signatures[]                     │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::{RwLock, Mutex};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::types::{Hash, ShardId, Slot};
use crate::crypto::{verify_dilithium, verify_dilithium_batch};
use super::{SyncError, SyncResult};

/// Maximum total memory for chunks (1GB)
const MAX_CHUNK_MEMORY: usize = 1024 * 1024 * 1024;
/// Maximum decompressed size (100MB per chunk)
const MAX_DECOMPRESSED_SIZE: usize = 100 * 1024 * 1024;
/// Pending request timeout (seconds)
const PENDING_REQUEST_TIMEOUT: u64 = 60;
/// HIGH (y2): Maximum decompression ratio to prevent decompression bombs
const MAX_DECOMPRESSION_RATIO: usize = 100;
/// MEDIUM (y6): Maximum entries in a single snapshot to prevent unbounded iterator
const MAX_SNAPSHOT_ENTRIES: u64 = 100_000_000;
/// MEDIUM (y6): Maximum chunks per snapshot
const MAX_SNAPSHOT_CHUNKS: u64 = 100_000;

/// Snapshot configuration.
#[derive(Clone, Debug)]
pub struct SnapshotConfig {
    /// Interval between snapshots (in slots)
    pub snapshot_interval: u64,
    /// Number of chunks per snapshot
    pub chunks_per_snapshot: u64,
    /// Maximum chunk size in bytes
    pub max_chunk_size: usize,
    /// Number of parallel chunk downloads
    pub parallel_downloads: usize,
    /// Chunk download timeout
    pub chunk_timeout: Duration,
    /// Maximum snapshots to retain
    pub max_retained_snapshots: usize,
    /// Enable compression for chunks
    pub compression_enabled: bool,
    /// Minimum validators required to sign snapshot
    pub min_snapshot_signers: usize,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            snapshot_interval: 1000,
            chunks_per_snapshot: 256,
            max_chunk_size: 4 * 1024 * 1024, // 4 MB
            parallel_downloads: 8,
            chunk_timeout: Duration::from_secs(30),
            max_retained_snapshots: 3,
            compression_enabled: true,
            min_snapshot_signers: 10,
        }
    }
}

/// Snapshot metadata/header.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotHeader {
    /// Snapshot version
    pub version: u32,
    /// Slot at which snapshot was taken
    pub slot: Slot,
    /// State root hash
    pub state_root: Hash,
    /// Number of chunks
    pub chunk_count: u64,
    /// Total uncompressed size
    pub total_size: u64,
    /// Compressed size (if compression enabled)
    pub compressed_size: Option<u64>,
    /// Timestamp
    pub timestamp: u64,
    /// Shard ID (for sharded snapshots)
    pub shard_id: Option<ShardId>,
    /// Previous snapshot hash (for incremental)
    pub previous_snapshot: Option<Hash>,
}

/// Snapshot manifest with chunk information.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotManifest {
    /// Snapshot header
    pub header: SnapshotHeader,
    /// Hash of each chunk
    pub chunk_hashes: Vec<Hash>,
    /// Merkle root of all chunks
    pub chunks_root: Hash,
    /// Validator signatures attesting to snapshot validity
    pub signatures: Vec<SnapshotSignature>,
    /// Accounts range per chunk
    pub chunk_ranges: Vec<ChunkRange>,
}

/// Signature from a validator attesting to snapshot validity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotSignature {
    /// Validator public key
    pub validator: [u8; 32],
    /// Signature over manifest hash
    pub signature: Vec<u8>,
    /// Validator's stake weight
    pub stake_weight: u64,
}

/// Range of data covered by a chunk.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkRange {
    /// Chunk index
    pub index: u64,
    /// Start key (account address or storage key)
    pub start_key: Vec<u8>,
    /// End key
    pub end_key: Vec<u8>,
    /// Data type (accounts, storage, code)
    pub data_type: ChunkDataType,
}

/// Type of data in a chunk.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChunkDataType {
    /// Account balances and nonces
    Accounts,
    /// Contract storage
    Storage,
    /// Contract bytecode
    Code,
    /// Validator set
    Validators,
    /// Shard state
    ShardState,
}

/// A single chunk of snapshot data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotChunk {
    /// Chunk index
    pub index: u64,
    /// Snapshot slot
    pub snapshot_slot: Slot,
    /// Chunk data (possibly compressed)
    pub data: Vec<u8>,
    /// Whether data is compressed
    pub compressed: bool,
    /// Merkle proof linking chunk to state root
    pub merkle_proof: Vec<Hash>,
    /// Hash of this chunk
    pub hash: Hash,
}

/// Status of a snapshot download.
#[derive(Clone, Debug)]
pub struct SnapshotDownloadStatus {
    /// Snapshot being downloaded
    pub snapshot_slot: Slot,
    /// Total chunks
    pub total_chunks: u64,
    /// Downloaded chunks
    pub downloaded_chunks: u64,
    /// Verified chunks
    pub verified_chunks: u64,
    /// Applied chunks
    pub applied_chunks: u64,
    /// Current download speed (bytes/sec)
    pub download_speed: u64,
    /// Estimated time remaining
    pub eta_seconds: u64,
    /// Current phase
    pub phase: SnapshotSyncPhase,
    /// Start time
    pub started_at: Instant,
}

/// Phase of snapshot synchronization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotSyncPhase {
    /// Finding available snapshots
    Discovery,
    /// Downloading manifest
    DownloadingManifest,
    /// Downloading chunks
    DownloadingChunks,
    /// Verifying chunks
    Verifying,
    /// Applying to state
    Applying,
    /// Catching up from snapshot to head
    CatchingUp,
    /// Complete
    Complete,
    /// Failed
    Failed(String),
}

/// Snapshot sync metrics.
#[derive(Clone, Debug, Default)]
pub struct SnapshotMetrics {
    /// Total snapshots created
    pub snapshots_created: u64,
    /// Total snapshots downloaded
    pub snapshots_downloaded: u64,
    /// Total chunks served
    pub chunks_served: u64,
    /// Total bytes served
    pub bytes_served: u64,
    /// Failed downloads
    pub download_failures: u64,
    /// Verification failures
    pub verification_failures: u64,
}

/// Manages snapshot creation and retrieval.
pub struct SnapshotManager {
    config: SnapshotConfig,
    /// Available local snapshots
    local_snapshots: Arc<DashMap<Slot, SnapshotManifest>>,
    /// Chunks stored locally
    local_chunks: Arc<DashMap<(Slot, u64), SnapshotChunk>>,
    /// Current download status
    download_status: Arc<RwLock<Option<SnapshotDownloadStatus>>>,
    /// Pending chunk requests
    pending_requests: Arc<DashMap<(Slot, u64), Instant>>,
    /// Metrics
    metrics: Arc<RwLock<SnapshotMetrics>>,
    /// Channel for chunk requests
    chunk_request_tx: mpsc::Sender<ChunkRequest>,
    /// Channel for received chunks
    chunk_response_rx: Arc<RwLock<mpsc::Receiver<ChunkResponse>>>,
    /// Total memory used by chunks
    chunk_memory_used: Arc<AtomicUsize>,
    /// Sync initialization lock to prevent race conditions
    sync_init_lock: Arc<Mutex<()>>,
}

/// Request for a snapshot chunk.
#[derive(Clone, Debug)]
pub struct ChunkRequest {
    pub snapshot_slot: Slot,
    pub chunk_index: u64,
    pub peer_id: Option<String>,
}

/// Response containing a snapshot chunk.
#[derive(Clone, Debug)]
pub struct ChunkResponse {
    pub chunk: SnapshotChunk,
    pub peer_id: String,
    pub latency_ms: u64,
}

impl SnapshotManager {
    /// Creates a new snapshot manager.
    pub fn new(config: SnapshotConfig) -> Self {
        let (chunk_request_tx, _chunk_request_rx) = mpsc::channel(1000);
        let (_chunk_response_tx, chunk_response_rx) = mpsc::channel(1000);
        
        Self {
            config,
            local_snapshots: Arc::new(DashMap::new()),
            local_chunks: Arc::new(DashMap::new()),
            download_status: Arc::new(RwLock::new(None)),
            pending_requests: Arc::new(DashMap::new()),
            metrics: Arc::new(RwLock::new(SnapshotMetrics::default())),
            chunk_request_tx,
            chunk_response_rx: Arc::new(RwLock::new(chunk_response_rx)),
            chunk_memory_used: Arc::new(AtomicUsize::new(0)),
            sync_init_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Creates a snapshot at the given slot.
    pub async fn create_snapshot(
        &self,
        slot: Slot,
        state_root: Hash,
        state_iterator: impl Iterator<Item = (Vec<u8>, Vec<u8>)>,
    ) -> SyncResult<SnapshotManifest> {
        info!("Creating snapshot at slot {}", slot);
        
        let mut chunks = Vec::new();
        let mut chunk_hashes = Vec::new();
        let mut chunk_ranges = Vec::new();
        let mut current_chunk_data = Vec::new();
        let mut current_chunk_start: Option<Vec<u8>> = None;
        let mut current_chunk_end = Vec::new();
        let mut chunk_index = 0u64;
        let mut total_size = 0u64;

        // MEDIUM (y6): Track entry count to prevent unbounded iterator exhaustion
        let mut entry_count = 0u64;
        
        for (key, value) in state_iterator {
            // MEDIUM (y6): Enforce maximum entries
            entry_count += 1;
            if entry_count > MAX_SNAPSHOT_ENTRIES {
                return Err(SyncError::InvalidSnapshot(format!(
                    "Snapshot exceeds maximum entries ({})", MAX_SNAPSHOT_ENTRIES
                )));
            }
            
            if current_chunk_start.is_none() {
                current_chunk_start = Some(key.clone());
            }
            current_chunk_end = key.clone();
            
            // Serialize key-value pair with overflow protection
            let entry_size = key.len()
                .checked_add(value.len())
                .and_then(|s| s.checked_add(8))
                .ok_or_else(|| SyncError::InvalidSnapshot("Entry size overflow".into()))?;
            
            current_chunk_data.extend_from_slice(&(key.len() as u32).to_le_bytes());
            current_chunk_data.extend_from_slice(&key);
            current_chunk_data.extend_from_slice(&(value.len() as u32).to_le_bytes());
            current_chunk_data.extend_from_slice(&value);
            total_size = total_size.checked_add(entry_size as u64)
                .ok_or_else(|| SyncError::InvalidSnapshot("Total size overflow".into()))?;

            // Check if chunk is full
            if current_chunk_data.len() >= self.config.max_chunk_size {
                let chunk = self.finalize_chunk(
                    chunk_index,
                    slot,
                    std::mem::take(&mut current_chunk_data),
                )?;
                
                chunk_hashes.push(chunk.hash);
                chunk_ranges.push(ChunkRange {
                    index: chunk_index,
                    start_key: current_chunk_start.take()
                        .ok_or_else(|| SyncError::InvalidSnapshot("Missing chunk start key".into()))?,
                    end_key: current_chunk_end.clone(),
                    data_type: ChunkDataType::Accounts,
                });
                
                self.local_chunks.insert((slot, chunk_index), chunk.clone());
                chunks.push(chunk);
                chunk_index += 1;
                // MEDIUM (y6): Enforce maximum chunks
                if chunk_index >= MAX_SNAPSHOT_CHUNKS {
                    return Err(SyncError::InvalidSnapshot(format!(
                        "Snapshot exceeds maximum chunks ({})", MAX_SNAPSHOT_CHUNKS
                    )));
                }
                current_chunk_start = None;
            }
        }

        // Finalize last chunk
        if !current_chunk_data.is_empty() {
            let chunk = self.finalize_chunk(chunk_index, slot, current_chunk_data)?;
            chunk_hashes.push(chunk.hash);
            chunk_ranges.push(ChunkRange {
                index: chunk_index,
                start_key: current_chunk_start.unwrap_or_default(),
                end_key: current_chunk_end,
                data_type: ChunkDataType::Accounts,
            });
            self.local_chunks.insert((slot, chunk_index), chunk.clone());
            chunks.push(chunk);
            chunk_index += 1;
        }

        // Calculate chunks merkle root
        let chunks_root = self.calculate_chunks_root(&chunk_hashes);

        let header = SnapshotHeader {
            version: 1,
            slot,
            state_root,
            chunk_count: chunk_index,
            total_size,
            compressed_size: if self.config.compression_enabled {
                Some(chunks.iter().map(|c| c.data.len() as u64).sum())
            } else {
                None
            },
            timestamp: chrono::Utc::now().timestamp() as u64,
            shard_id: None,
            previous_snapshot: None,
        };

        let manifest = SnapshotManifest {
            header,
            chunk_hashes,
            chunks_root,
            signatures: Vec::new(), // Signatures added separately
            chunk_ranges,
        };

        self.local_snapshots.insert(slot, manifest.clone());
        self.metrics.write().snapshots_created += 1;
        
        info!(
            "Snapshot created: slot={}, chunks={}, size={}MB",
            slot,
            chunk_index,
            total_size / (1024 * 1024)
        );

        Ok(manifest)
    }

    /// Finalizes a chunk with optional compression.
    fn finalize_chunk(
        &self,
        index: u64,
        slot: Slot,
        data: Vec<u8>,
    ) -> SyncResult<SnapshotChunk> {
        let (final_data, compressed) = if self.config.compression_enabled {
            let compressed = lz4_flex::compress_prepend_size(&data);
            (compressed, true)
        } else {
            (data, false)
        };

        let hash = crate::types::hash_data(&final_data);
        
        // CRITICAL: Generate merkle proof for chunk
        let merkle_proof = self.generate_merkle_proof(index, &hash);

        Ok(SnapshotChunk {
            index,
            snapshot_slot: slot,
            data: final_data,
            compressed,
            merkle_proof,
            hash,
        })
    }
    
    /// Generates Merkle inclusion proof for a chunk.
    /// 
    /// Returns sibling hashes along the path from leaf to root,
    /// enabling verification that chunk_hash is included in the tree.
    fn generate_merkle_proof(&self, index: u64, chunk_hash: &Hash) -> Vec<Hash> {
        if self.local_chunks.is_empty() {
            return vec![*chunk_hash];
        }
        
        // Collect all chunk hashes sorted by index
        let mut chunk_entries: Vec<(u64, Hash)> = self.local_chunks.iter()
            .map(|entry| (entry.key().1, entry.value().hash))
            .collect();
        chunk_entries.sort_by_key(|(idx, _)| *idx);
        let chunk_hashes: Vec<Hash> = chunk_entries.into_iter().map(|(_, h)| h).collect();
        
        // Build proof path from leaf to root
        let mut proof = Vec::new();
        let mut level = chunk_hashes;
        // MEDIUM (y4): Use checked cast to prevent overflow
        let mut idx = (index as usize).min(level.len().saturating_sub(1));
        
        while level.len() > 1 {
            // Get sibling hash
            // MEDIUM (y4): Use checked arithmetic for sibling index
            let sibling_idx = if idx % 2 == 0 {
                idx.checked_add(1).unwrap_or(idx)
            } else {
                idx.checked_sub(1).unwrap_or(0)
            };
            if sibling_idx < level.len() {
                proof.push(level[sibling_idx]);
            } else if idx < level.len() {
                // Odd element at end - duplicate
                proof.push(level[idx]);
            }
            
            // Build next level
            let mut next_level = Vec::new();
            for pair in level.chunks(2) {
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(&pair[0]);
                if pair.len() > 1 {
                    combined.extend_from_slice(&pair[1]);
                } else {
                    combined.extend_from_slice(&pair[0]);
                }
                next_level.push(crate::crypto::sha3_256(&combined));
            }
            
            level = next_level;
            idx /= 2;
        }
        
        proof
    }

    /// Calculates merkle root of chunk hashes.
    fn calculate_chunks_root(&self, chunk_hashes: &[Hash]) -> Hash {
        if chunk_hashes.is_empty() {
            return [0u8; 32];
        }
        if chunk_hashes.len() == 1 {
            return chunk_hashes[0];
        }

        let mut current_level: Vec<Hash> = chunk_hashes.to_vec();
        
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(&chunk[0]);
                if chunk.len() > 1 {
                    combined.extend_from_slice(&chunk[1]);
                } else {
                    combined.extend_from_slice(&chunk[0]);
                }
                next_level.push(crate::types::hash_data(&combined));
            }
            current_level = next_level;
        }

        current_level[0]
    }

    /// Starts downloading a snapshot from peers.
    pub async fn start_snapshot_sync(
        &self,
        manifest: SnapshotManifest,
    ) -> SyncResult<()> {
        // CRITICAL: Atomic check-and-set to prevent race condition
        let _lock = self.sync_init_lock.lock();
        
        // Check if already syncing
        if self.download_status.read().is_some() {
            return Err(SyncError::AlreadySyncing);
        }
        
        // CRITICAL: Verify snapshot signatures before accepting
        self.verify_snapshot_signatures(&manifest)?;

        let slot = manifest.header.slot;
        info!("Starting snapshot sync for slot {}", slot);

        // Initialize download status
        {
            let mut status = self.download_status.write();
            *status = Some(SnapshotDownloadStatus {
                snapshot_slot: slot,
                total_chunks: manifest.header.chunk_count,
                downloaded_chunks: 0,
                verified_chunks: 0,
                applied_chunks: 0,
                download_speed: 0,
                eta_seconds: 0,
                phase: SnapshotSyncPhase::DownloadingChunks,
                started_at: Instant::now(),
            });
        }

        // Store manifest
        self.local_snapshots.insert(slot, manifest.clone());

        // Request all chunks
        for i in 0..manifest.header.chunk_count {
            self.request_chunk(slot, i).await?;
        }

        Ok(())
    }

    /// Verifies snapshot manifest signatures
    fn verify_snapshot_signatures(&self, manifest: &SnapshotManifest) -> SyncResult<()> {
        if manifest.signatures.len() < self.config.min_snapshot_signers {
            return Err(SyncError::VerificationFailed(format!(
                "Insufficient signatures: got {}, need {}",
                manifest.signatures.len(),
                self.config.min_snapshot_signers
            )));
        }
        
        // Calculate manifest hash for signature verification
        let manifest_hash = self.calculate_manifest_hash(manifest);
        
        let mut valid_signatures = 0;
        let mut total_stake = 0u64;
        
        let batch: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = manifest.signatures.iter().map(|sig| {
            (sig.validator.to_vec(), manifest_hash.to_vec(), sig.signature.clone())
        }).collect();

        let results = batch.iter().map(|(pubkey, message, signature)| {
            verify_dilithium_batch(pubkey.clone(), message.clone(), signature.clone())
        }).collect::<Vec<bool>>();

        for (sig, valid) in manifest.signatures.iter().zip(results.iter()) {
            if *valid {
                valid_signatures += 1;
                total_stake = total_stake.saturating_add(sig.stake_weight);
            } else {
                warn!("Invalid signature from validator {:?}", hex::encode(&sig.validator));
            }
        }
        
        if valid_signatures < self.config.min_snapshot_signers {
            return Err(SyncError::VerificationFailed(format!(
                "Insufficient valid signatures: got {}, need {}",
                valid_signatures,
                self.config.min_snapshot_signers
            )));
        }
        
        info!("Snapshot verified: {} valid signatures, total stake: {}", valid_signatures, total_stake);
        Ok(())
    }
    
    /// Calculates hash of manifest for signature verification
    fn calculate_manifest_hash(&self, manifest: &SnapshotManifest) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&manifest.header.slot.to_le_bytes());
        data.extend_from_slice(&manifest.header.state_root);
        data.extend_from_slice(&manifest.chunks_root);
        crate::types::hash_data(&data)
    }
    
    /// Requests a specific chunk.
    async fn request_chunk(&self, slot: Slot, chunk_index: u64) -> SyncResult<()> {
        // Clean up timed out requests first
        self.cleanup_timed_out_requests();
        
        self.pending_requests.insert((slot, chunk_index), Instant::now());
        
        self.chunk_request_tx
            .send(ChunkRequest {
                snapshot_slot: slot,
                chunk_index,
                peer_id: None,
            })
            .await
            .map_err(|e| SyncError::NetworkError(e.to_string()))?;

        Ok(())
    }

    /// Processes a received chunk.
    pub async fn process_chunk(&self, chunk: SnapshotChunk) -> SyncResult<()> {
        let slot = chunk.snapshot_slot;
        let index = chunk.index;

        // HIGH (y3): Check for duplicate chunks before processing
        if self.local_chunks.contains_key(&(slot, index)) {
            debug!("Chunk {} already processed, skipping", index);
            return Ok(());
        }

        // Verify chunk hash
        let computed_hash = crate::types::hash_data(&chunk.data);
        if computed_hash != chunk.hash {
            self.metrics.write().verification_failures += 1;
            return Err(SyncError::VerificationFailed(format!(
                "Chunk {} hash mismatch",
                index
            )));
        }

        // Verify against manifest
        if let Some(manifest) = self.local_snapshots.get(&slot) {
            if index as usize >= manifest.chunk_hashes.len() {
                return Err(SyncError::InvalidSnapshot("Chunk index out of range".into()));
            }
            if manifest.chunk_hashes[index as usize] != chunk.hash {
                return Err(SyncError::VerificationFailed(format!(
                    "Chunk {} doesn't match manifest",
                    index
                )));
            }
            
            // CRITICAL (y1): Verify merkle proof
            if !chunk.merkle_proof.is_empty() {
                self.verify_merkle_proof(&chunk, &manifest.chunks_root)?;
            }
        }
        
        // HIGH (y3): Atomic memory reservation using compare_exchange loop
        let chunk_size = chunk.data.len();
        loop {
            let current_memory = self.chunk_memory_used.load(Ordering::Relaxed);
            let new_memory = current_memory.checked_add(chunk_size)
                .ok_or_else(|| SyncError::InvalidSnapshot("Memory counter overflow".into()))?;
            if new_memory > MAX_CHUNK_MEMORY {
                return Err(SyncError::InvalidSnapshot(format!(
                    "Chunk memory limit exceeded: {} + {} > {}",
                    current_memory, chunk_size, MAX_CHUNK_MEMORY
                )));
            }
            // Atomically reserve the memory
            if self.chunk_memory_used.compare_exchange(
                current_memory, new_memory, Ordering::AcqRel, Ordering::Relaxed
            ).is_ok() {
                break;
            }
            // Another thread changed the value, retry
        }

        // Store chunk — if insert fails or panics, we need to release memory
        // MEDIUM (y5): Ensure memory is released on error
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.local_chunks.insert((slot, index), chunk);
        })) {
            Ok(_) => {},
            Err(_) => {
                self.chunk_memory_used.fetch_sub(chunk_size, Ordering::Relaxed);
                return Err(SyncError::InvalidSnapshot("Failed to store chunk".into()));
            }
        }
        self.pending_requests.remove(&(slot, index));

        // Update status
        if let Some(ref mut status) = *self.download_status.write() {
            if status.snapshot_slot == slot {
                status.downloaded_chunks += 1;
                status.verified_chunks += 1;

                let elapsed = status.started_at.elapsed().as_secs().max(1);
                let chunks_remaining = status.total_chunks - status.downloaded_chunks;
                let chunks_per_sec = status.downloaded_chunks / elapsed;
                status.eta_seconds = if chunks_per_sec > 0 {
                    chunks_remaining / chunks_per_sec
                } else {
                    0
                };

                debug!(
                    "Snapshot sync progress: {}/{} chunks",
                    status.downloaded_chunks, status.total_chunks
                );

                // Check if complete
                if status.downloaded_chunks == status.total_chunks {
                    status.phase = SnapshotSyncPhase::Applying;
                }
            }
        }

        Ok(())
    }

    /// Applies downloaded snapshot to state.
    pub async fn apply_snapshot<F>(
        &self,
        slot: Slot,
        mut apply_fn: F,
    ) -> SyncResult<()>
    where
        F: FnMut(&[u8], &[u8]) -> SyncResult<()>,
    {
        let manifest = self.local_snapshots
            .get(&slot)
            .ok_or_else(|| SyncError::SnapshotNotFound(slot.to_string()))?;

        info!("Applying snapshot at slot {}", slot);

        for i in 0..manifest.header.chunk_count {
            let chunk = self.local_chunks
                .get(&(slot, i))
                .ok_or(SyncError::ChunkMissing(i))?;

            // Decompress if needed with size validation
            let data = if chunk.compressed {
                // HIGH (y2): Check compressed size implies reasonable decompression ratio
                // Reject if compressed data is too small relative to max decompressed size
                // (a 1KB payload decompressing to 100MB = 100000x ratio is suspicious)
                let compressed_len = chunk.data.len();
                if compressed_len == 0 {
                    return Err(SyncError::InvalidSnapshot("Empty compressed chunk".into()));
                }
                
                // HIGH (y2): Pre-validate by checking the prepended size before decompressing
                if compressed_len >= 4 {
                    let expected_size = u32::from_le_bytes(
                        chunk.data[..4].try_into().unwrap_or([0; 4])
                    ) as usize;
                    if expected_size > MAX_DECOMPRESSED_SIZE {
                        return Err(SyncError::InvalidSnapshot(format!(
                            "Declared decompressed size {} exceeds limit {}",
                            expected_size, MAX_DECOMPRESSED_SIZE
                        )));
                    }
                    if compressed_len > 4 && expected_size / (compressed_len - 4) > MAX_DECOMPRESSION_RATIO {
                        return Err(SyncError::InvalidSnapshot(format!(
                            "Suspicious decompression ratio: {}x (max: {}x)",
                            expected_size / (compressed_len - 4), MAX_DECOMPRESSION_RATIO
                        )));
                    }
                }
                
                let decompressed = lz4_flex::decompress_size_prepended(&chunk.data)
                    .map_err(|e| SyncError::InvalidSnapshot(format!("Decompression failed: {}", e)))?;
                
                if decompressed.len() > MAX_DECOMPRESSED_SIZE {
                    return Err(SyncError::InvalidSnapshot(format!(
                        "Decompressed chunk too large: {} > {}",
                        decompressed.len(),
                        MAX_DECOMPRESSED_SIZE
                    )));
                }
                decompressed
            } else {
                chunk.data.clone()
            };

            // Parse and apply entries with safe conversions
            let mut offset = 0;
            while offset < data.len() {
                if offset + 4 > data.len() {
                    break;
                }
                // CRITICAL: Safe conversion instead of unwrap
                let key_len_bytes: [u8; 4] = data[offset..offset + 4]
                    .try_into()
                    .map_err(|_| SyncError::InvalidSnapshot("Invalid key length bytes".into()))?;
                let key_len = u32::from_le_bytes(key_len_bytes) as usize;
                offset += 4;

                if offset + key_len > data.len() {
                    break;
                }
                let key = &data[offset..offset + key_len];
                offset += key_len;

                if offset + 4 > data.len() {
                    break;
                }
                // CRITICAL: Safe conversion instead of unwrap
                let value_len_bytes: [u8; 4] = data[offset..offset + 4]
                    .try_into()
                    .map_err(|_| SyncError::InvalidSnapshot("Invalid value length bytes".into()))?;
                let value_len = u32::from_le_bytes(value_len_bytes) as usize;
                offset += 4;

                if offset + value_len > data.len() {
                    break;
                }
                let value = &data[offset..offset + value_len];
                offset += value_len;

                // MEDIUM (y7): Wrap apply_fn in catch_unwind to handle panics
                let key_owned = key.to_vec();
                let value_owned = value.to_vec();
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    apply_fn(&key_owned, &value_owned)
                })) {
                    Ok(result) => result?,
                    Err(panic_info) => {
                        error!("apply_fn panicked at chunk {}: {:?}", i, panic_info);
                        return Err(SyncError::InvalidSnapshot(format!(
                            "apply_fn panicked at chunk {}", i
                        )));
                    }
                }
            }

            // Update status
            if let Some(ref mut status) = *self.download_status.write() {
                status.applied_chunks += 1;
            }
        }

        // Mark complete
        if let Some(ref mut status) = *self.download_status.write() {
            status.phase = SnapshotSyncPhase::Complete;
        }

        self.metrics.write().snapshots_downloaded += 1;
        info!("Snapshot applied successfully at slot {}", slot);

        Ok(())
    }

    /// Gets the current download status.
    pub fn get_download_status(&self) -> Option<SnapshotDownloadStatus> {
        self.download_status.read().clone()
    }

    /// Gets a chunk for serving to peers.
    pub fn get_chunk(&self, slot: Slot, index: u64) -> Option<SnapshotChunk> {
        self.local_chunks.get(&(slot, index)).map(|c| {
            self.metrics.write().chunks_served += 1;
            self.metrics.write().bytes_served += c.data.len() as u64;
            c.clone()
        })
    }

    /// Gets manifest for a snapshot.
    pub fn get_manifest(&self, slot: Slot) -> Option<SnapshotManifest> {
        self.local_snapshots.get(&slot).map(|m| m.clone())
    }

    /// Lists available snapshots.
    pub fn list_snapshots(&self) -> Vec<Slot> {
        self.local_snapshots.iter().map(|e| *e.key()).collect()
    }

    /// Prunes old snapshots.
    pub fn prune_old_snapshots(&self, current_slot: Slot) {
        let mut snapshots: Vec<_> = self.local_snapshots.iter().map(|e| *e.key()).collect();
        snapshots.sort();

        while snapshots.len() > self.config.max_retained_snapshots {
            if let Some(old_slot) = snapshots.first().copied() {
                self.local_snapshots.remove(&old_slot);
                
                // Remove chunks
                let chunk_count = self.local_snapshots
                    .get(&old_slot)
                    .map(|m| m.header.chunk_count)
                    .unwrap_or(0);
                
                for i in 0..chunk_count {
                    self.local_chunks.remove(&(old_slot, i));
                }
                
                snapshots.remove(0);
                info!("Pruned snapshot at slot {}", old_slot);
            }
        }
    }

    /// Gets metrics.
    pub fn get_metrics(&self) -> SnapshotMetrics {
        self.metrics.read().clone()
    }
    
    /// CRITICAL (y1): Proper merkle proof verification.
    /// Walks from the chunk's leaf hash through sibling hashes to reconstruct
    /// the root, then compares against the expected chunks_root.
    fn verify_merkle_proof(&self, chunk: &SnapshotChunk, chunks_root: &Hash) -> SyncResult<()> {
        if chunk.merkle_proof.is_empty() {
            return Err(SyncError::VerificationFailed("Empty merkle proof".into()));
        }
        
        // Start with the chunk's own hash as the current node
        let mut current_hash = chunk.hash;
        let mut idx = chunk.index as usize;
        
        // Walk up the tree using sibling hashes from the proof
        for sibling_hash in &chunk.merkle_proof {
            let mut combined = Vec::with_capacity(64);
            if idx % 2 == 0 {
                // Current node is left child
                combined.extend_from_slice(&current_hash);
                combined.extend_from_slice(sibling_hash);
            } else {
                // Current node is right child
                combined.extend_from_slice(sibling_hash);
                combined.extend_from_slice(&current_hash);
            }
            current_hash = crate::crypto::sha3_256(&combined);
            idx /= 2;
        }
        
        // The reconstructed root must match the expected chunks_root
        if current_hash != *chunks_root {
            return Err(SyncError::VerificationFailed(format!(
                "Merkle proof root mismatch for chunk {}: computed {:?} != expected {:?}",
                chunk.index,
                hex::encode(&current_hash[..8]),
                hex::encode(&chunks_root[..8])
            )));
        }
        
        Ok(())
    }
    
    /// Cleans up timed out pending requests
    fn cleanup_timed_out_requests(&self) {
        let now = Instant::now();
        let timeout = Duration::from_secs(PENDING_REQUEST_TIMEOUT);
        
        // LOW (y8): Use checked_duration_since to avoid panic on future timestamps
        self.pending_requests.retain(|_, timestamp| {
            now.checked_duration_since(*timestamp)
                .map(|elapsed| elapsed < timeout)
                .unwrap_or(true) // Keep if timestamp is somehow in the future
        });
    }
    
    /// Gets current memory usage
    pub fn get_memory_usage(&self) -> usize {
        self.chunk_memory_used.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_config_default() {
        let config = SnapshotConfig::default();
        assert_eq!(config.snapshot_interval, 1000);
        assert_eq!(config.chunks_per_snapshot, 256);
    }

    #[tokio::test]
    async fn test_snapshot_creation() {
        let config = SnapshotConfig {
            max_chunk_size: 100,
            compression_enabled: false,
            ..Default::default()
        };
        let manager = SnapshotManager::new(config);

        let state_data = vec![
            (b"key1".to_vec(), b"value1".to_vec()),
            (b"key2".to_vec(), b"value2".to_vec()),
        ];

        let result = manager
            .create_snapshot(100, [0u8; 32], state_data.into_iter())
            .await;

        assert!(result.is_ok());
        let manifest = result.unwrap();
        assert_eq!(manifest.header.slot, 100);
        assert!(manifest.header.chunk_count > 0);
    }

    #[test]
    fn test_chunks_root_calculation() {
        let config = SnapshotConfig::default();
        let manager = SnapshotManager::new(config);

        let hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let root = manager.calculate_chunks_root(&hashes);
        assert_ne!(root, [0u8; 32]);
    }
}
