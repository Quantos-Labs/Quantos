//! # Quantos Sync Module
//!
//! Fast synchronization via state snapshots and incremental updates.
//!
//! ## Features
//!
//! - **Snapshot Sync**: Download and verify state snapshots for fast bootstrap
//! - **Incremental Sync**: Catch up from snapshot to current head
//! - **Chunk-based Transfer**: Parallel download of state chunks
//! - **Merkle Verification**: Cryptographic proof of snapshot integrity

pub mod snapshot;

pub use snapshot::*;

use thiserror::Error;

/// Sync errors.
#[derive(Debug, Error)]
pub enum SyncError {
    #[error("Snapshot not found: {0}")]
    SnapshotNotFound(String),
    
    #[error("Invalid snapshot: {0}")]
    InvalidSnapshot(String),
    
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Chunk missing: {0}")]
    ChunkMissing(u64),
    
    #[error("Download failed: {0}")]
    DownloadFailed(String),
    
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Timeout")]
    Timeout,
    
    #[error("Already syncing")]
    AlreadySyncing,
}

pub type SyncResult<T> = Result<T, SyncError>;
