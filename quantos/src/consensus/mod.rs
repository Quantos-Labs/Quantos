//! # Quantos Consensus Engine
//!
//! This module implements the Quantos 3-layer hybrid consensus mechanism,
//! designed for massive parallelization and post-quantum security.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │              Layer 3: Finality Anchor                        │
//! │  ML-DSA-65 checkpoints every 1000 DAG vertices (~1 second) │
//! │  Super-committee of 100 validators for deterministic finality│
//! ├─────────────────────────────────────────────────────────────┤
//! │              Layer 2: Quantum Committees                     │
//! │  1000 committees × 21 validators = 21,000 total validators  │
//! │  VRF rotation using SPHINCS+ every 100ms                    │
//! │  Dilithium-3 aggregated signatures (14/21 threshold)        │
//! ├─────────────────────────────────────────────────────────────┤
//! │              Layer 1: Fast Path (DAG)                        │
//! │  Parallel transaction inclusion without sequential blocks   │
//! │  2-8 parent references per vertex for high throughput       │
//! │  Optimistic execution with <0.1% rollback rate             │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Consensus Phases
//!
//! 1. **Inclusion (0-10ms)**: TX signed with Dilithium-3, propagated via QUIC
//! 2. **Pre-consensus (10-50ms)**: Committee votes with 14/21 threshold
//! 3. **Ordering (50-100ms)**: Topological sort of DAG, conflict resolution
//! 4. **Finality (~1s)**: Checkpoint with ML-DSA-65 signatures

mod committee;
mod fast_path;
mod finality;
mod quantos;
mod slashing;
mod cross_shard_atomic;
pub mod dynamic_committee;
pub mod pipelining;
pub mod optimistic_responsiveness;
pub mod view_change;

pub use committee::*;
pub use fast_path::*;
pub use finality::*;
pub use quantos::*;
pub use slashing::*;
pub use cross_shard_atomic::*;
pub use dynamic_committee::*;
pub use pipelining::*;
pub use optimistic_responsiveness::*;
pub use view_change::*;

use thiserror::Error;

/// Errors that can occur during consensus operations.
#[derive(Error, Debug)]
pub enum ConsensusError {
    /// The DAG vertex is invalid (malformed or violates rules)
    #[error("Invalid vertex: {0}")]
    InvalidVertex(String),
    
    /// A committee vote is invalid
    #[error("Invalid vote: {0}")]
    InvalidVote(String),
    
    /// Not enough votes to reach quorum (66% threshold)
    #[error("Quorum not reached")]
    QuorumNotReached,
    
    /// Validator is not a member of the required committee
    #[error("Not a committee member")]
    NotCommitteeMember,
    
    /// VRF proof verification failed
    #[error("Invalid VRF proof")]
    InvalidVRFProof,
    
    /// Checkpoint signature verification failed
    #[error("Checkpoint verification failed")]
    CheckpointVerificationFailed,
    
    /// Storage layer error
    #[error("Storage error: {0}")]
    StorageError(String),
    
    /// Cryptographic operation error
    #[error("Crypto error: {0}")]
    CryptoError(String),
    
    /// Resource exhausted (memory, pending items, etc.)
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),
    
    /// Arithmetic overflow in calculations
    #[error("Arithmetic overflow: {0}")]
    ArithmeticOverflow(String),
    
    /// Unauthorized operation
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    
    /// Invalid data format
    #[error("Invalid data: {0}")]
    InvalidData(String),
    
    /// Invalid validator
    #[error("Invalid validator: {0}")]
    InvalidValidator(String),
}

/// Result type for consensus operations.
pub type ConsensusResult<T> = Result<T, ConsensusError>;
