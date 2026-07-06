//! # Quantos Network Layer
//!
//! Native TCP P2P with **full PQ wiring**: Kyber768 handshake + ML-DSA (Dilithium3) mutual auth,
//! AES-256-GCM transport. No libp2p, no classical TLS identities.

mod peer_id;
mod address;
mod peer_manager;
mod peer_store;
mod pq_identity_store;
mod pq_net;
mod protocol;
mod p2p;
mod pq_identity;
mod gossip;
mod prefilter;
mod sync;
pub mod erasure_coding;
pub mod turbo_gossip;
pub mod nat_traversal;
pub mod bandwidth_scheduler;

pub use address::*;
pub use peer_id::PeerId;
pub use peer_manager::PeerManager;
pub use peer_store::PeerStore;
pub use protocol::*;
pub use p2p::*;
pub use gossip::*;
pub use prefilter::*;
pub use sync::*;
pub use erasure_coding::*;
pub use turbo_gossip::*;
pub use nat_traversal::*;
pub use bandwidth_scheduler::*;

use thiserror::Error;

/// Errors that can occur in the network layer.
#[derive(Error, Debug)]
pub enum NetworkError {
    /// Failed to establish connection
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    /// Peer not found in the network
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    
    /// Message exceeds maximum size
    #[error("Message too large")]
    MessageTooLarge,
    
    /// Invalid message format
    #[error("Invalid message: {0}")]
    InvalidMessage(String),
    
    /// Operation timed out
    #[error("Timeout")]
    Timeout,
    
    /// IO error
    #[error("IO error: {0}")]
    IoError(String),
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    /// Compression error
    #[error("Compression error: {0}")]
    CompressionError(String),
    
    /// Peer is banned
    #[error("Peer is banned: {0}")]
    PeerBanned(String),
    
    /// Invalid address format
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    
    /// Not connected to any peers
    #[error("Not connected to any peers")]
    NoPeers,
}

/// Result type for network operations.
pub type NetworkResult<T> = Result<T, NetworkError>;
