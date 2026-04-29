//! # Quantos Network Layer
//!
//! P2P networking with QUIC transport, gossipsub, and Kademlia DHT.
//!
//! ## Features
//!
//! - **QUIC Transport**: Fast, multiplexed, encrypted connections
//! - **Gossipsub**: Efficient pub/sub message propagation
//! - **Kademlia DHT**: Decentralized peer discovery
//! - **Message Compression**: LZ4/Zstd for bandwidth efficiency
//! - **Batch Broadcasting**: Efficient multi-message transmission

mod p2p;
mod gossip;
mod sync;
pub mod erasure_coding;
pub mod turbo_gossip;
pub mod nat_traversal;
pub mod bandwidth_scheduler;

pub use p2p::*;
pub use gossip::*;
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
