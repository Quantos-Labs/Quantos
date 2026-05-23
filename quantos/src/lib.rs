//! # Quantos - Post-Quantum L1 Blockchain
//!
//! Quantos is a revolutionary Layer 1 blockchain featuring:
//! - **Post-Quantum Cryptography**: Dilithium-3, SPHINCS+, Falcon-512
//! - **DAG-based Consensus**: Parallel transaction processing
//! - **Massive Parallelization**: 1000+ shards, optimistic execution
//! - **Dynamic Sharding**: Auto-scaling based on load
//! - **Sidechains**: Application-specific chains with shared security
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Layer 3: Finality Anchor                  │
//! │         Falcon-512 checkpoints, deterministic finality       │
//! ├─────────────────────────────────────────────────────────────┤
//! │                 Layer 2: Quantum Committees                  │
//! │        1000 committees × 21 validators, VRF rotation         │
//! ├─────────────────────────────────────────────────────────────┤
//! │                   Layer 1: Fast Path (DAG)                   │
//! │          Parallel execution, optimistic processing           │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use quantos::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     let config = NodeConfig::default();
//!     let node = QuantosNode::new(config).await?;
//!     node.run().await
//! }
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

pub mod crypto;
pub mod types;
pub mod state;
pub mod storage;
pub mod dag;
pub mod mempool;
pub mod consensus;
pub mod network;
pub mod rpc;
pub mod sharding;
pub mod sidechain;
pub mod parallel;
pub mod vm;
pub mod standards;
pub mod security;
pub mod zk;
pub mod performance;
pub mod genesis;
pub mod stacc;

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::consensus::QuantosConsensus;
    pub use crate::crypto::{DilithiumKeypair, FalconKeypair, VRFKeypair};
    pub use crate::state::StateManager;
    pub use crate::storage::Storage;
    pub use crate::types::*;
    pub use crate::NodeConfig;
}

use serde::{Deserialize, Serialize};

/// Global configuration for a Quantos node.
///
/// This struct contains all the parameters needed to configure
/// and run a Quantos blockchain node.
///
/// # Example
///
/// ```rust
/// use quantos::NodeConfig;
///
/// let config = NodeConfig {
///     db_path: "./data/quantos".to_string(),
///     p2p_port: 30303,
///     rpc_port: 8545,
///     ..Default::default()
/// };
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Path to the RocksDB database directory
    pub db_path: String,
    
    /// P2P network listening port
    pub p2p_port: u16,
    
    /// JSON-RPC server port
    pub rpc_port: u16,
    
    /// Number of validator committees (default: 1000)
    pub num_committees: usize,
    
    /// Validators per committee (default: 21)
    pub validators_per_committee: usize,
    
    /// Number of shards for parallel execution (default: 1000)
    pub num_shards: usize,
    
    /// Committee rotation interval in milliseconds (default: 100ms)
    pub committee_rotation_ms: u64,
    
    /// Checkpoint interval in DAG vertices (default: 1000)
    pub checkpoint_interval: u64,
    
    /// Maximum parent references per DAG vertex
    pub max_dag_parents: usize,
    
    /// Minimum parent references per DAG vertex
    pub min_dag_parents: usize,
    
    /// Enable dynamic sharding auto-scaling
    pub dynamic_sharding: bool,
    
    /// Minimum shards when using dynamic sharding
    pub min_shards: usize,
    
    /// Maximum shards when using dynamic sharding
    pub max_shards: usize,
    
    /// Number of parallel execution threads per shard
    pub execution_threads: usize,
    
    /// Enable sidechain support
    pub sidechains_enabled: bool,
    
    /// Maximum number of connected sidechains
    pub max_sidechains: usize,

    /// Whether STACC requires sender activation before mempool admission.
    pub stacc_require_activation: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            db_path: "./data/quantos".to_string(),
            p2p_port: 30303,
            rpc_port: 8545,
            num_committees: 1000,
            validators_per_committee: 21,
            num_shards: 1000,
            committee_rotation_ms: 100,
            checkpoint_interval: 1000,
            max_dag_parents: 8,
            min_dag_parents: 2,
            dynamic_sharding: true,
            min_shards: 100,
            max_shards: 10000,
            execution_threads: num_cpus::get(),
            sidechains_enabled: true,
            max_sidechains: 1000,
            stacc_require_activation: true,
        }
    }
}

/// Quantos chain ID constants
pub mod chain_id {
    /// Mainnet chain ID
    pub const MAINNET: u64 = 1;
    /// Testnet chain ID
    pub const TESTNET: u64 = 2;
    /// Devnet chain ID
    pub const DEVNET: u64 = 3;
}

/// Protocol version constants
pub mod version {
    /// Current protocol version
    pub const PROTOCOL_VERSION: u32 = 1;
    /// Minimum supported protocol version
    pub const MIN_PROTOCOL_VERSION: u32 = 1;
}
