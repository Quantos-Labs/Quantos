//! # Quantos - Post-Quantum L1 Blockchain
//!
//! Quantos is a revolutionary Layer 1 blockchain featuring:
//! - **Post-Quantum Cryptography**: Dilithium-3, SPHINCS+, ML-DSA-65
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
//! │         ML-DSA-65 checkpoints, deterministic finality        │
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
pub mod l0;
pub mod privacy;
pub mod validator_keys;
pub mod config;

pub use config::NodeConfig;
pub use config::chain_id;
pub use config::version;

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::consensus::QuantosConsensus;
    pub use crate::crypto::{DilithiumKeypair, MlDsa65Keypair, VRFKeypair};
    pub use crate::state::StateManager;
    pub use crate::storage::Storage;
    pub use crate::types::*;
    pub use crate::NodeConfig;
}
