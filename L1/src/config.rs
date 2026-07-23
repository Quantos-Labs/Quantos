// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use serde::{Deserialize, Serialize};

use crate::l0::L0Config;
use crate::privacy::PrivacyConfig;

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

    /// Prometheus metrics port
    pub metrics_port: u16,

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

    /// Optional L0 finality hub configuration.
    pub l0_config: L0Config,

    /// Whether STACC requires sender activation before mempool admission.
    pub stacc_require_activation: bool,

    /// Optional confidential-mode (privacy) configuration. Disabled by default.
    #[serde(default)]
    pub privacy_config: PrivacyConfig,

    /// Network name (mainnet, testnet, devnet) used for bootnode selection.
    #[serde(default)]
    pub network_name: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            db_path: "./data/quantos".to_string(),
            p2p_port: 30303,
            rpc_port: 8545,
            metrics_port: 9615,
            num_committees: 1000,
            validators_per_committee: 21,
            num_shards: 1000,
            committee_rotation_ms: 100,
            checkpoint_interval: 1000,
            max_dag_parents: 8,
            min_dag_parents: 1,
            dynamic_sharding: true,
            min_shards: 100,
            max_shards: 10000,
            execution_threads: num_cpus::get(),
            sidechains_enabled: true,
            max_sidechains: 1000,
            l0_config: L0Config {
                enabled: true,
                ..L0Config::default()
            },
            stacc_require_activation: true,
            privacy_config: PrivacyConfig::default(),
            network_name: "testnet".to_string(),
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
