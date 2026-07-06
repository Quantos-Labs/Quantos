//! # Genesis Configuration
//!
//! Genesis block and initial chain state configuration for Quantos.
//!
//! ## Networks
//!
//! - **Mainnet**: Production network (chain_id: 1)
//! - **Testnet**: Public test network (chain_id: 2)
//! - **Devnet**: Local development network (chain_id: 3)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, Component};

use crate::types::{Address, Hash, Amount, hash_data};

/// Maximum commission rate in basis points (100% = 10000 bps)
const MAX_COMMISSION_BPS: u16 = 10_000;

/// Network identifier
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkId {
    Mainnet,
    Testnet,
    Devnet,
    Custom(u64),
}

impl NetworkId {
    pub fn chain_id(&self) -> u64 {
        match self {
            NetworkId::Mainnet => 1,
            NetworkId::Testnet => 2,
            NetworkId::Devnet => 3,
            NetworkId::Custom(id) => *id,
        }
    }
    
    pub fn from_chain_id(chain_id: u64) -> Self {
        match chain_id {
            1 => NetworkId::Mainnet,
            2 => NetworkId::Testnet,
            3 => NetworkId::Devnet,
            id => NetworkId::Custom(id),
        }
    }
    
    pub fn name(&self) -> &'static str {
        match self {
            NetworkId::Mainnet => "mainnet",
            NetworkId::Testnet => "testnet",
            NetworkId::Devnet => "devnet",
            NetworkId::Custom(_) => "custom",
        }
    }
}

/// Initial validator configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisValidator {
    /// Validator address (derived from public key)
    pub address: String,
    /// Dilithium public key (hex encoded)
    pub public_key: String,
    /// Initial stake amount in smallest units (1 QTS = 10^18 units)
    pub stake: u128,
    /// Human-readable name (optional)
    pub name: Option<String>,
    /// Commission rate in basis points (100 = 1%)
    pub commission_bps: u16,
}

/// Initial account allocation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisAllocation {
    /// Account address (hex encoded)
    pub address: String,
    /// Initial balance in smallest units
    pub balance: u128,
    /// Optional vesting schedule
    pub vesting: Option<VestingSchedule>,
    /// Label for the allocation (e.g., "team", "foundation", "community")
    pub label: Option<String>,
}

/// Vesting schedule for allocated tokens
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VestingSchedule {
    /// Timestamp when vesting starts (Unix seconds)
    pub start_time: u64,
    /// Cliff period in seconds (no tokens released before this)
    pub cliff_seconds: u64,
    /// Total vesting duration in seconds
    pub duration_seconds: u64,
    /// Amount immediately available (not vested)
    pub initial_unlock_percent: u8,
}

/// Chain configuration parameters
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Chain ID
    pub chain_id: u64,
    /// Block time target in milliseconds
    pub block_time_ms: u64,
    /// Maximum transactions per block
    pub max_tx_per_block: u64,
    /// Maximum block size in bytes
    pub max_block_size: u64,
    /// STACC: maximum compute units per transaction (CU).
    pub max_cu_per_tx: u64,
    /// STACC: maximum compute units per block (CU).
    pub block_cu_limit: u64,
    /// Minimum stake to become a validator
    pub min_validator_stake: u128,
    /// Maximum validators per committee
    pub max_validators_per_committee: u32,
    /// Number of shards
    pub initial_shards: u32,
    /// Epoch length in blocks
    pub epoch_length: u64,
    /// Slashing penalty for double signing (basis points)
    pub double_sign_slash_bps: u16,
    /// Slashing penalty for downtime (basis points)  
    pub downtime_slash_bps: u16,
    /// Unbonding period in seconds
    pub unbonding_period_seconds: u64,
    /// Enable dynamic shard scaling
    pub dynamic_sharding: bool,
    /// Minimum shards (floor for dynamic scaling)
    pub min_shards: u32,
    /// Maximum shards (ceiling for dynamic scaling)
    pub max_shards: u32,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            chain_id: 2, // Testnet
            block_time_ms: 200, // 200ms DAG slot interval (production target)
            max_tx_per_block: 10_000,
            max_block_size: 10 * 1024 * 1024, // 10MB
            max_cu_per_tx: 100_000_000,
            block_cu_limit: 30_000_000,
            min_validator_stake: 100_000 * 10u128.pow(18), // 100,000 QTS
            max_validators_per_committee: 21,
            initial_shards: 4,
            epoch_length: 32,
            double_sign_slash_bps: 500, // 5%
            downtime_slash_bps: 100, // 1%
            unbonding_period_seconds: 7 * 24 * 3600, // 7 days
            dynamic_sharding: true,
            min_shards: 1,
            max_shards: 10_000,
        }
    }
}

/// Complete genesis configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Network identifier
    pub network: NetworkId,
    /// Genesis timestamp (Unix seconds)
    pub genesis_time: u64,
    /// Chain configuration
    pub chain: ChainConfig,
    /// Initial validators
    pub validators: Vec<GenesisValidator>,
    /// Initial token allocations
    pub allocations: Vec<GenesisAllocation>,
    /// System contracts to deploy at genesis
    pub system_contracts: Vec<SystemContract>,
    /// Extra data (can include commit hash, etc.)
    pub extra_data: Option<String>,
}

/// System contract deployed at genesis
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemContract {
    /// Contract name
    pub name: String,
    /// Contract address (deterministic)
    pub address: String,
    /// Contract bytecode (hex encoded)
    pub bytecode: String,
    /// Initial storage (key-value pairs, hex encoded)
    pub storage: HashMap<String, String>,
}

/// Fixed genesis timestamps for deterministic genesis hash
mod genesis_timestamps {
    /// Testnet genesis: February 1, 2026 00:00:00 UTC
    pub const TESTNET: u64 = 1769904000;
    /// Devnet genesis: January 1, 2026 00:00:00 UTC
    pub const DEVNET: u64 = 1767225600;
    /// Mainnet genesis: TBD
    pub const MAINNET: u64 = 0;
}

impl GenesisConfig {
    /// Creates a new testnet genesis configuration
    /// 
    /// Uses a fixed genesis_time for deterministic genesis hash.
    /// Testnet launch: February 1, 2026 00:00:00 UTC
    ///
    /// WARNING: Validator keys are randomly generated each call.
    /// For persistent testnet deployments, export genesis to file and reuse it.
    pub fn testnet() -> Result<Self, GenesisError> {
        let genesis_time = genesis_timestamps::TESTNET;
        let chain_id: u64 = 2;
        
        // Generate random testnet validator keys
        // NOTE: These are NOT deterministic — export genesis to JSON for reuse
        let mut validators = Vec::with_capacity(4);
        for i in 0..4 {
            let keypair = crate::crypto::DilithiumKeypair::generate()
                .map_err(|e| GenesisError::ValidationError(
                    format!("Failed to generate validator key {}: {}", i, e)
                ))?;
            validators.push(GenesisValidator {
                address: hex::encode(&keypair.address()),
                public_key: hex::encode(&keypair.public_key),
                stake: 1_000_000 * 10u128.pow(18), // 1M QTS each
                name: Some(format!("Testnet Validator {}", i + 1)),
                commission_bps: 500, // 5%
            });
        }
        
        // Initial allocations with domain-separated address derivation
        let allocations = vec![
            // Foundation allocation
            GenesisAllocation {
                address: hex::encode(&Self::derive_allocation_address(chain_id, b"foundation")),
                balance: 100_000_000 * 10u128.pow(18), // 100M QTS
                vesting: None,
                label: Some("Foundation".to_string()),
            },
            // Community pool
            GenesisAllocation {
                address: hex::encode(&Self::derive_allocation_address(chain_id, b"community")),
                balance: 50_000_000 * 10u128.pow(18), // 50M QTS
                vesting: None,
                label: Some("Community Pool".to_string()),
            },
            // Development fund
            GenesisAllocation {
                address: hex::encode(&Self::derive_allocation_address(chain_id, b"dev-fund")),
                balance: 25_000_000 * 10u128.pow(18), // 25M QTS
                vesting: Some(VestingSchedule {
                    start_time: genesis_time,
                    cliff_seconds: 90 * 24 * 3600, // 90 days cliff
                    duration_seconds: 2 * 365 * 24 * 3600, // 2 years
                    initial_unlock_percent: 10,
                }),
                label: Some("Development Fund".to_string()),
            },
        ];
        
        Ok(Self {
            network: NetworkId::Testnet,
            genesis_time,
            chain: ChainConfig {
                chain_id,
                block_time_ms: 200, // 200ms production DAG slot
                initial_shards: 4, // Starting point, scales dynamically
                dynamic_sharding: true,
                min_shards: 1,
                max_shards: 10_000,
                min_validator_stake: 10_000 * 10u128.pow(18), // Lower for testnet
                ..Default::default()
            },
            validators,
            allocations,
            system_contracts: vec![],
            extra_data: Some(format!("Quantos Testnet Genesis v{}", env!("CARGO_PKG_VERSION"))),
        })
    }
    
    /// Creates a local devnet genesis configuration
    /// 
    /// Uses a fixed genesis_time for deterministic genesis hash.
    /// Devnet reference: January 1, 2026 00:00:00 UTC
    ///
    /// WARNING: Validator keys are randomly generated each call.
    /// For persistent devnet, export genesis to file and reuse it.
    pub fn devnet() -> Result<Self, GenesisError> {
        let genesis_time = genesis_timestamps::DEVNET;
        let chain_id: u64 = 3;
        
        // Generate random devnet validator key
        let keypair = crate::crypto::DilithiumKeypair::generate()
            .map_err(|e| GenesisError::ValidationError(
                format!("Failed to generate devnet validator key: {}", e)
            ))?;
        
        let validators = vec![GenesisValidator {
            address: hex::encode(&keypair.address()),
            public_key: hex::encode(&keypair.public_key),
            stake: 1_000_000 * 10u128.pow(18),
            name: Some("Devnet Validator".to_string()),
            commission_bps: 0,
        }];
        
        // No pre-funded accounts — only validator stake at genesis
        let allocations = vec![];
        
        Ok(Self {
            network: NetworkId::Devnet,
            genesis_time,
            chain: ChainConfig {
                chain_id,
                block_time_ms: 200, // Same as production target
                initial_shards: 2, // Starting point, scales dynamically
                dynamic_sharding: true,
                min_shards: 1,
                max_shards: 1_000,
                min_validator_stake: 1000 * 10u128.pow(18),
                epoch_length: 16,
                unbonding_period_seconds: 300, // 5 minutes for devnet
                ..Default::default()
            },
            validators,
            allocations,
            system_contracts: vec![],
            extra_data: Some("Quantos Devnet".to_string()),
        })
    }
    
    /// Loads genesis configuration from a JSON file.
    /// Validates the configuration after loading to prevent use of invalid state.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, GenesisError> {
        Self::validate_path(path.as_ref())?;
        
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| GenesisError::IoError(e.to_string()))?;
        
        let config: Self = serde_json::from_str(&content)
            .map_err(|e| GenesisError::ParseError(e.to_string()))?;
        
        // Automatically validate after loading to prevent invalid configs
        config.validate()?;
        Ok(config)
    }
    
    /// Saves genesis configuration to a JSON file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), GenesisError> {
        Self::validate_path(path.as_ref())?;
        
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| GenesisError::ParseError(e.to_string()))?;
        
        // Create parent directories if needed
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| GenesisError::IoError(e.to_string()))?;
        }
        
        std::fs::write(path.as_ref(), content)
            .map_err(|e| GenesisError::IoError(e.to_string()))
    }
    
    /// Validates a file path to prevent path traversal attacks.
    fn validate_path(path: &Path) -> Result<(), GenesisError> {
        for component in path.components() {
            if let Component::ParentDir = component {
                return Err(GenesisError::IoError(
                    "Path traversal sequences ('..') are not allowed".to_string()
                ));
            }
        }
        Ok(())
    }
    
    /// Computes the genesis block hash.
    /// Uses canonical (sorted-key) JSON serialization for determinism across platforms.
    pub fn genesis_hash(&self) -> Hash {
        // Use sorted-key serialization to ensure deterministic output
        // regardless of HashMap iteration order or serde version
        let value = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        let canonical = Self::canonical_json(&value);
        hash_data(canonical.as_bytes())
    }
    
    /// Produces a canonical JSON string with sorted keys for deterministic hashing.
    fn canonical_json(value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                let entries: Vec<String> = keys.iter().map(|k| {
                    format!("{}:{}", serde_json::to_string(k).unwrap(), Self::canonical_json(&map[*k]))
                }).collect();
                format!("{{{}}}", entries.join(","))
            }
            serde_json::Value::Array(arr) => {
                let items: Vec<String> = arr.iter().map(|v| Self::canonical_json(v)).collect();
                format!("[{}]", items.join(","))
            }
            _ => serde_json::to_string(value).unwrap_or_default(),
        }
    }
    
    /// Validates the genesis configuration
    pub fn validate(&self) -> Result<(), GenesisError> {
        // Must have at least one validator
        if self.validators.is_empty() {
            return Err(GenesisError::ValidationError(
                "Genesis must have at least one validator".to_string()
            ));
        }
        
        // Check validator count does not exceed committee limit
        if self.validators.len() > self.chain.max_validators_per_committee as usize {
            return Err(GenesisError::ValidationError(
                format!(
                    "Genesis has {} validators but max_validators_per_committee is {}",
                    self.validators.len(), self.chain.max_validators_per_committee
                )
            ));
        }
        
        // Check validator stakes and commission rates
        for validator in &self.validators {
            if validator.stake < self.chain.min_validator_stake {
                return Err(GenesisError::ValidationError(
                    format!(
                        "Validator {} stake {} is below minimum {}",
                        validator.address, validator.stake, self.chain.min_validator_stake
                    )
                ));
            }
            
            // Commission rate must not exceed 100% (10000 bps)
            if validator.commission_bps > MAX_COMMISSION_BPS {
                return Err(GenesisError::ValidationError(
                    format!(
                        "Validator {} commission {} bps exceeds maximum {} bps (100%)",
                        validator.address, validator.commission_bps, MAX_COMMISSION_BPS
                    )
                ));
            }
        }
        
        // Validate addresses are correct length
        for allocation in &self.allocations {
            if allocation.address.len() != 64 {
                return Err(GenesisError::ValidationError(
                    format!("Invalid address length for allocation: {}", allocation.address)
                ));
            }
            
            // Validate vesting schedule
            if let Some(ref vesting) = allocation.vesting {
                if vesting.initial_unlock_percent > 100 {
                    return Err(GenesisError::ValidationError(
                        format!(
                            "Allocation {} has initial_unlock_percent {} > 100",
                            allocation.address, vesting.initial_unlock_percent
                        )
                    ));
                }
            }
        }
        
        // Check chain_id matches network
        let expected_chain_id = self.network.chain_id();
        if self.chain.chain_id != expected_chain_id {
            return Err(GenesisError::ValidationError(
                format!(
                    "Chain ID {} doesn't match network {:?} (expected {})",
                    self.chain.chain_id, self.network, expected_chain_id
                )
            ));
        }
        
        Ok(())
    }
    
    /// Returns total supply from allocations.
    /// Uses checked arithmetic to prevent overflow with malicious configurations.
    pub fn total_supply(&self) -> Result<u128, GenesisError> {
        let mut allocation_total: u128 = 0;
        for a in &self.allocations {
            allocation_total = allocation_total.checked_add(a.balance)
                .ok_or_else(|| GenesisError::ValidationError(
                    "Overflow in allocation total supply calculation".to_string()
                ))?;
        }
        
        let mut validator_total: u128 = 0;
        for v in &self.validators {
            validator_total = validator_total.checked_add(v.stake)
                .ok_or_else(|| GenesisError::ValidationError(
                    "Overflow in validator total supply calculation".to_string()
                ))?;
        }
        
        allocation_total.checked_add(validator_total)
            .ok_or_else(|| GenesisError::ValidationError(
                "Overflow in combined total supply calculation".to_string()
            ))
    }
    
    /// Derives a deterministic allocation address with domain separation.
    /// Uses chain_id + label to prevent cross-chain address collisions.
    fn derive_allocation_address(chain_id: u64, label: &[u8]) -> Hash {
        let mut preimage = Vec::with_capacity(8 + 8 + label.len());
        preimage.extend_from_slice(b"quantos:");
        preimage.extend_from_slice(&chain_id.to_le_bytes());
        preimage.extend_from_slice(b":");
        preimage.extend_from_slice(label);
        hash_data(&preimage)
    }
    
    /// Converts allocation address to [u8; 32]
    pub fn parse_address(hex_addr: &str) -> Result<Address, GenesisError> {
        let bytes = hex::decode(hex_addr)
            .map_err(|e| GenesisError::ParseError(format!("Invalid hex address: {}", e)))?;
        
        if bytes.len() != 32 {
            return Err(GenesisError::ParseError(
                format!("Invalid address length: expected 32 bytes, got {}", bytes.len())
            ));
        }
        
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&bytes);
        Ok(addr)
    }
}

/// Genesis configuration errors
#[derive(Debug, Clone)]
pub enum GenesisError {
    IoError(String),
    ParseError(String),
    ValidationError(String),
}

impl std::fmt::Display for GenesisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenesisError::IoError(e) => write!(f, "IO error: {}", e),
            GenesisError::ParseError(e) => write!(f, "Parse error: {}", e),
            GenesisError::ValidationError(e) => write!(f, "Validation error: {}", e),
        }
    }
}

impl std::error::Error for GenesisError {}

/// Genesis state builder - applies genesis config to state
pub struct GenesisBuilder {
    config: GenesisConfig,
}

impl GenesisBuilder {
    pub fn new(config: GenesisConfig) -> Self {
        Self { config }
    }
    
    /// Validates and returns the genesis config
    pub fn build(self) -> Result<GenesisConfig, GenesisError> {
        self.config.validate()?;
        Ok(self.config)
    }
    
    /// Returns addresses and balances for state initialization
    pub fn get_initial_balances(&self) -> Vec<(Address, Amount)> {
        let mut balances = Vec::new();
        
        // Add allocation balances
        for allocation in &self.config.allocations {
            if let Ok(addr) = GenesisConfig::parse_address(&allocation.address) {
                balances.push((addr, Amount(allocation.balance)));
            }
        }
        
        // Add validator stake balances
        for validator in &self.config.validators {
            if let Ok(addr) = GenesisConfig::parse_address(&validator.address) {
                balances.push((addr, Amount(validator.stake)));
            }
        }
        
        balances
    }
    
    /// Returns validator set for consensus initialization
    pub fn get_validators(&self) -> Vec<(Address, Vec<u8>, u128)> {
        self.config.validators.iter()
            .filter_map(|v| {
                let addr = GenesisConfig::parse_address(&v.address).ok()?;
                let pubkey = hex::decode(&v.public_key).ok()?;
                Some((addr, pubkey, v.stake))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_testnet_genesis() {
        let genesis = GenesisConfig::testnet().unwrap();
        assert_eq!(genesis.network, NetworkId::Testnet);
        assert_eq!(genesis.chain.chain_id, 2);
        assert!(!genesis.validators.is_empty());
        assert!(genesis.validate().is_ok());
    }
    
    #[test]
    fn test_devnet_genesis() {
        let genesis = GenesisConfig::devnet().unwrap();
        assert_eq!(genesis.network, NetworkId::Devnet);
        assert_eq!(genesis.chain.chain_id, 3);
        assert!(genesis.validate().is_ok());
    }
    
    #[test]
    fn test_genesis_hash_canonical() {
        // Canonical hashing should produce consistent results for the same config
        let genesis = GenesisConfig::testnet().unwrap();
        let hash1 = genesis.genesis_hash();
        let hash2 = genesis.genesis_hash();
        assert_eq!(hash1, hash2);
        
        // Verify fixed timestamp
        assert_eq!(genesis.genesis_time, genesis_timestamps::TESTNET);
    }
    
    #[test]
    fn test_devnet_genesis_hash_canonical() {
        let genesis = GenesisConfig::devnet().unwrap();
        let hash1 = genesis.genesis_hash();
        let hash2 = genesis.genesis_hash();
        assert_eq!(hash1, hash2);
        assert_eq!(genesis.genesis_time, genesis_timestamps::DEVNET);
    }
    
    #[test]
    fn test_total_supply() {
        let genesis = GenesisConfig::testnet().unwrap();
        let supply = genesis.total_supply().unwrap();
        assert!(supply > 0);
    }
}
