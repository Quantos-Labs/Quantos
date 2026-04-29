use serde::{Deserialize, Serialize};
use crate::types::{Address, Hash, ShardId, SignedTransaction, hash_data};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub height: u64,
    pub timestamp: u64,
    pub parent_hash: Hash,
    pub state_root: Hash,
    pub transactions_root: Hash,
    pub receipts_root: Hash,
    pub proposer: Address,
    pub shard_id: ShardId,
    pub gas_limit: u64,
    pub gas_used: u64,
}

impl BlockHeader {
    /// CRITICAL (z2): Use deterministic manual serialization instead of bincode
    /// to ensure consistent hashing across all nodes and versions.
    pub fn hash(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&self.version.to_le_bytes());
        data.extend_from_slice(&self.height.to_le_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&self.parent_hash);
        data.extend_from_slice(&self.state_root);
        data.extend_from_slice(&self.transactions_root);
        data.extend_from_slice(&self.receipts_root);
        data.extend_from_slice(&self.proposer);
        data.extend_from_slice(&self.shard_id.to_le_bytes());
        data.extend_from_slice(&self.gas_limit.to_le_bytes());
        data.extend_from_slice(&self.gas_used.to_le_bytes());
        hash_data(&data)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<SignedTransaction>,
    pub signature: Vec<u8>,
}

impl Block {
    pub fn new(header: BlockHeader, transactions: Vec<SignedTransaction>) -> Self {
        Self {
            header,
            transactions,
            signature: Vec::new(),
        }
    }

    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    pub fn genesis(shard_id: ShardId) -> Self {
        let header = BlockHeader {
            version: 1,
            height: 0,
            timestamp: 0,
            parent_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions_root: [0u8; 32],
            receipts_root: [0u8; 32],
            proposer: [0u8; 32],
            shard_id,
            gas_limit: 30_000_000,
            gas_used: 0,
        };
        Self::new(header, Vec::new())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub chain_id: u64,
    pub timestamp: u64,
    pub initial_validators: Vec<GenesisValidator>,
    pub initial_accounts: Vec<GenesisAccount>,
    pub num_shards: u16,
    pub parameters: ChainParameters,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisValidator {
    pub address: Address,
    pub public_key: Vec<u8>,
    pub stake: u128,
    pub vrf_public_key: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisAccount {
    pub address: Address,
    pub balance: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainParameters {
    pub block_gas_limit: u64,
    pub min_gas_price: u64,
    pub committee_size: usize,
    pub num_committees: usize,
    pub epoch_length: u64,
    pub checkpoint_interval: u64,
    pub slash_fraction_double_sign: u16,
    pub slash_fraction_downtime: u16,
    pub min_stake: u128,
    pub unbonding_period: u64,
}

impl Default for ChainParameters {
    fn default() -> Self {
        Self {
            block_gas_limit: 30_000_000,
            min_gas_price: 1_000_000_000,
            committee_size: 21,
            num_committees: 1000,
            epoch_length: 32,
            checkpoint_interval: 1000,
            slash_fraction_double_sign: 5000,
            slash_fraction_downtime: 100,
            min_stake: 32_000_000_000_000_000_000,
            unbonding_period: 21 * 24 * 3600,
        }
    }
}

impl Default for GenesisConfig {
    fn default() -> Self {
        Self {
            chain_id: 1,
            timestamp: chrono::Utc::now().timestamp() as u64,
            initial_validators: Vec::new(),
            initial_accounts: Vec::new(),
            num_shards: 1000,
            parameters: ChainParameters::default(),
        }
    }
}
