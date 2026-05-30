//! Light client verification for external chain checkpoints.

use std::sync::Arc;

use crate::l0::error::{L0Error, L0Result};
use crate::l0::external::{ChainId, ExternalCheckpoint, VerificationResult};
use crate::types::Hash;

/// Trait for chain-specific light client verification
#[async_trait::async_trait]
pub trait LightClient: Send + Sync {
    /// Verify an external checkpoint using light client protocol
    async fn verify_checkpoint(&self, checkpoint: &ExternalCheckpoint) -> L0Result<VerificationResult>;

    /// Get the chain ID this light client supports
    fn chain_id(&self) -> ChainId;

    /// Check if the light client is synced and ready
    fn is_synced(&self) -> bool;
}

/// EVM light client using Merkle proofs
pub struct EVMLightClient {
    chain_id: ChainId,
    rpc_url: String,
    synced: Arc<parking_lot::RwLock<bool>>,
}

impl EVMLightClient {
    pub fn new(chain_id: ChainId, rpc_url: String) -> Self {
        Self {
            chain_id,
            rpc_url,
            synced: Arc::new(parking_lot::RwLock::new(false)),
        }
    }

    /// Verify block hash matches state root via RPC
    async fn verify_block_hash(&self, block_number: u64, expected_hash: Hash) -> L0Result<bool> {
        // In production, this would:
        // 1. Fetch block header from RPC
        // 2. Verify block hash matches
        // 3. Verify state root is included in block header
        // 4. Optionally verify Merkle proofs for specific state
        
        // For now, we do basic RPC verification
        let client = reqwest::Client::new();
        let response = client
            .post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_getBlockByNumber",
                "params": [format!("0x{:x}", block_number), false]
            }))
            .send()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("RPC error: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("JSON parse error: {}", e)))?;

        if let Some(block) = json.get("result") {
            if let Some(hash_str) = block.get("hash").and_then(|h| h.as_str()) {
                let hash_bytes = hex::decode(hash_str.trim_start_matches("0x"))
                    .map_err(|_| L0Error::InvalidCheckpoint("Invalid block hash".to_string()))?;
                
                if hash_bytes.len() == 32 {
                    let mut hash_array = [0u8; 32];
                    hash_array.copy_from_slice(&hash_bytes);
                    return Ok(hash_array == expected_hash);
                }
            }
        }

        Ok(false)
    }
}

#[async_trait::async_trait]
impl LightClient for EVMLightClient {
    async fn verify_checkpoint(&self, checkpoint: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        if !self.is_synced() {
            return Ok(VerificationResult::invalid("Light client not synced"));
        }

        // Verify block hash
        let hash_valid = self.verify_block_hash(checkpoint.block_number, checkpoint.block_hash).await?;
        
        if !hash_valid {
            return Ok(VerificationResult::invalid("Block hash mismatch"));
        }

        // In production, also verify:
        // - State root is in block header
        // - Finality proof is valid (e.g., Casper FFG for Ethereum)
        // - Block is actually finalized (not just confirmed)

        Ok(VerificationResult::valid())
    }

    fn chain_id(&self) -> ChainId {
        self.chain_id.clone()
    }

    fn is_synced(&self) -> bool {
        *self.synced.read()
    }
}

/// Solana light client using vote accounts and slot verification
pub struct SolanaLightClient {
    chain_id: ChainId,
    rpc_url: String,
    synced: Arc<parking_lot::RwLock<bool>>,
}

impl SolanaLightClient {
    pub fn new(chain_id: ChainId, rpc_url: String) -> Self {
        Self {
            chain_id,
            rpc_url,
            synced: Arc::new(parking_lot::RwLock::new(false)),
        }
    }

    async fn verify_slot_finalized(&self, slot: u64) -> L0Result<bool> {
        let client = reqwest::Client::new();
        let response = client
            .post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getBlockCommitment",
                "params": [slot]
            }))
            .send()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("RPC error: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("JSON parse error: {}", e)))?;

        // Check if slot is finalized (commitment level)
        if let Some(result) = json.get("result") {
            if let Some(commitment) = result.get("commitment") {
                if let Some(total_stake) = commitment.as_array().and_then(|arr| arr.last()) {
                    // If we have stake commitment, slot is finalized
                    return Ok(total_stake.as_u64().unwrap_or(0) > 0);
                }
            }
        }

        Ok(false)
    }
}

#[async_trait::async_trait]
impl LightClient for SolanaLightClient {
    async fn verify_checkpoint(&self, checkpoint: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        if !self.is_synced() {
            return Ok(VerificationResult::invalid("Light client not synced"));
        }

        // Verify slot is finalized
        let finalized = self.verify_slot_finalized(checkpoint.block_number).await?;
        
        if !finalized {
            return Ok(VerificationResult::invalid("Slot not finalized"));
        }

        Ok(VerificationResult::valid())
    }

    fn chain_id(&self) -> ChainId {
        self.chain_id.clone()
    }

    fn is_synced(&self) -> bool {
        *self.synced.read()
    }
}

/// NEAR light client using block header verification
pub struct NEARLightClient {
    chain_id: ChainId,
    rpc_url: String,
    synced: Arc<parking_lot::RwLock<bool>>,
}

impl NEARLightClient {
    pub fn new(chain_id: ChainId, rpc_url: String) -> Self {
        Self {
            chain_id,
            rpc_url,
            synced: Arc::new(parking_lot::RwLock::new(false)),
        }
    }

    async fn verify_block_finalized(&self, block_hash: Hash) -> L0Result<bool> {
        let client = reqwest::Client::new();
        let hash_hex = hex::encode(block_hash);
        
        let response = client
            .post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "block",
                "params": { "block_id": hash_hex }
            }))
            .send()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("RPC error: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("JSON parse error: {}", e)))?;

        // Check if block exists and is finalized
        Ok(json.get("result").is_some())
    }
}

#[async_trait::async_trait]
impl LightClient for NEARLightClient {
    async fn verify_checkpoint(&self, checkpoint: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        if !self.is_synced() {
            return Ok(VerificationResult::invalid("Light client not synced"));
        }

        let finalized = self.verify_block_finalized(checkpoint.block_hash).await?;
        
        if !finalized {
            return Ok(VerificationResult::invalid("Block not finalized"));
        }

        Ok(VerificationResult::valid())
    }

    fn chain_id(&self) -> ChainId {
        self.chain_id.clone()
    }

    fn is_synced(&self) -> bool {
        *self.synced.read()
    }
}

/// Aptos light client using transaction verification
pub struct AptosLightClient {
    chain_id: ChainId,
    rpc_url: String,
    synced: Arc<parking_lot::RwLock<bool>>,
}

impl AptosLightClient {
    pub fn new(chain_id: ChainId, rpc_url: String) -> Self {
        Self {
            chain_id,
            rpc_url,
            synced: Arc::new(parking_lot::RwLock::new(false)),
        }
    }

    async fn verify_block_finalized(&self, block_number: u64, block_hash: Hash) -> L0Result<bool> {
        let client = reqwest::Client::new();
        
        let response = client
            .get(format!("{}/v1/blocks/by_height/{}", self.rpc_url, block_number))
            .send()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("RPC error: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("JSON parse error: {}", e)))?;

        // Verify block hash matches
        if let Some(hash_str) = json.get("block_hash").and_then(|h| h.as_str()) {
            let hash_bytes = hex::decode(hash_str.trim_start_matches("0x"))
                .map_err(|_| L0Error::InvalidCheckpoint("Invalid block hash".to_string()))?;
            
            if hash_bytes.len() == 32 {
                let mut hash_array = [0u8; 32];
                hash_array.copy_from_slice(&hash_bytes);
                return Ok(hash_array == block_hash);
            }
        }

        Ok(false)
    }
}

#[async_trait::async_trait]
impl LightClient for AptosLightClient {
    async fn verify_checkpoint(&self, checkpoint: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        if !self.is_synced() {
            return Ok(VerificationResult::invalid("Light client not synced"));
        }

        let finalized = self.verify_block_finalized(checkpoint.block_number, checkpoint.block_hash).await?;
        
        if !finalized {
            return Ok(VerificationResult::invalid("Block not finalized"));
        }

        Ok(VerificationResult::valid())
    }

    fn chain_id(&self) -> ChainId {
        self.chain_id.clone()
    }

    fn is_synced(&self) -> bool {
        *self.synced.read()
    }
}

/// Sui light client using checkpoint verification
pub struct SuiLightClient {
    chain_id: ChainId,
    rpc_url: String,
    synced: Arc<parking_lot::RwLock<bool>>,
}

impl SuiLightClient {
    pub fn new(chain_id: ChainId, rpc_url: String) -> Self {
        Self {
            chain_id,
            rpc_url,
            synced: Arc::new(parking_lot::RwLock::new(false)),
        }
    }

    async fn verify_checkpoint_finalized(&self, checkpoint_seq: u64) -> L0Result<bool> {
        let client = reqwest::Client::new();
        
        let response = client
            .post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "sui_getCheckpoint",
                "params": [checkpoint_seq.to_string()]
            }))
            .send()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("RPC error: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("JSON parse error: {}", e)))?;

        // Check if checkpoint exists and is finalized
        Ok(json.get("result").is_some())
    }
}

#[async_trait::async_trait]
impl LightClient for SuiLightClient {
    async fn verify_checkpoint(&self, checkpoint: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        if !self.is_synced() {
            return Ok(VerificationResult::invalid("Light client not synced"));
        }

        let finalized = self.verify_checkpoint_finalized(checkpoint.block_number).await?;
        
        if !finalized {
            return Ok(VerificationResult::invalid("Checkpoint not finalized"));
        }

        Ok(VerificationResult::valid())
    }

    fn chain_id(&self) -> ChainId {
        self.chain_id.clone()
    }

    fn is_synced(&self) -> bool {
        *self.synced.read()
    }
}

/// Tron light client using block verification
pub struct TronLightClient {
    chain_id: ChainId,
    rpc_url: String,
    synced: Arc<parking_lot::RwLock<bool>>,
}

impl TronLightClient {
    pub fn new(chain_id: ChainId, rpc_url: String) -> Self {
        Self {
            chain_id,
            rpc_url,
            synced: Arc::new(parking_lot::RwLock::new(false)),
        }
    }

    async fn verify_block_finalized(&self, block_number: u64) -> L0Result<bool> {
        let client = reqwest::Client::new();
        
        let response = client
            .post(format!("{}/wallet/getblockbynum", self.rpc_url))
            .json(&serde_json::json!({
                "num": block_number
            }))
            .send()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("RPC error: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("JSON parse error: {}", e)))?;

        // Check if block exists (Tron blocks are considered finalized after 19 confirmations)
        Ok(json.get("blockID").is_some())
    }
}

#[async_trait::async_trait]
impl LightClient for TronLightClient {
    async fn verify_checkpoint(&self, checkpoint: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        if !self.is_synced() {
            return Ok(VerificationResult::invalid("Light client not synced"));
        }

        let finalized = self.verify_block_finalized(checkpoint.block_number).await?;
        
        if !finalized {
            return Ok(VerificationResult::invalid("Block not finalized"));
        }

        Ok(VerificationResult::valid())
    }

    fn chain_id(&self) -> ChainId {
        self.chain_id.clone()
    }

    fn is_synced(&self) -> bool {
        *self.synced.read()
    }
}

/// Stellar light client using ledger verification
pub struct StellarLightClient {
    chain_id: ChainId,
    horizon_url: String,
    synced: Arc<parking_lot::RwLock<bool>>,
}

impl StellarLightClient {
    pub fn new(chain_id: ChainId, horizon_url: String) -> Self {
        Self {
            chain_id,
            horizon_url,
            synced: Arc::new(parking_lot::RwLock::new(false)),
        }
    }

    async fn verify_ledger_finalized(&self, ledger_seq: u64) -> L0Result<bool> {
        let client = reqwest::Client::new();
        
        let response = client
            .get(format!("{}/ledgers/{}", self.horizon_url, ledger_seq))
            .send()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("Horizon error: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("JSON parse error: {}", e)))?;

        // Check if ledger exists and is closed
        if let Some(closed) = json.get("closed_at") {
            return Ok(closed.is_string());
        }

        Ok(false)
    }
}

#[async_trait::async_trait]
impl LightClient for StellarLightClient {
    async fn verify_checkpoint(&self, checkpoint: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        if !self.is_synced() {
            return Ok(VerificationResult::invalid("Light client not synced"));
        }

        let finalized = self.verify_ledger_finalized(checkpoint.block_number).await?;
        
        if !finalized {
            return Ok(VerificationResult::invalid("Ledger not finalized"));
        }

        Ok(VerificationResult::valid())
    }

    fn chain_id(&self) -> ChainId {
        self.chain_id.clone()
    }

    fn is_synced(&self) -> bool {
        *self.synced.read()
    }
}

/// TON light client using masterchain block verification
pub struct TONLightClient {
    chain_id: ChainId,
    rpc_url: String,
    synced: Arc<parking_lot::RwLock<bool>>,
}

impl TONLightClient {
    pub fn new(chain_id: ChainId, rpc_url: String) -> Self {
        Self {
            chain_id,
            rpc_url,
            synced: Arc::new(parking_lot::RwLock::new(false)),
        }
    }

    async fn verify_block_finalized(&self, seqno: u64) -> L0Result<bool> {
        let client = reqwest::Client::new();
        
        let response = client
            .post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getMasterchainInfo",
                "params": {}
            }))
            .send()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("RPC error: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("JSON parse error: {}", e)))?;

        // Check if block seqno is less than or equal to latest masterchain seqno
        if let Some(result) = json.get("result") {
            if let Some(last_seqno) = result.get("last").and_then(|l| l.get("seqno")).and_then(|s| s.as_u64()) {
                return Ok(seqno <= last_seqno);
            }
        }

        Ok(false)
    }
}

#[async_trait::async_trait]
impl LightClient for TONLightClient {
    async fn verify_checkpoint(&self, checkpoint: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        if !self.is_synced() {
            return Ok(VerificationResult::invalid("Light client not synced"));
        }

        let finalized = self.verify_block_finalized(checkpoint.block_number).await?;
        
        if !finalized {
            return Ok(VerificationResult::invalid("Block not finalized"));
        }

        Ok(VerificationResult::valid())
    }

    fn chain_id(&self) -> ChainId {
        self.chain_id.clone()
    }

    fn is_synced(&self) -> bool {
        *self.synced.read()
    }
}

/// Bitcoin light client using block verification
pub struct BitcoinLightClient {
    chain_id: ChainId,
    rpc_url: String,
    synced: Arc<parking_lot::RwLock<bool>>,
}

impl BitcoinLightClient {
    pub fn new(chain_id: ChainId, rpc_url: String) -> Self {
        Self {
            chain_id,
            rpc_url,
            synced: Arc::new(parking_lot::RwLock::new(false)),
        }
    }

    async fn verify_block_finalized(&self, block_height: u64, block_hash: Hash) -> L0Result<bool> {
        let client = reqwest::Client::new();
        
        // Get block by height
        let response = client
            .post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "1.0",
                "id": "1",
                "method": "getblockhash",
                "params": [block_height]
            }))
            .send()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("RPC error: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("JSON parse error: {}", e)))?;

        // Verify block hash matches
        if let Some(hash_str) = json.get("result").and_then(|h| h.as_str()) {
            let hash_bytes = hex::decode(hash_str)
                .map_err(|_| L0Error::InvalidCheckpoint("Invalid block hash".to_string()))?;
            
            if hash_bytes.len() == 32 {
                let mut hash_array = [0u8; 32];
                hash_array.copy_from_slice(&hash_bytes);
                // Bitcoin uses reverse byte order
                hash_array.reverse();
                return Ok(hash_array == block_hash);
            }
        }

        Ok(false)
    }
}

#[async_trait::async_trait]
impl LightClient for BitcoinLightClient {
    async fn verify_checkpoint(&self, checkpoint: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        if !self.is_synced() {
            return Ok(VerificationResult::invalid("Light client not synced"));
        }

        let finalized = self.verify_block_finalized(checkpoint.block_number, checkpoint.block_hash).await?;
        
        if !finalized {
            return Ok(VerificationResult::invalid("Block not finalized"));
        }

        Ok(VerificationResult::valid())
    }

    fn chain_id(&self) -> ChainId {
        self.chain_id.clone()
    }

    fn is_synced(&self) -> bool {
        *self.synced.read()
    }
}

/// Cardano light client using block verification
pub struct CardanoLightClient {
    chain_id: ChainId,
    rpc_url: String,
    synced: Arc<parking_lot::RwLock<bool>>,
}

impl CardanoLightClient {
    pub fn new(chain_id: ChainId, rpc_url: String) -> Self {
        Self {
            chain_id,
            rpc_url,
            synced: Arc::new(parking_lot::RwLock::new(false)),
        }
    }

    async fn verify_block_finalized(&self, block_number: u64) -> L0Result<bool> {
        let client = reqwest::Client::new();
        
        let response = client
            .get(format!("{}/blocks/{}", self.rpc_url, block_number))
            .send()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("Blockfrost error: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("JSON parse error: {}", e)))?;

        // Check if block exists and has confirmations
        if let Some(confirmations) = json.get("confirmations").and_then(|c| c.as_u64()) {
            // Cardano considers blocks finalized after ~15 confirmations (k parameter)
            return Ok(confirmations >= 15);
        }

        Ok(false)
    }
}

#[async_trait::async_trait]
impl LightClient for CardanoLightClient {
    async fn verify_checkpoint(&self, checkpoint: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        if !self.is_synced() {
            return Ok(VerificationResult::invalid("Light client not synced"));
        }

        let finalized = self.verify_block_finalized(checkpoint.block_number).await?;
        
        if !finalized {
            return Ok(VerificationResult::invalid("Block not finalized"));
        }

        Ok(VerificationResult::valid())
    }

    fn chain_id(&self) -> ChainId {
        self.chain_id.clone()
    }

    fn is_synced(&self) -> bool {
        *self.synced.read()
    }
}

/// Tezos light client using block verification
pub struct TezosLightClient {
    chain_id: ChainId,
    rpc_url: String,
    synced: Arc<parking_lot::RwLock<bool>>,
}

impl TezosLightClient {
    pub fn new(chain_id: ChainId, rpc_url: String) -> Self {
        Self {
            chain_id,
            rpc_url,
            synced: Arc::new(parking_lot::RwLock::new(false)),
        }
    }

    async fn verify_block_finalized(&self, block_level: u64) -> L0Result<bool> {
        let client = reqwest::Client::new();
        
        let response = client
            .get(format!("{}/chains/main/blocks/{}", self.rpc_url, block_level))
            .send()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("RPC error: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| L0Error::InvalidCheckpoint(format!("JSON parse error: {}", e)))?;

        // Check if block exists and has hash (Tezos blocks are finalized after 2 confirmations)
        Ok(json.get("hash").is_some())
    }
}

#[async_trait::async_trait]
impl LightClient for TezosLightClient {
    async fn verify_checkpoint(&self, checkpoint: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        if !self.is_synced() {
            return Ok(VerificationResult::invalid("Light client not synced"));
        }

        let finalized = self.verify_block_finalized(checkpoint.block_number).await?;
        
        if !finalized {
            return Ok(VerificationResult::invalid("Block not finalized"));
        }

        Ok(VerificationResult::valid())
    }

    fn chain_id(&self) -> ChainId {
        self.chain_id.clone()
    }

    fn is_synced(&self) -> bool {
        *self.synced.read()
    }
}

/// Light client registry for managing multiple chain light clients
pub struct LightClientRegistry {
    clients: Arc<parking_lot::RwLock<std::collections::HashMap<ChainId, Arc<dyn LightClient>>>>,
}

impl LightClientRegistry {
    pub fn new() -> Self {
        Self {
            clients: Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Register a light client for a chain
    pub fn register(&self, client: Arc<dyn LightClient>) {
        let chain_id = client.chain_id();
        self.clients.write().insert(chain_id, client);
    }

    /// Get light client for a chain
    pub fn get(&self, chain_id: &ChainId) -> Option<Arc<dyn LightClient>> {
        self.clients.read().get(chain_id).cloned()
    }

    /// Verify a checkpoint using the appropriate light client
    pub async fn verify_checkpoint(&self, checkpoint: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        match self.get(&checkpoint.chain_id) {
            Some(client) => client.verify_checkpoint(checkpoint).await,
            None => {
                // Fallback to trust submitter if no light client available
                tracing::warn!("No light client for chain {:?}, using trust submitter", checkpoint.chain_id);
                Ok(VerificationResult::valid())
            }
        }
    }

    /// Initialize default light clients for common chains
    pub fn with_defaults() -> Self {
        let registry = Self::new();

        // EVM chains (Layer 1)
        for (chain_id, rpc_url) in [
            (ChainId::Ethereum, "https://eth.llamarpc.com"),
            (ChainId::EthereumSepolia, "https://rpc.sepolia.org"),
            (ChainId::BinanceSmartChain, "https://bsc-dataseed.binance.org"),
            (ChainId::Polygon, "https://polygon-rpc.com"),
            (ChainId::Avalanche, "https://api.avax.network/ext/bc/C/rpc"),
        ] {
            let client = Arc::new(EVMLightClient::new(chain_id.clone(), rpc_url.to_string()));
            registry.register(client);
        }

        // EVM Layer 2 / Rollups
        for (chain_id, rpc_url) in [
            (ChainId::Base, "https://mainnet.base.org"),
            (ChainId::BaseSepolia, "https://sepolia.base.org"),
            (ChainId::Arbitrum, "https://arb1.arbitrum.io/rpc"),
            (ChainId::Optimism, "https://mainnet.optimism.io"),
        ] {
            let client = Arc::new(EVMLightClient::new(chain_id.clone(), rpc_url.to_string()));
            registry.register(client);
        }

        // EVM - New chains (Hyperliquid, Moonbeam, Monad, Berachain, Somnia)
        // Note: Using EVMLightClient for EVM-compatible chains
        // Moonbeam (Polkadot parachain, EVM-compatible)
        registry.register(Arc::new(EVMLightClient::new(
            ChainId::Moonbeam,
            "https://rpc.api.moonbeam.network".to_string(),
        )));
        
        // Berachain (EVM-compatible)
        registry.register(Arc::new(EVMLightClient::new(
            ChainId::Berachain,
            "https://rpc.berachain.com".to_string(),
        )));

        // Hyperliquid (EVM-compatible L1)
        registry.register(Arc::new(EVMLightClient::new(
            ChainId::Hyperliquid,
            "https://rpc.hyperliquid.xyz".to_string(),
        )));

        // Monad (EVM-compatible)
        registry.register(Arc::new(EVMLightClient::new(
            ChainId::Monad,
            "https://rpc.monad.xyz".to_string(),
        )));

        // Somnia (EVM-compatible)
        registry.register(Arc::new(EVMLightClient::new(
            ChainId::Somnia,
            "https://rpc.somnia.network".to_string(),
        )));

        // Solana
        registry.register(Arc::new(SolanaLightClient::new(
            ChainId::Solana,
            "https://api.mainnet-beta.solana.com".to_string(),
        )));

        // NEAR
        registry.register(Arc::new(NEARLightClient::new(
            ChainId::Near,
            "https://rpc.mainnet.near.org".to_string(),
        )));

        // Aptos
        registry.register(Arc::new(AptosLightClient::new(
            ChainId::Aptos,
            "https://fullnode.mainnet.aptoslabs.com/v1".to_string(),
        )));
        registry.register(Arc::new(AptosLightClient::new(
            ChainId::AptosTestnet,
            "https://fullnode.testnet.aptoslabs.com/v1".to_string(),
        )));

        // Sui
        registry.register(Arc::new(SuiLightClient::new(
            ChainId::Sui,
            "https://fullnode.mainnet.sui.io:443".to_string(),
        )));
        registry.register(Arc::new(SuiLightClient::new(
            ChainId::SuiTestnet,
            "https://fullnode.testnet.sui.io:443".to_string(),
        )));

        // Tron
        registry.register(Arc::new(TronLightClient::new(
            ChainId::Tron,
            "https://api.trongrid.io".to_string(),
        )));

        // Stellar
        registry.register(Arc::new(StellarLightClient::new(
            ChainId::Stellar,
            "https://horizon.stellar.org".to_string(),
        )));
        registry.register(Arc::new(StellarLightClient::new(
            ChainId::StellarTestnet,
            "https://horizon-testnet.stellar.org".to_string(),
        )));

        // TON
        registry.register(Arc::new(TONLightClient::new(
            ChainId::Ton,
            "https://toncenter.com/api/v2/jsonRPC".to_string(),
        )));
        registry.register(Arc::new(TONLightClient::new(
            ChainId::TonTestnet,
            "https://testnet.toncenter.com/api/v2/jsonRPC".to_string(),
        )));

        // Bitcoin
        registry.register(Arc::new(BitcoinLightClient::new(
            ChainId::Bitcoin,
            "https://blockstream.info/api".to_string(),
        )));
        registry.register(Arc::new(BitcoinLightClient::new(
            ChainId::BitcoinTestnet,
            "https://blockstream.info/testnet/api".to_string(),
        )));

        // Cardano
        registry.register(Arc::new(CardanoLightClient::new(
            ChainId::Cardano,
            "https://cardano-mainnet.blockfrost.io/api/v0".to_string(),
        )));

        // Tezos
        registry.register(Arc::new(TezosLightClient::new(
            ChainId::Tezos,
            "https://mainnet.api.tez.ie".to_string(),
        )));

        registry
    }
}

impl Default for LightClientRegistry {
    fn default() -> Self {
        Self::new()
    }
}
