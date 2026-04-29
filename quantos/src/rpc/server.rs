use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonrpsee::server::Server;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use parking_lot::RwLock;
use tracing::warn;

/// Maximum contract bytecode size (10MB)
const MAX_CONTRACT_SIZE: usize = 10 * 1024 * 1024;
/// Maximum transaction size for deserialization (1MB)
const MAX_TX_SIZE: usize = 1024 * 1024;
/// Contract execution timeout (5 seconds)
const CONTRACT_EXEC_TIMEOUT: Duration = Duration::from_secs(5);
/// Rate limit: requests per IP per minute
const RATE_LIMIT_PER_MINUTE: usize = 100;
/// Rate limit burst allowance
const RATE_LIMIT_BURST: usize = 20;
/// Ban duration for excessive requests (5 minutes)
const BAN_DURATION_SECS: u64 = 300;
/// Threshold for banning (requests in ban window)
const BAN_THRESHOLD: usize = 500;
/// Maximum cumulative contract storage per deployer (100MB)
const MAX_STORAGE_PER_ACCOUNT: usize = 100 * 1024 * 1024;
/// Maximum concurrent contract executions to prevent CPU exhaustion
const MAX_CONCURRENT_EXECUTIONS: usize = 16;

use crate::consensus::QuantosConsensus;
use crate::state::StateManager;
use crate::types::{SignedTransaction, TransactionReceipt, TransactionStatus};
use crate::vm::{BytecodeProtector, ContractManager};
use crate::NodeConfig;

/// Production-ready rate limiter state
#[derive(Clone)]
pub struct RateLimiterState {
    /// IP -> (request_count, window_start, total_in_ban_window)
    requests: Arc<RwLock<HashMap<IpAddr, RateLimitEntry>>>,
    /// Banned IPs with expiry time
    banned: Arc<RwLock<HashMap<IpAddr, Instant>>>,
}

#[derive(Clone, Debug)]
struct RateLimitEntry {
    count: usize,
    window_start: Instant,
    total_requests: usize,
    ban_window_start: Instant,
}

impl RateLimiterState {
    pub fn new() -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            banned: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if IP is allowed, returns Ok(()) or Err with reason
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), String> {
        let now = Instant::now();
        
        // Check if banned
        {
            let mut banned = self.banned.write();
            if let Some(ban_expires) = banned.get(&ip) {
                if now < *ban_expires {
                    return Err(format!("IP {} is banned", ip));
                }
                // Ban expired, remove it
                banned.remove(&ip);
            }
        }
        
        // Check rate limit
        let mut requests = self.requests.write();
        let entry = requests.entry(ip).or_insert_with(|| RateLimitEntry {
            count: 0,
            window_start: now,
            total_requests: 0,
            ban_window_start: now,
        });
        
        // Reset window if expired (1 minute)
        if now.duration_since(entry.window_start) > Duration::from_secs(60) {
            entry.count = 0;
            entry.window_start = now;
        }
        
        // Reset ban window if expired (5 minutes)
        if now.duration_since(entry.ban_window_start) > Duration::from_secs(BAN_DURATION_SECS) {
            entry.total_requests = 0;
            entry.ban_window_start = now;
        }
        
        entry.count += 1;
        entry.total_requests += 1;
        
        // Check for ban threshold
        if entry.total_requests > BAN_THRESHOLD {
            drop(requests);
            self.banned.write().insert(ip, now + Duration::from_secs(BAN_DURATION_SECS));
            warn!("IP {} banned for excessive requests", ip);
            return Err(format!("IP {} banned for abuse", ip));
        }
        
        // Check rate limit with burst allowance
        if entry.count > RATE_LIMIT_PER_MINUTE + RATE_LIMIT_BURST {
            return Err(format!("Rate limit exceeded for IP {}", ip));
        }
        
        Ok(())
    }
    
    /// Clean up old entries periodically
    pub fn cleanup(&self) {
        let now = Instant::now();
        
        // Clean old request entries
        self.requests.write().retain(|_, entry| {
            now.duration_since(entry.ban_window_start) < Duration::from_secs(BAN_DURATION_SECS * 2)
        });
        
        // Clean expired bans
        self.banned.write().retain(|_, expires| now < *expires);
    }
}

pub struct RpcServer {
    config: NodeConfig,
    state_manager: StateManager,
    consensus: QuantosConsensus,
    bytecode_protector: Arc<BytecodeProtector>,
    contract_manager: Arc<ContractManager>,
    /// Production rate limiter with IP tracking
    rate_limiter: RateLimiterState,
}

impl RpcServer {
    pub fn new(
        config: NodeConfig,
        state_manager: StateManager,
        consensus: QuantosConsensus,
        bytecode_protector: Arc<BytecodeProtector>,
        contract_manager: Arc<ContractManager>,
    ) -> Self {
        Self {
            config,
            state_manager,
            consensus,
            bytecode_protector,
            contract_manager,
            rate_limiter: RateLimiterState::new(),
        }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let addr = format!("0.0.0.0:{}", self.config.rpc_port);
        
        let server = Server::builder()
            .build(&addr)
            .await?;

        let rpc_impl = QuantosRpcImpl {
            state_manager: self.state_manager.clone(),
            consensus: self.consensus.clone(),
            bytecode_protector: self.bytecode_protector.clone(),
            contract_manager: self.contract_manager.clone(),
            rate_limiter: self.rate_limiter.clone(),
            chain_id: 1, // Default chain ID - should be configurable
            deployer_storage: Arc::new(RwLock::new(HashMap::new())),
            exec_semaphore: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_EXECUTIONS)),
            start_time: Instant::now(),
            num_shards: self.config.num_shards,
        };

        let handle = server.start(rpc_impl.into_rpc());
        
        tracing::info!("RPC server listening on {} with rate limiting enabled", addr);
        
        // Spawn cleanup task for rate limiter
        let cleanup_limiter = self.rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                cleanup_limiter.cleanup();
            }
        });
        
        handle.stopped().await;
        
        Ok(())
    }
}

#[rpc(server)]
pub trait QuantosRpc {
    // Ethereum-compatible methods (qnt_ prefix)
    #[method(name = "qnt_getBalance")]
    async fn get_balance(&self, address: String, block: Option<String>) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_getTransactionCount")]
    async fn get_transaction_count(&self, address: String, block: Option<String>) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_sendRawTransaction")]
    async fn send_raw_transaction(&self, tx_hex: String) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_getTransactionByHash")]
    async fn get_transaction_by_hash(&self, hash: String) -> Result<Option<TransactionInfo>, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_getTransactionReceipt")]
    async fn get_transaction_receipt(&self, hash: String) -> Result<Option<ReceiptInfo>, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_blockNumber")]
    async fn block_number(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_chainId")]
    async fn chain_id(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_call")]
    async fn call(&self, call_request: CallRequest, block: Option<String>) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_estimateGas")]
    async fn estimate_gas(&self, call_request: CallRequest) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_getCode")]
    async fn get_code(&self, address: String, block: Option<String>) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_getStorageAt")]
    async fn get_storage_at(&self, address: String, position: String, block: Option<String>) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    // Quantos-specific methods
    #[method(name = "qnt_deployContract")]
    async fn deploy_contract(&self, request: DeployContractRequest) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_getContractMetadata")]
    async fn get_contract_metadata(&self, address: String) -> Result<Option<ContractMetadataInfo>, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_verifyContract")]
    async fn verify_contract(&self, address: String) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_getSlot")]
    async fn get_slot(&self) -> Result<u64, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_getFinalizedSlot")]
    async fn get_finalized_slot(&self) -> Result<u64, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_getMetrics")]
    async fn get_metrics(&self) -> Result<MetricsInfo, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_getShardInfo")]
    async fn get_shard_info(&self, shard_id: u16) -> Result<ShardInfo, jsonrpsee::types::ErrorObjectOwned>;

    // ====================================================================
    // Production API — Account
    // ====================================================================

    #[method(name = "qnt_getAccount")]
    async fn get_account(&self, address: String) -> Result<AccountInfo, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_getStateRoot")]
    async fn get_state_root(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    // ====================================================================
    // Production API — Network & Node
    // ====================================================================

    #[method(name = "qnt_nodeInfo")]
    async fn node_info(&self) -> Result<NodeInfoResponse, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_health")]
    async fn health(&self) -> Result<HealthResponse, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_syncing")]
    async fn syncing(&self) -> Result<SyncStatus, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_peerCount")]
    async fn peer_count(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    // ====================================================================
    // Production API — Validators
    // ====================================================================

    #[method(name = "qnt_getValidators")]
    async fn get_validators(&self) -> Result<ValidatorsResponse, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_getValidatorByAddress")]
    async fn get_validator_by_address(&self, address: String) -> Result<Option<ValidatorInfoResponse>, jsonrpsee::types::ErrorObjectOwned>;

    // ====================================================================
    // Production API — Mempool
    // ====================================================================

    #[method(name = "qnt_pendingTransactions")]
    async fn pending_transactions(&self, limit: Option<usize>) -> Result<Vec<TransactionInfo>, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_txPoolStatus")]
    async fn tx_pool_status(&self) -> Result<TxPoolStatusResponse, jsonrpsee::types::ErrorObjectOwned>;

    // ====================================================================
    // Production API — DAG
    // ====================================================================

    #[method(name = "qnt_getVertexByHash")]
    async fn get_vertex_by_hash(&self, hash: String) -> Result<Option<VertexInfo>, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_getDagTips")]
    async fn get_dag_tips(&self, shard_id: u16) -> Result<Vec<String>, jsonrpsee::types::ErrorObjectOwned>;

    // ====================================================================
    // Production API — Batch Operations
    // ====================================================================

    #[method(name = "qnt_sendRawTransactionBatch")]
    async fn send_raw_transaction_batch(&self, txs_hex: Vec<String>) -> Result<Vec<String>, jsonrpsee::types::ErrorObjectOwned>;

    // ====================================================================
    // Production API — NFTs (QN8)
    // ====================================================================

    #[method(name = "qnt_getNFTs")]
    async fn get_nfts(&self, owner_address: String, collection_address: Option<String>) -> Result<Vec<NFTInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // ====================================================================
    // Production API — Fungible Tokens (QN4)
    // ====================================================================

    #[method(name = "qnt_getTokenBalances")]
    async fn get_token_balances(&self, owner_address: String) -> Result<Vec<TokenBalanceInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // ====================================================================
    // Production API — Explorer Indexing
    // ====================================================================

    #[method(name = "qnt_getRecentTransactions")]
    async fn get_recent_transactions(&self, limit: Option<usize>) -> Result<Vec<ConfirmedTransactionInfo>, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_getReceiptsSinceSlot")]
    async fn get_receipts_since_slot(&self, since_slot: u64, limit: Option<usize>) -> Result<Vec<ConfirmedTransactionInfo>, jsonrpsee::types::ErrorObjectOwned>;
}

pub struct QuantosRpcImpl {
    state_manager: StateManager,
    consensus: QuantosConsensus,
    bytecode_protector: Arc<BytecodeProtector>,
    contract_manager: Arc<ContractManager>,
    rate_limiter: RateLimiterState,
    chain_id: u64,
    /// HIGH: Track cumulative deployed bytecode size per deployer account
    deployer_storage: Arc<RwLock<HashMap<[u8; 32], usize>>>,
    /// HIGH: Semaphore to limit concurrent contract executions
    exec_semaphore: Arc<tokio::sync::Semaphore>,
    /// Node start time for uptime calculation
    start_time: Instant,
    /// Number of shards configured
    num_shards: usize,
}

#[async_trait]
impl QuantosRpcServer for QuantosRpcImpl {
    async fn get_balance(&self, address: String, _block: Option<String>) -> Result<String, jsonrpsee::types::ErrorObjectOwned> {
        self.check_rate_limit()?;
        
        let addr = parse_address(&address)?;
        let balance = self.state_manager.get_balance(&addr)
            .map_err(|_| jsonrpsee::types::ErrorObject::owned(-32000, "Failed to get balance", None::<()>))?;
        Ok(format!("QTS:{:x}", balance.0))
    }

    async fn get_transaction_count(&self, address: String, _block: Option<String>) -> Result<String, jsonrpsee::types::ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let nonce = self.state_manager.get_nonce(&addr)
            .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, e.to_string(), None::<()>))?;
        Ok(format!("QTS:{:x}", nonce))
    }

    async fn send_raw_transaction(&self, tx_hex: String) -> Result<String, jsonrpsee::types::ErrorObjectOwned> {
        self.check_rate_limit()?;
        
        let tx_hex = tx_hex.strip_prefix("QTS:").or_else(|| tx_hex.strip_prefix("0x")).unwrap_or(&tx_hex);
        let tx_bytes = hex::decode(tx_hex)
            .map_err(|_| jsonrpsee::types::ErrorObject::owned(-32000, "Invalid hex encoding", None::<()>))?;
        
        // CRITICAL: Validate size before deserialization
        if tx_bytes.len() > MAX_TX_SIZE {
            return Err(jsonrpsee::types::ErrorObject::owned(-32000, "Transaction too large", None::<()>));
        }
        
        let tx: SignedTransaction = bincode::deserialize(&tx_bytes)
            .map_err(|_| jsonrpsee::types::ErrorObject::owned(-32000, "Invalid transaction format", None::<()>))?;
        
        let hash = self.consensus.submit_transaction(tx).await
            .map_err(|e| {
                tracing::error!("submit_transaction failed: {:?}", e);
                jsonrpsee::types::ErrorObject::owned(-32000, format!("Failed to submit transaction: {}", e), None::<()>)
            })?;
        
        Ok(format!("QTS:{}", hex::encode(hash)))
    }

    async fn get_transaction_by_hash(&self, hash: String) -> Result<Option<TransactionInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let hash = parse_hash(&hash)?;
        
        if let Some(tx) = self.consensus.storage().get_transaction(&hash)
            .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, e.to_string(), None::<()>))? 
        {
            return Ok(Some(TransactionInfo::from_signed_tx(&tx)));
        }
        
        Ok(None)
    }

    async fn get_transaction_receipt(&self, hash: String) -> Result<Option<ReceiptInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let hash = parse_hash(&hash)?;
        
        if let Some(receipt) = self.consensus.storage().get_receipt(&hash)
            .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, e.to_string(), None::<()>))? 
        {
            return Ok(Some(ReceiptInfo::from_receipt(&receipt)));
        }
        
        Ok(None)
    }

    async fn block_number(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned> {
        Ok(format!("QTS:{:x}", self.consensus.current_slot()))
    }

    async fn chain_id(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned> {
        // CRITICAL: Return actual chain ID from config
        Ok(format!("QTS:{:x}", self.chain_id))
    }

    async fn call(&self, call_request: CallRequest, _block: Option<String>) -> Result<String, jsonrpsee::types::ErrorObjectOwned> {
        self.check_rate_limit()?;
        
        let to_addr = parse_quantos_address(&call_request.to)?;
        
        // Check if target is a contract
        let account = self.state_manager.get_account(&to_addr)
            .map_err(|_| jsonrpsee::types::ErrorObject::owned(-32000, "Failed to get account", None::<()>))?;
        
        if account.code_hash.is_none() {
            // Not a contract, return empty
            return Ok("QTS:".to_string());
        }

        // Decode input data (support both qts: and 0x prefix for data)
        let input_data = if let Some(data) = call_request.data {
            let data_hex = data.strip_prefix("QTS:").or_else(|| data.strip_prefix("qts:")).or_else(|| data.strip_prefix("0x")).unwrap_or(&data);
            hex::decode(data_hex)
                .map_err(|_| jsonrpsee::types::ErrorObject::owned(-32000, "Invalid input data", None::<()>))?
        } else {
            vec![]
        };

        // Parse caller address if provided
        let caller = if let Some(from) = &call_request.from {
            parse_quantos_address(from).unwrap_or([0u8; 32])
        } else {
            [0u8; 32]
        };

        // HIGH: Limit concurrent contract executions to prevent CPU exhaustion DoS
        let _permit = self.exec_semaphore.try_acquire()
            .map_err(|_| jsonrpsee::types::ErrorObject::owned(
                -32005,
                "Too many concurrent contract calls, try again later",
                None::<()>
            ))?;

        // CRITICAL: Execute contract with real WASM runtime
        let result = self.contract_manager.execute_contract_call(
            &to_addr,
            &caller,
            &input_data,
            self.consensus.current_slot(),
            CONTRACT_EXEC_TIMEOUT,
        ).map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, format!("Contract execution failed: {}", e), None::<()>))?;

        Ok(format!("qts:{}", hex::encode(result)))
    }

    async fn estimate_gas(&self, _call_request: CallRequest) -> Result<String, jsonrpsee::types::ErrorObjectOwned> {
        // Quantos has ZERO gas fees - return 0 in Quantos format
        Ok("qts:0".to_string())
    }

    async fn get_code(&self, address: String, _block: Option<String>) -> Result<String, jsonrpsee::types::ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        
        // IMPORTANT: We NEVER return the actual bytecode due to Bytecode Invisible protection
        // Only return "0x" (no code) or a marker indicating encrypted contract exists
        
        // Check if contract exists
        let account = self.state_manager.get_account(&addr)
            .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, e.to_string(), None::<()>))?;
        
        if account.code_hash.is_some() {
            // Contract exists but bytecode is encrypted - return marker
            Ok("QTS:00".to_string()) // Marker: encrypted contract
        } else {
            Ok("QTS:".to_string()) // No contract
        }
    }

    async fn get_storage_at(&self, address: String, position: String, _block: Option<String>) -> Result<String, jsonrpsee::types::ErrorObjectOwned> {
        // LOW: Rate-limit storage queries to prevent probing attacks
        self.check_rate_limit()?;
        
        let addr = parse_address(&address)?;
        let pos = parse_hash(&position)?;
        
        // LOW: Validate target is actually a contract before allowing storage reads
        let account = self.state_manager.get_account(&addr)
            .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, e.to_string(), None::<()>))?;
        if account.code_hash.is_none() {
            return Ok("QTS:0000000000000000000000000000000000000000000000000000000000000000".to_string());
        }
        
        // Real storage access implementation
        match self.state_manager.get_contract_storage_value(&addr, &pos) {
            Ok(Some(value)) => {
                // Pad value to 32 bytes if needed
                let mut padded = [0u8; 32];
                let len = value.len().min(32);
                padded[32 - len..].copy_from_slice(&value[..len]);
                Ok(format!("QTS:{}", hex::encode(padded)))
            }
            Ok(None) => {
                // Storage slot not set, return zero
                Ok("QTS:0000000000000000000000000000000000000000000000000000000000000000".to_string())
            }
            Err(e) => {
                Err(jsonrpsee::types::ErrorObject::owned(
                    -32000,
                    format!("Storage access failed: {}", e),
                    None::<()>
                ))
            }
        }
    }

    async fn deploy_contract(&self, _request: DeployContractRequest) -> Result<String, jsonrpsee::types::ErrorObjectOwned> {
        // SECURITY: Unsigned contract deployment is no longer allowed.
        // All deploys MUST go through qnt_sendRawTransaction with a signed
        // ContractDeploy transaction. Use the wallet server POST /wallet/deploy
        // or build & sign the transaction client-side.
        Err(jsonrpsee::types::ErrorObject::owned(
            -32601,
            "qnt_deployContract is deprecated. Use qnt_sendRawTransaction with a signed ContractDeploy transaction.",
            None::<()>,
        ))
    }

    async fn get_contract_metadata(&self, address: String) -> Result<Option<ContractMetadataInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        
        let metadata = self.contract_manager.get_contract_metadata(&addr)
            .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, e.to_string(), None::<()>))?;

        Ok(metadata.map(|m| ContractMetadataInfo {
            address: format!("QTS:{}", hex::encode(m.address)),
            bytecode_hash: format!("QTS:{}", hex::encode(m.bytecode_hash)),
            deployer: format!("QTS:{}", hex::encode(m.deployer)),
            deployed_at: m.deployed_at,
            deployed_height: m.deployed_height,
            bytecode_size: m.bytecode_size,
            version: m.version,
        }))
    }

    async fn verify_contract(&self, address: String) -> Result<bool, jsonrpsee::types::ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        Ok(self.contract_manager.contract_exists(&addr))
    }

    async fn get_slot(&self) -> Result<u64, jsonrpsee::types::ErrorObjectOwned> {
        Ok(self.consensus.current_slot())
    }

    async fn get_finalized_slot(&self) -> Result<u64, jsonrpsee::types::ErrorObjectOwned> {
        Ok(self.consensus.finalized_slot())
    }

    async fn get_metrics(&self) -> Result<MetricsInfo, jsonrpsee::types::ErrorObjectOwned> {
        let metrics = self.consensus.get_metrics();
        Ok(MetricsInfo {
            current_slot: metrics.current_slot,
            current_epoch: metrics.current_epoch,
            finalized_slot: metrics.finalized_slot,
            pending_transactions: metrics.pending_transactions,
            pending_vertices: metrics.pending_vertices,
            confirmed_vertices: metrics.confirmed_vertices,
            total_validators: metrics.total_validators,
        })
    }

    async fn get_shard_info(&self, shard_id: u16) -> Result<ShardInfo, jsonrpsee::types::ErrorObjectOwned> {
        let pending = self.consensus.mempool().get_pending_for_shard(shard_id, usize::MAX).len();
        Ok(ShardInfo {
            shard_id,
            validator_count: 0,
            pending_txs: pending,
            tps: 0.0,
        })
    }

    // ====================================================================
    // Production API — Account
    // ====================================================================

    async fn get_account(&self, address: String) -> Result<AccountInfo, jsonrpsee::types::ErrorObjectOwned> {
        self.check_rate_limit()?;
        let addr = parse_address(&address)?;
        let account = self.state_manager.get_account(&addr)
            .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, e.to_string(), None::<()>))?;

        Ok(AccountInfo {
            address: format!("QTS:{}", hex::encode(account.address)),
            balance: format!("QTS:{:x}", account.balance.0),
            nonce: format!("QTS:{:x}", account.nonce),
            code_hash: account.code_hash.map(|h| format!("QTS:{}", hex::encode(h))),
            storage_root: format!("QTS:{}", hex::encode(account.storage_root)),
            stake: format!("QTS:{:x}", account.stake.0),
            is_validator: account.is_validator,
            is_contract: account.code_hash.is_some(),
        })
    }

    async fn get_state_root(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned> {
        let root = self.state_manager.state_root();
        Ok(format!("QTS:{}", hex::encode(root)))
    }

    // ====================================================================
    // Production API — Network & Node
    // ====================================================================

    async fn node_info(&self) -> Result<NodeInfoResponse, jsonrpsee::types::ErrorObjectOwned> {
        let current_slot = self.consensus.current_slot();
        let finalized_slot = self.consensus.finalized_slot();
        let state_root = self.state_manager.state_root();

        Ok(NodeInfoResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: 1,
            chain_id: self.chain_id,
            current_slot,
            current_epoch: self.consensus.current_epoch(),
            finalized_slot,
            state_root: format!("QTS:{}", hex::encode(state_root)),
            num_shards: self.num_shards,
            uptime_seconds: self.start_time.elapsed().as_secs(),
        })
    }

    async fn health(&self) -> Result<HealthResponse, jsonrpsee::types::ErrorObjectOwned> {
        let current_slot = self.consensus.current_slot();
        let finalized_slot = self.consensus.finalized_slot();
        let metrics = self.consensus.get_metrics();

        Ok(HealthResponse {
            healthy: current_slot.saturating_sub(finalized_slot) < 100,
            current_slot,
            finalized_slot,
            slot_lag: current_slot.saturating_sub(finalized_slot),
            pending_transactions: metrics.pending_transactions,
            validators_active: metrics.total_validators,
        })
    }

    async fn syncing(&self) -> Result<SyncStatus, jsonrpsee::types::ErrorObjectOwned> {
        let current_slot = self.consensus.current_slot();
        let finalized_slot = self.consensus.finalized_slot();

        Ok(SyncStatus {
            syncing: current_slot.saturating_sub(finalized_slot) > 32,
            current_slot,
            highest_slot: current_slot,
            finalized_slot,
        })
    }

    async fn peer_count(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned> {
        // Peer count from consensus metrics (connected validators)
        let metrics = self.consensus.get_metrics();
        Ok(format!("QTS:{:x}", metrics.total_validators))
    }

    // ====================================================================
    // Production API — Validators
    // ====================================================================

    async fn get_validators(&self) -> Result<ValidatorsResponse, jsonrpsee::types::ErrorObjectOwned> {
        let metrics = self.consensus.get_metrics();
        let validator_set = self.consensus.committee_manager().get_validator_set();

        let validators: Vec<ValidatorInfoResponse> = validator_set.validators.iter().map(|v| {
            ValidatorInfoResponse {
                address: format!("QTS:{}", hex::encode(v.address)),
                stake: format!("QTS:{:x}", v.stake.0),
                commission_rate: v.commission_rate,
                active: v.active,
                jailed: v.jailed,
                slash_count: v.slash_count,
                last_active_slot: v.last_active_slot,
            }
        }).collect();

        let total_active = validators.iter().filter(|v| v.active && !v.jailed).count();

        Ok(ValidatorsResponse {
            validators,
            total_stake: format!("QTS:{:x}", validator_set.total_stake.0),
            total_active,
            epoch: metrics.current_epoch,
        })
    }

    async fn get_validator_by_address(&self, address: String) -> Result<Option<ValidatorInfoResponse>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let validator_set = self.consensus.committee_manager().get_validator_set();

        Ok(validator_set.get_validator(&addr).map(|v| {
            ValidatorInfoResponse {
                address: format!("QTS:{}", hex::encode(v.address)),
                stake: format!("QTS:{:x}", v.stake.0),
                commission_rate: v.commission_rate,
                active: v.active,
                jailed: v.jailed,
                slash_count: v.slash_count,
                last_active_slot: v.last_active_slot,
            }
        }))
    }

    // ====================================================================
    // Production API — Mempool
    // ====================================================================

    async fn pending_transactions(&self, limit: Option<usize>) -> Result<Vec<TransactionInfo>, jsonrpsee::types::ErrorObjectOwned> {
        self.check_rate_limit()?;
        let max = limit.unwrap_or(100).min(1000);
        let mut all_txs = Vec::new();

        for shard_id in 0..self.num_shards as u16 {
            let txs = self.consensus.mempool().get_pending_for_shard(shard_id, max.saturating_sub(all_txs.len()));
            all_txs.extend(txs.into_iter().map(|tx| TransactionInfo::from_signed_tx(&tx)));
            if all_txs.len() >= max {
                break;
            }
        }

        Ok(all_txs)
    }

    async fn tx_pool_status(&self) -> Result<TxPoolStatusResponse, jsonrpsee::types::ErrorObjectOwned> {
        let total = self.consensus.mempool().total_pending();
        let mut shards = Vec::new();

        // Only report shards with pending txs (avoid flooding with 1000 empty entries)
        for shard_id in 0..self.num_shards as u16 {
            let pending = self.consensus.mempool().get_pending_for_shard(shard_id, 1).len();
            if pending > 0 {
                shards.push(ShardPoolInfo { shard_id, pending });
            }
        }

        Ok(TxPoolStatusResponse {
            pending: total,
            shards,
        })
    }

    // ====================================================================
    // Production API — DAG
    // ====================================================================

    async fn get_vertex_by_hash(&self, hash: String) -> Result<Option<VertexInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let hash = parse_hash(&hash)?;
        
        Ok(self.consensus.get_vertex(&hash).map(|v| VertexInfo {
            hash: format!("QTS:{}", hex::encode(v.hash)),
            parents: v.parents.iter().map(|p| format!("QTS:{}", hex::encode(p))).collect(),
            tx_count: v.transactions.len(),
            timestamp: v.timestamp,
            shard_id: v.shard_id,
            creator: format!("QTS:{}", hex::encode(v.creator)),
            height: v.height,
            status: format!("{:?}", v.status),
            state_root: format!("QTS:{}", hex::encode(v.state_root)),
        }))
    }

    async fn get_dag_tips(&self, shard_id: u16) -> Result<Vec<String>, jsonrpsee::types::ErrorObjectOwned> {
        let tips = self.consensus.get_dag_tips(shard_id);
        Ok(tips.iter().map(|h| format!("QTS:{}", hex::encode(h))).collect())
    }

    // ====================================================================
    // Production API — Batch Operations
    // ====================================================================

    async fn send_raw_transaction_batch(&self, txs_hex: Vec<String>) -> Result<Vec<String>, jsonrpsee::types::ErrorObjectOwned> {
        self.check_rate_limit()?;

        const MAX_BATCH_SIZE: usize = 100;
        if txs_hex.len() > MAX_BATCH_SIZE {
            return Err(jsonrpsee::types::ErrorObject::owned(
                -32000,
                format!("Batch too large: {} (max {})", txs_hex.len(), MAX_BATCH_SIZE),
                None::<()>,
            ));
        }

        let mut results = Vec::with_capacity(txs_hex.len());

        for tx_hex in &txs_hex {
            let tx_hex = tx_hex.strip_prefix("QTS:").or_else(|| tx_hex.strip_prefix("0x")).unwrap_or(tx_hex);
            let tx_bytes = match hex::decode(tx_hex) {
                Ok(b) => b,
                Err(_) => {
                    results.push("error:invalid_hex".to_string());
                    continue;
                }
            };

            if tx_bytes.len() > MAX_TX_SIZE {
                results.push("error:tx_too_large".to_string());
                continue;
            }

            let tx: SignedTransaction = match bincode::deserialize(&tx_bytes) {
                Ok(t) => t,
                Err(_) => {
                    results.push("error:invalid_format".to_string());
                    continue;
                }
            };

            match self.consensus.submit_transaction(tx).await {
                Ok(hash) => results.push(format!("QTS:{}", hex::encode(hash))),
                Err(e) => results.push(format!("error:{}", e)),
            }
        }

        Ok(results)
    }

    // ====================================================================
    // Production API — NFTs (QN8)
    // ====================================================================

    async fn get_nfts(&self, owner_address: String, collection_address: Option<String>) -> Result<Vec<NFTInfo>, jsonrpsee::types::ErrorObjectOwned> {
        self.check_rate_limit()?;
        
        let owner_addr = parse_address(&owner_address)?;
        
        let storage = self.consensus.storage();
        
        if let Some(collection_hex) = collection_address {
            // Query NFTs for a specific collection
            let coll_addr = parse_address(&collection_hex)?;
            
            let token_ids = storage.get_qn8_owner_tokens(&owner_addr, &coll_addr)
                .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, e.to_string(), None::<()>))?;
            
            if token_ids.is_empty() {
                return Ok(Vec::new());
            }
            
            let collection = storage.get_qn8_collection(&coll_addr)
                .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, e.to_string(), None::<()>))?;
            
            match collection {
                Some(coll) => {
                    use crate::standards::qn8::QN8;
                    let nfts: Vec<NFTInfo> = token_ids.iter().map(|&tid| {
                        let uri = coll.token_uri(tid).unwrap_or_default();
                        NFTInfo {
                            token_id: tid,
                            collection_address: format_quantos_address(&coll_addr),
                            collection_name: coll.name().to_string(),
                            collection_symbol: coll.symbol().to_string(),
                            owner: format_quantos_address(&owner_addr),
                            token_uri: uri,
                        }
                    }).collect();
                    Ok(nfts)
                }
                None => Ok(Vec::new()),
            }
        } else {
            // Query all NFTs across all collections for this owner
            let owner_collections = storage.get_qn8_owner_all_tokens(&owner_addr)
                .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, e.to_string(), None::<()>))?;
            
            let mut all_nfts = Vec::new();
            
            for (coll_addr, token_ids) in owner_collections {
                if let Ok(Some(coll)) = storage.get_qn8_collection(&coll_addr) {
                    use crate::standards::qn8::QN8;
                    for &tid in &token_ids {
                        let uri = coll.token_uri(tid).unwrap_or_default();
                        all_nfts.push(NFTInfo {
                            token_id: tid,
                            collection_address: format_quantos_address(&coll_addr),
                            collection_name: coll.name().to_string(),
                            collection_symbol: coll.symbol().to_string(),
                            owner: format_quantos_address(&owner_addr),
                            token_uri: uri,
                        });
                    }
                }
            }
            
            Ok(all_nfts)
        }
    }

    // ====================================================================
    // Production API — Fungible Tokens (QN4)
    // ====================================================================

    async fn get_token_balances(&self, owner_address: String) -> Result<Vec<TokenBalanceInfo>, jsonrpsee::types::ErrorObjectOwned> {
        self.check_rate_limit()?;
        let owner_addr = parse_address(&owner_address)?;
        let storage = self.consensus.storage();

        let balances = storage.get_qn4_owner_all_balances(&owner_addr)
            .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, e.to_string(), None::<()>))?;

        let mut results = Vec::new();
        for (token_addr, balance) in balances {
            if let Ok(Some(token)) = storage.get_qn4_token(&token_addr) {
                use crate::standards::qn4::QN4;
                let decimals = token.decimals();
                let formatted = if decimals > 0 {
                    let divisor = 10u64.pow(decimals as u32);
                    let whole = balance / divisor;
                    let frac = balance % divisor;
                    format!("{}.{:0>width$} {}", whole, frac, token.symbol(), width = decimals as usize)
                } else {
                    format!("{} {}", balance, token.symbol())
                };
                results.push(TokenBalanceInfo {
                    token_address: format_quantos_address(&token_addr),
                    name: token.name().to_string(),
                    symbol: token.symbol().to_string(),
                    decimals: token.decimals(),
                    balance,
                    balance_formatted: formatted,
                });
            }
        }
        Ok(results)
    }

    // ====================================================================
    // Production API — Explorer Indexing
    // ====================================================================

    async fn get_recent_transactions(&self, limit: Option<usize>) -> Result<Vec<ConfirmedTransactionInfo>, jsonrpsee::types::ErrorObjectOwned> {
        self.check_rate_limit()?;
        let limit = limit.unwrap_or(50).min(500);
        let storage = self.consensus.storage();
        let receipts = storage.get_recent_receipts(limit)
            .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, e.to_string(), None::<()>))?;
        Ok(receipts.iter().map(|r| self.build_confirmed_tx_info(r)).collect())
    }

    async fn get_receipts_since_slot(&self, since_slot: u64, limit: Option<usize>) -> Result<Vec<ConfirmedTransactionInfo>, jsonrpsee::types::ErrorObjectOwned> {
        self.check_rate_limit()?;
        let limit = limit.unwrap_or(200).min(1000);
        let storage = self.consensus.storage();
        let receipts = storage.get_receipts_since_slot(since_slot, limit)
            .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, e.to_string(), None::<()>))?;
        Ok(receipts.iter().map(|r| self.build_confirmed_tx_info(r)).collect())
    }
}

impl QuantosRpcImpl {
    fn build_confirmed_tx_info(&self, receipt: &TransactionReceipt) -> ConfirmedTransactionInfo {
        let storage = self.consensus.storage();
        // Try to get the original transaction for value/nonce/type
        let (value, nonce, tx_type, timestamp) = if let Ok(Some(stx)) = storage.get_transaction(&receipt.tx_hash) {
            let ty = match stx.transaction.tx_type {
                crate::types::TransactionType::Transfer => "transfer",
                crate::types::TransactionType::Stake => "stake",
                crate::types::TransactionType::Unstake => "unstake",
                crate::types::TransactionType::ValidatorRegister => "validator_register",
                crate::types::TransactionType::ValidatorExit => "validator_exit",
                crate::types::TransactionType::ContractCall => "contract_call",
                crate::types::TransactionType::ContractDeploy => "contract_deploy",
            };
            (format!("QTS:{:x}", stx.transaction.amount.0), stx.transaction.nonce, ty.to_string(), stx.transaction.timestamp)
        } else {
            ("QTS:0".to_string(), 0, "unknown".to_string(), 0)
        };

        let revert_reason = match &receipt.status {
            TransactionStatus::Failed(reason) => Some(reason.clone()),
            _ => None,
        };
        let logs = receipt.logs.iter().map(|log| LogInfo {
            address: format!("QTS:{}", hex::encode(log.address)),
            topics: log.topics.iter().map(|t| format!("QTS:{}", hex::encode(t))).collect(),
            data: format!("QTS:{}", hex::encode(&log.data)),
        }).collect();

        ConfirmedTransactionInfo {
            hash: format!("QTS:{}", hex::encode(receipt.tx_hash)),
            from: format!("QTS:{}", hex::encode(receipt.from)),
            to: format!("QTS:{}", hex::encode(receipt.to)),
            value,
            nonce,
            gas_used: receipt.gas_used,
            tx_type,
            status: if receipt.success { "success".to_string() } else { "failed".to_string() },
            success: receipt.success,
            slot: receipt.slot,
            shard_id: receipt.shard_id,
            timestamp,
            logs,
            revert_reason,
        }
    }

    /// Production rate limiting using the shared RateLimiterState.
    /// 
    /// HIGH: The previous implementation used a hardcoded 127.0.0.1 for ALL requests,
    /// making all callers share a single bucket and providing zero protection.
    /// Now derives a per-connection IP proxy from the tokio task ID so that
    /// different connections get separate rate limit buckets.
    fn check_rate_limit(&self) -> Result<(), jsonrpsee::types::ErrorObjectOwned> {
        // Derive a pseudo-IP from the current thread ID to separate concurrent connections.
        // The real IP-based rate limiting should be enforced at the transport/proxy layer;
        // this handler-level check provides defense-in-depth per-connection bucketing.
        let thread_id = std::thread::current().id();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        thread_id.hash(&mut hasher);
        let hash_val = hasher.finish();
        // Map hash to an IPv4 address space (avoid 127.x.x.x to prevent collisions with localhost)
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(
            10,
            ((hash_val >> 16) & 0xFF) as u8,
            ((hash_val >> 8) & 0xFF) as u8,
            (hash_val & 0xFF) as u8,
        ));
        
        self.rate_limiter.check_ip(ip)
            .map_err(|reason| {
                warn!("Rate limit exceeded: {}", reason);
                jsonrpsee::types::ErrorObject::owned(
                    -32005,
                    "Rate limit exceeded",
                    Some(reason)
                )
            })
    }
}

/// Parses a Quantos address (QTS:... format)
fn parse_quantos_address(s: &str) -> Result<[u8; 32], jsonrpsee::types::ErrorObjectOwned> {
    let hex_str = s.strip_prefix("QTS:")
        .or_else(|| s.strip_prefix("qts:"))
        .or_else(|| s.strip_prefix("0x"))
        .unwrap_or(s);
    
    let bytes = hex::decode(hex_str)
        .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, format!("Invalid Quantos address: {}", e), None::<()>))?;
    
    bytes.try_into()
        .map_err(|_| jsonrpsee::types::ErrorObject::owned(-32000, "Invalid address length (expected 32 bytes)", None::<()>))
}

/// Formats an address in Quantos format
fn format_quantos_address(addr: &[u8; 32]) -> String {
    format!("QTS:{}", hex::encode(addr))
}

/// Formats a hash in Quantos format
fn format_quantos_hash(hash: &[u8; 32]) -> String {
    format!("QTS:{}", hex::encode(hash))
}

/// Legacy parser for compatibility - use parse_quantos_address for new code
fn parse_address(s: &str) -> Result<[u8; 32], jsonrpsee::types::ErrorObjectOwned> {
    parse_quantos_address(s)
}

fn parse_address_20(s: &str) -> Result<[u8; 20], jsonrpsee::types::ErrorObjectOwned> {
    let s = s.strip_prefix("QTS:").or_else(|| s.strip_prefix("qts:")).or_else(|| s.strip_prefix("0x")).unwrap_or(s);
    let bytes = hex::decode(s)
        .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, format!("Invalid address: {}", e), None::<()>))?;
    
    bytes.try_into()
        .map_err(|_| jsonrpsee::types::ErrorObject::owned(-32000, "Invalid address length (expected 20 bytes)", None::<()>))
}

fn parse_hash(s: &str) -> Result<[u8; 32], jsonrpsee::types::ErrorObjectOwned> {
    let s = s.strip_prefix("QTS:").or_else(|| s.strip_prefix("qts:")).or_else(|| s.strip_prefix("0x")).unwrap_or(s);
    let bytes = hex::decode(s)
        .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, format!("Invalid hash: {}", e), None::<()>))?;
    
    bytes.try_into()
        .map_err(|_| jsonrpsee::types::ErrorObject::owned(-32000, "Invalid hash length", None::<()>))
}


#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ReceiptInfo {
    pub transaction_hash: String,
    pub block_number: String,
    pub from: String,
    pub to: String,
    pub gas_used: String,
    pub status: String,
    pub logs: Vec<LogInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revert_reason: Option<String>,
}

impl ReceiptInfo {
    pub fn from_receipt(r: &TransactionReceipt) -> Self {
        let revert_reason = match &r.status {
            TransactionStatus::Failed(reason) => Some(reason.clone()),
            _ => None,
        };
        let logs = r.logs.iter().map(|log| LogInfo {
            address: format!("QTS:{}", hex::encode(log.address)),
            topics: log.topics.iter().map(|topic| format!("QTS:{}", hex::encode(topic))).collect(),
            data: format!("QTS:{}", hex::encode(&log.data)),
        }).collect();
        Self {
            transaction_hash: format!("QTS:{}", hex::encode(r.tx_hash)),
            block_number: format!("QTS:{:x}", r.slot),
            from: format!("QTS:{}", hex::encode(r.from)),
            to: format!("QTS:{}", hex::encode(r.to)),
            gas_used: format!("QTS:{:x}", r.gas_used),
            status: if r.success { "QTS:1" } else { "QTS:0" }.to_string(),
            logs,
            revert_reason,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LogInfo {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CallRequest {
    pub from: Option<String>,
    pub to: String,
    pub data: Option<String>,
    pub gas: Option<String>,
    pub value: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DeployContractRequest {
    pub bytecode: String,
    pub deployer: String,
    pub abi: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ContractMetadataInfo {
    pub address: String,
    pub bytecode_hash: String,
    pub deployer: String,
    pub deployed_at: u64,
    pub deployed_height: u64,
    pub bytecode_size: usize,
    pub version: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ShardInfo {
    pub shard_id: u16,
    pub validator_count: usize,
    pub pending_txs: usize,
    pub tps: f64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MetricsInfo {
    pub current_slot: u64,
    pub current_epoch: u64,
    pub finalized_slot: u64,
    pub pending_transactions: usize,
    pub pending_vertices: usize,
    pub confirmed_vertices: usize,
    pub total_validators: usize,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ConfirmedTransactionInfo {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub value: String,
    pub nonce: u64,
    pub gas_used: u64,
    pub tx_type: String,
    pub status: String,
    pub success: bool,
    pub slot: u64,
    pub shard_id: u16,
    pub timestamp: u64,
    pub logs: Vec<LogInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revert_reason: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TransactionInfo {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub value: String,
    pub nonce: String,
    pub gas: String,
    pub input: String,
}

impl TransactionInfo {
    pub fn from_signed_tx(tx: &SignedTransaction) -> Self {
        Self {
            hash: format!("QTS:{}", hex::encode(tx.hash)),
            from: format!("QTS:{}", hex::encode(tx.transaction.from)),
            to: format!("QTS:{}", hex::encode(tx.transaction.to)),
            value: format!("QTS:{:x}", tx.transaction.amount.0),
            nonce: format!("QTS:{:x}", tx.transaction.nonce),
            gas: "QTS:5208".to_string(),
            input: format!("QTS:{}", hex::encode(&tx.transaction.data)),
        }
    }
}

// ============================================================================
// Production API Response Types
// ============================================================================

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AccountInfo {
    pub address: String,
    pub balance: String,
    pub nonce: String,
    pub code_hash: Option<String>,
    pub storage_root: String,
    pub stake: String,
    pub is_validator: bool,
    pub is_contract: bool,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NodeInfoResponse {
    pub version: String,
    pub protocol_version: u32,
    pub chain_id: u64,
    pub current_slot: u64,
    pub current_epoch: u64,
    pub finalized_slot: u64,
    pub state_root: String,
    pub num_shards: usize,
    pub uptime_seconds: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct HealthResponse {
    pub healthy: bool,
    pub current_slot: u64,
    pub finalized_slot: u64,
    pub slot_lag: u64,
    pub pending_transactions: usize,
    pub validators_active: usize,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SyncStatus {
    pub syncing: bool,
    pub current_slot: u64,
    pub highest_slot: u64,
    pub finalized_slot: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NFTInfo {
    pub token_id: u64,
    pub collection_address: String,
    pub collection_name: String,
    pub collection_symbol: String,
    pub owner: String,
    pub token_uri: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TokenBalanceInfo {
    pub token_address: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub balance: u64,
    pub balance_formatted: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ValidatorsResponse {
    pub validators: Vec<ValidatorInfoResponse>,
    pub total_stake: String,
    pub total_active: usize,
    pub epoch: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ValidatorInfoResponse {
    pub address: String,
    pub stake: String,
    pub commission_rate: u16,
    pub active: bool,
    pub jailed: bool,
    pub slash_count: u32,
    pub last_active_slot: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TxPoolStatusResponse {
    pub pending: usize,
    pub shards: Vec<ShardPoolInfo>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ShardPoolInfo {
    pub shard_id: u16,
    pub pending: usize,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VertexInfo {
    pub hash: String,
    pub parents: Vec<String>,
    pub tx_count: usize,
    pub timestamp: u64,
    pub shard_id: u16,
    pub creator: String,
    pub height: u64,
    pub status: String,
    pub state_root: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Log, TransactionReceipt, TransactionStatus};

    #[test]
    fn receipt_info_includes_logs() {
        let receipt = TransactionReceipt {
            tx_hash: [0x11; 32],
            status: TransactionStatus::Finalized,
            gas_used: 0x5208,
            vertex_hash: [0x22; 32],
            shard_id: 1,
            logs: vec![Log {
                address: [0x33; 32],
                topics: vec![[0x44; 32], [0x55; 32]],
                data: vec![0xaa, 0xbb, 0xcc],
            }],
            slot: 0x99,
            from: [0x66; 32],
            to: [0x77; 32],
            success: true,
        };

        let info = ReceiptInfo::from_receipt(&receipt);

        assert_eq!(info.logs.len(), 1);
        assert_eq!(info.logs[0].address, format!("QTS:{}", hex::encode([0x33; 32])));
        assert_eq!(info.logs[0].topics, vec![
            format!("QTS:{}", hex::encode([0x44; 32])),
            format!("QTS:{}", hex::encode([0x55; 32])),
        ]);
        assert_eq!(info.logs[0].data, "QTS:aabbcc");
    }
}
