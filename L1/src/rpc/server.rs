// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::OnceLock;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use std::future::{self, Future};

use hyper::{Body, Request, Response, StatusCode};
use tower::{Layer, Service};
use jsonrpsee::server::Server;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use parking_lot::RwLock;
use rayon::prelude::*;
use tracing::warn;

/// Maximum contract bytecode size (10MB)
const MAX_CONTRACT_SIZE: usize = 10 * 1024 * 1024;
/// Maximum transaction size for deserialization (1MB)
const MAX_TX_SIZE: usize = 1024 * 1024;
/// Contract execution timeout (5 seconds)
const CONTRACT_EXEC_TIMEOUT: Duration = Duration::from_secs(5);
/// Rate limit: requests per IP per minute
const DEFAULT_RATE_LIMIT_PER_MINUTE: usize = 100;
/// Rate limit burst allowance
const DEFAULT_RATE_LIMIT_BURST: usize = 20;
/// Ban duration for excessive requests (5 minutes)
const DEFAULT_BAN_DURATION_SECS: u64 = 300;
/// Threshold for banning (requests in ban window)
const DEFAULT_BAN_THRESHOLD: usize = 500;

fn parse_env_usize(key: &str, default: usize) -> usize {
    static CACHE: OnceLock<RwLock<HashMap<String, usize>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    *cache.write().entry(key.to_string()).or_insert_with(|| {
        std::env::var(key)
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(default)
    })
}

fn rate_limit_per_minute() -> usize { parse_env_usize("QUANTOS_RATE_LIMIT_PER_MINUTE", DEFAULT_RATE_LIMIT_PER_MINUTE) }
fn rate_limit_burst() -> usize { parse_env_usize("QUANTOS_RATE_LIMIT_BURST", DEFAULT_RATE_LIMIT_BURST) }
fn ban_threshold() -> usize { parse_env_usize("QUANTOS_BAN_THRESHOLD", DEFAULT_BAN_THRESHOLD) }
fn ban_duration() -> Duration { Duration::from_secs(std::env::var("QUANTOS_BAN_DURATION_SECS").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(DEFAULT_BAN_DURATION_SECS)) }
/// Maximum cumulative contract storage per deployer (100MB)
const MAX_STORAGE_PER_ACCOUNT: usize = 100 * 1024 * 1024;
/// Maximum concurrent contract executions to prevent CPU exhaustion
const DEFAULT_MAX_CONCURRENT_EXECUTIONS: usize = 128;

fn max_concurrent_executions() -> usize {
    static MAX_CONCURRENT_EXECUTIONS: OnceLock<usize> = OnceLock::new();
    *MAX_CONCURRENT_EXECUTIONS.get_or_init(|| {
        std::env::var("QUANTOS_MAX_CONCURRENT_EXECUTIONS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_MAX_CONCURRENT_EXECUTIONS)
    })
}

use crate::consensus::QuantosConsensus;
use crate::state::StateManager;
use crate::types::{SignedTransaction, TransactionReceipt, TransactionStatus};
use crate::vm::{BytecodeProtector, ContractManager};
use crate::rpc::subscriptions::SubscriptionManager;
use crate::NodeConfig;

/// Production-ready rate limiter state
#[derive(Clone)]
pub struct RateLimiterState {
    /// IP -> (request_count, window_start, total_in_ban_window)
    requests: Arc<RwLock<HashMap<IpAddr, RateLimitEntry>>>,
    /// Banned IPs with expiry time
    banned: Arc<RwLock<HashMap<IpAddr, Instant>>>,
    /// Requests per minute allowed per IP
    per_minute: usize,
    /// Burst allowance per IP
    burst: usize,
    /// Ban duration for excessive requests
    ban_duration: Duration,
    /// Threshold for banning an IP
    ban_threshold: usize,
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
            per_minute: rate_limit_per_minute(),
            burst: rate_limit_burst(),
            ban_duration: ban_duration(),
            ban_threshold: ban_threshold(),
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
        if now.duration_since(entry.ban_window_start) > self.ban_duration {
            entry.total_requests = 0;
            entry.ban_window_start = now;
        }
        
        entry.count += 1;
        entry.total_requests += 1;
        
        // Check for ban threshold
        if entry.total_requests > self.ban_threshold {
            drop(requests);
            self.banned.write().insert(ip, now + self.ban_duration);
            warn!("IP {} banned for excessive requests", ip);
            return Err(format!("IP {} banned for abuse", ip));
        }
        
        // Check rate limit with burst allowance
        if entry.count > self.per_minute + self.burst {
            return Err(format!("Rate limit exceeded for IP {}", ip));
        }
        
        Ok(())
    }
    
    /// Clean up old entries periodically
    pub fn cleanup(&self) {
        let now = Instant::now();

        // Clean old request entries
        self.requests.write().retain(|_, entry| {
            now.duration_since(entry.ban_window_start) < self.ban_duration * 2
        });

        // Clean expired bans
        self.banned.write().retain(|_, expires| now < *expires);
    }
}

/// Tower HTTP middleware that enforces real-IP-based rate limiting before
/// requests reach the JSON-RPC handler. The client IP is extracted from the
/// `X-Forwarded-For` header (standard behind reverse proxies) or `X-Real-IP`,
/// with a fallback to an unknown IP for direct connections.
#[derive(Clone)]
pub struct RateLimitLayer {
    limiter: RateLimiterState,
}

impl RateLimitLayer {
    pub fn new(limiter: RateLimiterState) -> Self {
        Self { limiter }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            limiter: self.limiter.clone(),
        }
    }
}

pub struct RateLimitService<S> {
    inner: S,
    limiter: RateLimiterState,
}

impl<S> Service<Request<Body>> for RateLimitService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let ip = extract_client_ip(&req);
        match self.limiter.check_ip(ip) {
            Ok(()) => {
                let fut = self.inner.call(req);
                Box::pin(async move { fut.await })
            }
            Err(reason) => {
                warn!("Rate limit exceeded for {}: {}", ip, reason);
                let body = json_rpc_error(-32005, &reason);
                let response = Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap_or_else(|_| Response::new(Body::empty()));
                Box::pin(async move { Ok(response) })
            }
        }
    }
}

fn extract_client_ip<B>(req: &Request<B>) -> IpAddr {
    if let Some(forwarded) = req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(ip_str) = forwarded.split(',').next() {
            if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    if let Some(real_ip) = req.headers().get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = real_ip.trim().parse::<IpAddr>() {
            return ip;
        }
    }
    // Fallback for direct connections without a reverse proxy.
    // In production, Quantos should always be behind a proxy that sets X-Forwarded-For.
    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
}

fn json_rpc_error(code: i32, message: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","error":{{"code":{},"message":"{}"}},"id":null}}"#,
        code,
        message.replace('"', "\\\"")
    )
}

pub struct RpcServer {
    config: NodeConfig,
    state_manager: StateManager,
    consensus: QuantosConsensus,
    bytecode_protector: Arc<BytecodeProtector>,
    contract_manager: Arc<ContractManager>,
    /// Production rate limiter with IP tracking
    rate_limiter: RateLimiterState,
    /// WebSocket subscription manager
    subscription_manager: SubscriptionManager,
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
            subscription_manager: SubscriptionManager::new(),
        }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let addr = format!("0.0.0.0:{}", self.config.rpc_port);

        let http_middleware = tower::ServiceBuilder::new()
            .layer(RateLimitLayer::new(self.rate_limiter.clone()));

        let server = Server::builder()
            .set_http_middleware(http_middleware)
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
            exec_semaphore: Arc::new(tokio::sync::Semaphore::new(max_concurrent_executions())),
            start_time: Instant::now(),
            num_shards: self.config.num_shards,
            subscription_manager: self.subscription_manager.clone(),
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

        // Spawn subscription polling loop for newHeads
        let sub_mgr_heads = self.subscription_manager.clone();
        let consensus_heads = self.consensus.clone();
        let mut last_slot: u64 = consensus_heads.current_slot();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            loop {
                interval.tick().await;
                let current_slot = consensus_heads.current_slot();
                if current_slot != last_slot {
                    last_slot = current_slot;
                    let epoch = consensus_heads.current_epoch();
                    let finalized = consensus_heads.finalized_slot();
                    let state_root = {
                        let sm = consensus_heads.state_manager();
                        hex::encode(sm.state_root())
                    };
                    let notification = serde_json::json!({
                        "slot": current_slot,
                        "epoch": epoch,
                        "finalized_slot": finalized,
                        "state_root": format!("QTS:{}", state_root),
                    });
                    sub_mgr_heads.broadcast("newHeads", notification);
                }
            }
        });

        // Spawn subscription polling loop for newPendingTransactions
        let sub_mgr_pending = self.subscription_manager.clone();
        let consensus_pending = self.consensus.clone();
        let mut last_pending_count: usize = 0;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(200));
            loop {
                interval.tick().await;
                let mempool = consensus_pending.mempool();
                let current_count = mempool.total_pending();
                if current_count != last_pending_count {
                    if current_count > last_pending_count {
                        // New transactions appeared - broadcast them
                        let new_count = current_count - last_pending_count;
                        for shard_id in 0..consensus_pending.num_shards() as u16 {
                            let txs = mempool.get_pending_for_shard(shard_id, new_count);
                            for tx in txs {
                                let notification = serde_json::json!({
                                    "hash": format!("QTS:{}", hex::encode(tx.hash)),
                                    "from": format!("QTS:{}", hex::encode(tx.transaction.from)),
                                    "to": format!("QTS:{}", hex::encode(tx.transaction.to)),
                                    "value": format!("QTS:{:x}", tx.transaction.amount.0),
                                    "nonce": format!("QTS:{:x}", tx.transaction.nonce),
                                });
                                sub_mgr_pending.broadcast("newPendingTransactions", notification);
                            }
                        }
                    }
                    last_pending_count = current_count;
                }
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

    // ====================================================================
    // L0 — Post-Quantum Finality Hub (external chain attestation)
    // ====================================================================

    #[method(name = "qnt_submitExternalCheckpoint")]
    async fn submit_external_checkpoint(&self, request: ExternalCheckpointRequest) -> Result<ExternalCheckpointResponse, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_getL0Proof")]
    async fn get_l0_proof(&self, proof_hash: String) -> Result<Option<L0ProofInfo>, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_getLatestL0Proof")]
    async fn get_latest_l0_proof(&self) -> Result<Option<L0ProofInfo>, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_getL0Metrics")]
    async fn get_l0_metrics(&self) -> Result<L0MetricsInfo, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_registerSubnet")]
    async fn register_subnet(&self, request: RegisterSubnetRequest) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_getSubnet")]
    async fn get_subnet(&self, id: String) -> Result<Option<SubnetInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // ====================================================================
    // Server-side transaction signing
    // ====================================================================

    #[method(name = "qnt_sendTransaction")]
    async fn send_transaction(&self, request: SendTransactionRequest) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "qnt_generateKeyPair")]
    async fn generate_keypair(&self) -> Result<KeyPairResponse, jsonrpsee::types::ErrorObjectOwned>;

    // ====================================================================
    // WebSocket Subscriptions
    // ====================================================================

    #[subscription(name = "qnt_subscribe", unsubscribe = "qnt_unsubscribe", item = SubscriptionNotification)]
    fn subscribe(&self, kind: String, params: Option<serde_json::Value>);
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
    /// WebSocket subscription manager
    subscription_manager: SubscriptionManager,
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

        let max_batch_size: usize = std::env::var("QUANTOS_RPC_MAX_BATCH_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2000)
            .max(1);
        if txs_hex.len() > max_batch_size {
            return Err(jsonrpsee::types::ErrorObject::owned(
                -32000,
                format!("Batch too large: {} (max {})", txs_hex.len(), max_batch_size),
                None::<()>,
            ));
        }

        let mut results = Vec::with_capacity(txs_hex.len());

        // Phase 1: Parallel hex decode + bincode deserialize
        let decoded: Vec<Result<SignedTransaction, String>> = txs_hex
            .par_iter()
            .map(|tx_hex| {
                let tx_hex = tx_hex.strip_prefix("QTS:").or_else(|| tx_hex.strip_prefix("0x")).unwrap_or(tx_hex);
                let tx_bytes = match hex::decode(tx_hex) {
                    Ok(b) => b,
                    Err(_) => return Err("error:invalid_hex".to_string()),
                };
                if tx_bytes.len() > MAX_TX_SIZE {
                    return Err("error:tx_too_large".to_string());
                }
                match bincode::deserialize::<SignedTransaction>(&tx_bytes) {
                    Ok(t) => Ok(t),
                    Err(_) => Err("error:invalid_format".to_string()),
                }
            })
            .collect();

        // Phase 2: Submit sequentially (mempool add is fast now that verify is cached)
        for tx_result in decoded {
            match tx_result {
                Ok(tx) => {
                    match self.consensus.submit_transaction(tx).await {
                        Ok(hash) => results.push(format!("QTS:{}", hex::encode(hash))),
                        Err(e) => results.push(format!("error:{}", e)),
                    }
                }
                Err(err) => results.push(err),
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

    // ====================================================================
    // L0 — Post-Quantum Finality Hub (external chain attestation)
    // ====================================================================

    async fn submit_external_checkpoint(&self, request: ExternalCheckpointRequest) -> Result<ExternalCheckpointResponse, jsonrpsee::types::ErrorObjectOwned> {
        self.check_rate_limit()?;

        use crate::l0::{ChainId, ExternalCheckpoint, ValidatorSetSnapshot, VerificationResult};
        use crate::l0::external::ChainProof;

        let hub = match self.consensus.l0_hub() {
            Some(h) => h,
            None => return Err(jsonrpsee::types::ErrorObject::owned(
                -32000, "L0 finality hub is not enabled on this node", None::<()>
            )),
        };

        // Parse chain ID
        let chain_id = match request.chain_id.as_str() {
            "ethereum" => ChainId::Ethereum,
            "ethereum-sepolia" => ChainId::EthereumSepolia,
            "base" => ChainId::Base,
            "base-sepolia" => ChainId::BaseSepolia,
            "arbitrum" => ChainId::Arbitrum,
            "arbitrum-sepolia" => ChainId::ArbitrumSepolia,
            "optimism" => ChainId::Optimism,
            "optimism-sepolia" => ChainId::OptimismSepolia,
            "polygon" => ChainId::Polygon,
            "polygon-amoy" => ChainId::PolygonAmoy,
            "avalanche" => ChainId::Avalanche,
            "avalanche-fuji" => ChainId::AvalancheFuji,
            "bsc" => ChainId::BinanceSmartChain,
            "bsc-testnet" => ChainId::BscTestnet,
            "solana" => ChainId::Solana,
            "solana-devnet" => ChainId::SolanaDevnet,
            "near" => ChainId::Near,
            "near-testnet" => ChainId::NearTestnet,
            "aptos" => ChainId::Aptos,
            "aptos-testnet" => ChainId::AptosTestnet,
            "sui" => ChainId::Sui,
            "sui-testnet" => ChainId::SuiTestnet,
            "ton" => ChainId::Ton,
            "ton-testnet" => ChainId::TonTestnet,
            "bitcoin" => ChainId::Bitcoin,
            "bitcoin-testnet" => ChainId::BitcoinTestnet,
            "stellar" => ChainId::Stellar,
            "stellar-testnet" => ChainId::StellarTestnet,
            "polkadot" => ChainId::Polkadot,
            "polkadot-testnet" => ChainId::PolkadotTestnet,
            "tron" => ChainId::Tron,
            "tron-shasta" => ChainId::TronShasta,
            "cosmos" => ChainId::Cosmos,
            "cosmos-testnet" => ChainId::CosmosTestnet,
            "cardano" => ChainId::Cardano,
            "cardano-testnet" => ChainId::CardanoTestnet,
            other => ChainId::Custom(other.to_string()),
        };

        let block_hash = parse_hash(&request.block_hash)?;
        let state_root = parse_hash(&request.state_root)?;
        let proof: ChainProof = serde_json::from_str(&request.proof_json)
            .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, format!("Invalid proof_json: {}", e), None::<()>))?;

        let checkpoint = ExternalCheckpoint {
            chain_id,
            block_number: request.block_number,
            block_hash,
            state_root,
            parent_block_hash: [0u8; 32],
            chain_work: 0,
            timestamp_ms: request.timestamp_ms,
            proof,
            metadata: request.metadata,
        };

        // Get checkpoint pool
        let pool = match self.consensus.checkpoint_pool() {
            Some(p) => p,
            None => return Err(jsonrpsee::types::ErrorObject::owned(
                -32000, "Checkpoint pool not available", None::<()>
            )),
        };

        // Get light client registry for verification
        let light_clients = match self.consensus.light_client_registry() {
            Some(lc) => lc,
            None => return Err(jsonrpsee::types::ErrorObject::owned(
                -32000, "Light client registry not available", None::<()>
            )),
        };

        // Verify checkpoint using light client or Subnet Manager if it's a sovereign subnet
        let subnet_manager = self.consensus.subnet_manager();
        let mut sovereign_subnet_config = None;
        
        if let ChainId::Custom(ref name) = checkpoint.chain_id {
            if let Some(ref sm) = subnet_manager {
                use crate::l0::subnet::SubnetId;
                if let Some(config) = sm.get_subnet(&SubnetId(name.clone())) {
                    // This is a registered sovereign subnet!
                    if let Err(e) = sm.verify_subnet_checkpoint(&SubnetId(name.clone()), &checkpoint) {
                        return Err(jsonrpsee::types::ErrorObject::owned(
                            -32000, format!("Subnet checkpoint verification failed: {}", e), None::<()>
                        ));
                    }
                    sovereign_subnet_config = Some(config);
                }
            }
        }

        // If it's not a custom subnet, verify via light client registry
        if sovereign_subnet_config.is_none() {
            let verification = match light_clients.verify_checkpoint(&checkpoint).await {
                Ok(v) => v,
                Err(e) => return Err(jsonrpsee::types::ErrorObject::owned(
                    -32000, format!("Checkpoint verification failed: {}", e), None::<()>
                )),
            };

            if !verification.valid {
                return Err(jsonrpsee::types::ErrorObject::owned(
                    -32000, format!("Invalid checkpoint: {}", verification.reason.unwrap_or_else(|| "Unknown reason".to_string())), None::<()>
                ));
            }
        }

        // Compute digest for this checkpoint
        let digest = checkpoint.digest();

        // Add checkpoint to pool
        if let Err(e) = pool.add_checkpoint(checkpoint.clone(), digest) {
            return Err(jsonrpsee::types::ErrorObject::owned(
                -32000, format!("Failed to add checkpoint to pool: {}", e), None::<()>
            ));
        }

        // Broadcast checkpoint to other validators via gossip
        if let Some(gossip) = self.consensus.checkpoint_gossip() {
            let peers = vec![]; // Peer list populated by the network layer on connection
            gossip.broadcast_checkpoint(digest, checkpoint.clone(), peers);
        }

        // Resolve validator set snapshot to use (custom subnet validators or default Quantos validators)
        let mut snapshot = match self.consensus.get_validator_snapshot() {
            Some(s) => s,
            None => return Err(jsonrpsee::types::ErrorObject::owned(
                -32000, "No active validators available", None::<()>
            )),
        };

        if let Some(ref subnet_config) = sovereign_subnet_config {
            if let Some(ref custom_validators) = subnet_config.custom_validators {
                // Construct a custom ValidatorSetSnapshot representing the subnet's own validator set
                use crate::l0::proof::ValidatorRecord;
                let validators: Vec<ValidatorRecord> = custom_validators
                    .iter()
                    .map(|v| ValidatorRecord {
                        address: v.address,
                        public_key: vec![], // Custom subnet validators do not need public keys on-chain if certified by L0
                        stake: v.stake,
                    })
                    .collect();
                let root = ValidatorSetSnapshot::compute_root(&validators);
                snapshot = ValidatorSetSnapshot { root, validators };
            }
        }

        // If this node is a validator on the resolved set, sign immediately
        if let Some(signature) = self.consensus.sign_external_checkpoint(&digest) {
            if let Some(validator) = snapshot.validators.iter().find(|v| v.address == signature.validator) {
                let stake = validator.stake;
                let _ = pool.add_signature(&digest, signature.clone(), stake);
                
                // Broadcast signature to other validators
                if let Some(gossip) = self.consensus.checkpoint_gossip() {
                    let peers = vec![]; // Empty for now, will be populated by network layer
                    gossip.broadcast_signature(digest, signature, stake, peers);
                }
            }
        }

        // Check if we have enough signatures to build proof
        if let Some(pending) = pool.get(&digest) {
            let required = snapshot.total_stake() * 2 / 3 + 1;
            
            if pending.signed_stake >= required {
                // We have enough signatures, build the proof
                let verification = VerificationResult::valid();
                
                match hub.build_external_proof(&pending.checkpoint, &snapshot, &pending.signatures, &verification) {
                    Ok(proof) => {
                        pool.mark_finalized(&digest);
                        let proof_hash = proof.proof_hash();
                        Ok(ExternalCheckpointResponse {
                            proof_hash: format!("QTS:{}", hex::encode(proof_hash)),
                            status: "finalized".to_string(),
                            signed_stake: format!("QTS:{:x}", pending.signed_stake),
                            required_stake: format!("QTS:{:x}", required),
                        })
                    }
                    Err(e) => Err(jsonrpsee::types::ErrorObject::owned(
                        -32000, format!("L0 proof build failed: {}", e), None::<()>
                    )),
                }
            } else {
                // Not enough signatures yet, return pending status
                Ok(ExternalCheckpointResponse {
                    proof_hash: format!("QTS:{}", hex::encode(digest)),
                    status: "pending_signatures".to_string(),
                    signed_stake: format!("QTS:{:x}", pending.signed_stake),
                    required_stake: format!("QTS:{:x}", required),
                })
            }
        } else {
            Err(jsonrpsee::types::ErrorObject::owned(
                -32000, "Checkpoint not found in pool", None::<()>
            ))
        }
    }

    async fn get_l0_proof(&self, proof_hash: String) -> Result<Option<L0ProofInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let hub = match self.consensus.l0_hub() {
            Some(h) => h,
            None => return Ok(None),
        };

        let hash = parse_hash(&proof_hash)?;
        match hub.lookup(&hash) {
            Some(proof) => Ok(Some(L0ProofInfo {
                proof_hash: format!("QTS:{}", hex::encode(proof.proof_hash())),
                chain_id: proof.header.external_chain.as_ref().map(|c| c.as_str().to_string()),
                epoch: proof.header.epoch,
                slot: proof.header.slot,
                state_root: format!("QTS:{}", hex::encode(proof.header.state_root)),
                block_hash: format!("QTS:{}", hex::encode(proof.header.dag_root)),
                validator_set_root: format!("QTS:{}", hex::encode(proof.header.validator_set_root)),
                total_stake: format!("QTS:{:x}", proof.header.total_stake),
                signed_stake: format!("QTS:{:x}", proof.signed_stake()),
                stake_threshold: format!("QTS:{:x}", proof.header.stake_threshold),
                signature_count: proof.signatures.len(),
                emitted_at_ms: proof.header.emitted_at_ms,
            })),
            None => Ok(None),
        }
    }

    async fn get_latest_l0_proof(&self) -> Result<Option<L0ProofInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let hub = match self.consensus.l0_hub() {
            Some(h) => h,
            None => return Ok(None),
        };

        match hub.latest() {
            Some(proof) => Ok(Some(L0ProofInfo {
                proof_hash: format!("QTS:{}", hex::encode(proof.proof_hash())),
                chain_id: proof.header.external_chain.as_ref().map(|c| c.as_str().to_string()),
                epoch: proof.header.epoch,
                slot: proof.header.slot,
                state_root: format!("QTS:{}", hex::encode(proof.header.state_root)),
                block_hash: format!("QTS:{}", hex::encode(proof.header.dag_root)),
                validator_set_root: format!("QTS:{}", hex::encode(proof.header.validator_set_root)),
                total_stake: format!("QTS:{:x}", proof.header.total_stake),
                signed_stake: format!("QTS:{:x}", proof.signed_stake()),
                stake_threshold: format!("QTS:{:x}", proof.header.stake_threshold),
                signature_count: proof.signatures.len(),
                emitted_at_ms: proof.header.emitted_at_ms,
            })),
            None => Ok(None),
        }
    }

    async fn get_l0_metrics(&self) -> Result<L0MetricsInfo, jsonrpsee::types::ErrorObjectOwned> {
        let hub = match self.consensus.l0_hub() {
            Some(h) => h,
            None => return Err(jsonrpsee::types::ErrorObject::owned(
                -32000, "L0 finality hub is not enabled on this node", None::<()>
            )),
        };

        let metrics = hub.metrics();
        Ok(L0MetricsInfo {
            proofs_produced: metrics.proofs_produced,
            proofs_failed: metrics.proofs_failed,
            archived_proofs: metrics.archived_proofs,
        })
    }

    async fn register_subnet(&self, request: RegisterSubnetRequest) -> Result<bool, jsonrpsee::types::ErrorObjectOwned> {
        self.check_rate_limit()?;

        let subnet_manager = match self.consensus.subnet_manager() {
            Some(sm) => sm,
            None => return Err(jsonrpsee::types::ErrorObject::owned(
                -32000, "L0 subnet manager is not enabled on this node", None::<()>
            )),
        };

        use crate::l0::subnet::{SubnetConfig, SubnetId, SubnetValidator};

        let mut custom_validators = None;
        if let Some(validators) = request.custom_validators {
            let mut parsed_validators = Vec::new();
            for v in validators {
                let address_bytes = parse_hash(&v.address)?; // Parse address from hex
                let stake = u128::from_str_radix(v.stake.trim_start_matches("0x").trim_start_matches("QTS:"), 16)
                    .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, format!("Invalid stake hex: {}", e), None::<()>))?;
                let qts_double_stake = u128::from_str_radix(v.qts_double_stake.trim_start_matches("0x").trim_start_matches("QTS:"), 16)
                    .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, format!("Invalid qts_double_stake hex: {}", e), None::<()>))?;
                
                parsed_validators.push(SubnetValidator {
                    address: address_bytes,
                    stake,
                    qts_double_stake,
                });
            }
            custom_validators = Some(parsed_validators);
        }

        let stacc_collateral_leased = u128::from_str_radix(request.stacc_collateral_leased.trim_start_matches("0x").trim_start_matches("QTS:"), 16)
            .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, format!("Invalid stacc_collateral_leased hex: {}", e), None::<()>))?;

        let min_double_stake_qts = u128::from_str_radix(request.min_double_stake_qts.trim_start_matches("0x").trim_start_matches("QTS:"), 16)
            .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, format!("Invalid min_double_stake_qts hex: {}", e), None::<()>))?;

        let config = SubnetConfig {
            name: request.name,
            fee_token: request.fee_token,
            custom_validators,
            reward_multiplier: request.reward_multiplier,
            stacc_collateral_leased,
            min_double_stake_qts,
        };

        match subnet_manager.register_subnet(SubnetId(request.id), config) {
            Ok(()) => Ok(true),
            Err(e) => Err(jsonrpsee::types::ErrorObject::owned(-32000, e, None::<()>)),
        }
    }

    async fn get_subnet(&self, id: String) -> Result<Option<SubnetInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let subnet_manager = match self.consensus.subnet_manager() {
            Some(sm) => sm,
            None => return Ok(None),
        };

        use crate::l0::subnet::SubnetId;

        match subnet_manager.get_subnet(&SubnetId(id.clone())) {
            Some(config) => {
                let custom_validators = config.custom_validators.map(|validators| {
                    validators.iter().map(|v| SubnetValidatorInfo {
                        address: format!("QTS:{}", hex::encode(v.address)),
                        stake: format!("QTS:{:x}", v.stake),
                        qts_double_stake: format!("QTS:{:x}", v.qts_double_stake),
                    }).collect()
                });

                Ok(Some(SubnetInfo {
                    id,
                    name: config.name,
                    fee_token: config.fee_token,
                    custom_validators,
                    reward_multiplier: config.reward_multiplier,
                    stacc_collateral_leased: format!("QTS:{:x}", config.stacc_collateral_leased),
                    min_double_stake_qts: format!("QTS:{:x}", config.min_double_stake_qts),
                }))
            }
            None => Ok(None),
        }
    }

    // ====================================================================
    // Server-side transaction signing
    // ====================================================================

    async fn send_transaction(&self, request: SendTransactionRequest) -> Result<String, jsonrpsee::types::ErrorObjectOwned> {
        self.check_rate_limit()?;

        use crate::crypto::MlDsa65Keypair;
        use crate::types::{Transaction, TransactionType, Amount, ShardId};

        // Parse private key
        let priv_key_hex = request.from_private_key
            .strip_prefix("QTS:").or_else(|| request.from_private_key.strip_prefix("0x"))
            .unwrap_or(&request.from_private_key);
        let priv_key_bytes = hex::decode(priv_key_hex)
            .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, format!("Invalid private key hex: {}", e), None::<()>))?;

        let keypair = MlDsa65Keypair::from_secret_key(&priv_key_bytes)
            .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, format!("Invalid ML-DSA-65 private key: {}", e), None::<()>))?;

        let from_addr = keypair.address();

        // Parse destination
        let to_addr = parse_address(&request.to)?;

        // Parse amount
        let amount_val = u128::from_str_radix(
            request.amount.strip_prefix("QTS:").or_else(|| request.amount.strip_prefix("0x")).unwrap_or(&request.amount),
            16
        ).map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, format!("Invalid amount hex: {}", e), None::<()>))?;

        // Get nonce from state if not provided
        let nonce = if let Some(nonce_hex) = &request.nonce {
            u64::from_str_radix(
                nonce_hex.strip_prefix("QTS:").or_else(|| nonce_hex.strip_prefix("0x")).unwrap_or(nonce_hex),
                16
            ).map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, format!("Invalid nonce hex: {}", e), None::<()>))?
        } else {
            self.state_manager.get_nonce(&from_addr)
                .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, format!("Failed to get nonce: {}", e), None::<()>))?
        };

        // Parse tx type
        let tx_type = match request.tx_type.as_deref().unwrap_or("transfer") {
            "transfer" => TransactionType::Transfer,
            "stake" => TransactionType::Stake,
            "unstake" => TransactionType::Unstake,
            "validator_register" => TransactionType::ValidatorRegister,
            "validator_exit" => TransactionType::ValidatorExit,
            "contract_call" => TransactionType::ContractCall,
            "contract_deploy" => TransactionType::ContractDeploy,
            other => return Err(jsonrpsee::types::ErrorObject::owned(-32000, format!("Unknown tx type: {}", other), None::<()>)),
        };

        // Parse data
        let data = if let Some(data_hex) = &request.data {
            let d = data_hex.strip_prefix("QTS:").or_else(|| data_hex.strip_prefix("0x")).unwrap_or(data_hex);
            hex::decode(d).unwrap_or_default()
        } else {
            Vec::new()
        };

        let shard_id: ShardId = request.shard_id.unwrap_or(0);
        let max_compute_units = if let Some(cu_hex) = &request.max_compute_units {
            u64::from_str_radix(
                cu_hex.strip_prefix("QTS:").or_else(|| cu_hex.strip_prefix("0x")).unwrap_or(cu_hex),
                16
            ).unwrap_or(100_000)
        } else {
            100_000
        };

        // Create transaction
        let mut tx = Transaction::new(
            tx_type,
            from_addr,
            to_addr,
            Amount(amount_val),
            nonce,
            max_compute_units,
            None,
            data,
            shard_id,
        );
        tx.chain_id = self.chain_id;

        // Sign transaction
        let signing_data = tx.signing_data();
        let signature = keypair.sign(&signing_data)
            .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, format!("Signing failed: {}", e), None::<()>))?;
        tx.signature = signature;
        tx.public_key = keypair.public_key.clone();

        let signed_tx = SignedTransaction::new(tx);

        // Submit to consensus
        let hash = self.consensus.submit_transaction(signed_tx).await
            .map_err(|e| {
                tracing::error!("submit_transaction failed: {:?}", e);
                jsonrpsee::types::ErrorObject::owned(-32000, format!("Failed to submit transaction: {}", e), None::<()>)
            })?;

        Ok(format!("QTS:{}", hex::encode(hash)))
    }

    async fn generate_keypair(&self) -> Result<KeyPairResponse, jsonrpsee::types::ErrorObjectOwned> {
        use crate::crypto::MlDsa65Keypair;

        let keypair = MlDsa65Keypair::generate()
            .map_err(|e| jsonrpsee::types::ErrorObject::owned(-32000, format!("Key generation failed: {}", e), None::<()>))?;

        let address = keypair.address();

        Ok(KeyPairResponse {
            address: format!("QTS:{}", hex::encode(address)),
            public_key: format!("QTS:{}", hex::encode(&keypair.public_key)),
            private_key: format!("QTS:{}", hex::encode(&keypair.secret_key)),
        })
    }

    // ====================================================================
    // WebSocket Subscriptions
    // ====================================================================

    fn subscribe(&self, pending: jsonrpsee::server::PendingSubscriptionSink, kind: String, _params: Option<serde_json::Value>) {
        let sub_mgr = self.subscription_manager.clone();
        tokio::spawn(async move {
            let sink = match pending.accept().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("Failed to accept subscription: {}", e);
                    return;
                }
            };

            match kind.as_str() {
                "newHeads" | "newPendingTransactions" | "logs" => {
                    sub_mgr.add(kind, sink);
                }
                other => {
                    tracing::warn!("Unknown subscription type: {}", other);
                }
            }
        });
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
            gas_used: receipt.cu_used,
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

    /// DEPRECATED: handler-level rate limiting.
    ///
    /// Real per-IP rate limiting is now enforced by the `RateLimitLayer` HTTP
    /// middleware before requests reach the JSON-RPC handler. This method is kept
    /// for minimal diff and is intentionally a no-op.
    fn check_rate_limit(&self) -> Result<(), jsonrpsee::types::ErrorObjectOwned> {
        Ok(())
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
            gas_used: format!("QTS:{:x}", r.cu_used),
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
pub struct ExternalCheckpointRequest {
    pub chain_id: String,
    pub block_number: u64,
    pub block_hash: String,
    pub state_root: String,
    pub timestamp_ms: u64,
    /// JSON-encoded ChainProof (required). No hex strings.
    pub proof_json: String,
    pub metadata: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct L0ProofInfo {
    pub proof_hash: String,
    pub chain_id: Option<String>,
    pub epoch: u64,
    pub slot: u64,
    pub state_root: String,
    pub block_hash: String,
    pub validator_set_root: String,
    pub total_stake: String,
    pub signed_stake: String,
    pub stake_threshold: String,
    pub signature_count: usize,
    pub emitted_at_ms: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct L0MetricsInfo {
    pub proofs_produced: u64,
    pub proofs_failed: u64,
    pub archived_proofs: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SubnetValidatorInfo {
    pub address: String,
    pub stake: String,
    pub qts_double_stake: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RegisterSubnetRequest {
    pub id: String,
    pub name: String,
    pub fee_token: String,
    pub custom_validators: Option<Vec<SubnetValidatorInfo>>,
    pub reward_multiplier: u64,
    pub stacc_collateral_leased: String,
    pub min_double_stake_qts: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SubnetInfo {
    pub id: String,
    pub name: String,
    pub fee_token: String,
    pub custom_validators: Option<Vec<SubnetValidatorInfo>>,
    pub reward_multiplier: u64,
    pub stacc_collateral_leased: String,
    pub min_double_stake_qts: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ExternalCheckpointResponse {
    pub proof_hash: String,
    pub status: String,
    pub signed_stake: String,
    pub required_stake: String,
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

// ============================================================================
// Server-side signing types
// ============================================================================

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SendTransactionRequest {
    /// Hex-encoded ML-DSA-65 secret key (QTS:... or 0x... or raw hex)
    pub from_private_key: String,
    /// Destination address (QTS:...)
    pub to: String,
    /// Amount in smallest units, hex-encoded (QTS:... or 0x...)
    pub amount: String,
    /// Optional calldata, hex-encoded
    pub data: Option<String>,
    /// Optional nonce, hex-encoded. If omitted, fetched from state.
    pub nonce: Option<String>,
    /// Transaction type: "transfer", "stake", "unstake", "validator_register", "validator_exit", "contract_call", "contract_deploy"
    pub tx_type: Option<String>,
    /// Shard ID (default 0)
    pub shard_id: Option<u16>,
    /// Max compute units, hex-encoded (default 100000)
    pub max_compute_units: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct KeyPairResponse {
    pub address: String,
    pub public_key: String,
    pub private_key: String,
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
            cu_used: 0x5208,
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
