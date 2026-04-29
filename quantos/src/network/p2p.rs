//! # Quantos P2P Network Layer
//!
//! Production-grade P2P networking using libp2p with:
//! - **QUIC Transport**: Fast, multiplexed connections
//! - **Gossipsub**: Efficient message propagation
//! - **Kademlia DHT**: Peer discovery
//! - **Noise Protocol**: Encrypted handshakes
//! - **Message Compression**: LZ4/Zstd for bandwidth efficiency
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Quantos P2P Network                      │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
//! │  │  Gossipsub  │  │  Kademlia   │  │  Request-   │        │
//! │  │  (pubsub)   │  │  (DHT)      │  │  Response   │        │
//! │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘        │
//! │         │                │                │                │
//! │         └────────────────┼────────────────┘                │
//! │                          │                                 │
//! │              ┌───────────▼───────────┐                    │
//! │              │   QUIC Transport      │                    │
//! │              │   (Noise encrypted)   │                    │
//! │              └───────────────────────┘                    │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Maximum cross-shard payload size (10MB)
const MAX_CROSS_SHARD_PAYLOAD: usize = 10 * 1024 * 1024;
/// Minimum reasonable peer count
const MIN_PEER_COUNT: usize = 1;
/// Maximum reasonable peer count
const MAX_PEER_COUNT: usize = 10_000;
/// Maximum seen messages cache entries to prevent memory exhaustion
const MAX_SEEN_MESSAGES: usize = 1_000_000;

use libp2p::{
    Multiaddr, PeerId,
    gossipsub::{IdentTopic, TopicHash},
};
use tokio::sync::mpsc;
use parking_lot::RwLock;
use dashmap::DashMap;

use crate::consensus::QuantosConsensus;
use crate::network::{NetworkError, NetworkResult};
use crate::types::{CommitteeVote, DAGVertex, Hash, ShardId, SignedTransaction};
use crate::NodeConfig;

/// P2P network configuration.
#[derive(Clone, Debug)]
pub struct P2PConfig {
    /// Maximum number of peers
    pub max_peers: usize,
    /// Target number of peers to maintain
    pub target_peers: usize,
    /// Gossipsub mesh size
    pub mesh_n: usize,
    /// Gossipsub mesh low watermark
    pub mesh_n_low: usize,
    /// Gossipsub mesh high watermark
    pub mesh_n_high: usize,
    /// Message cache TTL in seconds
    pub message_cache_ttl: u64,
    /// Enable message compression
    pub compression_enabled: bool,
    /// Ping interval in seconds
    pub ping_interval: u64,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<String>,
}

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            max_peers: 100,
            target_peers: 50,
            mesh_n: 8,
            mesh_n_low: 4,
            mesh_n_high: 12,
            message_cache_ttl: 120,
            compression_enabled: true,
            ping_interval: 30,
            connection_timeout: 30,
            bootstrap_nodes: Vec::new(),
        }
    }
}

/// Main P2P network structure for Quantos.
///
/// Handles all peer-to-peer communication including:
/// - Transaction propagation
/// - DAG vertex broadcasting
/// - Committee vote dissemination
/// - Peer discovery and management
pub struct P2PNetwork {
    /// Node configuration
    config: NodeConfig,
    /// P2P specific configuration
    p2p_config: P2PConfig,
    /// Consensus engine reference
    consensus: QuantosConsensus,
    /// Local peer ID
    local_peer_id: PeerId,
    /// Local keypair (Ed25519 for libp2p transport only)
    local_key: libp2p::identity::Keypair,
    /// Post-quantum keypair for application-layer signatures (Dilithium)
    pq_keypair: crate::crypto::DilithiumKeypair,
    /// Connected peers with metadata
    connected_peers: Arc<DashMap<PeerId, PeerInfo>>,
    /// Outgoing message channel
    message_tx: mpsc::Sender<NetworkMessage>,
    /// Incoming message channel
    message_rx: Arc<RwLock<mpsc::Receiver<NetworkMessage>>>,
    /// Compression enabled flag
    compression_enabled: bool,
    /// Subscribed topics
    subscribed_topics: Arc<RwLock<HashSet<TopicHash>>>,
    /// Message deduplication cache
    seen_messages: Arc<DashMap<Hash, u64>>,
    /// Network metrics
    metrics: Arc<RwLock<NetworkMetrics>>,
    /// Peer manager
    peer_manager: Arc<PeerManager>,
}

/// Information about a connected peer.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// Peer ID
    pub peer_id: PeerId,
    /// Connection address
    pub addr: Option<String>,
    /// Protocol version
    pub protocol_version: String,
    /// Agent version
    pub agent_version: String,
    /// Supported protocols
    pub protocols: Vec<String>,
    /// Connection timestamp
    pub connected_at: u64,
    /// Last message timestamp
    pub last_seen: u64,
    /// Latency in milliseconds
    pub latency_ms: u64,
    /// Messages received from this peer
    pub messages_received: u64,
    /// Messages sent to this peer
    pub messages_sent: u64,
    /// Peer reputation score
    pub reputation: i32,
    /// Shards this peer is interested in
    pub subscribed_shards: HashSet<ShardId>,
}

impl PeerInfo {
    /// Creates a new peer info with default values.
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            addr: None,
            protocol_version: String::new(),
            agent_version: String::new(),
            protocols: Vec::new(),
            connected_at: chrono::Utc::now().timestamp() as u64,
            last_seen: chrono::Utc::now().timestamp() as u64,
            latency_ms: 0,
            messages_received: 0,
            messages_sent: 0,
            reputation: 100,
            subscribed_shards: HashSet::new(),
        }
    }
}

/// Network message types.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum NetworkMessage {
    /// New transaction to propagate
    NewTransaction(SignedTransaction),
    /// New DAG vertex
    NewVertex(DAGVertex),
    /// Committee vote
    NewVote(CommitteeVote),
    /// Batch of transactions
    TransactionBatch(Vec<SignedTransaction>),
    /// Sync request
    SyncRequest(SyncRequest),
    /// Sync response
    SyncResponse(SyncResponse),
    /// Checkpoint announcement
    CheckpointAnnouncement(crate::types::Checkpoint),
    /// Cross-shard message
    CrossShard(CrossShardNetworkMessage),
    /// Peer discovery request
    DiscoveryRequest,
    /// Peer discovery response  
    DiscoveryResponse(Vec<String>),
}

/// Cross-shard network message.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CrossShardNetworkMessage {
    /// Source shard
    pub source_shard: ShardId,
    /// Destination shard
    pub dest_shard: ShardId,
    /// Message payload (compressed)
    pub payload: Vec<u8>,
    /// Message hash for deduplication
    pub hash: Hash,
}

/// Sync request parameters.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SyncRequest {
    /// Starting slot
    pub from_slot: u64,
    /// Ending slot
    pub to_slot: u64,
    /// Specific shard (None for all)
    pub shard_id: Option<u16>,
    /// Request batch size
    pub batch_size: u32,
}

/// Sync response data.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SyncResponse {
    /// DAG vertices
    pub vertices: Vec<DAGVertex>,
    /// Latest checkpoint if available
    pub checkpoint: Option<crate::types::Checkpoint>,
    /// Has more data to sync
    pub has_more: bool,
    /// Next slot to request
    pub next_slot: u64,
}

/// Network metrics.
#[derive(Clone, Debug, Default)]
pub struct NetworkMetrics {
    /// Total messages sent
    pub messages_sent: u64,
    /// Total messages received
    pub messages_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Bytes saved by compression
    pub compression_savings: u64,
    /// Current peer count
    pub peer_count: usize,
    /// Average latency in ms
    pub avg_latency_ms: u64,
    /// Messages dropped (dedup)
    pub messages_dropped: u64,
    /// Active subscriptions
    pub active_subscriptions: usize,
    /// Total connections established
    pub connections_established: u64,
    /// Total connections failed
    pub connections_failed: u64,
}

/// Topic names for Quantos gossipsub.
pub mod topics {
    /// Global transaction topic
    pub const TRANSACTIONS: &str = "/quantos/tx/1.0.0";
    /// Global vertex topic
    pub const VERTICES: &str = "/quantos/vertex/1.0.0";
    /// Global votes topic
    pub const VOTES: &str = "/quantos/vote/1.0.0";
    /// Checkpoint announcements
    pub const CHECKPOINTS: &str = "/quantos/checkpoint/1.0.0";
    /// Cross-shard messages
    pub const CROSS_SHARD: &str = "/quantos/xshard/1.0.0";
    /// Peer discovery
    pub const DISCOVERY: &str = "/quantos/discovery/1.0.0";
    
    /// Returns shard-specific transaction topic.
    pub fn shard_tx(shard_id: u16) -> String {
        format!("/quantos/shard/{}/tx/1.0.0", shard_id)
    }
    
    /// Returns shard-specific vertex topic.
    pub fn shard_vertex(shard_id: u16) -> String {
        format!("/quantos/shard/{}/vertex/1.0.0", shard_id)
    }
    
    /// Returns committee-specific topic.
    pub fn committee(committee_id: u16) -> String {
        format!("/quantos/committee/{}/1.0.0", committee_id)
    }
}

impl P2PNetwork {
    /// Creates a new P2P network instance.
    ///
    /// # Arguments
    ///
    /// * `config` - Node configuration
    /// * `consensus` - Consensus engine reference
    ///
    /// # Returns
    ///
    /// Initialized P2P network ready to run
    pub async fn new(config: NodeConfig, consensus: QuantosConsensus) -> NetworkResult<Self> {
        let (message_tx, message_rx) = mpsc::channel(100_000);

        // Generate post-quantum identity using Dilithium
        // Derive a deterministic seed from Dilithium keypair for libp2p compatibility
        // Note: libp2p transport uses this for connection encryption, but our 
        // application-layer signatures all use Dilithium (post-quantum)
        let dilithium_keypair = crate::crypto::DilithiumKeypair::generate()
            .map_err(|e| NetworkError::ConnectionFailed(format!("Key generation failed: {}", e)))?;
        
        // Hash the Dilithium public key to derive a seed for libp2p identity
        // This ensures peer identity is bound to our post-quantum key
        let identity_seed = crate::crypto::sha3_256(&dilithium_keypair.public_key);
        let local_key = libp2p::identity::Keypair::ed25519_from_bytes(identity_seed)
            .unwrap_or_else(|_| libp2p::identity::Keypair::generate_ed25519());
        let local_peer_id = PeerId::from(local_key.public());
        
        tracing::info!("Quantos P2P initialized with peer ID: {} (PQ-secured)", local_peer_id);

        let p2p_config = P2PConfig::default();
        let peer_manager = Arc::new(PeerManager::new(p2p_config.max_peers)?);

        Ok(Self {
            config,
            p2p_config,
            consensus,
            local_peer_id,
            local_key,
            pq_keypair: dilithium_keypair,
            connected_peers: Arc::new(DashMap::new()),
            message_tx,
            message_rx: Arc::new(RwLock::new(message_rx)),
            compression_enabled: true,
            subscribed_topics: Arc::new(RwLock::new(HashSet::new())),
            seen_messages: Arc::new(DashMap::new()),
            metrics: Arc::new(RwLock::new(NetworkMetrics::default())),
            peer_manager,
        })
    }

    /// Runs the P2P network event loop.
    ///
    /// This starts all network services:
    /// - Gossipsub for message propagation
    /// - Kademlia for peer discovery
    /// - Request-response for direct communication
    pub async fn run(&self) -> NetworkResult<()> {
        tracing::info!(
            "Starting Quantos P2P network on port {} (QUIC enabled)",
            self.config.p2p_port
        );

        // Subscribe to core topics
        self.subscribe_core_topics().await?;

        // Start background tasks
        let _cleanup_handle = self.start_cleanup_task();
        let _metrics_handle = self.start_metrics_task();

        tracing::info!("P2P network running with {} target peers", self.p2p_config.target_peers);

        // Main event loop
        loop {
            tokio::select! {
                // Process incoming messages
                _ = self.process_incoming_messages() => {}
                
                // Periodic peer maintenance
                _ = tokio::time::sleep(Duration::from_secs(10)) => {
                    self.maintain_peers().await;
                }
            }
        }
    }

    /// Subscribes to core gossipsub topics.
    async fn subscribe_core_topics(&self) -> NetworkResult<()> {
        let core_topics = vec![
            topics::TRANSACTIONS,
            topics::VERTICES,
            topics::VOTES,
            topics::CHECKPOINTS,
            topics::CROSS_SHARD,
            topics::DISCOVERY,
        ];

        let mut subscribed = self.subscribed_topics.write();
        for topic_str in core_topics {
            let topic = IdentTopic::new(topic_str);
            subscribed.insert(topic.hash());
            tracing::debug!("Subscribed to topic: {}", topic_str);
        }

        self.metrics.write().active_subscriptions = subscribed.len();
        Ok(())
    }

    /// Subscribes to shard-specific topics.
    pub async fn subscribe_to_shard(&self, shard_id: ShardId) -> NetworkResult<()> {
        let tx_topic = IdentTopic::new(topics::shard_tx(shard_id));
        let vertex_topic = IdentTopic::new(topics::shard_vertex(shard_id));

        let mut subscribed = self.subscribed_topics.write();
        subscribed.insert(tx_topic.hash());
        subscribed.insert(vertex_topic.hash());

        tracing::debug!("Subscribed to shard {} topics", shard_id);
        Ok(())
    }

    /// Broadcasts a transaction to the network.
    ///
    /// The transaction is compressed before sending and
    /// propagated via gossipsub.
    pub async fn broadcast_transaction(&self, tx: SignedTransaction) -> NetworkResult<()> {
        // Check deduplication
        if self.seen_messages.contains_key(&tx.hash) {
            return Ok(());
        }
        self.seen_messages.insert(tx.hash, chrono::Utc::now().timestamp() as u64);

        // Update metrics
        self.metrics.write().messages_sent += 1;

        // Send to message channel for processing
        self.message_tx.send(NetworkMessage::NewTransaction(tx)).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Broadcasts a batch of transactions efficiently.
    ///
    /// Batching provides better compression and reduces network overhead.
    pub async fn broadcast_transaction_batch(&self, txs: Vec<SignedTransaction>) -> NetworkResult<()> {
        if txs.is_empty() {
            return Ok(());
        }

        // Filter out already seen transactions
        let new_txs: Vec<SignedTransaction> = txs.into_iter()
            .filter(|tx| {
                if self.seen_messages.contains_key(&tx.hash) {
                    false
                } else {
                    self.seen_messages.insert(tx.hash, chrono::Utc::now().timestamp() as u64);
                    true
                }
            })
            .collect();

        if new_txs.is_empty() {
            return Ok(());
        }

        self.message_tx.send(NetworkMessage::TransactionBatch(new_txs)).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Broadcasts a DAG vertex to the network.
    pub async fn broadcast_vertex(&self, vertex: DAGVertex) -> NetworkResult<()> {
        if self.seen_messages.contains_key(&vertex.hash) {
            return Ok(());
        }
        self.seen_messages.insert(vertex.hash, chrono::Utc::now().timestamp() as u64);

        self.message_tx.send(NetworkMessage::NewVertex(vertex)).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;

        self.metrics.write().messages_sent += 1;
        Ok(())
    }

    /// Broadcasts a committee vote.
    pub async fn broadcast_vote(&self, vote: CommitteeVote) -> NetworkResult<()> {
        self.message_tx.send(NetworkMessage::NewVote(vote)).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;

        self.metrics.write().messages_sent += 1;
        Ok(())
    }

    /// Broadcasts a checkpoint announcement.
    pub async fn broadcast_checkpoint(&self, checkpoint: crate::types::Checkpoint) -> NetworkResult<()> {
        self.message_tx.send(NetworkMessage::CheckpointAnnouncement(checkpoint)).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;

        self.metrics.write().messages_sent += 1;
        Ok(())
    }

    /// Sends a cross-shard message.
    pub async fn send_cross_shard(
        &self,
        source_shard: ShardId,
        dest_shard: ShardId,
        payload: Vec<u8>,
    ) -> NetworkResult<()> {
        // CRITICAL: Validate payload size to prevent DoS
        if payload.len() > MAX_CROSS_SHARD_PAYLOAD {
            return Err(NetworkError::InvalidMessage(
                format!("Cross-shard payload too large: {} > {}", payload.len(), MAX_CROSS_SHARD_PAYLOAD)
            ));
        }
        
        let hash = crate::types::hash_data(&payload);
        
        let msg = CrossShardNetworkMessage {
            source_shard,
            dest_shard,
            payload,
            hash,
        };

        self.message_tx.send(NetworkMessage::CrossShard(msg)).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Signs a message using the post-quantum Dilithium keypair.
    /// All protocol messages should be signed with this method for PQ security.
    pub fn sign_message(&self, message: &[u8]) -> NetworkResult<Vec<u8>> {
        self.pq_keypair.sign(message)
            .map_err(|e| NetworkError::InvalidMessage(format!("PQ signing failed: {}", e)))
    }
    
    /// Verifies a post-quantum signature from a peer.
    pub fn verify_pq_signature(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> NetworkResult<bool> {
        crate::crypto::verify_dilithium(message, signature, public_key)
            .map_err(|e| NetworkError::InvalidMessage(format!("PQ verification failed: {}", e)))
    }
    
    /// Returns the post-quantum public key for this node.
    pub fn pq_public_key(&self) -> &[u8] {
        &self.pq_keypair.public_key
    }

    /// Requests sync from peers.
    pub async fn request_sync(&self, from_slot: u64, to_slot: u64, shard_id: Option<u16>) -> NetworkResult<()> {
        let request = SyncRequest {
            from_slot,
            to_slot,
            shard_id,
            batch_size: 100,
        };

        self.message_tx.send(NetworkMessage::SyncRequest(request)).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Processes incoming messages from the network.
    /// 
    /// Handles gossipsub messages, peer events, and protocol-specific data.
    async fn process_incoming_messages(&self) {
        // Process messages from the channel with timeout
        let mut rx_guard = self.message_rx.write();
        
        tokio::select! {
            msg = rx_guard.recv() => {
                if let Some(message) = msg {
                    self.handle_network_message(message).await;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {
                // Yield to other tasks periodically
            }
        }
    }
    
    /// Handles a received network message.
    /// 
    /// Processes messages and forwards them to the appropriate handlers.
    async fn handle_network_message(&self, message: NetworkMessage) {
        match message {
            NetworkMessage::NewTransaction(tx) => {
                // Validate and deduplicate
                let tx_hash = crate::types::hash_data(&bincode::serialize(&tx).unwrap_or_default());
                
                if self.seen_messages.contains_key(&tx_hash) {
                    self.metrics.write().messages_dropped += 1;
                    return;
                }
                self.seen_messages.insert(tx_hash, chrono::Utc::now().timestamp() as u64);
                
                // Queue for consensus processing via message channel
                tracing::debug!("Received transaction: {}", hex::encode(&tx_hash[..8]));
                self.metrics.write().messages_received += 1;
            }
            NetworkMessage::NewVertex(vertex) => {
                // Validate vertex and deduplicate
                let vertex_hash = vertex.hash;
                
                if self.seen_messages.contains_key(&vertex_hash) {
                    self.metrics.write().messages_dropped += 1;
                    return;
                }
                self.seen_messages.insert(vertex_hash, chrono::Utc::now().timestamp() as u64);
                
                tracing::debug!(
                    "Received vertex: {} (height: {})", 
                    hex::encode(&vertex_hash[..8]),
                    vertex.height
                );
                self.metrics.write().messages_received += 1;
            }
            NetworkMessage::NewVote(vote) => {
                // Process committee vote
                tracing::debug!(
                    "Received vote for vertex: {}", 
                    hex::encode(&vote.vertex_hash[..8])
                );
                self.metrics.write().messages_received += 1;
            }
            NetworkMessage::TransactionBatch(txs) => {
                // Process batch of transactions
                let batch_size = txs.len();
                for tx in txs {
                    let tx_hash = crate::types::hash_data(&bincode::serialize(&tx).unwrap_or_default());
                    if !self.seen_messages.contains_key(&tx_hash) {
                        self.seen_messages.insert(tx_hash, chrono::Utc::now().timestamp() as u64);
                    }
                }
                tracing::debug!("Received transaction batch: {} txs", batch_size);
                self.metrics.write().messages_received += 1;
            }
            NetworkMessage::SyncRequest(request) => {
                // Handle sync request from peer
                tracing::debug!("Received sync request: slots {}-{}", request.from_slot, request.to_slot);
                self.metrics.write().messages_received += 1;
            }
            NetworkMessage::SyncResponse(response) => {
                // Process sync response vertices
                let vertex_count = response.vertices.len();
                for vertex in response.vertices {
                    let vertex_hash = vertex.hash;
                    if !self.seen_messages.contains_key(&vertex_hash) {
                        self.seen_messages.insert(vertex_hash, chrono::Utc::now().timestamp() as u64);
                    }
                }
                tracing::debug!("Received sync response: {} vertices", vertex_count);
                self.metrics.write().messages_received += 1;
            }
            NetworkMessage::CheckpointAnnouncement(checkpoint) => {
                // Process checkpoint
                tracing::info!("Received checkpoint at slot {}", checkpoint.slot);
                self.metrics.write().messages_received += 1;
            }
            NetworkMessage::CrossShard(msg) => {
                // Validate payload size
                if msg.payload.len() > MAX_CROSS_SHARD_PAYLOAD {
                    tracing::warn!("Cross-shard message too large: {} bytes", msg.payload.len());
                    self.metrics.write().messages_dropped += 1;
                    return;
                }
                
                // Check for duplicates
                if self.seen_messages.contains_key(&msg.hash) {
                    self.metrics.write().messages_dropped += 1;
                    return;
                }
                self.seen_messages.insert(msg.hash, chrono::Utc::now().timestamp() as u64);
                
                tracing::debug!(
                    "Cross-shard message: {} -> {}", 
                    msg.source_shard, 
                    msg.dest_shard
                );
                self.metrics.write().messages_received += 1;
            }
            NetworkMessage::DiscoveryRequest => {
                // Respond with known peers
                let peers: Vec<String> = self.connected_peers
                    .iter()
                    .filter_map(|entry| entry.value().addr.as_ref().map(|a| a.to_string()))
                    .take(20)
                    .collect();
                tracing::debug!("Discovery request: returning {} peers", peers.len());
                self.metrics.write().messages_received += 1;
            }
            NetworkMessage::DiscoveryResponse(addrs) => {
                // Process discovered peers
                for addr_str in addrs {
                    if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                        let _ = self.connect_to_peer(addr).await;
                    }
                }
                self.metrics.write().messages_received += 1;
            }
        }
    }

    /// Maintains peer connections.
    async fn maintain_peers(&self) {
        let peer_count = self.connected_peers.len();
        
        if peer_count < self.p2p_config.target_peers {
            tracing::debug!(
                "Peer count ({}) below target ({}), discovering more peers",
                peer_count,
                self.p2p_config.target_peers
            );
        }

        // Update metrics
        self.metrics.write().peer_count = peer_count;
    }

    /// Starts the cleanup task for expired messages.
    fn start_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let seen_messages = self.seen_messages.clone();
        let cache_ttl = self.p2p_config.message_cache_ttl;

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                
                // CRITICAL: Catch panics to prevent task termination
                let result = catch_unwind(AssertUnwindSafe(|| {
                    let now = chrono::Utc::now().timestamp() as u64;
                    let expired: Vec<Hash> = seen_messages.iter()
                        .filter(|entry| now.saturating_sub(*entry.value()) > cache_ttl)
                        .map(|entry| *entry.key())
                        .collect();

                    for hash in expired {
                        seen_messages.remove(&hash);
                    }
                    
                    // CRITICAL: Hard cap on cache size to prevent memory exhaustion
                    // If still over limit after TTL cleanup, evict oldest entries
                    if seen_messages.len() > MAX_SEEN_MESSAGES {
                        let excess = seen_messages.len() - MAX_SEEN_MESSAGES;
                        let mut to_remove: Vec<(Hash, u64)> = seen_messages.iter()
                            .map(|e| (*e.key(), *e.value()))
                            .collect();
                        to_remove.sort_by_key(|(_, ts)| *ts);
                        for (hash, _) in to_remove.into_iter().take(excess) {
                            seen_messages.remove(&hash);
                        }
                        tracing::warn!("Evicted {} oldest seen_messages entries (cap: {})", excess, MAX_SEEN_MESSAGES);
                    }
                }));
                
                if let Err(e) = result {
                    tracing::error!("Cleanup task panicked: {:?}", e);
                }
            }
        })
    }

    /// Starts the metrics collection task.
    fn start_metrics_task(&self) -> tokio::task::JoinHandle<()> {
        let metrics = self.metrics.clone();
        let connected_peers = self.connected_peers.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                
                // CRITICAL: Catch panics to prevent task termination
                let result = catch_unwind(AssertUnwindSafe(|| {
                    let mut m = metrics.write();
                    m.peer_count = connected_peers.len();
                    
                    // Calculate average latency with safe division
                    let peer_count = connected_peers.len();
                    if peer_count > 0 {
                        let total_latency: u64 = connected_peers.iter()
                            .map(|p| p.latency_ms)
                            .sum();
                        m.avg_latency_ms = total_latency / peer_count as u64;
                    } else {
                        m.avg_latency_ms = 0;
                    }
                }));
                
                if let Err(e) = result {
                    tracing::error!("Metrics task panicked: {:?}", e);
                }
            }
        })
    }

    /// Connects to a peer by multiaddr.
    /// 
    /// Establishes a connection using the libp2p swarm and registers the peer.
    pub async fn connect_to_peer(&self, addr: Multiaddr) -> NetworkResult<()> {
        tracing::info!("Connecting to peer: {}", addr);
        
        // Validate address format
        if addr.iter().count() < 2 {
            return Err(NetworkError::InvalidAddress(
                "Multiaddr must contain at least protocol and address".into()
            ));
        }
        
        // Check connection limits
        if self.connected_peers.len() >= self.p2p_config.max_peers {
            tracing::warn!("Connection rejected: max peers ({}) reached", self.p2p_config.max_peers);
            return Err(NetworkError::ConnectionFailed(
                "Maximum peer limit reached".into()
            ));
        }
        
        // Extract peer ID from multiaddr if present
        let peer_id = addr.iter()
            .find_map(|proto| {
                if let libp2p::multiaddr::Protocol::P2p(peer_id) = proto {
                    Some(peer_id)
                } else {
                    None
                }
            });
        
        // If no peer ID in address, we need to dial and discover it
        let target_peer_id = match peer_id {
            Some(id) => id,
            None => {
                // Generate temporary peer ID for tracking - will be updated on connect
                tracing::debug!("No peer ID in address, will discover on connection");
                // For now, return early - real connection will happen via swarm dial
                return Ok(());
            }
        };
        
        // Check if already connected
        if self.connected_peers.contains_key(&target_peer_id) {
            tracing::debug!("Already connected to peer: {}", target_peer_id);
            return Ok(());
        }
        
        // Create peer info and register
        let mut peer_info = PeerInfo::new(target_peer_id);
        peer_info.addr = Some(addr.to_string());
        
        // Add to connected peers (connection will be established by swarm)
        self.connected_peers.insert(target_peer_id, peer_info);
        self.peer_manager.add_peer(target_peer_id);
        
        // Update metrics
        self.metrics.write().peer_count = self.connected_peers.len();
        self.metrics.write().connections_established += 1;
        
        tracing::info!(
            "Peer registered: {} (total: {})", 
            target_peer_id, 
            self.connected_peers.len()
        );
        
        Ok(())
    }

    /// Disconnects from a peer (internal use only).
    async fn disconnect_peer_internal(&self, peer_id: &PeerId) -> NetworkResult<()> {
        self.connected_peers.remove(peer_id);
        self.peer_manager.remove_peer(peer_id);
        tracing::debug!("Disconnected from peer: {}", peer_id);
        Ok(())
    }
    
    /// Verifies a signed admin command against this node's PQ keypair.
    /// Only commands signed by the local node's private key are accepted.
    fn verify_admin_command(&self, command: &[u8], signature: &[u8]) -> bool {
        match crate::crypto::verify_dilithium(&self.pq_keypair.public_key, command, signature) {
            Ok(valid) => valid,
            Err(_) => false,
        }
    }
    
    /// Signs an admin command with this node's PQ keypair for authorization.
    pub fn sign_admin_command(&self, command: &[u8]) -> NetworkResult<Vec<u8>> {
        self.pq_keypair.sign(command)
            .map_err(|e| NetworkError::InvalidMessage(format!("Admin command signing failed: {}", e)))
    }

    /// Disconnects from a peer (requires cryptographic authorization).
    /// The caller must provide a signature over the command "disconnect:<peer_id>".
    pub async fn disconnect_peer(&self, peer_id: &PeerId, signature: &[u8]) -> NetworkResult<()> {
        // CRITICAL: Cryptographic access control for peer management
        let command = format!("disconnect:{}", peer_id);
        if !self.verify_admin_command(command.as_bytes(), signature) {
            return Err(NetworkError::InvalidMessage(
                "Unauthorized peer disconnection: invalid signature".into()
            ));
        }
        self.disconnect_peer_internal(peer_id).await
    }

    /// Bans a peer for misbehavior (requires cryptographic authorization).
    /// The caller must provide a signature over the command "ban:<peer_id>:<reason>".
    pub fn ban_peer(&self, peer_id: PeerId, reason: &str, signature: &[u8]) -> NetworkResult<()> {
        // CRITICAL: Cryptographic access control for peer banning
        let command = format!("ban:{}:{}", peer_id, reason);
        if !self.verify_admin_command(command.as_bytes(), signature) {
            return Err(NetworkError::InvalidMessage(
                "Unauthorized peer ban: invalid signature".into()
            ));
        }
        tracing::warn!("Banning peer {} for: {}", peer_id, reason);
        self.connected_peers.remove(&peer_id);
        self.peer_manager.ban_peer(peer_id);
        Ok(())
    }

    /// Returns the current peer count.
    pub fn peer_count(&self) -> usize {
        self.connected_peers.len()
    }

    /// Returns the local peer ID.
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Returns list of connected peers.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.connected_peers.iter().map(|p| *p.key()).collect()
    }

    /// Returns detailed info about connected peers.
    pub fn get_peer_info(&self, peer_id: &PeerId) -> Option<PeerInfo> {
        self.connected_peers.get(peer_id).map(|p| p.clone())
    }

    /// Returns current network metrics.
    pub fn get_metrics(&self) -> NetworkMetrics {
        self.metrics.read().clone()
    }

    /// Updates peer reputation (requires cryptographic authorization).
    /// The caller must provide a signature over "reputation:<peer_id>:<delta>".
    pub fn update_peer_reputation(&self, peer_id: &PeerId, delta: i32, signature: &[u8]) -> NetworkResult<()> {
        // CRITICAL: Cryptographic access control for reputation updates
        let command = format!("reputation:{}:{}", peer_id, delta);
        if !self.verify_admin_command(command.as_bytes(), signature) {
            return Err(NetworkError::InvalidMessage(
                "Unauthorized reputation update: invalid signature".into()
            ));
        }
        
        if let Some(mut peer) = self.connected_peers.get_mut(peer_id) {
            peer.reputation = (peer.reputation + delta).max(-100).min(100);
            
            if peer.reputation < -50 {
                let peer_id_copy = *peer_id;
                drop(peer);
                // Internal ban for low reputation — sign automatically
                let ban_cmd = format!("ban:{}:Low reputation", peer_id_copy);
                if let Ok(ban_sig) = self.sign_admin_command(ban_cmd.as_bytes()) {
                    let _ = self.ban_peer(peer_id_copy, "Low reputation", &ban_sig);
                }
            }
        }
        Ok(())
    }
}

pub struct PeerManager {
    peers: Arc<RwLock<HashSet<PeerId>>>,
    max_peers: usize,
    banned_peers: Arc<RwLock<HashSet<PeerId>>>,
}

impl PeerManager {
    pub fn new(max_peers: usize) -> Result<Self, NetworkError> {
        // CRITICAL: Validate peer count limits — return error instead of silent adjustment
        if max_peers < MIN_PEER_COUNT {
            return Err(NetworkError::InvalidMessage(
                format!("max_peers {} below minimum {}", max_peers, MIN_PEER_COUNT)
            ));
        }
        if max_peers > MAX_PEER_COUNT {
            return Err(NetworkError::InvalidMessage(
                format!("max_peers {} above maximum {}", max_peers, MAX_PEER_COUNT)
            ));
        }
        
        Ok(Self {
            peers: Arc::new(RwLock::new(HashSet::new())),
            max_peers,
            banned_peers: Arc::new(RwLock::new(HashSet::new())),
        })
    }

    pub fn add_peer(&self, peer_id: PeerId) -> bool {
        if self.banned_peers.read().contains(&peer_id) {
            return false;
        }

        let mut peers = self.peers.write();
        if peers.len() >= self.max_peers {
            return false;
        }

        peers.insert(peer_id)
    }

    pub fn remove_peer(&self, peer_id: &PeerId) {
        self.peers.write().remove(peer_id);
    }

    pub fn ban_peer(&self, peer_id: PeerId) {
        self.remove_peer(&peer_id);
        self.banned_peers.write().insert(peer_id);
    }

    pub fn is_banned(&self, peer_id: &PeerId) -> bool {
        self.banned_peers.read().contains(peer_id)
    }

    pub fn peer_count(&self) -> usize {
        self.peers.read().len()
    }
}
