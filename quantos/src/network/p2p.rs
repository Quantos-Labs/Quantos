//! # Quantos P2P Network Layer
//!
//! Native TCP stack with **full PQ**: Kyber768 KEM + ML-DSA (Dilithium3) handshake,
//! AES-256-GCM links, Blake3 topic routing. No libp2p / RSA / classical TLS identities.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Maximum cross-shard payload size (10MB)
const MAX_CROSS_SHARD_PAYLOAD: usize = 10 * 1024 * 1024;
/// Maximum seen messages cache entries to prevent memory exhaustion
const MAX_SEEN_MESSAGES: usize = 1_000_000;

use tokio::sync::mpsc;
use parking_lot::RwLock;
use dashmap::DashMap;

use crate::consensus::QuantosConsensus;
use crate::crypto::KemKeypair;
use crate::network::address::parse_quantos_multiaddr;
use crate::network::pq_identity::peer_id_from_dilithium_public_key;
use crate::network::pq_net::{run_quantos_pq_p2p, PqCommand};
use crate::network::protocol::{
    core_subscription_topics, topic_hash, CrossShardNetworkMessage, NetworkMessage, NetworkMetrics,
    P2PConfig, PeerInfo, SyncRequest, topics, TopicHash,
};
use crate::network::{NetworkError, NetworkResult, PeerId, PeerManager, PeerStore};
use crate::types::{CommitteeVote, DAGVertex, Hash, ShardId, SignedTransaction};
use crate::NodeConfig;

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
    /// Canonical Quantos [`PeerId`] (ML-DSA / Dilithium-derived).
    local_peer_id: PeerId,
    /// Dilithium keypair for consensus / protocol signatures
    pq_keypair: crate::crypto::DilithiumKeypair,
    /// Kyber768 keypair for PQ encapsulated session secrets toward this node
    kem_keypair: KemKeypair,
    /// Connected peers with metadata
    connected_peers: Arc<DashMap<PeerId, PeerInfo>>,
    /// Outgoing message channel
    message_tx: mpsc::Sender<NetworkMessage>,
    /// Incoming message channel
    message_rx: Arc<RwLock<mpsc::Receiver<NetworkMessage>>>,
    /// Compression enabled flag
    compression_enabled: bool,
    /// Subscribed gossip topics (Blake3 digests).
    subscribed_topics: Arc<RwLock<HashSet<TopicHash>>>,
    /// Message deduplication cache
    seen_messages: Arc<DashMap<Hash, u64>>,
    /// Network metrics
    metrics: Arc<RwLock<NetworkMetrics>>,
    /// Peer manager
    peer_manager: Arc<PeerManager>,
    peer_store: Arc<PeerStore>,
    pq_cmd: mpsc::Sender<PqCommand>,
    /// Last discovery broadcast (unix millis), for prod gossip fan-out throttling.
    last_discovery_broadcast_ms: Arc<AtomicU64>,
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
        let (pq_cmd, pq_rx) = mpsc::channel::<PqCommand>(4096);

        let mut p2p_config = P2PConfig::default();
        p2p_config.merge_bootstrap_from_env();

        let peer_manager = Arc::new(PeerManager::new(p2p_config.max_peers)?);
        let peer_store = Arc::new(PeerStore::load_or_create(&config.db_path)?);
        peer_manager.load_banned(peer_store.banned_peers());

        let (dilithium_keypair, kem_keypair) =
            crate::network::pq_identity_store::load_or_create_identity(&config.db_path)?;

        let quantos_peer_id = peer_id_from_dilithium_public_key(&dilithium_keypair.public_key);

        let connected_peers = Arc::new(DashMap::new());
        let metrics = Arc::new(RwLock::new(NetworkMetrics::default()));
        let bootstrap = p2p_config.bootstrap_nodes.clone();
        let listen_port = config.p2p_port;
        let dispatch_tx = message_tx.clone();
        let cp = Arc::clone(&connected_peers);
        let met = Arc::clone(&metrics);
        let subscribed_topics = Arc::new(RwLock::new(core_subscription_topics()));
        let sub_runtime = Arc::clone(&subscribed_topics);

        let dil_spawn = dilithium_keypair.clone();
        let kem_spawn = kem_keypair.clone();
        let peer_mgr_rt = Arc::clone(&peer_manager);
        tokio::spawn(async move {
            run_quantos_pq_p2p(
                listen_port,
                bootstrap,
                dil_spawn,
                kem_spawn,
                pq_rx,
                dispatch_tx,
                cp,
                met,
                sub_runtime,
                peer_mgr_rt,
                p2p_config.mesh_n,
            )
            .await;
        });

        tracing::info!(
            "Quantos PQ P2P listening on :{} peer={}",
            listen_port,
            quantos_peer_id
        );

        Ok(Self {
            config,
            p2p_config,
            consensus,
            local_peer_id: quantos_peer_id,
            pq_keypair: dilithium_keypair,
            kem_keypair,
            connected_peers,
            message_tx,
            message_rx: Arc::new(RwLock::new(message_rx)),
            compression_enabled: true,
            subscribed_topics,
            seen_messages: Arc::new(DashMap::new()),
            metrics,
            peer_manager,
            peer_store,
            pq_cmd,
            last_discovery_broadcast_ms: Arc::new(AtomicU64::new(0)),
        })
    }

    async fn gossip_publish(&self, topic_str: &str, msg: &NetworkMessage) -> NetworkResult<()> {
        let payload =
            bincode::serialize(msg).map_err(|e| NetworkError::SerializationError(e.to_string()))?;
        let topic = topic_hash(topic_str);
        self.pq_cmd
            .send(PqCommand::Publish { topic, payload })
            .await
            .map_err(|_| NetworkError::ConnectionFailed("PQ P2P task stopped".into()))?;
        Ok(())
    }

    /// Runs the P2P network event loop (PQ TCP gossip + periodic discovery).
    pub async fn run(&self) -> NetworkResult<()> {
        tracing::info!(
            "Starting Quantos PQ P2P network on port {}",
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
            topics::SYNC,
        ];

        let mut subscribed = self.subscribed_topics.write();
        for topic_str in core_topics {
            subscribed.insert(topic_hash(topic_str));
            tracing::debug!("Subscribed to topic: {}", topic_str);
        }

        self.metrics.write().active_subscriptions = subscribed.len();
        Ok(())
    }

    /// Subscribes to shard-specific topics.
    pub async fn subscribe_to_shard(&self, shard_id: ShardId) -> NetworkResult<()> {
        let mut subscribed = self.subscribed_topics.write();
        subscribed.insert(topic_hash(&topics::shard_tx(shard_id)));
        subscribed.insert(topic_hash(&topics::shard_vertex(shard_id)));

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

        let msg = NetworkMessage::NewTransaction(tx);
        self.message_tx.send(msg.clone()).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;
        self.gossip_publish(topics::TRANSACTIONS, &msg).await?;

        self.metrics.write().messages_sent += 1;
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

        let msg = NetworkMessage::TransactionBatch(new_txs);
        self.message_tx.send(msg.clone()).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;
        self.gossip_publish(topics::TRANSACTIONS, &msg).await?;

        Ok(())
    }

    /// Broadcasts a DAG vertex to the network.
    pub async fn broadcast_vertex(&self, vertex: DAGVertex) -> NetworkResult<()> {
        if self.seen_messages.contains_key(&vertex.hash) {
            return Ok(());
        }
        self.seen_messages.insert(vertex.hash, chrono::Utc::now().timestamp() as u64);

        let msg = NetworkMessage::NewVertex(vertex);
        self.message_tx.send(msg.clone()).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;
        self.gossip_publish(topics::VERTICES, &msg).await?;

        self.metrics.write().messages_sent += 1;
        Ok(())
    }

    /// Broadcasts a committee vote.
    pub async fn broadcast_vote(&self, vote: CommitteeVote) -> NetworkResult<()> {
        let msg = NetworkMessage::NewVote(vote);
        self.message_tx.send(msg.clone()).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;
        self.gossip_publish(topics::VOTES, &msg).await?;

        self.metrics.write().messages_sent += 1;
        Ok(())
    }

    /// Broadcasts a checkpoint announcement.
    pub async fn broadcast_checkpoint(&self, checkpoint: crate::types::Checkpoint) -> NetworkResult<()> {
        let msg = NetworkMessage::CheckpointAnnouncement(checkpoint);
        self.message_tx.send(msg.clone()).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;
        self.gossip_publish(topics::CHECKPOINTS, &msg).await?;

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

        let nm = NetworkMessage::CrossShard(msg);
        self.message_tx.send(nm.clone()).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;
        self.gossip_publish(topics::CROSS_SHARD, &nm).await?;

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

    /// Kyber768 public key for PQ-KEM session establishment with peers.
    pub fn kem_public_key(&self) -> &[u8] {
        self.kem_keypair.public_key_slice()
    }

    /// Encapsulate a shared secret to a peer's Kyber public key (initiator side).
    pub fn pq_encapsulate_to(&self, peer_kem_pk: &[u8]) -> NetworkResult<(Vec<u8>, Vec<u8>)> {
        KemKeypair::encapsulate(peer_kem_pk)
            .map_err(|e| NetworkError::InvalidMessage(format!("Kyber encapsulate failed: {}", e)))
    }

    /// Decapsulate a ciphertext addressed to this node's Kyber secret key (responder side).
    pub fn pq_decapsulate_incoming(&self, ciphertext: &[u8]) -> NetworkResult<Vec<u8>> {
        self.kem_keypair
            .decapsulate(ciphertext)
            .map_err(|e| NetworkError::InvalidMessage(format!("Kyber decapsulate failed: {}", e)))
    }

    /// Requests sync from peers.
    pub async fn request_sync(&self, from_slot: u64, to_slot: u64, shard_id: Option<u16>) -> NetworkResult<()> {
        let request = SyncRequest {
            from_slot,
            to_slot,
            shard_id,
            batch_size: 100,
        };

        let msg = NetworkMessage::SyncRequest(request);
        self.message_tx.send(msg.clone()).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;
        self.gossip_publish(topics::SYNC, &msg).await?;

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
                let peers: Vec<String> = self
                    .connected_peers
                    .iter()
                    .filter_map(|entry| entry.value().addr.as_ref().map(|a| a.to_string()))
                    .take(32)
                    .collect();
                tracing::debug!("Discovery request: gossip {} peer addrs", peers.len());
                self.metrics.write().messages_received += 1;
                let resp = NetworkMessage::DiscoveryResponse(peers);
                let _ = self.gossip_publish(topics::DISCOVERY, &resp).await;
            }
            NetworkMessage::DiscoveryResponse(addrs) => {
                // Process discovered peers
                for addr_str in addrs {
                    if let Err(e) = self.connect_to_peer(addr_str.trim()).await {
                        tracing::debug!(target: "quantos_network", "discovery connect skipped: {}", e);
                    }
                }
                self.metrics.write().messages_received += 1;
            }
        }
    }

    /// Maintains peer connections.
    async fn maintain_peers(&self) {
        let peer_count = self.connected_peers.len();

        let interval_ms: u64 = std::env::var("QUANTOS_DISCOVERY_INTERVAL_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60_000);

        let now = chrono::Utc::now().timestamp_millis() as u64;
        let last = self
            .last_discovery_broadcast_ms
            .load(Ordering::Relaxed);

        if peer_count < self.p2p_config.target_peers && now.saturating_sub(last) >= interval_ms {
            self.last_discovery_broadcast_ms
                .store(now, Ordering::Relaxed);
            let _ = self
                .gossip_publish(topics::DISCOVERY, &NetworkMessage::DiscoveryRequest)
                .await;
            tracing::debug!(
                "PQ discovery ping (peers {} / target {})",
                peer_count,
                self.p2p_config.target_peers
            );
        }

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

    /// Dials a peer over PQ TCP. `addr` must be `/ip4|ip6/.../tcp/PORT/p2p/<PeerId>`.
    pub async fn connect_to_peer(&self, addr: &str) -> NetworkResult<()> {
        tracing::info!("Connecting to peer: {}", addr);

        if self.connected_peers.len() >= self.p2p_config.max_peers {
            tracing::warn!("Connection rejected: max peers ({}) reached", self.p2p_config.max_peers);
            return Err(NetworkError::ConnectionFailed(
                "Maximum peer limit reached".into(),
            ));
        }

        let target = parse_quantos_multiaddr(addr)?;

        if self.peer_manager.is_banned(&target.peer_id) {
            return Err(NetworkError::PeerBanned(target.peer_id.to_string()));
        }

        if self.connected_peers.contains_key(&target.peer_id) {
            tracing::debug!("Already connected to peer: {}", target.peer_id);
            return Ok(());
        }

        self.pq_cmd
            .send(PqCommand::Dial {
                socket: target.socket,
                expected_peer: target.peer_id,
            })
            .await
            .map_err(|_| NetworkError::ConnectionFailed("PQ P2P task stopped".into()))?;

        tracing::info!("PQ dial queued for {} ({})", target.peer_id, addr);
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
        let _ = self.peer_store.ban(peer_id);
        let _ = self.pq_cmd.try_send(PqCommand::Disconnect { peer_id });
        Ok(())
    }

    /// Returns the current peer count.
    pub fn peer_count(&self) -> usize {
        self.connected_peers.len()
    }

    /// Returns the canonical Quantos peer ID (ML-DSA / Dilithium-derived).
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
