//! Wire protocol types shared by native PQ P2P (TCP).

use std::collections::HashSet;

use crate::network::peer_id::PeerId;

use crate::types::{CommitteeVote, DAGVertex, Hash, ShardId, SignedTransaction};

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
    /// Bootstrap nodes: `/ip4|ip6/.../tcp/PORT/p2p/<PeerId>` with Dilithium-derived [`PeerId`].
    pub bootstrap_nodes: Vec<String>,
    /// Known peer addresses persisted from previous sessions.
    pub known_peer_addresses: Vec<String>,
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
            known_peer_addresses: Vec::new(),
        }
    }
}

/// Information about a connected peer.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub addr: Option<String>,
    pub protocol_version: String,
    pub agent_version: String,
    pub protocols: Vec<String>,
    pub connected_at: u64,
    pub last_seen: u64,
    pub latency_ms: u64,
    pub messages_received: u64,
    pub messages_sent: u64,
    pub reputation: i32,
    pub subscribed_shards: HashSet<ShardId>,
}

impl PeerInfo {
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

/// Blake3 topic digest for PQ gossip routing.
pub type TopicHash = [u8; 32];

#[must_use]
pub fn topic_hash(label: &str) -> TopicHash {
    *blake3::hash(label.as_bytes()).as_bytes()
}

/// Application-level message envelope on PQ gossip (bincode).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum NetworkMessage {
    NewTransaction(SignedTransaction),
    NewVertex(DAGVertex),
    NewVote(CommitteeVote),
    TransactionBatch(Vec<SignedTransaction>),
    SyncRequest(SyncRequest),
    SyncResponse(SyncResponse),
    CheckpointAnnouncement(crate::types::Checkpoint),
    CrossShard(CrossShardNetworkMessage),
    DiscoveryRequest,
    DiscoveryResponse(Vec<String>),
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CrossShardNetworkMessage {
    pub source_shard: ShardId,
    pub dest_shard: ShardId,
    pub payload: Vec<u8>,
    pub hash: Hash,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SyncRequest {
    pub from_slot: u64,
    pub to_slot: u64,
    pub shard_id: Option<u16>,
    pub batch_size: u32,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SyncResponse {
    pub vertices: Vec<DAGVertex>,
    pub checkpoint: Option<crate::types::Checkpoint>,
    pub has_more: bool,
    pub next_slot: u64,
}

#[derive(Clone, Debug, Default)]
pub struct NetworkMetrics {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub compression_savings: u64,
    pub peer_count: usize,
    pub avg_latency_ms: u64,
    pub messages_dropped: u64,
    pub active_subscriptions: usize,
    pub connections_established: u64,
    pub connections_failed: u64,
}

pub mod topics {
    pub const TRANSACTIONS: &str = "/quantos/tx/1.0.0";
    pub const VERTICES: &str = "/quantos/vertex/1.0.0";
    pub const VOTES: &str = "/quantos/vote/1.0.0";
    pub const CHECKPOINTS: &str = "/quantos/checkpoint/1.0.0";
    pub const CROSS_SHARD: &str = "/quantos/xshard/1.0.0";
    pub const DISCOVERY: &str = "/quantos/discovery/1.0.0";
    pub const SYNC: &str = "/quantos/sync/1.0.0";

    pub fn shard_tx(shard_id: u16) -> String {
        format!("/quantos/shard/{}/tx/1.0.0", shard_id)
    }

    pub fn shard_vertex(shard_id: u16) -> String {
        format!("/quantos/shard/{}/vertex/1.0.0", shard_id)
    }

    pub fn committee(committee_id: u16) -> String {
        format!("/quantos/committee/{}/1.0.0", committee_id)
    }
}

#[must_use]
pub fn core_subscription_topics() -> HashSet<TopicHash> {
    [
        topics::TRANSACTIONS,
        topics::VERTICES,
        topics::VOTES,
        topics::CHECKPOINTS,
        topics::CROSS_SHARD,
        topics::DISCOVERY,
        topics::SYNC,
    ]
    .into_iter()
    .map(topic_hash)
    .collect()
}

impl P2PConfig {
    pub fn merge_bootstrap_from_env(&mut self) {
        if let Ok(raw) = std::env::var("QUANTOS_BOOTSTRAP_PEERS") {
            if raw.is_empty() {
                return;
            }
            for part in raw.split(',') {
                let s = part.trim();
                if !s.is_empty() {
                    self.bootstrap_nodes.push(s.to_string());
                }
            }
        }
    }

    /// Load bootstrap nodes from `config/bootnodes.json` for the given network.
    /// Falls back to `QUANTOS_BOOTNODES_PATH` env var for the config file path.
    pub fn merge_bootstrap_from_file(&mut self, network_name: &str) {
        let default_path = std::path::PathBuf::from("config/bootnodes.json");
        let path = std::env::var("QUANTOS_BOOTNODES_PATH")
            .map(|p| std::path::PathBuf::from(p))
            .unwrap_or(default_path);

        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Bootnode file {} not readable: {}", path.display(), e);
                return;
            }
        };

        let parsed: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Failed to parse bootnode file {}: {}", path.display(), e);
                return;
            }
        };

        let Some(networks) = parsed.get("networks") else {
            return;
        };

        let Some(net) = networks.get(network_name) else {
            tracing::warn!("No bootnodes defined for network '{}' in {}", network_name, path.display());
            return;
        };

        let Some(peers) = net.get("peers").and_then(|p| p.as_array()) else {
            return;
        };

        for peer in peers {
            if let Some(addr) = peer.get("addr").and_then(|a| a.as_str()) {
                if !self.bootstrap_nodes.contains(&addr.to_string()) {
                    self.bootstrap_nodes.push(addr.to_string());
                }
            }
        }

        tracing::info!(
            "Loaded {} bootstrap nodes for '{}' from {}",
            self.bootstrap_nodes.len(),
            network_name,
            path.display()
        );
    }

    /// Merge known peer addresses persisted by the peer store.
    pub fn merge_known_peers(&mut self, peers: &[String]) {
        for p in peers {
            if !self.bootstrap_nodes.contains(p) && !self.known_peer_addresses.contains(p) {
                self.known_peer_addresses.push(p.clone());
            }
        }
    }
}
