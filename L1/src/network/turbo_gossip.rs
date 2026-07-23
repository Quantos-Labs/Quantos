// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Turbo Gossip Protocol
//!
//! Optimized gossip protocol with message prioritization, adaptive fanout,
//! and intelligent peer selection for maximum propagation efficiency.
//!
//! ## Features
//!
//! - **Priority Queues**: Consensus > Votes > Vertices > Transactions
//! - **Adaptive Fanout**: Adjusts based on network conditions
//! - **Lazy Push/Pull**: Reduces redundant message transmission
//! - **Bloom Filters**: Efficient duplicate detection
//! - **Proximity-Aware Routing**: Prefers low-latency peers

use std::collections::{BinaryHeap, HashMap};
use std::time::{Duration, Instant};
use parking_lot::{Mutex, RwLock};
use std::cmp::Ordering;

/// Message priority levels (higher = more urgent)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessagePriority {
    /// Highest: Finality checkpoints, view changes
    Critical = 4,
    /// High: Consensus votes, committee messages
    High = 3,
    /// Medium: DAG vertices, block proposals
    Medium = 2,
    /// Low: Regular transactions
    Low = 1,
    /// Lowest: Sync requests, peer discovery
    Background = 0,
}

impl MessagePriority {
    /// Returns the maximum queue delay for this priority
    pub fn max_delay(&self) -> Duration {
        match self {
            MessagePriority::Critical => Duration::from_millis(10),
            MessagePriority::High => Duration::from_millis(50),
            MessagePriority::Medium => Duration::from_millis(100),
            MessagePriority::Low => Duration::from_millis(500),
            MessagePriority::Background => Duration::from_secs(2),
        }
    }
    
    /// Returns the base fanout for this priority
    pub fn base_fanout(&self) -> usize {
        match self {
            MessagePriority::Critical => 12,
            MessagePriority::High => 8,
            MessagePriority::Medium => 6,
            MessagePriority::Low => 4,
            MessagePriority::Background => 2,
        }
    }
}

/// Message type for gossip routing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GossipMessageType {
    Checkpoint,
    ViewChange,
    Vote,
    Vertex,
    Transaction,
    SyncRequest,
    SyncResponse,
    PeerExchange,
}

impl GossipMessageType {
    pub fn priority(&self) -> MessagePriority {
        match self {
            GossipMessageType::Checkpoint => MessagePriority::Critical,
            GossipMessageType::ViewChange => MessagePriority::Critical,
            GossipMessageType::Vote => MessagePriority::High,
            GossipMessageType::Vertex => MessagePriority::Medium,
            GossipMessageType::Transaction => MessagePriority::Low,
            GossipMessageType::SyncRequest => MessagePriority::Background,
            GossipMessageType::SyncResponse => MessagePriority::Background,
            GossipMessageType::PeerExchange => MessagePriority::Background,
        }
    }
}

/// Peer identifier (32-byte public key hash)
pub type PeerId = [u8; 32];

/// Message envelope for gossip
#[derive(Clone)]
pub struct GossipEnvelope {
    /// Unique message ID (hash)
    pub id: [u8; 32],
    /// Message type for routing
    pub msg_type: GossipMessageType,
    /// Serialized message payload
    pub payload: Vec<u8>,
    /// Origin peer (first sender)
    pub origin: PeerId,
    /// Hop count
    pub hops: u8,
    /// Creation timestamp (milliseconds)
    pub timestamp: u64,
    /// TTL in hops
    pub ttl: u8,
}

impl GossipEnvelope {
    pub fn priority(&self) -> MessagePriority {
        self.msg_type.priority()
    }
}

/// Priority queue entry
struct PriorityEntry {
    envelope: GossipEnvelope,
    enqueued_at: Instant,
}

impl PartialEq for PriorityEntry {
    fn eq(&self, other: &Self) -> bool {
        self.envelope.id == other.envelope.id
    }
}

impl Eq for PriorityEntry {}

impl PartialOrd for PriorityEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PriorityEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first, then older messages
        match (self.envelope.priority() as u8).cmp(&(other.envelope.priority() as u8)) {
            Ordering::Equal => other.enqueued_at.cmp(&self.enqueued_at),
            other => other,
        }
    }
}

/// Peer metadata for intelligent gossip routing.
/// For basic peer info, see `p2p::GossipPeerInfo`.
pub struct GossipPeerInfo {
    pub id: PeerId,
    /// Estimated round-trip latency
    pub latency_ms: u32,
    /// Message success rate (0.0 - 1.0)
    pub success_rate: f32,
    /// Bandwidth capacity estimate (bytes/sec)
    pub bandwidth: u32,
    /// Last seen timestamp
    pub last_seen: Instant,
    /// Messages sent to this peer
    pub messages_sent: u64,
    /// Messages received from this peer
    pub messages_received: u64,
    /// Is this peer in our committee?
    pub is_committee_member: bool,
    /// Peer's shard assignments
    pub shards: Vec<u16>,
    /// Reputation-based penalty factor; reduces score and increases backpressure.
    pub penalty_score: f32,
    /// Peer is explicitly whitelisted and bypasses rate backpressure.
    pub is_whitelisted: bool,
    /// Peer is explicitly blacklisted and must be rejected.
    pub is_blacklisted: bool,
    /// Per-peer token bucket for rate limiting (bytes)
    pub token_bucket: Mutex<TokenBucket>,
}

impl Clone for GossipPeerInfo {
    fn clone(&self) -> Self {
        let tb = self.token_bucket.lock();
        Self {
            id: self.id,
            latency_ms: self.latency_ms,
            success_rate: self.success_rate,
            bandwidth: self.bandwidth,
            last_seen: self.last_seen,
            messages_sent: self.messages_sent,
            messages_received: self.messages_received,
            is_committee_member: self.is_committee_member,
            shards: self.shards.clone(),
            penalty_score: self.penalty_score,
            is_whitelisted: self.is_whitelisted,
            is_blacklisted: self.is_blacklisted,
            token_bucket: Mutex::new(TokenBucket {
                capacity: tb.capacity,
                tokens: tb.tokens,
                refill_rate: tb.refill_rate,
                last_refill: tb.last_refill,
            }),
        }
    }
}

impl GossipPeerInfo {
    pub fn new(id: PeerId) -> Self {
        Self {
            id,
            latency_ms: 100,
            success_rate: 1.0,
            bandwidth: 10_000_000, // 10 MB/s default
            last_seen: Instant::now(),
            messages_sent: 0,
            messages_received: 0,
            is_committee_member: false,
            shards: Vec::new(),
            penalty_score: 0.0,
            is_whitelisted: false,
            is_blacklisted: false,
            token_bucket: Mutex::new(TokenBucket::new(10_000_000_f32, 1_000_000_f32)),
        }
    }
    
    /// Calculates peer score for selection (higher = better)
    pub fn score(&self) -> f32 {
        if self.is_blacklisted {
            return 0.0;
        }

        let latency_score = 1.0 / (1.0 + self.latency_ms as f32 / 100.0);
        let success_score = self.success_rate;
        let freshness = 1.0 / (1.0 + self.last_seen.elapsed().as_secs() as f32 / 60.0);
        let committee_bonus = if self.is_committee_member { 1.5 } else { 1.0 };
        let penalty_factor = (1.0 - self.penalty_score).max(0.1);
        
        (latency_score * 0.4 + success_score * 0.4 + freshness * 0.2) * committee_bonus * penalty_factor
    }
    
    /// Updates latency with exponential moving average
    pub fn update_latency(&mut self, new_latency_ms: u32) {
        const ALPHA: f32 = 0.3;
        self.latency_ms = (ALPHA * new_latency_ms as f32 + (1.0 - ALPHA) * self.latency_ms as f32) as u32;
    }

    /// Apply a penalty to this peer for misbehavior or rate pressure.
    pub fn penalize(&mut self, amount: f32) {
        self.penalty_score = (self.penalty_score + amount).min(0.9);
    }

    /// Reward a peer by reducing its penalty.
    pub fn reward(&mut self, amount: f32) {
        self.penalty_score = (self.penalty_score - amount).max(0.0);
    }

    /// Ban the peer from gossip.
    pub fn ban(&mut self) {
        self.is_blacklisted = true;
    }

    /// Unban the peer.
    pub fn unban(&mut self) {
        self.is_blacklisted = false;
    }

    /// Whitelist the peer, bypassing backpressure.
    pub fn whitelist(&mut self) {
        self.is_whitelisted = true;
        self.is_blacklisted = false;
    }

    /// Checks whether this peer can receive a message of size `bytes`.
    pub fn is_allowed(&self, bytes: usize) -> bool {
        if self.is_blacklisted {
            return false;
        }
        if self.is_whitelisted {
            return true;
        }
        let mut bucket = self.token_bucket.lock();
        bucket.can_consume(bytes)
    }

    /// Attempts to consume send tokens for this peer.
    pub fn try_consume(&self, bytes: usize) -> bool {
        if self.is_blacklisted {
            return false;
        }
        if self.is_whitelisted {
            return true;
        }
        let mut bucket = self.token_bucket.lock();
        bucket.try_consume(bytes)
    }
}

/// Simple token bucket for per-peer rate limiting (bytes)
pub struct TokenBucket {
    pub capacity: f32,
    pub tokens: f32,
    pub refill_rate: f32, // tokens per second
    pub last_refill: Instant,
}

impl TokenBucket {
    pub fn new(capacity: f32, refill_rate: f32) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    pub fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed().as_secs_f32();
        if elapsed <= 0.0 {
            return;
        }
        let added = elapsed * self.refill_rate;
        self.tokens = (self.tokens + added).min(self.capacity);
        self.last_refill = Instant::now();
    }

    /// Check if we can consume `bytes` without mutating state.
    pub fn can_consume(&mut self, bytes: usize) -> bool {
        self.refill();
        (self.tokens as f32) >= bytes as f32
    }

    /// Try to consume tokens; returns true if successful.
    pub fn try_consume(&mut self, bytes: usize) -> bool {
        self.refill();
        if self.tokens >= bytes as f32 {
            self.tokens -= bytes as f32;
            true
        } else {
            false
        }
    }
}

/// Bloom filter for efficient duplicate detection
pub struct BloomFilter {
    bits: Vec<u64>,
    num_hashes: usize,
    size_bits: usize,
}

impl BloomFilter {
    pub fn new(expected_items: usize, false_positive_rate: f64) -> Self {
        let size_bits = Self::optimal_size(expected_items, false_positive_rate);
        let num_hashes = Self::optimal_hashes(size_bits, expected_items);
        
        Self {
            bits: vec![0u64; (size_bits + 63) / 64],
            num_hashes,
            size_bits,
        }
    }
    
    fn optimal_size(n: usize, p: f64) -> usize {
        let ln2_sq = std::f64::consts::LN_2 * std::f64::consts::LN_2;
        (-(n as f64 * p.ln()) / ln2_sq).ceil() as usize
    }
    
    fn optimal_hashes(m: usize, n: usize) -> usize {
        ((m as f64 / n as f64) * std::f64::consts::LN_2).ceil() as usize
    }
    
    fn hash(&self, data: &[u8], seed: usize) -> usize {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        seed.hash(&mut hasher);
        (hasher.finish() as usize) % self.size_bits
    }
    
    pub fn insert(&mut self, data: &[u8]) {
        for i in 0..self.num_hashes {
            let idx = self.hash(data, i);
            self.bits[idx / 64] |= 1 << (idx % 64);
        }
    }
    
    pub fn contains(&self, data: &[u8]) -> bool {
        for i in 0..self.num_hashes {
            let idx = self.hash(data, i);
            if self.bits[idx / 64] & (1 << (idx % 64)) == 0 {
                return false;
            }
        }
        true
    }
    
    pub fn clear(&mut self) {
        self.bits.fill(0);
    }
}

/// IHAVE/IWANT protocol for lazy push/pull
#[derive(Clone, Debug)]
pub struct IHaveMessage {
    pub message_ids: Vec<[u8; 32]>,
    pub message_types: Vec<GossipMessageType>,
}

#[derive(Clone, Debug)]
pub struct IWantMessage {
    pub message_ids: Vec<[u8; 32]>,
}

/// Turbo Gossip Router
pub struct TurboGossipRouter {
    /// Local peer ID
    local_id: PeerId,
    /// Priority message queue
    outbound_queue: Mutex<BinaryHeap<PriorityEntry>>,
    /// Known peers
    peers: RwLock<HashMap<PeerId, GossipPeerInfo>>,
    /// Bloom filter for seen messages
    seen_filter: Mutex<BloomFilter>,
    /// Recent message cache for IWANT requests
    message_cache: RwLock<HashMap<[u8; 32], GossipEnvelope>>,
    /// Pending IWANT requests
    pending_wants: Mutex<HashMap<[u8; 32], Instant>>,
    /// Configuration
    config: TurboGossipConfig,
    /// Metrics
    metrics: Mutex<GossipMetrics>,
}

/// Configuration for Turbo Gossip
#[derive(Clone)]
pub struct TurboGossipConfig {
    /// Maximum outbound queue size
    pub max_queue_size: usize,
    /// Bloom filter capacity
    pub bloom_filter_capacity: usize,
    /// Message cache TTL
    pub cache_ttl: Duration,
    /// IHAVE message threshold (send IHAVE instead of full message if > this)
    pub ihave_threshold_bytes: usize,
    /// Maximum peers to gossip to
    pub max_gossip_peers: usize,
    /// Minimum peers for critical messages
    pub min_critical_peers: usize,
    /// Enable lazy push/pull
    pub enable_lazy_push: bool,
}

impl Default for TurboGossipConfig {
    fn default() -> Self {
        Self {
            max_queue_size: 10_000,
            bloom_filter_capacity: 100_000,
            cache_ttl: Duration::from_secs(120),
            ihave_threshold_bytes: 1024,
            max_gossip_peers: 20,
            min_critical_peers: 6,
            enable_lazy_push: true,
        }
    }
}

/// Gossip metrics
#[derive(Default)]
pub struct GossipMetrics {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub duplicates_filtered: u64,
    pub ihave_sent: u64,
    pub iwant_sent: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub avg_propagation_time_ms: f64,
}

/// Result of peer selection
pub struct GossipTargets {
    /// Peers to send full message to (eager push)
    pub eager_peers: Vec<PeerId>,
    /// Peers to send IHAVE to (lazy push)
    pub lazy_peers: Vec<PeerId>,
}

impl TurboGossipRouter {
    pub fn new(local_id: PeerId, config: TurboGossipConfig) -> Self {
        Self {
            local_id,
            outbound_queue: Mutex::new(BinaryHeap::new()),
            peers: RwLock::new(HashMap::new()),
            seen_filter: Mutex::new(BloomFilter::new(config.bloom_filter_capacity, 0.01)),
            message_cache: RwLock::new(HashMap::new()),
            pending_wants: Mutex::new(HashMap::new()),
            config,
            metrics: Mutex::new(GossipMetrics::default()),
        }
    }
    
    /// Adds a peer to the router
    pub fn add_peer(&self, peer: GossipPeerInfo) {
        self.peers.write().insert(peer.id, peer);
    }
    
    /// Removes a peer from the router
    pub fn remove_peer(&self, peer_id: &PeerId) {
        self.peers.write().remove(peer_id);
    }
    
    /// Updates peer latency after a successful message
    pub fn update_peer_latency(&self, peer_id: &PeerId, latency_ms: u32) {
        if let Some(peer) = self.peers.write().get_mut(peer_id) {
            peer.update_latency(latency_ms);
            peer.last_seen = Instant::now();
        }
    }

    /// Penalizes a peer for bad behavior or excessive load
    pub fn penalize_peer(&self, peer_id: &PeerId, amount: f32) {
        if let Some(peer) = self.peers.write().get_mut(peer_id) {
            peer.penalize(amount);
        }
    }

    /// Rewards a peer for good behavior and successful relays
    pub fn reward_peer(&self, peer_id: &PeerId, amount: f32) {
        if let Some(peer) = self.peers.write().get_mut(peer_id) {
            peer.reward(amount);
        }
    }

    /// Bans a peer from gossip entirely
    pub fn ban_peer(&self, peer_id: &PeerId) {
        if let Some(peer) = self.peers.write().get_mut(peer_id) {
            peer.ban();
        }
    }

    /// Unbans a peer so it can participate again
    pub fn unban_peer(&self, peer_id: &PeerId) {
        if let Some(peer) = self.peers.write().get_mut(peer_id) {
            peer.unban();
        }
    }

    /// Whitelists a peer, bypassing normal backpressure limits
    pub fn whitelist_peer(&self, peer_id: &PeerId) {
        if let Some(peer) = self.peers.write().get_mut(peer_id) {
            peer.whitelist();
        }
    }
    
    /// Queues a message for gossip
    pub fn queue_message(&self, envelope: GossipEnvelope) -> bool {
        // Stateless prefilter for large payloads
        if envelope.msg_type == GossipMessageType::Transaction {
            if let Err(_e) = crate::network::prefilter_tx_bytes(&envelope.payload) {
                self.metrics.lock().duplicates_filtered += 1;
                return false;
            }
        }

        // Check if already seen
        {
            let mut filter = self.seen_filter.lock();
            if filter.contains(&envelope.id) {
                self.metrics.lock().duplicates_filtered += 1;
                return false;
            }
            filter.insert(&envelope.id);
        }
        
        // Cache for IWANT requests
        {
            let mut cache = self.message_cache.write();
            cache.insert(envelope.id, envelope.clone());
        }
        
        // Add to priority queue
        {
            let mut queue = self.outbound_queue.lock();
            if queue.len() >= self.config.max_queue_size {
                // Drop lowest priority message
                // Note: BinaryHeap doesn't support this directly, would need custom impl
            }
            queue.push(PriorityEntry {
                envelope,
                enqueued_at: Instant::now(),
            });
        }
        
        true
    }
    
    /// Gets next batch of messages to send
    pub fn get_outbound_batch(&self, max_messages: usize) -> Vec<GossipEnvelope> {
        let mut queue = self.outbound_queue.lock();
        let mut batch = Vec::with_capacity(max_messages);
        
        while batch.len() < max_messages {
            match queue.pop() {
                Some(entry) => {
                    // Check if message hasn't exceeded its max delay
                    let max_delay = entry.envelope.priority().max_delay();
                    if entry.enqueued_at.elapsed() <= max_delay * 2 {
                        batch.push(entry.envelope);
                    }
                }
                None => break,
            }
        }
        
        batch
    }
    
    /// Selects peers for gossiping a message
    pub fn select_gossip_targets(&self, envelope: &GossipEnvelope) -> GossipTargets {
        let peers = self.peers.read();
        let priority = envelope.priority();
        let base_fanout = priority.base_fanout();
        
        // Sort peers by score and apply per-peer backpressure limits.
        let payload_bytes = envelope.payload.len();
        let mut scored_peers: Vec<_> = peers
            .values()
            .filter(|p| p.id != self.local_id && p.id != envelope.origin)
            .filter_map(|p| {
                if p.is_allowed(payload_bytes) {
                    let score = if p.is_whitelisted { f32::INFINITY } else { p.score() };
                    Some((p.id, score))
                } else {
                    None
                }
            })
            .collect();
        
        scored_peers.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));
        
        // Calculate adaptive fanout based on network size
        let network_size = peers.len();
        let adaptive_fanout = if network_size < 10 {
            network_size.saturating_sub(1)
        } else {
            // log(N) + base_fanout
            let log_n = (network_size as f64).log2().ceil() as usize;
            (log_n + base_fanout).min(self.config.max_gossip_peers)
        };
        
        // Ensure minimum peers for critical messages
        let fanout = if priority == MessagePriority::Critical {
            adaptive_fanout.max(self.config.min_critical_peers)
        } else {
            adaptive_fanout
        };
        
        // Split between eager and lazy push
        let eager_count = if self.config.enable_lazy_push && 
                          envelope.payload.len() > self.config.ihave_threshold_bytes {
            fanout / 3 // 1/3 eager, 2/3 lazy for large messages
        } else {
            fanout // All eager for small messages
        };
        
        let eager_peers: Vec<PeerId> = scored_peers
            .iter()
            .take(eager_count)
            .filter_map(|(id, _)| {
                if let Some(peer) = peers.get(id) {
                    if peer.try_consume(payload_bytes) {
                        return Some(*id);
                    }
                }
                None
            })
            .collect();
        
        let ihave_cost = (payload_bytes / 8).max(32);
        let lazy_peers: Vec<PeerId> = scored_peers
            .iter()
            .skip(eager_count)
            .take(fanout - eager_count)
            .filter_map(|(id, _)| {
                if let Some(peer) = peers.get(id) {
                    if peer.try_consume(ihave_cost) {
                        return Some(*id);
                    }
                }
                None
            })
            .collect();
        
        GossipTargets { eager_peers, lazy_peers }
    }
    
    /// Handles incoming IHAVE message
    pub fn handle_ihave(&self, _from: PeerId, ihave: IHaveMessage) -> IWantMessage {
        let filter = self.seen_filter.lock();
        let mut wanted = Vec::new();
        
        for (id, msg_type) in ihave.message_ids.iter().zip(ihave.message_types.iter()) {
            if !filter.contains(id) {
                // Prioritize based on message type
                let priority = msg_type.priority();
                if priority as u8 >= MessagePriority::Medium as u8 {
                    wanted.push(*id);
                }
            }
        }
        
        // Track pending wants
        {
            let mut pending = self.pending_wants.lock();
            for id in &wanted {
                pending.insert(*id, Instant::now());
            }
        }
        
        self.metrics.lock().iwant_sent += wanted.len() as u64;
        
        IWantMessage { message_ids: wanted }
    }
    
    /// Handles incoming IWANT message
    pub fn handle_iwant(&self, iwant: IWantMessage) -> Vec<GossipEnvelope> {
        let cache = self.message_cache.read();
        
        iwant.message_ids
            .iter()
            .filter_map(|id| cache.get(id).cloned())
            .collect()
    }
    
    /// Creates IHAVE message for lazy push
    pub fn create_ihave(&self, envelopes: &[GossipEnvelope]) -> IHaveMessage {
        self.metrics.lock().ihave_sent += envelopes.len() as u64;
        
        IHaveMessage {
            message_ids: envelopes.iter().map(|e| e.id).collect(),
            message_types: envelopes.iter().map(|e| e.msg_type).collect(),
        }
    }
    
    /// Cleans up expired cache entries
    pub fn cleanup(&self) {
        let now = Instant::now();
        
        // Clean message cache
        {
            let mut cache = self.message_cache.write();
            cache.retain(|_, envelope| {
                let age = Duration::from_millis(
                    chrono::Utc::now().timestamp_millis() as u64 - envelope.timestamp
                );
                age < self.config.cache_ttl
            });
        }
        
        // Clean pending wants
        {
            let mut pending = self.pending_wants.lock();
            pending.retain(|_, instant| now.duration_since(*instant) < Duration::from_secs(30));
        }
        
        // Rotate bloom filter periodically (would need two filters for proper rotation)
    }
    
    /// Returns current metrics
    pub fn metrics(&self) -> GossipMetrics {
        let m = self.metrics.lock();
        GossipMetrics {
            messages_sent: m.messages_sent,
            messages_received: m.messages_received,
            duplicates_filtered: m.duplicates_filtered,
            ihave_sent: m.ihave_sent,
            iwant_sent: m.iwant_sent,
            bytes_sent: m.bytes_sent,
            bytes_received: m.bytes_received,
            avg_propagation_time_ms: m.avg_propagation_time_ms,
        }
    }
    
    /// Records a sent message
    pub fn record_sent(&self, bytes: usize) {
        let mut m = self.metrics.lock();
        m.messages_sent += 1;
        m.bytes_sent += bytes as u64;
    }
    
    /// Records a received message
    pub fn record_received(&self, bytes: usize, propagation_time_ms: u64) {
        let mut m = self.metrics.lock();
        m.messages_received += 1;
        m.bytes_received += bytes as u64;
        
        // Update EMA for propagation time
        const ALPHA: f64 = 0.1;
        m.avg_propagation_time_ms = ALPHA * propagation_time_ms as f64 
            + (1.0 - ALPHA) * m.avg_propagation_time_ms;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_priority_ordering() {
        let config = TurboGossipConfig::default();
        let router = TurboGossipRouter::new([0u8; 32], config);
        
        // Queue messages with different priorities
        for (i, msg_type) in [
            GossipMessageType::Transaction,
            GossipMessageType::Vote,
            GossipMessageType::Checkpoint,
            GossipMessageType::Vertex,
        ].iter().enumerate() {
            router.queue_message(GossipEnvelope {
                id: [i as u8; 32],
                msg_type: *msg_type,
                payload: vec![],
                origin: [1u8; 32],
                hops: 0,
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
                ttl: 10,
            });
        }
        
        let batch = router.get_outbound_batch(4);
        
        // Should be ordered: Checkpoint (Critical), Vote (High), Vertex (Medium), Transaction (Low)
        assert_eq!(batch[0].msg_type, GossipMessageType::Checkpoint);
        assert_eq!(batch[1].msg_type, GossipMessageType::Vote);
        assert_eq!(batch[2].msg_type, GossipMessageType::Vertex);
        assert_eq!(batch[3].msg_type, GossipMessageType::Transaction);
    }
    
    #[test]
    fn test_bloom_filter() {
        let mut filter = BloomFilter::new(1000, 0.01);
        
        let data1 = b"message1";
        let data2 = b"message2";
        
        assert!(!filter.contains(data1));
        filter.insert(data1);
        assert!(filter.contains(data1));
        assert!(!filter.contains(data2));
    }
    
    #[test]
    fn test_peer_selection() {
        let config = TurboGossipConfig::default();
        let router = TurboGossipRouter::new([0u8; 32], config);
        
        // Add some peers
        for i in 1..10 {
            let mut peer = GossipPeerInfo::new([i as u8; 32]);
            peer.latency_ms = (100 - i * 10) as u32; // Lower latency = better
            router.add_peer(peer);
        }
        
        let envelope = GossipEnvelope {
            id: [0u8; 32],
            msg_type: GossipMessageType::Vote,
            payload: vec![0u8; 100],
            origin: [99u8; 32],
            hops: 0,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            ttl: 10,
        };
        
        let targets = router.select_gossip_targets(&envelope);
        
        // Should have selected peers based on score
        assert!(!targets.eager_peers.is_empty());
    }
}
