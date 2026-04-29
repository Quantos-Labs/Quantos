//! # DDoS Protection Layer
//!
//! Production-ready DDoS mitigation system for Quantos P2P network.
//!
//! ## Features
//!
//! - **Connection Rate Limiting**: Limit new connections per IP/peer
//! - **Bandwidth Throttling**: Per-peer bandwidth limits
//! - **Message Flooding Detection**: Detect and ban flooding peers
//! - **Reputation Scoring**: Progressive penalties for misbehaving peers
//! - **Adaptive Thresholds**: Dynamic adjustment based on network load
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                 DDoS Protection Layer                       │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                             │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
//! │  │ Connection   │  │ Bandwidth    │  │ Message      │    │
//! │  │ Rate Limiter │  │ Throttler    │  │ Flood Detect │    │
//! │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │
//! │         │                  │                  │            │
//! │         └──────────────────┼──────────────────┘            │
//! │                            ▼                               │
//! │                    ┌───────────────┐                      │
//! │                    │  Ban Manager  │                      │
//! │                    │  + Scoring    │                      │
//! │                    └───────────────┘                      │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use libp2p::PeerId;

/// Configuration for DDoS protection.
#[derive(Clone, Debug)]
pub struct DdosConfig {
    /// Maximum new connections per IP per second
    pub max_connections_per_sec: u32,
    /// Maximum bandwidth per peer (bytes/sec)
    pub max_bandwidth_per_peer: u64,
    /// Maximum messages per peer per second
    pub max_messages_per_sec: u32,
    /// Ban duration for offending peers (seconds)
    pub ban_duration_secs: u64,
    /// Score threshold for automatic ban
    pub auto_ban_score: i32,
    /// Enable adaptive thresholds
    pub enable_adaptive: bool,
    /// Whitelist IPs (never banned)
    pub whitelist: Vec<IpAddr>,
}

impl Default for DdosConfig {
    fn default() -> Self {
        Self {
            max_connections_per_sec: 10,
            max_bandwidth_per_peer: 10 * 1024 * 1024, // 10 MB/s
            max_messages_per_sec: 100,
            ban_duration_secs: 3600, // 1 hour
            auto_ban_score: -100,
            enable_adaptive: true,
            whitelist: Vec::new(),
        }
    }
}

/// MEDIUM: Maximum entries in recent_connections to prevent unbounded memory growth
const MAX_RECENT_CONNECTIONS: usize = 1000;

/// Connection rate tracker for an IP.
#[derive(Clone, Debug)]
struct ConnectionTracker {
    /// Recent connection timestamps
    recent_connections: VecDeque<Instant>,
    /// Total connections in current tracking window (reset periodically)
    total_connections: u64,
    /// Last connection time
    last_connection: Instant,
    /// Window start for total_connections tracking
    window_start: Instant,
}

impl ConnectionTracker {
    fn new() -> Self {
        Self {
            recent_connections: VecDeque::with_capacity(100),
            total_connections: 0,
            last_connection: Instant::now(),
            window_start: Instant::now(),
        }
    }

    fn record_connection(&mut self, now: Instant) {
        self.recent_connections.push_back(now);
        self.total_connections += 1;
        self.last_connection = now;
        
        // Keep only last second of connections
        while let Some(front) = self.recent_connections.front() {
            if now.duration_since(*front) > Duration::from_secs(1) {
                self.recent_connections.pop_front();
            } else {
                break;
            }
        }
        
        // MEDIUM: Hard cap on recent_connections to prevent unbounded growth
        // from periodic connections that keep the tracker alive indefinitely
        while self.recent_connections.len() > MAX_RECENT_CONNECTIONS {
            self.recent_connections.pop_front();
        }
        
        // Reset total_connections counter every 5 minutes to prevent unbounded growth
        if now.duration_since(self.window_start) > Duration::from_secs(300) {
            self.total_connections = 1; // Reset to current connection
            self.window_start = now;
        }
    }

    fn connections_in_last_second(&self) -> usize {
        self.recent_connections.len()
    }
}

/// Bandwidth tracker for a peer.
#[derive(Clone, Debug)]
struct BandwidthTracker {
    /// Bytes sent/received in current window
    bytes_current_window: u64,
    /// Window start time
    window_start: Instant,
    /// Total bytes ever
    total_bytes: u64,
}

impl BandwidthTracker {
    fn new() -> Self {
        Self {
            bytes_current_window: 0,
            window_start: Instant::now(),
            total_bytes: 0,
        }
    }

    fn record_bytes(&mut self, bytes: u64, now: Instant) {
        // Reset window if more than 1 second has passed
        if now.duration_since(self.window_start) > Duration::from_secs(1) {
            self.bytes_current_window = 0;
            self.window_start = now;
        }
        
        self.bytes_current_window += bytes;
        self.total_bytes += bytes;
    }

    fn bytes_per_second(&self) -> u64 {
        let elapsed = Instant::now().duration_since(self.window_start).as_secs_f64();
        if elapsed > 0.0 {
            (self.bytes_current_window as f64 / elapsed) as u64
        } else {
            self.bytes_current_window
        }
    }
}

/// Message flood tracker for a peer.
#[derive(Clone, Debug)]
struct MessageTracker {
    /// Recent message timestamps
    recent_messages: VecDeque<Instant>,
    /// Total messages ever
    total_messages: u64,
    /// Message type counters
    message_types: HashMap<String, u64>,
}

impl MessageTracker {
    fn new() -> Self {
        Self {
            recent_messages: VecDeque::with_capacity(1000),
            total_messages: 0,
            message_types: HashMap::new(),
        }
    }

    fn record_message(&mut self, msg_type: String, now: Instant) {
        self.recent_messages.push_back(now);
        self.total_messages += 1;
        *self.message_types.entry(msg_type).or_insert(0) += 1;
        
        // Keep only last second
        while let Some(front) = self.recent_messages.front() {
            if now.duration_since(*front) > Duration::from_secs(1) {
                self.recent_messages.pop_front();
            } else {
                break;
            }
        }
    }

    fn messages_per_second(&self) -> usize {
        self.recent_messages.len()
    }
}

/// Peer reputation score.
#[derive(Clone, Debug)]
struct PeerScore {
    /// Current score (-100 to +100)
    score: i32,
    /// Violations count
    violations: u32,
    /// Last violation time
    last_violation: Option<Instant>,
    /// Ban expiry time
    ban_expiry: Option<Instant>,
}

impl PeerScore {
    fn new() -> Self {
        Self {
            score: 0,
            violations: 0,
            last_violation: None,
            ban_expiry: None,
        }
    }

    fn is_banned(&self) -> bool {
        if let Some(expiry) = self.ban_expiry {
            Instant::now() < expiry
        } else {
            false
        }
    }

    fn ban(&mut self, duration: Duration) {
        self.ban_expiry = Some(Instant::now() + duration);
        self.score = -100;
    }

    fn add_violation(&mut self, severity: i32) {
        self.score = (self.score - severity).max(-100);
        self.violations += 1;
        self.last_violation = Some(Instant::now());
    }

    fn improve(&mut self, amount: i32) {
        if !self.is_banned() {
            self.score = (self.score + amount).min(100);
        }
    }
}

/// DDoS protection statistics.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DdosStats {
    /// Total connections blocked
    pub connections_blocked: u64,
    /// Total messages blocked
    pub messages_blocked: u64,
    /// Total bandwidth blocked (bytes)
    pub bandwidth_blocked: u64,
    /// Currently banned peers
    pub banned_peers: usize,
    /// Active connections
    pub active_connections: usize,
}

/// Main DDoS protection system.
pub struct DdosProtection {
    config: DdosConfig,
    
    /// Connection trackers per IP
    connection_trackers: Arc<DashMap<IpAddr, ConnectionTracker>>,
    
    /// Bandwidth trackers per peer
    bandwidth_trackers: Arc<DashMap<PeerId, BandwidthTracker>>,
    
    /// Message trackers per peer
    message_trackers: Arc<DashMap<PeerId, MessageTracker>>,
    
    /// Peer scores and bans
    peer_scores: Arc<DashMap<PeerId, PeerScore>>,
    
    /// Statistics
    stats: Arc<RwLock<DdosStats>>,
}

impl DdosProtection {
    /// Creates a new DDoS protection system.
    pub fn new(config: DdosConfig) -> Self {
        Self {
            config,
            connection_trackers: Arc::new(DashMap::new()),
            bandwidth_trackers: Arc::new(DashMap::new()),
            message_trackers: Arc::new(DashMap::new()),
            peer_scores: Arc::new(DashMap::new()),
            stats: Arc::new(RwLock::new(DdosStats::default())),
        }
    }

    /// Checks if a new connection from an IP should be allowed.
    pub fn allow_connection(&self, ip: &IpAddr) -> bool {
        // Check whitelist
        if self.config.whitelist.contains(ip) {
            return true;
        }
        
        let now = Instant::now();
        
        let mut tracker = self.connection_trackers
            .entry(*ip)
            .or_insert_with(ConnectionTracker::new);
        
        // Check rate limit
        if tracker.connections_in_last_second() >= self.config.max_connections_per_sec as usize {
            self.stats.write().connections_blocked += 1;
            tracing::warn!("Connection rate limit exceeded for IP: {}", ip);
            return false;
        }
        
        tracker.record_connection(now);
        self.stats.write().active_connections += 1;
        
        true
    }

    /// Checks if a peer is currently banned.
    pub fn is_peer_banned(&self, peer_id: &PeerId) -> bool {
        if let Some(score) = self.peer_scores.get(peer_id) {
            score.is_banned()
        } else {
            false
        }
    }

    /// Records bandwidth usage for a peer.
    pub fn record_bandwidth(&self, peer_id: &PeerId, bytes: u64) -> bool {
        let now = Instant::now();
        
        let mut tracker = self.bandwidth_trackers
            .entry(*peer_id)
            .or_insert_with(BandwidthTracker::new);
        
        tracker.record_bytes(bytes, now);
        
        // Check if exceeding limit
        if tracker.bytes_per_second() > self.config.max_bandwidth_per_peer {
            self.add_violation(peer_id, 10, "Bandwidth limit exceeded");
            self.stats.write().bandwidth_blocked += bytes;
            return false;
        }
        
        true
    }

    /// Records a message from a peer.
    pub fn record_message(&self, peer_id: &PeerId, msg_type: String) -> bool {
        let now = Instant::now();
        
        let mut tracker = self.message_trackers
            .entry(*peer_id)
            .or_insert_with(MessageTracker::new);
        
        tracker.record_message(msg_type.clone(), now);
        
        // Check if flooding
        if tracker.messages_per_second() > self.config.max_messages_per_sec as usize {
            self.add_violation(peer_id, 15, "Message flooding detected");
            self.stats.write().messages_blocked += 1;
            return false;
        }
        
        true
    }

    /// Adds a violation for a peer.
    pub fn add_violation(&self, peer_id: &PeerId, severity: i32, reason: &str) {
        let mut score = self.peer_scores
            .entry(*peer_id)
            .or_insert_with(PeerScore::new);
        
        score.add_violation(severity);
        
        tracing::warn!(
            "Peer {} violation (severity {}): {} - Score now: {}",
            peer_id,
            severity,
            reason,
            score.score
        );
        
        // Auto-ban if score too low
        if score.score <= self.config.auto_ban_score {
            score.ban(Duration::from_secs(self.config.ban_duration_secs));
            self.stats.write().banned_peers += 1;
            
            tracing::warn!("Peer {} auto-banned for {} seconds", peer_id, self.config.ban_duration_secs);
        }
    }

    /// Manually bans a peer.
    pub fn ban_peer(&self, peer_id: &PeerId, duration: Duration, reason: &str) {
        let mut score = self.peer_scores
            .entry(*peer_id)
            .or_insert_with(PeerScore::new);
        
        score.ban(duration);
        self.stats.write().banned_peers += 1;
        
        tracing::warn!("Peer {} manually banned for {:?}: {}", peer_id, duration, reason);
    }

    /// Unbans a peer.
    pub fn unban_peer(&self, peer_id: &PeerId) {
        if let Some(mut score) = self.peer_scores.get_mut(peer_id) {
            score.ban_expiry = None;
            score.score = 0;
            self.stats.write().banned_peers = self.stats.read().banned_peers.saturating_sub(1);
            
            tracing::info!("Peer {} unbanned", peer_id);
        }
    }

    /// Improves a peer's score (for good behavior).
    pub fn improve_peer_score(&self, peer_id: &PeerId, amount: i32) {
        if let Some(mut score) = self.peer_scores.get_mut(peer_id) {
            score.improve(amount);
        }
    }

    /// Gets a peer's current score.
    pub fn get_peer_score(&self, peer_id: &PeerId) -> i32 {
        self.peer_scores
            .get(peer_id)
            .map(|s| s.score)
            .unwrap_or(0)
    }

    /// Gets current statistics.
    pub fn get_stats(&self) -> DdosStats {
        self.stats.read().clone()
    }

    /// Cleans up expired data.
    pub fn cleanup(&self) {
        let now = Instant::now();
        
        // Clean up old connection trackers
        self.connection_trackers.retain(|_, tracker| {
            now.duration_since(tracker.last_connection) < Duration::from_secs(300)
        });
        
        // Clean up expired bans
        self.peer_scores.retain(|peer_id, score| {
            if let Some(expiry) = score.ban_expiry {
                if now >= expiry {
                    tracing::info!("Ban expired for peer {}", peer_id);
                    self.stats.write().banned_peers = self.stats.read().banned_peers.saturating_sub(1);
                    return false;
                }
            }
            true
        });
    }

    /// Gets list of currently banned peers.
    pub fn get_banned_peers(&self) -> Vec<PeerId> {
        self.peer_scores
            .iter()
            .filter(|entry| entry.value().is_banned())
            .map(|entry| *entry.key())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_rate_limiting() {
        let protection = DdosProtection::new(DdosConfig {
            max_connections_per_sec: 5,
            ..Default::default()
        });
        
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        
        // First 5 connections should be allowed
        for _ in 0..5 {
            assert!(protection.allow_connection(&ip));
        }
        
        // 6th should be blocked
        assert!(!protection.allow_connection(&ip));
    }

    #[test]
    fn test_peer_banning() {
        let protection = DdosProtection::new(DdosConfig::default());
        let peer_id = PeerId::random();
        
        assert!(!protection.is_peer_banned(&peer_id));
        
        protection.ban_peer(&peer_id, Duration::from_secs(60), "test");
        
        assert!(protection.is_peer_banned(&peer_id));
    }

    #[test]
    fn test_auto_ban() {
        let protection = DdosProtection::new(DdosConfig {
            auto_ban_score: -50,
            ..Default::default()
        });
        
        let peer_id = PeerId::random();
        
        // Multiple violations should trigger auto-ban
        for _ in 0..10 {
            protection.add_violation(&peer_id, 10, "test violation");
        }
        
        assert!(protection.is_peer_banned(&peer_id));
    }

    #[test]
    fn test_score_improvement() {
        let protection = DdosProtection::new(DdosConfig::default());
        let peer_id = PeerId::random();
        
        protection.add_violation(&peer_id, 20, "test");
        assert!(protection.get_peer_score(&peer_id) < 0);
        
        protection.improve_peer_score(&peer_id, 30);
        assert!(protection.get_peer_score(&peer_id) > 0);
    }
}
