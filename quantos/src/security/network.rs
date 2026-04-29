//! # Network Attack Protection
//!
//! Protection against network-level attacks including Eclipse, MITM, Sybil, and DoS.
//!
//! ## Eclipse Attack Protection
//!
//! Eclipse attacks isolate a node by controlling all its connections.
//! Mitigations:
//! - Minimum peer diversity (different ASNs, geographic regions)
//! - Outbound connection priority
//! - Peer reputation scoring
//! - Random peer selection from large pool
//!
//! ## MITM Protection
//!
//! Man-in-the-Middle attacks intercept communications.
//! Mitigations:
//! - Noise protocol for encrypted channels
//! - Mutual authentication with PQ signatures
//! - Certificate pinning for known validators
//! - Message authentication codes
//!
//! ## Sybil Attack Protection
//!
//! Sybil attacks create many fake identities.
//! Mitigations:
//! - Stake requirements for validators
//! - Proof of identity for peer connections
//! - Rate limiting per IP/subnet
//! - Resource commitments (PoW for connection)
//!
//! ## DoS/DDoS Protection
//!
//! Denial of service attacks overwhelm resources.
//! Mitigations:
//! - Adaptive rate limiting
//! - Request prioritization
//! - Proof of work for expensive operations
//! - Connection limits per IP

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;
use rand::RngCore;
use rand::rngs::OsRng;

use super::{SecurityError, SecurityResult};

/// Minimum number of violations before auto-ban is triggered
const AUTO_BAN_VIOLATION_THRESHOLD: u32 = 3;

/// Network security configuration.
#[derive(Clone, Debug)]
pub struct NetworkSecurityConfig {
    /// Minimum number of outbound peers
    pub min_outbound_peers: usize,
    /// Maximum peers per IP
    pub max_peers_per_ip: usize,
    /// Maximum peers per /24 subnet
    pub max_peers_per_subnet: usize,
    /// Minimum ASN diversity (unique ASNs)
    pub min_asn_diversity: usize,
    /// Peer ban duration
    pub ban_duration: Duration,
    /// Rate limit window
    pub rate_limit_window: Duration,
    /// Maximum requests per window
    pub max_requests_per_window: u64,
    /// Maximum message size
    pub max_message_size: usize,
    /// Enable IP reputation tracking
    pub ip_reputation_enabled: bool,
    /// Minimum reputation to connect
    pub min_reputation_score: i32,
}

impl Default for NetworkSecurityConfig {
    fn default() -> Self {
        Self {
            min_outbound_peers: 8,
            max_peers_per_ip: 2,
            max_peers_per_subnet: 10,
            min_asn_diversity: 5,
            ban_duration: Duration::from_secs(3600),
            rate_limit_window: Duration::from_secs(60),
            max_requests_per_window: 1000,
            max_message_size: 10 * 1024 * 1024, // 10 MB
            ip_reputation_enabled: true,
            min_reputation_score: -10,
        }
    }
}

/// Peer reputation and tracking.
#[derive(Clone, Debug)]
pub struct PeerReputation {
    /// Peer identifier
    pub peer_id: String,
    /// IP address
    pub ip: IpAddr,
    /// Reputation score (-100 to 100)
    pub score: i32,
    /// Total messages received
    pub messages_received: u64,
    /// Invalid messages received
    pub invalid_messages: u64,
    /// First seen timestamp
    pub first_seen: Instant,
    /// Last seen timestamp
    pub last_seen: Instant,
    /// Is currently banned
    pub banned: bool,
    /// Ban expiry
    pub ban_expires: Option<Instant>,
    /// ASN (Autonomous System Number)
    pub asn: Option<u32>,
    /// Geographic region
    pub region: Option<String>,
}

impl PeerReputation {
    /// Creates a new peer reputation entry.
    pub fn new(peer_id: String, ip: IpAddr) -> Self {
        Self {
            peer_id,
            ip,
            score: 50, // Start neutral-positive
            messages_received: 0,
            invalid_messages: 0,
            first_seen: Instant::now(),
            last_seen: Instant::now(),
            banned: false,
            ban_expires: None,
            asn: None,
            region: None,
        }
    }

    /// Updates reputation score.
    pub fn update_score(&mut self, delta: i32) {
        self.score = (self.score + delta).clamp(-100, 100);
    }

    /// Checks if peer is banned.
    pub fn is_banned(&self) -> bool {
        if !self.banned {
            return false;
        }
        if let Some(expires) = self.ban_expires {
            if Instant::now() > expires {
                return false;
            }
        }
        true
    }
}

/// Rate limiter for DoS protection.
pub struct RateLimiter {
    config: NetworkSecurityConfig,
    /// Request counts per IP
    request_counts: Arc<DashMap<IpAddr, RequestCounter>>,
    /// Global request count
    global_counter: Arc<RwLock<RequestCounter>>,
}

/// Request counter with sliding window.
#[derive(Clone, Debug)]
pub struct RequestCounter {
    pub counts: VecDeque<(Instant, u64)>,
    pub total_in_window: u64,
}

impl RequestCounter {
    pub fn new() -> Self {
        Self {
            counts: VecDeque::new(),
            total_in_window: 0,
        }
    }

    /// Records a request and returns if it should be allowed.
    pub fn record(&mut self, window: Duration, max_requests: u64) -> bool {
        let now = Instant::now();
        let cutoff = now - window;

        // Remove old entries
        while let Some((time, count)) = self.counts.front() {
            if *time < cutoff {
                self.total_in_window = self.total_in_window.saturating_sub(*count);
                self.counts.pop_front();
            } else {
                break;
            }
        }

        // Check if over limit
        if self.total_in_window >= max_requests {
            return false;
        }

        // Add new request
        if let Some((time, count)) = self.counts.back_mut() {
            if now.duration_since(*time) < Duration::from_millis(100) {
                *count += 1;
                self.total_in_window += 1;
                return true;
            }
        }

        self.counts.push_back((now, 1));
        self.total_in_window += 1;
        true
    }
}

impl RateLimiter {
    /// Creates a new rate limiter.
    pub fn new(config: NetworkSecurityConfig) -> Self {
        Self {
            config,
            request_counts: Arc::new(DashMap::new()),
            global_counter: Arc::new(RwLock::new(RequestCounter::new())),
        }
    }

    /// Checks if a request should be allowed.
    pub fn allow_request(&self, ip: IpAddr) -> bool {
        // Check per-IP limit
        let mut counter = self.request_counts
            .entry(ip)
            .or_insert_with(RequestCounter::new);
        
        if !counter.record(self.config.rate_limit_window, self.config.max_requests_per_window) {
            return false;
        }

        // Check global limit (10x per-IP limit)
        let mut global = self.global_counter.write();
        global.record(
            self.config.rate_limit_window,
            self.config.max_requests_per_window * 10,
        )
    }

    /// Gets current request rate for an IP.
    pub fn get_rate(&self, ip: &IpAddr) -> u64 {
        self.request_counts
            .get(ip)
            .map(|c| c.total_in_window)
            .unwrap_or(0)
    }

    /// Cleans up old entries.
    pub fn cleanup(&self) {
        let cutoff = Instant::now() - self.config.rate_limit_window * 2;
        self.request_counts.retain(|_, counter| {
            counter.counts.back()
                .map(|(time, _)| *time > cutoff)
                .unwrap_or(false)
        });
    }
}

/// Eclipse attack detector.
pub struct EclipseDetector {
    config: NetworkSecurityConfig,
    /// Connected peers
    peers: Arc<DashMap<String, PeerReputation>>,
    /// ASN distribution
    asn_counts: Arc<RwLock<HashMap<u32, usize>>>,
    /// Subnet distribution (/24)
    subnet_counts: Arc<DashMap<String, usize>>,
    /// Outbound peer count
    outbound_count: Arc<RwLock<usize>>,
}

impl EclipseDetector {
    /// Creates a new eclipse detector.
    pub fn new(config: NetworkSecurityConfig) -> Self {
        Self {
            config,
            peers: Arc::new(DashMap::new()),
            asn_counts: Arc::new(RwLock::new(HashMap::new())),
            subnet_counts: Arc::new(DashMap::new()),
            outbound_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Registers a peer connection.
    pub fn register_peer(
        &self,
        peer_id: String,
        ip: IpAddr,
        asn: Option<u32>,
        is_outbound: bool,
    ) -> SecurityResult<()> {
        // Check per-IP limit
        let ip_count = self.peers.iter()
            .filter(|p| p.ip == ip)
            .count();
        
        if ip_count >= self.config.max_peers_per_ip {
            return Err(SecurityError::NetworkAttack(
                format!("Too many peers from IP {}", ip)
            ));
        }

        // Check subnet limit
        let subnet = self.get_subnet(&ip);
        let subnet_count = self.subnet_counts.get(&subnet).map(|c| *c).unwrap_or(0);
        
        if subnet_count >= self.config.max_peers_per_subnet {
            return Err(SecurityError::NetworkAttack(
                format!("Too many peers from subnet {}", subnet)
            ));
        }

        // Register peer
        let mut reputation = PeerReputation::new(peer_id.clone(), ip);
        reputation.asn = asn;
        self.peers.insert(peer_id, reputation);

        // Update counters
        *self.subnet_counts.entry(subnet).or_insert(0) += 1;
        
        if let Some(asn) = asn {
            *self.asn_counts.write().entry(asn).or_insert(0) += 1;
        }

        if is_outbound {
            *self.outbound_count.write() += 1;
        }

        Ok(())
    }

    /// Unregisters a peer.
    pub fn unregister_peer(&self, peer_id: &str) {
        if let Some((_, peer)) = self.peers.remove(peer_id) {
            let subnet = self.get_subnet(&peer.ip);
            if let Some(mut count) = self.subnet_counts.get_mut(&subnet) {
                *count = count.saturating_sub(1);
            }
            
            if let Some(asn) = peer.asn {
                if let Some(count) = self.asn_counts.write().get_mut(&asn) {
                    *count = count.saturating_sub(1);
                }
            }
        }
    }

    /// Checks if we might be under eclipse attack.
    pub fn check_eclipse_risk(&self) -> EclipseRiskLevel {
        let outbound = *self.outbound_count.read();
        let asn_diversity = self.asn_counts.read().len();
        let total_peers = self.peers.len();

        // Check outbound count
        if outbound < self.config.min_outbound_peers / 2 {
            return EclipseRiskLevel::Critical;
        }

        // Check ASN diversity
        if total_peers > 10 && asn_diversity < self.config.min_asn_diversity / 2 {
            return EclipseRiskLevel::High;
        }

        if outbound < self.config.min_outbound_peers {
            return EclipseRiskLevel::Elevated;
        }

        if asn_diversity < self.config.min_asn_diversity {
            return EclipseRiskLevel::Elevated;
        }

        EclipseRiskLevel::Low
    }

    /// Gets the /24 subnet for an IP.
    fn get_subnet(&self, ip: &IpAddr) -> String {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
            }
            IpAddr::V6(v6) => {
                // Use /48 for IPv6
                let segments = v6.segments();
                format!("{:x}:{:x}:{:x}::/48", segments[0], segments[1], segments[2])
            }
        }
    }

    /// Gets diversity statistics.
    pub fn get_diversity_stats(&self) -> NetworkDiversityStats {
        NetworkDiversityStats {
            total_peers: self.peers.len(),
            outbound_peers: *self.outbound_count.read(),
            unique_asns: self.asn_counts.read().len(),
            unique_subnets: self.subnet_counts.len(),
        }
    }
}

/// Eclipse risk level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EclipseRiskLevel {
    Low,
    Elevated,
    High,
    Critical,
}

/// Network-layer diversity statistics.
/// For eclipse protection diversity stats, see `eclipse_protection::DiversityStats`.
#[derive(Clone, Debug)]
pub struct NetworkDiversityStats {
    pub total_peers: usize,
    pub outbound_peers: usize,
    pub unique_asns: usize,
    pub unique_subnets: usize,
}

/// MITM protection with mutual authentication.
pub struct MitmProtection {
    /// Known validator certificates/keys
    known_validators: Arc<DashMap<String, ValidatorCert>>,
    /// Session keys
    session_keys: Arc<DashMap<String, SessionKey>>,
    /// Message authentication codes
    active_macs: Arc<DashMap<String, [u8; 32]>>,
}

/// Validator certificate for authentication.
#[derive(Clone, Debug)]
pub struct ValidatorCert {
    pub validator_id: [u8; 32],
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub expires: u64,
}

/// Session key for encrypted communication.
#[derive(Clone)]
pub struct SessionKey {
    pub peer_id: String,
    pub key: [u8; 32],
    pub created: Instant,
    pub expires: Instant,
}

impl MitmProtection {
    /// Creates new MITM protection.
    pub fn new() -> Self {
        Self {
            known_validators: Arc::new(DashMap::new()),
            session_keys: Arc::new(DashMap::new()),
            active_macs: Arc::new(DashMap::new()),
        }
    }

    /// Registers a known validator.
    pub fn register_validator(&self, id: String, cert: ValidatorCert) {
        self.known_validators.insert(id, cert);
    }

    /// Verifies a validator's identity.
    pub fn verify_validator(&self, id: &str, signature: &[u8], message: &[u8]) -> bool {
        if let Some(cert) = self.known_validators.get(id) {
            // Check expiry
            let now = chrono::Utc::now().timestamp() as u64;
            if cert.expires < now {
                tracing::warn!("Validator certificate expired for {}", id);
                return false;
            }
            
            // Verify signature using Dilithium post-quantum signature
            match crate::crypto::verify_dilithium(&cert.public_key, message, signature) {
                Ok(valid) => {
                    if !valid {
                        tracing::warn!("Invalid signature from validator {}", id);
                    }
                    valid
                }
                Err(e) => {
                    tracing::error!("Signature verification error for {}: {}", id, e);
                    false
                }
            }
        } else {
            tracing::debug!("Unknown validator: {}", id);
            false
        }
    }

    /// Creates a session key for a peer.
    pub fn create_session(&self, peer_id: String) -> [u8; 32] {
        let mut key = [0u8; 32];
        // CRITICAL: Use cryptographically secure random number generator
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut key);

        let session = SessionKey {
            peer_id: peer_id.clone(),
            key,
            created: Instant::now(),
            expires: Instant::now() + Duration::from_secs(3600),
        };
        self.session_keys.insert(peer_id, session);
        key
    }

    /// Computes MAC for a message.
    pub fn compute_mac(&self, peer_id: &str, message: &[u8]) -> Option<[u8; 32]> {
        self.session_keys.get(peer_id).map(|session| {
            let mut data = Vec::with_capacity(32 + message.len());
            data.extend_from_slice(&session.key);
            data.extend_from_slice(message);
            crate::types::hash_data(&data)
        })
    }

    /// Verifies MAC for a message.
    pub fn verify_mac(&self, peer_id: &str, message: &[u8], mac: &[u8; 32]) -> bool {
        self.compute_mac(peer_id, message)
            .map(|computed| &computed == mac)
            .unwrap_or(false)
    }
}


/// Combined network security manager.
pub struct NetworkSecurityManager {
    pub config: NetworkSecurityConfig,
    pub rate_limiter: RateLimiter,
    pub eclipse_detector: EclipseDetector,
    pub mitm_protection: MitmProtection,
    /// Banned IPs
    banned_ips: Arc<DashMap<IpAddr, Instant>>,
    /// Banned peers
    banned_peers: Arc<DashMap<String, Instant>>,
    /// Authorization token for privileged operations
    auth_token: Arc<Mutex<Option<[u8; 32]>>>,
}

impl NetworkSecurityManager {
    /// Creates a new network security manager.
    pub fn new(config: NetworkSecurityConfig) -> Self {
        // HIGH: Use OsRng for cryptographically secure authorization token
        // rand::thread_rng() may not guarantee CSPRNG on all platforms
        let mut token = [0u8; 32];
        OsRng.fill_bytes(&mut token);
        
        Self {
            rate_limiter: RateLimiter::new(config.clone()),
            eclipse_detector: EclipseDetector::new(config.clone()),
            mitm_protection: MitmProtection::new(),
            banned_ips: Arc::new(DashMap::new()),
            banned_peers: Arc::new(DashMap::new()),
            config,
            auth_token: Arc::new(Mutex::new(Some(token))),
        }
    }

    /// Checks if a connection should be allowed.
    pub fn allow_connection(&self, ip: IpAddr, peer_id: &str) -> SecurityResult<()> {
        // Check IP ban
        if let Some(expires) = self.banned_ips.get(&ip) {
            if Instant::now() < *expires {
                return Err(SecurityError::PeerBanned(ip.to_string()));
            }
            self.banned_ips.remove(&ip);
        }

        // Check peer ban
        if let Some(expires) = self.banned_peers.get(peer_id) {
            if Instant::now() < *expires {
                return Err(SecurityError::PeerBanned(peer_id.to_string()));
            }
            self.banned_peers.remove(peer_id);
        }

        // Check rate limit
        if !self.rate_limiter.allow_request(ip) {
            return Err(SecurityError::RateLimitExceeded);
        }

        Ok(())
    }

    /// CRITICAL: Access control check for privileged operations
    fn check_authorization(&self, token: &[u8; 32]) -> bool {
        match self.auth_token.lock() {
            Ok(guard) => guard.as_ref().map(|t| t == token).unwrap_or(false),
            Err(_) => false,
        }
    }
    
    /// Gets the authorization token (should be called once at startup)
    pub fn get_auth_token(&self) -> Option<[u8; 32]> {
        match self.auth_token.lock() {
            Ok(guard) => *guard,
            Err(_) => None,
        }
    }

    /// Bans an IP address (requires authorization).
    pub fn ban_ip(&self, ip: IpAddr, duration: Option<Duration>, auth_token: &[u8; 32]) -> Result<(), SecurityError> {
        if !self.check_authorization(auth_token) {
            return Err(SecurityError::Unauthorized);
        }
        
        let duration = duration.unwrap_or(self.config.ban_duration);
        self.banned_ips.insert(ip, Instant::now() + duration);
        tracing::warn!("Banned IP: {} for {:?}", ip, duration);
        Ok(())}

    /// Bans a peer (requires authorization).
    pub fn ban_peer(&self, peer_id: String, duration: Option<Duration>, auth_token: &[u8; 32]) -> Result<(), SecurityError> {
        if !self.check_authorization(auth_token) {
            return Err(SecurityError::Unauthorized);
        }
        
        let duration = duration.unwrap_or(self.config.ban_duration);
        self.banned_peers.insert(peer_id.clone(), Instant::now() + duration);
        self.eclipse_detector.unregister_peer(&peer_id);
        tracing::warn!("Banned peer: {} for {:?}", peer_id, duration);
        Ok(())
    }

    /// Reports a security violation.
    /// 
    /// HIGH: Auto-ban now requires both low reputation AND repeated violations
    /// to prevent an attacker from banning legitimate peers via crafted reports.
    pub fn report_violation(&self, ip: IpAddr, peer_id: &str, violation: &str) {
        tracing::warn!(
            "Security violation from {} ({}): {}",
            peer_id, ip, violation
        );

        // Update peer reputation
        if let Some(mut peer) = self.eclipse_detector.peers.get_mut(peer_id) {
            peer.invalid_messages = peer.invalid_messages.saturating_add(1);
            peer.update_score(-20);
            
            // HIGH: Require both low reputation AND multiple violations before auto-ban
            // This prevents a single crafted violation from banning a legitimate peer
            let violation_count = peer.invalid_messages;
            let score = peer.score;
            if score < self.config.min_reputation_score 
                && violation_count >= AUTO_BAN_VIOLATION_THRESHOLD as u64 
            {
                drop(peer);
                let duration = self.config.ban_duration;
                self.banned_peers.insert(peer_id.to_string(), Instant::now() + duration);
                self.banned_ips.insert(ip, Instant::now() + duration);
                self.eclipse_detector.unregister_peer(peer_id);
                tracing::warn!(
                    "Auto-banned peer {} (IP {}) for {:?} after {} violations (score: {})",
                    peer_id, ip, duration, violation_count, score
                );
            }
        }
    }

    /// Gets security status.
    pub fn get_status(&self) -> NetworkSecurityStatus {
        NetworkSecurityStatus {
            eclipse_risk: self.eclipse_detector.check_eclipse_risk(),
            diversity: self.eclipse_detector.get_diversity_stats(),
            banned_ips: self.banned_ips.len(),
            banned_peers: self.banned_peers.len(),
        }
    }
}

/// Network security status.
#[derive(Clone, Debug)]
pub struct NetworkSecurityStatus {
    pub eclipse_risk: EclipseRiskLevel,
    pub diversity: NetworkDiversityStats,
    pub banned_ips: usize,
    pub banned_peers: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_rate_limiter() {
        let config = NetworkSecurityConfig {
            max_requests_per_window: 10,
            rate_limit_window: Duration::from_secs(1),
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Should allow first 10 requests
        for _ in 0..10 {
            assert!(limiter.allow_request(ip));
        }

        // Should deny 11th request
        assert!(!limiter.allow_request(ip));
    }

    #[test]
    fn test_eclipse_detector() {
        let config = NetworkSecurityConfig::default();
        let detector = EclipseDetector::new(config);

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(detector.register_peer("peer1".into(), ip, Some(12345), true).is_ok());

        let stats = detector.get_diversity_stats();
        assert_eq!(stats.total_peers, 1);
        assert_eq!(stats.outbound_peers, 1);
    }

    #[test]
    fn test_pow_leading_zeros() {
        // Inline leading zero count (ConnectionPoW was removed)
        fn count_leading_zeros(hash: &[u8; 32]) -> u32 {
            let mut count = 0u32;
            for &byte in hash.iter() {
                if byte == 0 {
                    count += 8;
                } else {
                    count += byte.leading_zeros();
                    break;
                }
            }
            count
        }

        let hash = [0u8; 32];
        assert_eq!(count_leading_zeros(&hash), 256);

        let mut hash2 = [0u8; 32];
        hash2[0] = 0x0F;
        assert_eq!(count_leading_zeros(&hash2), 4);
    }
}
