//! # Eclipse Attack Prevention
//!
//! Protection against eclipse attacks where an attacker isolates a node
//! by controlling all its peer connections.
//!
//! ## Techniques
//!
//! - **Diverse Peer Selection**: Peers from different ASNs/geolocations
//! - **Anchor Peers**: Maintain trusted long-lived connections
//! - **Peer Rotation**: Regular rotation of non-anchor peers
//! - **Connection Diversity**: Limit connections per subnet/ASN
//! - **Inbound/Outbound Balance**: Maintain healthy ratio
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                Eclipse Attack Prevention                    │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                             │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
//! │  │ Anchor Peers │  │ Geographic   │  │ ASN          │    │
//! │  │ Manager      │  │ Diversity    │  │ Diversity    │    │
//! │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │
//! │         │                  │                  │            │
//! │         └──────────────────┼──────────────────┘            │
//! │                            ▼                               │
//! │                  ┌─────────────────┐                      │
//! │                  │ Connection      │                      │
//! │                  │ Validator       │                      │
//! │                  └─────────────────┘                      │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use libp2p::PeerId;

/// Configuration for eclipse attack prevention.
#[derive(Clone, Debug)]
pub struct EclipseConfig {
    /// Minimum number of anchor peers
    pub min_anchor_peers: usize,
    /// Maximum connections from same ASN
    pub max_peers_per_asn: usize,
    /// Maximum connections from same /24 subnet
    pub max_peers_per_subnet: usize,
    /// Minimum geographic diversity (different regions)
    pub min_geographic_diversity: usize,
    /// Minimum inbound/outbound ratio (0.0 to 1.0)
    pub min_inbound_ratio: f64,
    /// Peer rotation interval (seconds)
    pub rotation_interval_secs: u64,
    /// Enable automatic peer rotation
    pub enable_rotation: bool,
    /// Trusted anchor peer IDs
    pub anchor_peer_ids: Vec<String>,
}

impl Default for EclipseConfig {
    fn default() -> Self {
        Self {
            min_anchor_peers: 3,
            max_peers_per_asn: 10,
            max_peers_per_subnet: 5,
            min_geographic_diversity: 3,
            min_inbound_ratio: 0.3,
            rotation_interval_secs: 3600, // 1 hour
            enable_rotation: true,
            anchor_peer_ids: Vec::new(),
        }
    }
}

/// Peer connection type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionType {
    /// Inbound connection (peer connected to us)
    Inbound,
    /// Outbound connection (we connected to peer)
    Outbound,
    /// Anchor peer (trusted long-lived)
    Anchor,
}

/// Geographic region for diversity tracking.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum GeographicRegion {
    NorthAmerica,
    SouthAmerica,
    Europe,
    Asia,
    Africa,
    Oceania,
    Unknown,
}

impl GeographicRegion {
    /// Determines region from IP address using IANA allocation data.
    /// 
    /// Uses Regional Internet Registry (RIR) allocation blocks:
    /// - ARIN: North America (parts of 3.0.0.0/8, 4.0.0.0/8, etc.)
    /// - RIPE: Europe/Middle East (parts of 2.0.0.0/8, 5.0.0.0/8, etc.)
    /// - APNIC: Asia-Pacific (parts of 1.0.0.0/8, 14.0.0.0/8, etc.)
    /// - LACNIC: Latin America
    /// - AFRINIC: Africa
    /// 
    /// **MEDIUM: Security Warning**: These mappings are hardcoded, incomplete,
    /// and can be gamed by attackers who know the ranges. This is a best-effort
    /// heuristic only. For production deployments, consider integrating an external
    /// GeoIP database (e.g., MaxMind GeoLite2) for accurate geographic detection.
    /// Eclipse attack prevention should NOT rely solely on this function.
    pub fn from_ip(ip: &IpAddr) -> Self {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                let first = octets[0];
                let second = octets[1];
                
                // Use RIR allocation data for accurate region detection
                // Based on IANA IPv4 Address Space Registry
                match first {
                    // APNIC allocations (Asia-Pacific)
                    1 | 14 | 27 | 36 | 39 | 42 | 49 | 58 | 59 | 60 | 61 => Self::Asia,
                    101 | 103 | 106 | 110 | 111 | 112..=126 | 150 | 153 | 163 | 175 | 180 | 182 | 183 | 202 | 203 | 210 | 211 | 218 | 219 | 220 | 221 | 222 | 223 => Self::Asia,
                    
                    // RIPE allocations (Europe, Middle East)
                    2 | 5 | 31 | 37 | 46 | 62 | 77 | 78 | 79 | 80 | 81 | 82 | 83 | 84 | 85 | 86 | 87 | 88 | 89 | 90 | 91 | 92 | 93 | 94 | 95 => Self::Europe,
                    109 | 141 | 145 | 151 | 176 | 178 | 185 | 188 | 193 | 194 | 195 | 212 | 213 | 217 => Self::Europe,
                    
                    // ARIN allocations (North America)
                    3 | 4 | 6 | 7 | 8 | 9 | 11 | 12 | 13 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 26 | 28 | 29 | 30 | 32 | 33 | 34 | 35 | 38 | 40 | 44 | 45 | 47 | 48 | 50 | 52 | 54 | 55 | 56 | 57 | 63 | 64 | 65 | 66 | 67 | 68 | 69 | 70 | 71 | 72 | 73 | 74 | 75 | 76 => Self::NorthAmerica,
                    96 | 97 | 98 | 99 | 100 | 104 | 107 | 108 | 128 | 129 | 130 | 131 | 132 | 134 | 135 | 136 | 137 | 138 | 139 | 140 | 142 | 143 | 144 | 146 | 147 | 148 | 149 | 152 | 155 | 156 | 157 | 158 | 159 | 160 | 161 | 162 | 164 | 165 | 166 | 167 | 168 | 169 | 170 | 172 | 173 | 174 | 184 | 192 | 198 | 199 | 204 | 205 | 206 | 207 | 208 | 209 | 214 | 215 | 216 => Self::NorthAmerica,
                    
                    // LACNIC allocations (Latin America/Caribbean)
                    177 | 179 | 181 | 186 | 187 | 189 | 190 | 191 | 200 | 201 => Self::SouthAmerica,
                    
                    // AFRINIC allocations (Africa)
                    41 | 102 | 105 | 154 | 196 | 197 => Self::Africa,
                    
                    // Australia/Oceania (subset of APNIC)
                    _ if first == 1 && second >= 120 && second <= 127 => Self::Oceania,
                    _ if first == 101 && second <= 127 => Self::Oceania,
                    _ if first == 103 && second <= 63 => Self::Oceania,
                    _ if first == 202 && second <= 63 => Self::Oceania,
                    
                    // Private/Reserved ranges
                    10 | 127 => Self::Unknown,
                    
                    // Multicast and reserved
                    224..=255 => Self::Unknown,
                    
                    _ => Self::Unknown,
                }
            }
            IpAddr::V6(ipv6) => {
                // IPv6 region detection based on allocation prefixes
                let segments = ipv6.segments();
                let first_segment = segments[0];
                
                match first_segment {
                    // 2001::/32 allocations
                    0x2001 => {
                        let second = segments[1];
                        match second >> 8 {
                            0x02 => {
                                // APNIC sub-allocation for Asia
                                if second & 0xFF >= 0x20 { Self::Asia } else { Self::NorthAmerica }
                            }
                            0x03..=0x04 => Self::NorthAmerica, // ARIN
                            0x06..=0x0f => Self::Europe,       // RIPE
                            _ => Self::Unknown,
                        }
                    }
                    // 2400::/12 - APNIC (Asia-Pacific)
                    0x2400..=0x24FF => Self::Asia,
                    // 2600::/12 - ARIN (North America)
                    0x2600..=0x26FF => Self::NorthAmerica,
                    // 2800::/12 - LACNIC (Latin America)
                    0x2800..=0x28FF => Self::SouthAmerica,
                    // 2A00::/12 - RIPE (Europe)
                    0x2A00..=0x2AFF => Self::Europe,
                    // 2C00::/12 - AFRINIC (Africa)
                    0x2C00..=0x2CFF => Self::Africa,
                    _ => Self::Unknown,
                }
            }
        }
    }
}

/// Peer metadata for eclipse prevention.
#[derive(Clone, Debug)]
pub struct PeerMetadata {
    /// Peer ID
    pub peer_id: PeerId,
    /// IP address
    pub ip: IpAddr,
    /// ASN (Autonomous System Number)
    pub asn: u32,
    /// Geographic region
    pub region: GeographicRegion,
    /// Connection type
    pub connection_type: ConnectionType,
    /// Connection establishment time
    pub connected_since: Instant,
    /// Last activity time
    pub last_active: Instant,
    /// Is this an anchor peer?
    pub is_anchor: bool,
}

impl PeerMetadata {
    pub fn new(peer_id: PeerId, ip: IpAddr, connection_type: ConnectionType, is_anchor: bool) -> Self {
        Self {
            peer_id,
            ip,
            asn: Self::detect_asn(&ip),
            region: GeographicRegion::from_ip(&ip),
            connection_type,
            connected_since: Instant::now(),
            last_active: Instant::now(),
            is_anchor,
        }
    }

    /// Detects ASN from IP using known major network allocations.
    /// 
    /// Maps IP ranges to well-known ASNs for major cloud providers,
    /// ISPs, and hosting companies to enable diversity-aware peer selection.
    /// 
    /// **MEDIUM: Security Warning**: Like `from_ip`, these hardcoded ranges are
    /// incomplete and can be gamed. An attacker knowing these ranges could choose
    /// IPs that map to diverse ASNs while actually being on the same network.
    /// For production, consider using an external ASN lookup service (e.g., Team Cymru).
    fn detect_asn(ip: &IpAddr) -> u32 {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                let first = octets[0];
                let second = octets[1];
                let _ip_u32 = u32::from_be_bytes(octets);
                
                // Major cloud provider ASN mappings
                // AWS ranges (AS16509, AS14618)
                if (first == 3 && second <= 127) ||
                   (first == 13 && second >= 32 && second <= 35) ||
                   (first == 15 && second >= 160 && second <= 191) ||
                   (first == 18 && second >= 128) ||
                   (first == 52) || (first == 54) || (first == 99) {
                    return 16509; // Amazon AWS
                }
                
                // Google Cloud (AS15169, AS396982)
                if (first == 8 && second == 8) ||  // 8.8.0.0/16
                   (first == 34 && second >= 64 && second <= 127) ||
                   (first == 35 && second >= 184) ||
                   (first == 104 && second >= 196 && second <= 199) ||
                   (first == 142 && second >= 250 && second <= 251) {
                    return 15169; // Google
                }
                
                // Microsoft Azure (AS8075)
                if (first == 13 && second >= 64 && second <= 107) ||
                   (first == 20 && second >= 33 && second <= 47) ||
                   (first == 20 && second >= 135 && second <= 143) ||
                   (first == 40 && second >= 74 && second <= 125) ||
                   (first == 52 && second >= 96 && second <= 191) ||
                   (first == 104 && second >= 40 && second <= 47) {
                    return 8075; // Microsoft
                }
                
                // Cloudflare (AS13335)
                if (first == 104 && second >= 16 && second <= 31) ||
                   (first == 172 && second >= 64 && second <= 71) ||
                   (first == 173 && second >= 245 && second <= 245) ||
                   (first == 198 && second == 41) {
                    return 13335; // Cloudflare
                }
                
                // DigitalOcean (AS14061)
                if (first == 67 && second >= 205 && second <= 207) ||
                   (first == 68 && second >= 183 && second <= 183) ||
                   (first == 104 && second >= 131 && second <= 131) ||
                   (first == 138 && second >= 68 && second <= 68) ||
                   (first == 159 && second >= 65 && second <= 65) ||
                   (first == 167 && second >= 99 && second <= 99) {
                    return 14061; // DigitalOcean
                }
                
                // OVH (AS16276)
                if (first == 51 && second >= 68 && second <= 91) ||
                   (first == 54 && second >= 36 && second <= 39) ||
                   (first == 91 && second >= 134 && second <= 134) ||
                   (first == 137 && second >= 74 && second <= 74) ||
                   (first == 139 && second >= 99 && second <= 99) ||
                   (first == 151 && second >= 80 && second <= 80) {
                    return 16276; // OVH
                }
                
                // Hetzner (AS24940)
                if (first == 88 && second >= 198 && second <= 199) ||
                   (first == 94 && second >= 130 && second <= 130) ||
                   (first == 116 && second >= 202 && second <= 203) ||
                   (first == 138 && second >= 201 && second <= 201) ||
                   (first == 148 && second >= 251 && second <= 251) ||
                   (first == 167 && second >= 235 && second <= 235) {
                    return 24940; // Hetzner
                }
                
                // Linode/Akamai (AS63949)
                if (first == 45 && second >= 33 && second <= 33) ||
                   (first == 45 && second >= 56 && second <= 56) ||
                   (first == 45 && second >= 79 && second <= 79) ||
                   (first == 66 && second >= 175 && second <= 175) ||
                   (first == 69 && second >= 164 && second <= 164) ||
                   (first == 96 && second >= 126 && second <= 126) ||
                   (first == 172 && second >= 104 && second <= 105) {
                    return 63949; // Linode
                }
                
                // Vultr (AS20473)
                if (first == 45 && second >= 32 && second <= 32) ||
                   (first == 45 && second >= 63 && second <= 63) ||
                   (first == 45 && second >= 76 && second <= 77) ||
                   (first == 64 && second >= 156 && second <= 156) ||
                   (first == 66 && second >= 42 && second <= 42) ||
                   (first == 108 && second >= 61 && second <= 61) {
                    return 20473; // Vultr
                }
                
                // For unknown IPs, generate deterministic ASN from IP prefix
                // This ensures consistent ASN for same /16 block
                let prefix_asn = ((first as u32) << 8) | (second as u32);
                // Map to realistic ASN range (1-65535 for 16-bit ASNs)
                prefix_asn.max(1)
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                let first = segments[0];
                
                // Map major IPv6 allocations to ASNs
                match first {
                    0x2607 if segments[1] == 0xf8b0 => 15169, // Google
                    0x2600..=0x260F => 16509,  // AWS IPv6
                    0x2a01 => 16276,           // OVH
                    0x2a02 => 24940,           // Hetzner
                    0x2a00 | 0x2a03..=0x2a0f => 13335, // Cloudflare
                    _ => {
                        // Generate from first two segments
                        ((first as u32) ^ (segments[1] as u32)).max(1)
                    }
                }
            }
        }
    }

    pub fn subnet(&self) -> String {
        match self.ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                format!("{}.{}.{}", octets[0], octets[1], octets[2])
            }
            IpAddr::V6(_) => "unknown".to_string(),
        }
    }

    pub fn connection_duration(&self) -> Duration {
        self.connected_since.elapsed()
    }

    pub fn update_activity(&mut self) {
        self.last_active = Instant::now();
    }
}

/// Connection diversity statistics.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DiversityStats {
    /// Number of unique ASNs
    pub unique_asns: usize,
    /// Number of unique subnets
    pub unique_subnets: usize,
    /// Number of unique regions
    pub unique_regions: usize,
    /// Inbound connections
    pub inbound_count: usize,
    /// Outbound connections
    pub outbound_count: usize,
    /// Anchor connections
    pub anchor_count: usize,
    /// Inbound/outbound ratio
    pub inbound_ratio: f64,
}

/// Eclipse attack prevention system.
pub struct EclipseProtection {
    config: EclipseConfig,
    
    /// Active peer connections
    peers: Arc<DashMap<PeerId, PeerMetadata>>,
    
    /// ASN connection counts
    asn_counts: Arc<RwLock<HashMap<u32, usize>>>,
    
    /// Subnet connection counts
    subnet_counts: Arc<RwLock<HashMap<String, usize>>>,
    
    /// Region connection counts
    region_counts: Arc<RwLock<HashMap<GeographicRegion, usize>>>,
    
    /// Last rotation timestamp
    last_rotation: Arc<RwLock<Instant>>,
}

impl EclipseProtection {
    /// Creates a new eclipse protection system.
    pub fn new(config: EclipseConfig) -> Self {
        Self {
            config,
            peers: Arc::new(DashMap::new()),
            asn_counts: Arc::new(RwLock::new(HashMap::new())),
            subnet_counts: Arc::new(RwLock::new(HashMap::new())),
            region_counts: Arc::new(RwLock::new(HashMap::new())),
            last_rotation: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Checks if a new connection should be accepted.
    pub fn should_accept_connection(
        &self,
        peer_id: &PeerId,
        ip: &IpAddr,
        connection_type: ConnectionType,
    ) -> Result<(), String> {
        // Always accept anchor peers
        if connection_type == ConnectionType::Anchor {
            return Ok(());
        }

        let metadata = PeerMetadata::new(*peer_id, *ip, connection_type.clone(), false);
        
        // Check ASN diversity
        let asn_counts = self.asn_counts.read();
        if let Some(count) = asn_counts.get(&metadata.asn) {
            if *count >= self.config.max_peers_per_asn {
                return Err(format!("Too many peers from ASN {}", metadata.asn));
            }
        }
        
        // Check subnet diversity
        let subnet = metadata.subnet();
        let subnet_counts = self.subnet_counts.read();
        if let Some(count) = subnet_counts.get(&subnet) {
            if *count >= self.config.max_peers_per_subnet {
                return Err(format!("Too many peers from subnet {}", subnet));
            }
        }
        
        Ok(())
    }

    /// Adds a peer connection.
    pub fn add_peer(&self, metadata: PeerMetadata) {
        let peer_id = metadata.peer_id;
        let asn = metadata.asn;
        let subnet = metadata.subnet();
        let region = metadata.region.clone();
        
        // Update counts
        *self.asn_counts.write().entry(asn).or_insert(0) += 1;
        *self.subnet_counts.write().entry(subnet).or_insert(0) += 1;
        *self.region_counts.write().entry(region).or_insert(0) += 1;
        
        self.peers.insert(peer_id, metadata);
        
        tracing::debug!("Peer {} added to eclipse protection", peer_id);
    }

    /// Removes a peer connection.
    pub fn remove_peer(&self, peer_id: &PeerId) {
        if let Some((_, metadata)) = self.peers.remove(peer_id) {
            let asn = metadata.asn;
            let subnet = metadata.subnet();
            let region = metadata.region;
            
            // Decrement counts
            if let Some(count) = self.asn_counts.write().get_mut(&asn) {
                *count = count.saturating_sub(1);
            }
            
            if let Some(count) = self.subnet_counts.write().get_mut(&subnet) {
                *count = count.saturating_sub(1);
            }
            
            if let Some(count) = self.region_counts.write().get_mut(&region) {
                *count = count.saturating_sub(1);
            }
            
            tracing::debug!("Peer {} removed from eclipse protection", peer_id);
        }
    }

    /// Updates peer activity.
    pub fn update_peer_activity(&self, peer_id: &PeerId) {
        if let Some(mut peer) = self.peers.get_mut(peer_id) {
            peer.update_activity();
        }
    }

    /// Gets current diversity statistics.
    pub fn get_diversity_stats(&self) -> DiversityStats {
        let asn_counts = self.asn_counts.read();
        let subnet_counts = self.subnet_counts.read();
        let region_counts = self.region_counts.read();
        
        let mut inbound_count = 0;
        let mut outbound_count = 0;
        let mut anchor_count = 0;
        
        for peer in self.peers.iter() {
            match peer.connection_type {
                ConnectionType::Inbound => inbound_count += 1,
                ConnectionType::Outbound => outbound_count += 1,
                ConnectionType::Anchor => anchor_count += 1,
            }
        }
        
        let total = inbound_count + outbound_count + anchor_count;
        let inbound_ratio = if total > 0 {
            inbound_count as f64 / total as f64
        } else {
            0.0
        };
        
        DiversityStats {
            unique_asns: asn_counts.len(),
            unique_subnets: subnet_counts.len(),
            unique_regions: region_counts.len(),
            inbound_count,
            outbound_count,
            anchor_count,
            inbound_ratio,
        }
    }

    /// Checks if connection diversity is sufficient.
    pub fn is_diversity_sufficient(&self) -> bool {
        let stats = self.get_diversity_stats();
        
        // Check minimum anchor peers
        if stats.anchor_count < self.config.min_anchor_peers {
            tracing::warn!("Insufficient anchor peers: {} < {}", 
                stats.anchor_count, self.config.min_anchor_peers);
            return false;
        }
        
        // Check geographic diversity
        if stats.unique_regions < self.config.min_geographic_diversity {
            tracing::warn!("Insufficient geographic diversity: {} < {}", 
                stats.unique_regions, self.config.min_geographic_diversity);
            return false;
        }
        
        // Check inbound/outbound ratio
        if stats.inbound_ratio < self.config.min_inbound_ratio {
            tracing::warn!("Insufficient inbound ratio: {:.2} < {:.2}", 
                stats.inbound_ratio, self.config.min_inbound_ratio);
            return false;
        }
        
        true
    }

    /// Selects peers for rotation (excludes anchors).
    pub fn select_peers_for_rotation(&self) -> Vec<PeerId> {
        if !self.config.enable_rotation {
            return Vec::new();
        }
        
        let rotation_age = Duration::from_secs(self.config.rotation_interval_secs);
        
        self.peers
            .iter()
            .filter(|entry| {
                let peer = entry.value();
                !peer.is_anchor 
                    && peer.connection_type == ConnectionType::Outbound
                    && peer.connection_duration() > rotation_age
            })
            .map(|entry| *entry.key())
            .collect()
    }

    /// Performs peer rotation if needed.
    pub fn rotate_peers_if_needed(&self) -> Vec<PeerId> {
        let mut last_rotation = self.last_rotation.write();
        
        if last_rotation.elapsed() < Duration::from_secs(self.config.rotation_interval_secs) {
            return Vec::new();
        }
        
        *last_rotation = Instant::now();
        
        let to_rotate = self.select_peers_for_rotation();
        
        if !to_rotate.is_empty() {
            tracing::info!("Rotating {} non-anchor peers for eclipse prevention", to_rotate.len());
        }
        
        to_rotate
    }

    /// Detects potential eclipse attack.
    pub fn detect_eclipse_attack(&self) -> Option<String> {
        let stats = self.get_diversity_stats();
        
        // Check if too many connections from single ASN
        let asn_counts = self.asn_counts.read();
        let total_peers = stats.inbound_count + stats.outbound_count + stats.anchor_count;
        
        for (asn, count) in asn_counts.iter() {
            let percentage = (*count as f64 / total_peers as f64) * 100.0;
            if percentage > 70.0 {
                return Some(format!(
                    "Potential eclipse: {}% of peers from ASN {}",
                    percentage as u32, asn
                ));
            }
        }
        
        // Check if too few regions
        if stats.unique_regions < 2 && total_peers > 10 {
            return Some(format!(
                "Potential eclipse: Only {} geographic regions represented",
                stats.unique_regions
            ));
        }
        
        // Check if inbound ratio too low (might be isolated)
        if stats.inbound_ratio < 0.1 && total_peers > 5 {
            return Some(format!(
                "Potential eclipse: Very low inbound ratio ({:.1}%)",
                stats.inbound_ratio * 100.0
            ));
        }
        
        None
    }

    /// Gets anchor peer IDs.
    pub fn get_anchor_peers(&self) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|entry| entry.value().is_anchor)
            .map(|entry| *entry.key())
            .collect()
    }

    /// Gets all connected peer IDs.
    pub fn get_all_peers(&self) -> Vec<PeerId> {
        self.peers.iter().map(|entry| *entry.key()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asn_diversity() {
        let protection = EclipseProtection::new(EclipseConfig {
            max_peers_per_asn: 2,
            ..Default::default()
        });
        
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "1.1.2.1".parse().unwrap();
        let ip3: IpAddr = "1.1.3.1".parse().unwrap();
        
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();
        
        // Same ASN (first two octets)
        assert!(protection.should_accept_connection(&peer1, &ip1, ConnectionType::Outbound).is_ok());
        protection.add_peer(PeerMetadata::new(peer1, ip1, ConnectionType::Outbound, false));
        
        assert!(protection.should_accept_connection(&peer2, &ip2, ConnectionType::Outbound).is_ok());
        protection.add_peer(PeerMetadata::new(peer2, ip2, ConnectionType::Outbound, false));
        
        // Should reject third peer from same ASN
        assert!(protection.should_accept_connection(&peer3, &ip3, ConnectionType::Outbound).is_err());
    }

    #[test]
    fn test_diversity_stats() {
        let protection = EclipseProtection::new(EclipseConfig::default());
        
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "100.100.1.1".parse().unwrap();
        
        protection.add_peer(PeerMetadata::new(
            PeerId::random(),
            ip1,
            ConnectionType::Outbound,
            false,
        ));
        
        protection.add_peer(PeerMetadata::new(
            PeerId::random(),
            ip2,
            ConnectionType::Inbound,
            false,
        ));
        
        let stats = protection.get_diversity_stats();
        assert_eq!(stats.outbound_count, 1);
        assert_eq!(stats.inbound_count, 1);
        assert!(stats.unique_asns >= 1);
    }

    #[test]
    fn test_anchor_peers() {
        let protection = EclipseProtection::new(EclipseConfig {
            min_anchor_peers: 2,
            ..Default::default()
        });
        
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        
        protection.add_peer(PeerMetadata::new(
            PeerId::random(),
            ip,
            ConnectionType::Anchor,
            true,
        ));
        
        let stats = protection.get_diversity_stats();
        assert_eq!(stats.anchor_count, 1);
        
        // Should not be sufficient yet
        assert!(!protection.is_diversity_sufficient());
    }

    #[test]
    fn test_eclipse_detection() {
        let protection = EclipseProtection::new(EclipseConfig::default());
        
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        
        // Add many peers from same ASN
        for _ in 0..15 {
            protection.add_peer(PeerMetadata::new(
                PeerId::random(),
                ip,
                ConnectionType::Outbound,
                false,
            ));
        }
        
        let alert = protection.detect_eclipse_attack();
        assert!(alert.is_some());
    }

    #[test]
    fn test_peer_rotation() {
        let protection = EclipseProtection::new(EclipseConfig {
            rotation_interval_secs: 0, // Immediate rotation for testing
            enable_rotation: true,
            ..Default::default()
        });
        
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        let peer_id = PeerId::random();
        
        protection.add_peer(PeerMetadata::new(
            peer_id,
            ip,
            ConnectionType::Outbound,
            false,
        ));
        
        let to_rotate = protection.rotate_peers_if_needed();
        assert!(to_rotate.contains(&peer_id));
    }
}
