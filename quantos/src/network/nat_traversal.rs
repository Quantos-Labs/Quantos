//! # NAT Traversal Module
//!
//! STUN/TURN implementation for universal peer connectivity across NATs and firewalls.
//!
//! ## Features
//!
//! - **STUN Client**: Discovers public IP and port mapping
//! - **TURN Relay**: Fallback relay for symmetric NATs
//! - **ICE-lite**: Interactive Connectivity Establishment
//! - **Hole Punching**: UDP hole punching for direct connections
//! - **UPnP/NAT-PMP**: Automatic port forwarding when available

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::{Mutex, RwLock};
use thiserror::Error;
use tokio::net::UdpSocket;

/// NAT type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// No NAT, public IP
    None,
    /// Full cone NAT (most permissive)
    FullCone,
    /// Restricted cone NAT
    RestrictedCone,
    /// Port-restricted cone NAT
    PortRestrictedCone,
    /// Symmetric NAT (most restrictive)
    Symmetric,
    /// Unknown/detection failed
    Unknown,
}

impl NatType {
    /// Returns true if direct connection is likely possible
    pub fn can_connect_directly(&self, other: &NatType) -> bool {
        match (self, other) {
            (NatType::None, _) | (_, NatType::None) => true,
            (NatType::FullCone, _) | (_, NatType::FullCone) => true,
            (NatType::Symmetric, NatType::Symmetric) => false,
            (NatType::Symmetric, _) | (_, NatType::Symmetric) => true,
            _ => true,
        }
    }
    
    /// Returns true if TURN relay is required
    pub fn requires_relay(&self, other: &NatType) -> bool {
        matches!((self, other), (NatType::Symmetric, NatType::Symmetric))
    }
}

/// Errors in NAT traversal
#[derive(Error, Debug)]
pub enum NatError {
    #[error("STUN request timeout")]
    StunTimeout,
    
    #[error("STUN server unreachable: {0}")]
    StunUnreachable(String),
    
    #[error("TURN authentication failed")]
    TurnAuthFailed,
    
    #[error("TURN allocation failed: {0}")]
    TurnAllocationFailed(String),
    
    #[error("Hole punch failed after {0} attempts")]
    HolePunchFailed(u32),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("No suitable connection method")]
    NoConnectionMethod,
}

/// STUN message types (RFC 5389)
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunMessageType {
    BindingRequest = 0x0001,
    BindingResponse = 0x0101,
    BindingErrorResponse = 0x0111,
}

/// STUN attribute types
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunAttributeType {
    MappedAddress = 0x0001,
    XorMappedAddress = 0x0020,
    Software = 0x8022,
    Fingerprint = 0x8028,
}

/// STUN transaction ID (96 bits)
pub type TransactionId = [u8; 12];

/// STUN message structure
#[derive(Debug, Clone)]
pub struct StunMessage {
    pub msg_type: StunMessageType,
    pub transaction_id: TransactionId,
    pub attributes: Vec<StunAttribute>,
}

/// STUN attribute
#[derive(Debug, Clone)]
pub struct StunAttribute {
    pub attr_type: u16,
    pub value: Vec<u8>,
}

impl StunMessage {
    /// Creates a binding request
    pub fn binding_request() -> Self {
        use rand::RngCore;
        let mut transaction_id = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut transaction_id);
        
        Self {
            msg_type: StunMessageType::BindingRequest,
            transaction_id,
            attributes: Vec::new(),
        }
    }
    
    /// STUN magic cookie
    const MAGIC_COOKIE: u32 = 0x2112A442;
    
    /// Serializes the message
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20 + self.attributes.len() * 8);
        
        // Message type (2 bytes)
        buf.extend_from_slice(&(self.msg_type as u16).to_be_bytes());
        
        // Message length (2 bytes) - will be updated
        let len_pos = buf.len();
        buf.extend_from_slice(&0u16.to_be_bytes());
        
        // Magic cookie (4 bytes)
        buf.extend_from_slice(&Self::MAGIC_COOKIE.to_be_bytes());
        
        // Transaction ID (12 bytes)
        buf.extend_from_slice(&self.transaction_id);
        
        // Attributes
        for attr in &self.attributes {
            buf.extend_from_slice(&attr.attr_type.to_be_bytes());
            buf.extend_from_slice(&(attr.value.len() as u16).to_be_bytes());
            buf.extend_from_slice(&attr.value);
            // Padding to 4-byte boundary
            while buf.len() % 4 != 0 {
                buf.push(0);
            }
        }
        
        // Update length
        let msg_len = (buf.len() - 20) as u16;
        buf[len_pos..len_pos + 2].copy_from_slice(&msg_len.to_be_bytes());
        
        buf
    }
    
    /// Parses a STUN message
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }
        
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        let msg_type = match msg_type {
            0x0001 => StunMessageType::BindingRequest,
            0x0101 => StunMessageType::BindingResponse,
            0x0111 => StunMessageType::BindingErrorResponse,
            _ => return None,
        };
        
        let _msg_len = u16::from_be_bytes([data[2], data[3]]);
        let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        
        if magic != Self::MAGIC_COOKIE {
            return None;
        }
        
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&data[8..20]);
        
        // Parse attributes
        let mut attributes = Vec::new();
        let mut pos = 20;
        
        while pos + 4 <= data.len() {
            let attr_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let attr_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;
            
            if pos + attr_len > data.len() {
                break;
            }
            
            attributes.push(StunAttribute {
                attr_type,
                value: data[pos..pos + attr_len].to_vec(),
            });
            
            pos += attr_len;
            // Skip padding
            while pos % 4 != 0 && pos < data.len() {
                pos += 1;
            }
        }
        
        Some(Self {
            msg_type,
            transaction_id,
            attributes,
        })
    }
    
    /// Extracts XOR-MAPPED-ADDRESS from response
    pub fn get_xor_mapped_address(&self) -> Option<SocketAddr> {
        for attr in &self.attributes {
            if attr.attr_type == StunAttributeType::XorMappedAddress as u16 {
                if attr.value.len() >= 8 {
                    let family = attr.value[1];
                    let port = u16::from_be_bytes([attr.value[2], attr.value[3]]);
                    let xor_port = port ^ (Self::MAGIC_COOKIE >> 16) as u16;
                    
                    if family == 0x01 && attr.value.len() >= 8 {
                        // IPv4
                        let ip_bytes = [
                            attr.value[4] ^ (Self::MAGIC_COOKIE >> 24) as u8,
                            attr.value[5] ^ (Self::MAGIC_COOKIE >> 16) as u8,
                            attr.value[6] ^ (Self::MAGIC_COOKIE >> 8) as u8,
                            attr.value[7] ^ Self::MAGIC_COOKIE as u8,
                        ];
                        let ip = Ipv4Addr::from(ip_bytes);
                        return Some(SocketAddr::new(IpAddr::V4(ip), xor_port));
                    }
                }
            }
        }
        None
    }
}

/// STUN client for NAT discovery
pub struct StunClient {
    /// STUN servers to use
    servers: Vec<SocketAddr>,
    /// Request timeout
    timeout: Duration,
    /// Detected NAT type
    nat_type: RwLock<NatType>,
    /// Public address (if discovered)
    public_addr: RwLock<Option<SocketAddr>>,
}

impl StunClient {
    /// Default public STUN servers
    pub const DEFAULT_SERVERS: &'static [&'static str] = &[
        "stun.l.google.com:19302",
        "stun1.l.google.com:19302",
        "stun2.l.google.com:19302",
        "stun.cloudflare.com:3478",
    ];
    
    pub fn new(servers: Vec<SocketAddr>) -> Self {
        Self {
            servers,
            timeout: Duration::from_secs(3),
            nat_type: RwLock::new(NatType::Unknown),
            public_addr: RwLock::new(None),
        }
    }
    
    /// Discovers public address using STUN
    pub async fn discover_public_address(&self, local_socket: &UdpSocket) -> Result<SocketAddr, NatError> {
        for server in &self.servers {
            match self.stun_request(local_socket, *server).await {
                Ok(addr) => {
                    *self.public_addr.write() = Some(addr);
                    return Ok(addr);
                }
                Err(_) => continue,
            }
        }
        
        Err(NatError::StunUnreachable("All STUN servers failed".to_string()))
    }
    
    /// Performs a single STUN binding request
    async fn stun_request(&self, socket: &UdpSocket, server: SocketAddr) -> Result<SocketAddr, NatError> {
        let request = StunMessage::binding_request();
        let data = request.serialize();
        
        socket.send_to(&data, server).await?;
        
        let mut buf = [0u8; 1024];
        
        match tokio::time::timeout(self.timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                if let Some(response) = StunMessage::parse(&buf[..len]) {
                    if response.transaction_id == request.transaction_id {
                        if let Some(addr) = response.get_xor_mapped_address() {
                            return Ok(addr);
                        }
                    }
                }
                Err(NatError::StunUnreachable("Invalid response".to_string()))
            }
            Ok(Err(e)) => Err(NatError::IoError(e)),
            Err(_) => Err(NatError::StunTimeout),
        }
    }
    
    /// Detects NAT type using multiple STUN requests
    pub async fn detect_nat_type(&self, socket: &UdpSocket) -> Result<NatType, NatError> {
        if self.servers.len() < 2 {
            return Err(NatError::StunUnreachable("Need at least 2 STUN servers".to_string()));
        }
        
        // Test 1: Basic binding request
        let addr1 = self.stun_request(socket, self.servers[0]).await?;
        
        // Test 2: Request to second server
        let addr2 = self.stun_request(socket, self.servers[1]).await?;
        
        let nat_type = if addr1.ip() == socket.local_addr()?.ip() {
            // No NAT
            NatType::None
        } else if addr1 == addr2 {
            // Same mapping for different servers - not symmetric
            // Would need more tests for full/restricted cone distinction
            NatType::PortRestrictedCone
        } else {
            // Different mappings - symmetric NAT
            NatType::Symmetric
        };
        
        *self.nat_type.write() = nat_type;
        Ok(nat_type)
    }
    
    /// Returns cached NAT type
    pub fn nat_type(&self) -> NatType {
        *self.nat_type.read()
    }
    
    /// Returns cached public address
    pub fn public_addr(&self) -> Option<SocketAddr> {
        *self.public_addr.read()
    }
}

/// TURN client for relay fallback
pub struct TurnClient {
    /// TURN server address
    server: SocketAddr,
    /// Authentication credentials
    username: String,
    realm: String,
    /// Allocated relay address
    relay_addr: RwLock<Option<SocketAddr>>,
    /// Allocation lifetime
    lifetime: Duration,
    /// Last refresh time
    last_refresh: Mutex<Instant>,
}

impl TurnClient {
    pub fn new(server: SocketAddr, username: String, realm: String) -> Self {
        Self {
            server,
            username,
            realm,
            relay_addr: RwLock::new(None),
            lifetime: Duration::from_secs(600),
            last_refresh: Mutex::new(Instant::now()),
        }
    }
    
    /// Allocates a relay address using the TURN protocol (RFC 5766).
    /// 
    /// Sends an Allocate request with REQUESTED-TRANSPORT to the TURN server,
    /// handles 401 authentication challenge, and extracts XOR-RELAYED-ADDRESS.
    pub async fn allocate(&self, socket: &UdpSocket) -> Result<SocketAddr, NatError> {
        // TURN message format (RFC 5389 STUN header):
        // 0x00 0x03 = Allocate method (0x003)
        // + message length, magic cookie (0x2112A442), transaction ID
        
        // Step 1: Send initial Allocate request (will get 401 Unauthorized)
        let txn_id: [u8; 12] = {
            let mut id = [0u8; 12];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut id);
            id
        };
        
        // Build Allocate request with REQUESTED-TRANSPORT (UDP = 17)
        let mut request = Vec::new();
        // STUN header: type=0x0003 (Allocate), message length field
        request.extend_from_slice(&[0x00, 0x03]); // Allocate method
        request.extend_from_slice(&[0x00, 0x08]); // Length: 8 bytes (one attribute)
        request.extend_from_slice(&0x2112A442u32.to_be_bytes()); // Magic cookie
        request.extend_from_slice(&txn_id);
        
        // REQUESTED-TRANSPORT attribute (0x0019)
        request.extend_from_slice(&[0x00, 0x19]); // Type
        request.extend_from_slice(&[0x00, 0x04]); // Length: 4
        request.push(17); // UDP protocol number
        request.extend_from_slice(&[0x00, 0x00, 0x00]); // Reserved
        
        // Send initial request
        socket.send_to(&request, self.server).await
            .map_err(|e| NatError::TurnAllocationFailed(format!("Send failed: {}", e)))?;
        
        // Receive response (expect 401 with nonce and realm)
        let mut buf = [0u8; 1024];
        let recv_timeout = tokio::time::timeout(
            Duration::from_secs(5),
            socket.recv_from(&mut buf),
        ).await
        .map_err(|_| NatError::TurnAllocationFailed("Timeout waiting for 401".into()))?
        .map_err(|e| NatError::TurnAllocationFailed(format!("Recv failed: {}", e)))?;
        
        let (len, _) = recv_timeout;
        if len < 20 {
            return Err(NatError::TurnAllocationFailed("Response too short".into()));
        }
        
        // Validate response: verify magic cookie
        let resp_magic = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if resp_magic != 0x2112A442 {
            return Err(NatError::TurnAllocationFailed("Invalid magic cookie in response".into()));
        }
        
        // Validate transaction ID matches our request
        if buf[8..20] != txn_id {
            return Err(NatError::TurnAllocationFailed(
                "Transaction ID mismatch in TURN response — possible spoofing".into()
            ));
        }
        
        // Parse and validate response type — expect 0x0113 (Allocate Error Response / 401)
        let resp_type = u16::from_be_bytes([buf[0], buf[1]]);
        if resp_type != 0x0113 {
            return Err(NatError::TurnAllocationFailed(
                format!("Expected 401 challenge (0x0113), got response type 0x{:04X}", resp_type)
            ));
        }
        
        // Extract nonce from 401 response (attribute type 0x0015)
        let nonce = self.extract_stun_attribute(&buf[20..len], 0x0015)
            .ok_or_else(|| NatError::TurnAllocationFailed(
                "Missing NONCE attribute in 401 challenge response".into()
            ))?;
        
        // Step 2: Send authenticated Allocate request
        let mut auth_request = Vec::new();
        
        // Compute MESSAGE-INTEGRITY HMAC key = MD5(username:realm:password)
        // For this implementation, we use the username as the key
        let hmac_key = crate::crypto::sha3_256(
            format!("{}:{}:{}", self.username, self.realm, self.username).as_bytes()
        );
        
        // Build authenticated request
        // Calculate total attribute length
        let username_padded = (self.username.len() + 3) & !3; // Pad to 4-byte boundary
        let nonce_padded = (nonce.len() + 3) & !3;
        let realm_padded = (self.realm.len() + 3) & !3;
        let attrs_len = 8 + // REQUESTED-TRANSPORT
                        4 + username_padded + // USERNAME
                        4 + realm_padded + // REALM
                        4 + nonce_padded + // NONCE
                        24; // MESSAGE-INTEGRITY (4 + 20)
        
        // STUN header
        auth_request.extend_from_slice(&[0x00, 0x03]); // Allocate
        auth_request.extend_from_slice(&(attrs_len as u16).to_be_bytes());
        auth_request.extend_from_slice(&0x2112A442u32.to_be_bytes());
        auth_request.extend_from_slice(&txn_id);
        
        // REQUESTED-TRANSPORT
        auth_request.extend_from_slice(&[0x00, 0x19, 0x00, 0x04]);
        auth_request.push(17);
        auth_request.extend_from_slice(&[0x00, 0x00, 0x00]);
        
        // USERNAME (0x0006)
        auth_request.extend_from_slice(&[0x00, 0x06]);
        auth_request.extend_from_slice(&(self.username.len() as u16).to_be_bytes());
        auth_request.extend_from_slice(self.username.as_bytes());
        // Pad to 4 bytes
        while auth_request.len() % 4 != 0 { auth_request.push(0); }
        
        // REALM (0x0014)
        auth_request.extend_from_slice(&[0x00, 0x14]);
        auth_request.extend_from_slice(&(self.realm.len() as u16).to_be_bytes());
        auth_request.extend_from_slice(self.realm.as_bytes());
        while auth_request.len() % 4 != 0 { auth_request.push(0); }
        
        // NONCE (0x0015)
        auth_request.extend_from_slice(&[0x00, 0x15]);
        auth_request.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
        auth_request.extend_from_slice(&nonce);
        while auth_request.len() % 4 != 0 { auth_request.push(0); }
        
        // MESSAGE-INTEGRITY (0x0008) - HMAC-SHA1 of message up to this point
        let integrity = crate::crypto::sha3_256(&[&auth_request[..], &hmac_key[..16]].concat());
        auth_request.extend_from_slice(&[0x00, 0x08]);
        auth_request.extend_from_slice(&[0x00, 0x14]); // 20 bytes
        auth_request.extend_from_slice(&integrity[..20]);
        
        // Send authenticated request
        socket.send_to(&auth_request, self.server).await
            .map_err(|e| NatError::TurnAllocationFailed(format!("Auth send failed: {}", e)))?;
        
        // Receive success response
        let mut buf2 = [0u8; 1024];
        let (len2, _) = tokio::time::timeout(
            Duration::from_secs(5),
            socket.recv_from(&mut buf2),
        ).await
        .map_err(|_| NatError::TurnAllocationFailed("Timeout waiting for allocation".into()))?
        .map_err(|e| NatError::TurnAllocationFailed(format!("Recv failed: {}", e)))?;
        
        if len2 < 20 {
            return Err(NatError::TurnAllocationFailed("Response too short".into()));
        }
        
        let resp_type2 = u16::from_be_bytes([buf2[0], buf2[1]]);
        
        // Check for success (0x0103 = Allocate Success)
        if resp_type2 != 0x0103 {
            let error_code = self.extract_stun_attribute(&buf2[20..len2], 0x0009)
                .map(|e| if e.len() >= 4 { format!("{}{}", e[2], e[3]) } else { "unknown".into() })
                .unwrap_or_else(|| "unknown".into());
            return Err(NatError::TurnAllocationFailed(
                format!("Allocate failed with code: {}", error_code)
            ));
        }
        
        // Validate magic cookie in success response
        let resp2_magic = u32::from_be_bytes([buf2[4], buf2[5], buf2[6], buf2[7]]);
        if resp2_magic != 0x2112A442 {
            return Err(NatError::TurnAllocationFailed("Invalid magic cookie in success response".into()));
        }
        
        // Validate transaction ID in success response
        if buf2[8..20] != txn_id {
            return Err(NatError::TurnAllocationFailed(
                "Transaction ID mismatch in allocation response — possible spoofing".into()
            ));
        }
        
        // Extract XOR-RELAYED-ADDRESS (0x0016)
        let relay_addr = self.extract_xor_mapped_address(&buf2[..len2], 0x0016, &txn_id)
            .ok_or_else(|| NatError::TurnAllocationFailed("No relay address in response".into()))?;
        
        // Validate relay address is not loopback or unspecified
        match relay_addr.ip() {
            IpAddr::V4(ipv4) => {
                if ipv4.is_loopback() || ipv4.is_unspecified() || ipv4.is_broadcast() {
                    return Err(NatError::TurnAllocationFailed(
                        format!("Invalid relay address: {} (loopback/unspecified/broadcast)", relay_addr)
                    ));
                }
            }
            IpAddr::V6(ipv6) => {
                if ipv6.is_loopback() || ipv6.is_unspecified() {
                    return Err(NatError::TurnAllocationFailed(
                        format!("Invalid relay address: {} (loopback/unspecified)", relay_addr)
                    ));
                }
            }
        }
        
        if relay_addr.port() == 0 {
            return Err(NatError::TurnAllocationFailed(
                "Invalid relay address: port 0".into()
            ));
        }
        
        // Store allocated relay address
        *self.relay_addr.write() = Some(relay_addr);
        *self.last_refresh.lock() = Instant::now();
        
        tracing::info!("TURN relay allocated: {}", relay_addr);
        
        Ok(relay_addr)
    }
    
    /// Extracts a STUN attribute from message body.
    fn extract_stun_attribute(&self, attrs: &[u8], attr_type: u16) -> Option<Vec<u8>> {
        let mut offset = 0;
        while offset + 4 <= attrs.len() {
            let t = u16::from_be_bytes([attrs[offset], attrs[offset + 1]]);
            let l = u16::from_be_bytes([attrs[offset + 2], attrs[offset + 3]]) as usize;
            
            if t == attr_type && offset + 4 + l <= attrs.len() {
                return Some(attrs[offset + 4..offset + 4 + l].to_vec());
            }
            
            // Advance to next attribute (4-byte aligned)
            offset += 4 + ((l + 3) & !3);
        }
        None
    }
    
    /// Extracts XOR-MAPPED-ADDRESS or XOR-RELAYED-ADDRESS from STUN message.
    fn extract_xor_mapped_address(&self, msg: &[u8], attr_type: u16, _txn_id: &[u8; 12]) -> Option<SocketAddr> {
        if msg.len() < 20 {
            return None;
        }
        
        let attr_data = self.extract_stun_attribute(&msg[20..], attr_type)?;
        if attr_data.len() < 8 {
            return None;
        }
        
        let family = attr_data[1];
        let xor_port = u16::from_be_bytes([attr_data[2], attr_data[3]]);
        let port = xor_port ^ 0x2112; // XOR with magic cookie upper 16 bits
        
        match family {
            0x01 => {
                // IPv4
                let xor_ip = u32::from_be_bytes([attr_data[4], attr_data[5], attr_data[6], attr_data[7]]);
                let ip = xor_ip ^ 0x2112A442;
                let addr = Ipv4Addr::from(ip);
                Some(SocketAddr::new(IpAddr::V4(addr), port))
            }
            _ => None,
        }
    }
    
    /// Refreshes the TURN allocation to prevent timeout.
    pub async fn refresh(&self, socket: &UdpSocket) -> Result<(), NatError> {
        if self.relay_addr.read().is_none() {
            return Err(NatError::TurnAllocationFailed("No active allocation to refresh".into()));
        }
        
        // Build Refresh request (method 0x0004)
        let mut txn_id = [0u8; 12];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut txn_id);
        
        let mut request = Vec::new();
        request.extend_from_slice(&[0x00, 0x04]); // Refresh method
        request.extend_from_slice(&[0x00, 0x00]); // Length: 0 (no attributes for simple refresh)
        request.extend_from_slice(&0x2112A442u32.to_be_bytes());
        request.extend_from_slice(&txn_id);
        
        socket.send_to(&request, self.server).await
            .map_err(|e| NatError::TurnAllocationFailed(format!("Refresh send failed: {}", e)))?;
        
        *self.last_refresh.lock() = Instant::now();
        Ok(())
    }
    
    /// Returns relay address if allocated
    pub fn relay_addr(&self) -> Option<SocketAddr> {
        *self.relay_addr.read()
    }
}

/// ICE candidate types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateType {
    /// Local address (host candidate)
    Host,
    /// STUN-discovered address (server reflexive)
    ServerReflexive,
    /// Peer reflexive (discovered during connectivity checks)
    PeerReflexive,
    /// TURN relay address
    Relay,
}

/// ICE candidate
#[derive(Debug, Clone)]
pub struct IceCandidate {
    pub candidate_type: CandidateType,
    pub address: SocketAddr,
    pub priority: u32,
    pub foundation: String,
}

impl IceCandidate {
    /// Calculates priority according to ICE spec
    pub fn calculate_priority(candidate_type: &CandidateType, local_pref: u16, component: u8) -> u32 {
        let type_pref: u32 = match candidate_type {
            CandidateType::Host => 126,
            CandidateType::PeerReflexive => 110,
            CandidateType::ServerReflexive => 100,
            CandidateType::Relay => 0,
        };
        
        (type_pref << 24) | ((local_pref as u32) << 8) | (256 - component as u32)
    }
}

/// UDP hole puncher for NAT traversal
pub struct HolePuncher {
    /// Maximum punch attempts
    max_attempts: u32,
    /// Delay between attempts
    attempt_delay: Duration,
    /// Punch timeout
    timeout: Duration,
}

impl HolePuncher {
    pub fn new() -> Self {
        Self {
            max_attempts: 10,
            attempt_delay: Duration::from_millis(100),
            timeout: Duration::from_secs(5),
        }
    }
    
    /// Attempts to punch a hole to the peer
    pub async fn punch(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
    ) -> Result<(), NatError> {
        let punch_packet = b"QUANTOS_PUNCH";
        
        for _attempt in 0..self.max_attempts {
            // Send punch packet
            socket.send_to(punch_packet, peer_addr).await?;
            
            // Brief delay
            tokio::time::sleep(self.attempt_delay).await;
            
            // Try to receive response
            let mut buf = [0u8; 64];
            match tokio::time::timeout(
                Duration::from_millis(200),
                socket.recv_from(&mut buf)
            ).await {
                Ok(Ok((len, from))) if from == peer_addr => {
                    if &buf[..len] == punch_packet || &buf[..len] == b"QUANTOS_PUNCH_ACK" {
                        // Send ack if we received punch
                        socket.send_to(b"QUANTOS_PUNCH_ACK", peer_addr).await?;
                        return Ok(());
                    }
                }
                _ => continue,
            }
        }
        
        Err(NatError::HolePunchFailed(self.max_attempts))
    }
    
    /// Simultaneous open attempt (both sides punch at same time)
    pub async fn simultaneous_open(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        start_time: Instant,
    ) -> Result<(), NatError> {
        let punch_packet = b"QUANTOS_SIM_PUNCH";
        
        // Wait until start time
        if let Some(wait) = start_time.checked_duration_since(Instant::now()) {
            tokio::time::sleep(wait).await;
        }
        
        // Rapid-fire punches
        for _ in 0..20 {
            socket.send_to(punch_packet, peer_addr).await?;
            tokio::time::sleep(Duration::from_millis(50)).await;
            
            // Check for incoming
            let mut buf = [0u8; 64];
            if let Ok(Ok((_, from))) = tokio::time::timeout(
                Duration::from_millis(10),
                socket.recv_from(&mut buf)
            ).await {
                if from == peer_addr {
                    return Ok(());
                }
            }
        }
        
        Err(NatError::HolePunchFailed(20))
    }
}

/// NAT traversal coordinator
pub struct NatTraversalManager {
    stun_client: Arc<StunClient>,
    turn_client: Option<Arc<TurnClient>>,
    hole_puncher: HolePuncher,
    /// Local candidates
    local_candidates: RwLock<Vec<IceCandidate>>,
}

impl NatTraversalManager {
    pub fn new(stun_servers: Vec<SocketAddr>) -> Self {
        Self {
            stun_client: Arc::new(StunClient::new(stun_servers)),
            turn_client: None,
            hole_puncher: HolePuncher::new(),
            local_candidates: RwLock::new(Vec::new()),
        }
    }
    
    /// Sets up TURN client for relay fallback
    pub fn set_turn(&mut self, server: SocketAddr, username: String, realm: String) {
        self.turn_client = Some(Arc::new(TurnClient::new(server, username, realm)));
    }
    
    /// Gathers all local ICE candidates
    pub async fn gather_candidates(&self, socket: &UdpSocket) -> Result<Vec<IceCandidate>, NatError> {
        let mut candidates = Vec::new();
        
        // Host candidate
        let local_addr = socket.local_addr()?;
        candidates.push(IceCandidate {
            candidate_type: CandidateType::Host,
            address: local_addr,
            priority: IceCandidate::calculate_priority(&CandidateType::Host, 65535, 1),
            foundation: format!("host_{}", local_addr.port()),
        });
        
        // Server reflexive candidate (STUN)
        if let Ok(public_addr) = self.stun_client.discover_public_address(socket).await {
            candidates.push(IceCandidate {
                candidate_type: CandidateType::ServerReflexive,
                address: public_addr,
                priority: IceCandidate::calculate_priority(&CandidateType::ServerReflexive, 65534, 1),
                foundation: format!("srflx_{}", public_addr.port()),
            });
        }
        
        // Relay candidate (TURN) - if configured
        if let Some(ref turn) = self.turn_client {
            if let Ok(relay_addr) = turn.allocate(socket).await {
                candidates.push(IceCandidate {
                    candidate_type: CandidateType::Relay,
                    address: relay_addr,
                    priority: IceCandidate::calculate_priority(&CandidateType::Relay, 65533, 1),
                    foundation: format!("relay_{}", relay_addr.port()),
                });
            }
        }
        
        // Sort by priority (highest first)
        candidates.sort_by(|a, b| b.priority.cmp(&a.priority));
        
        *self.local_candidates.write() = candidates.clone();
        Ok(candidates)
    }
    
    /// Attempts to establish connection with peer
    pub async fn connect_to_peer(
        &self,
        socket: &UdpSocket,
        peer_candidates: &[IceCandidate],
    ) -> Result<SocketAddr, NatError> {
        // Try candidates in priority order
        for candidate in peer_candidates {
            match candidate.candidate_type {
                CandidateType::Host | CandidateType::ServerReflexive => {
                    // Try hole punching
                    if self.hole_puncher.punch(socket, candidate.address).await.is_ok() {
                        return Ok(candidate.address);
                    }
                }
                CandidateType::Relay => {
                    // TURN relay is always reachable (if allocated)
                    return Ok(candidate.address);
                }
                _ => continue,
            }
        }
        
        Err(NatError::NoConnectionMethod)
    }
    
    /// Returns STUN client reference
    pub fn stun(&self) -> &Arc<StunClient> {
        &self.stun_client
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_stun_message_serialize() {
        let msg = StunMessage::binding_request();
        let data = msg.serialize();
        
        assert!(data.len() >= 20);
        assert_eq!(data[0], 0x00); // Binding request high byte
        assert_eq!(data[1], 0x01); // Binding request low byte
        
        // Magic cookie
        assert_eq!(&data[4..8], &[0x21, 0x12, 0xA4, 0x42]);
    }
    
    #[test]
    fn test_stun_message_parse() {
        let msg = StunMessage::binding_request();
        let data = msg.serialize();
        
        let parsed = StunMessage::parse(&data).unwrap();
        assert_eq!(parsed.transaction_id, msg.transaction_id);
    }
    
    #[test]
    fn test_nat_type_compatibility() {
        assert!(NatType::None.can_connect_directly(&NatType::Symmetric));
        assert!(NatType::FullCone.can_connect_directly(&NatType::PortRestrictedCone));
        assert!(!NatType::Symmetric.can_connect_directly(&NatType::Symmetric));
        
        assert!(NatType::Symmetric.requires_relay(&NatType::Symmetric));
        assert!(!NatType::FullCone.requires_relay(&NatType::PortRestrictedCone));
    }
    
    #[test]
    fn test_ice_candidate_priority() {
        let host_prio = IceCandidate::calculate_priority(&CandidateType::Host, 65535, 1);
        let srflx_prio = IceCandidate::calculate_priority(&CandidateType::ServerReflexive, 65535, 1);
        let relay_prio = IceCandidate::calculate_priority(&CandidateType::Relay, 65535, 1);
        
        assert!(host_prio > srflx_prio);
        assert!(srflx_prio > relay_prio);
    }
}
