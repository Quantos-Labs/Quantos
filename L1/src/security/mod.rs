//! # Quantos Security Module
//!
//! Comprehensive protection against quantum and classical attacks.
//!
//! ## Protected Attack Vectors
//!
//! | Attack | Protection | Status |
//! |--------|------------|--------|
//! | Shor's Algorithm | Post-quantum crypto (ML-DSA-65, SPHINCS+) | ✅ |
//! | Grover's Algorithm | 256-bit security (doubles effective key size) | ✅ |
//! | 51% Attack | Stake-weighted committees + slashing | ✅ |
//! | Eclipse Attack | Peer diversity + reputation | ✅ |
//! | MITM Attack | End-to-end encryption + mutual auth | ✅ |
//! | Double Spend | DAG conflict resolution + finality | ✅ |
//! | Replay Attack | Nonce + chain ID + expiry | ✅ |
//! | Long-Range Attack | Checkpoints + weak subjectivity | ✅ |
//! | Sybil Attack | Stake requirements + identity proofs | ✅ |
//! | Time Warp | Median time + bounds checking | ✅ |
//! | Selfish Mining | DAG structure eliminates advantage | ✅ |
//! | Front-Running | Commit-reveal + encrypted mempool | ✅ |
//! | DoS/DDoS | Rate limiting + proof of work | ✅ |
//! | Nothing-at-Stake | Slashing + deposit lockup | ✅ |

pub mod quantum;
pub mod network;
pub mod transaction;
pub mod consensus;
pub mod ddos_protection;
pub mod sybil_protection;
pub mod eclipse_protection;
pub mod time_sync;

pub use quantum::*;
pub use network::*;
pub use transaction::*;
pub use consensus::*;
pub use ddos_protection::*;
pub use sybil_protection::*;
pub use eclipse_protection::*;
pub use time_sync::*;

use thiserror::Error;
use std::time::Instant;

/// Security-related errors.
#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("Quantum attack detected: {0}")]
    QuantumAttack(String),
    
    #[error("Network attack detected: {0}")]
    NetworkAttack(String),
    
    #[error("Transaction attack detected: {0}")]
    TransactionAttack(String),
    
    #[error("Consensus attack detected: {0}")]
    ConsensusAttack(String),
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Replay detected")]
    ReplayDetected,
    
    #[error("Double spend detected")]
    DoubleSpendDetected,
    
    #[error("Eclipse attack suspected")]
    EclipseAttackSuspected,
    
    #[error("Peer banned: {0}")]
    PeerBanned(String),
    
    #[error("Unauthorized access to privileged operation")]
    Unauthorized,
}

pub type SecurityResult<T> = Result<T, SecurityError>;

/// Global security configuration.
#[derive(Clone, Debug)]
pub struct SecurityConfig {
    /// Quantum protection settings
    pub quantum: QuantumSecurityConfig,
    /// Network protection settings
    pub network: NetworkSecurityConfig,
    /// Transaction protection settings
    pub transaction: TransactionSecurityConfig,
    /// Consensus protection settings
    pub consensus: ConsensusSecurityConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            quantum: QuantumSecurityConfig::default(),
            network: NetworkSecurityConfig::default(),
            transaction: TransactionSecurityConfig::default(),
            consensus: ConsensusSecurityConfig::default(),
        }
    }
}

/// Security audit log entry.
#[derive(Clone, Debug)]
pub struct SecurityEvent {
    pub timestamp: Instant,
    pub event_type: SecurityEventType,
    pub severity: Severity,
    pub details: String,
    pub source: Option<String>,
}

/// Types of security events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecurityEventType {
    QuantumThreat,
    NetworkAttack,
    TransactionAnomaly,
    ConsensusViolation,
    RateLimitHit,
    PeerBanned,
    SuspiciousActivity,
}

/// Severity levels.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}
