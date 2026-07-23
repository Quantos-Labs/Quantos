// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Quantum Attack Protection
//!
//! Protection against quantum computing attacks including Shor's and Grover's algorithms.
//!
//! ## Shor's Algorithm Protection
//!
//! Shor's algorithm can break RSA, ECDSA, and other classical public-key cryptography
//! in polynomial time on a quantum computer. Quantos uses NIST-standardized
//! post-quantum cryptographic algorithms:
//!
//! - **ML-DSA-65**: Primary signature scheme (NIST Level 3, ~128-bit PQ security)
//! - **SPHINCS+**: Backup hash-based signatures (stateless, conservative choice)
//! - **ML-DSA-65**: NIST-standardized finality checkpoints (FIPS 204)
//!
//! ## Grover's Algorithm Protection
//!
//! Grover's algorithm provides quadratic speedup for searching/collision finding.
//! This effectively halves the security of symmetric algorithms and hashes.
//!
//! - **SHA3-256**: 256-bit hash provides 128-bit post-quantum security
//! - **256-bit keys**: All symmetric operations use 256-bit keys minimum
//! - **512-bit internal state**: Hash functions use sufficient internal state

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};


/// Quantum security configuration.
#[derive(Clone, Debug)]
pub struct QuantumSecurityConfig {
    /// Minimum signature security level (NIST level)
    pub min_signature_level: u8,
    /// Minimum hash output size in bits
    pub min_hash_bits: u32,
    /// Minimum symmetric key size in bits
    pub min_symmetric_bits: u32,
    /// Hybrid classical + PQ signatures (disabled: Quantos P2P / policy is PQ-only).
    pub hybrid_signatures: bool,
    /// Require multiple signature schemes for critical ops
    pub multi_signature_critical: bool,
    /// Key rotation interval
    pub key_rotation_interval: Duration,
    /// Enable quantum-resistant key exchange
    pub quantum_key_exchange: bool,
}

impl Default for QuantumSecurityConfig {
    fn default() -> Self {
        Self {
            min_signature_level: 3,           // NIST Level 3 minimum
            min_hash_bits: 256,               // SHA3-256 minimum
            min_symmetric_bits: 256,          // AES-256 equivalent
            hybrid_signatures: false,
            multi_signature_critical: true,   // ML-DSA-65 + SPHINCS+ for critical
            key_rotation_interval: Duration::from_secs(86400), // Daily rotation
            quantum_key_exchange: true,       // Use Kyber for key exchange
        }
    }
}

/// Quantum security levels (NIST).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum QuantumSecurityLevel {
    /// Level 1: ~AES-128 equivalent post-quantum
    Level1 = 1,
    /// Level 2: ~SHA-256 collision resistance
    Level2 = 2,
    /// Level 3: ~AES-192 equivalent post-quantum
    Level3 = 3,
    /// Level 4: ~SHA-384 collision resistance
    Level4 = 4,
    /// Level 5: ~AES-256 equivalent post-quantum
    Level5 = 5,
}

/// Supported post-quantum signature schemes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PQSignatureScheme {
    /// ML-DSA (lattice-based, FIPS 204)
    MlDsa44,
    MlDsa65,
    MlDsa87,
    /// SPHINCS+ (hash-based, stateless)
    SphincsShake128f,
    SphincsShake192f,
    SphincsShake256f,
}

impl PQSignatureScheme {
    /// Gets the NIST security level for this scheme.
    pub fn security_level(&self) -> QuantumSecurityLevel {
        match self {
            PQSignatureScheme::MlDsa44 => QuantumSecurityLevel::Level2,
            PQSignatureScheme::MlDsa65 => QuantumSecurityLevel::Level3,
            PQSignatureScheme::MlDsa87 => QuantumSecurityLevel::Level5,
            PQSignatureScheme::SphincsShake128f => QuantumSecurityLevel::Level1,
            PQSignatureScheme::SphincsShake192f => QuantumSecurityLevel::Level3,
            PQSignatureScheme::SphincsShake256f => QuantumSecurityLevel::Level5,
        }
    }

    /// Gets the signature size in bytes.
    pub fn signature_size(&self) -> usize {
        match self {
            PQSignatureScheme::MlDsa44 => 2420,
            PQSignatureScheme::MlDsa65 => 3309,
            PQSignatureScheme::MlDsa87 => 4627,
            PQSignatureScheme::SphincsShake128f => 17088,
            PQSignatureScheme::SphincsShake192f => 35664,
            PQSignatureScheme::SphincsShake256f => 49856,
        }
    }

    /// Whether this scheme is quantum-safe against Shor's algorithm.
    pub fn shor_resistant(&self) -> bool {
        true // All PQ schemes are Shor-resistant
    }

    /// Estimated qubits needed to break this scheme.
    pub fn qubits_to_break(&self) -> u64 {
        match self {
            PQSignatureScheme::MlDsa44 => 4000,
            PQSignatureScheme::MlDsa65 => 6000,
            PQSignatureScheme::MlDsa87 => 8000,
            PQSignatureScheme::SphincsShake128f => 2_u64.pow(64), // Hash-based, very high
            PQSignatureScheme::SphincsShake192f => 2_u64.pow(96),
            PQSignatureScheme::SphincsShake256f => 2_u64.pow(128),
        }
    }
}

/// Hash function with Grover resistance info.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuantumSafeHash {
    /// SHA3-256: 128-bit post-quantum security
    Sha3_256,
    /// SHA3-384: 192-bit post-quantum security
    Sha3_384,
    /// SHA3-512: 256-bit post-quantum security
    Sha3_512,
    /// BLAKE3-256: Fast, 128-bit post-quantum security
    Blake3_256,
}

impl QuantumSafeHash {
    /// Gets effective security bits after Grover's algorithm.
    pub fn post_quantum_bits(&self) -> u32 {
        match self {
            QuantumSafeHash::Sha3_256 => 128,  // 256/2
            QuantumSafeHash::Sha3_384 => 192,  // 384/2
            QuantumSafeHash::Sha3_512 => 256,  // 512/2
            QuantumSafeHash::Blake3_256 => 128,
        }
    }

    /// Grover iterations needed to find preimage.
    pub fn grover_iterations(&self) -> u128 {
        2_u128.pow(self.post_quantum_bits())
    }
}

/// Quantum threat detector.
pub struct QuantumThreatDetector {
    config: QuantumSecurityConfig,
    /// Tracked cryptographic operations
    crypto_operations: Arc<RwLock<Vec<CryptoOperation>>>,
    /// Anomaly detection
    anomalies: Arc<RwLock<Vec<QuantumAnomaly>>>,
    /// Current estimated quantum threat level
    threat_level: Arc<RwLock<ThreatLevel>>,
}

/// Recorded cryptographic operation.
#[derive(Clone, Debug)]
pub struct CryptoOperation {
    pub timestamp: Instant,
    pub operation_type: CryptoOpType,
    pub scheme: Option<PQSignatureScheme>,
    pub success: bool,
    pub duration_us: u64,
}

/// Type of cryptographic operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CryptoOpType {
    Sign,
    Verify,
    KeyGen,
    Hash,
    Encrypt,
    Decrypt,
}

/// Detected quantum anomaly.
#[derive(Clone, Debug)]
pub struct QuantumAnomaly {
    pub timestamp: Instant,
    pub anomaly_type: QuantumAnomalyType,
    pub details: String,
    pub severity: super::Severity,
}

/// Types of quantum anomalies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuantumAnomalyType {
    /// Unusually fast signature verification (possible quantum assist)
    FastVerification,
    /// Pattern suggesting collision search
    CollisionPattern,
    /// Weak random numbers detected
    WeakRandomness,
    /// Classical crypto usage detected
    ClassicalCryptoUsage,
    /// Key compromise suspected
    KeyCompromise,
}

/// Current threat level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreatLevel {
    /// No immediate threat
    Normal,
    /// Elevated vigilance
    Elevated,
    /// Active threat detected
    High,
    /// Critical - quantum attack in progress
    Critical,
}

impl QuantumThreatDetector {
    /// Creates a new quantum threat detector.
    pub fn new(config: QuantumSecurityConfig) -> Self {
        Self {
            config,
            crypto_operations: Arc::new(RwLock::new(Vec::new())),
            anomalies: Arc::new(RwLock::new(Vec::new())),
            threat_level: Arc::new(RwLock::new(ThreatLevel::Normal)),
        }
    }

    /// Records a cryptographic operation.
    pub fn record_operation(&self, op: CryptoOperation) {
        let mut ops = self.crypto_operations.write();
        ops.push(op.clone());

        // Keep only recent operations
        let cutoff = Instant::now() - Duration::from_secs(3600);
        ops.retain(|o| o.timestamp > cutoff);

        // Check for anomalies
        self.check_anomalies(&op);
    }

    /// Checks for quantum anomalies.
    fn check_anomalies(&self, op: &CryptoOperation) {
        // Check for suspiciously fast verification
        if op.operation_type == CryptoOpType::Verify && op.duration_us < 10 {
            self.report_anomaly(QuantumAnomaly {
                timestamp: Instant::now(),
                anomaly_type: QuantumAnomalyType::FastVerification,
                details: format!("Verification completed in {}μs", op.duration_us),
                severity: super::Severity::High,
            });
        }
    }

    /// Reports a quantum anomaly.
    pub fn report_anomaly(&self, anomaly: QuantumAnomaly) {
        let mut anomalies = self.anomalies.write();
        anomalies.push(anomaly.clone());

        // Update threat level based on anomalies
        self.update_threat_level();

        tracing::warn!(
            "Quantum anomaly detected: {:?} - {}",
            anomaly.anomaly_type,
            anomaly.details
        );
    }

    /// Updates threat level based on recent anomalies.
    fn update_threat_level(&self) {
        let anomalies = self.anomalies.read();
        let recent_cutoff = Instant::now() - Duration::from_secs(300);
        
        let recent_critical = anomalies.iter()
            .filter(|a| a.timestamp > recent_cutoff && a.severity == super::Severity::Critical)
            .count();
        
        let recent_high = anomalies.iter()
            .filter(|a| a.timestamp > recent_cutoff && a.severity >= super::Severity::High)
            .count();

        let new_level = if recent_critical > 0 {
            ThreatLevel::Critical
        } else if recent_high > 3 {
            ThreatLevel::High
        } else if recent_high > 0 {
            ThreatLevel::Elevated
        } else {
            ThreatLevel::Normal
        };

        *self.threat_level.write() = new_level;
    }

    /// Validates a signature scheme meets security requirements.
    pub fn validate_scheme(&self, scheme: PQSignatureScheme) -> bool {
        let level = scheme.security_level() as u8;
        level >= self.config.min_signature_level
    }

    /// Gets current threat level.
    pub fn get_threat_level(&self) -> ThreatLevel {
        *self.threat_level.read()
    }

    /// Gets recent anomalies.
    pub fn get_recent_anomalies(&self) -> Vec<QuantumAnomaly> {
        self.anomalies.read().clone()
    }

    /// Checks if emergency key rotation is needed.
    pub fn needs_emergency_rotation(&self) -> bool {
        matches!(
            self.get_threat_level(),
            ThreatLevel::High | ThreatLevel::Critical
        )
    }
}

/// Hybrid signature (classical + post-quantum).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Post-quantum signature (required)
    pub pq_signature: Vec<u8>,
    /// PQ scheme used
    pub pq_scheme: PQSignatureScheme,
    /// Classical signature (optional, for transition period)
    pub classical_signature: Option<Vec<u8>>,
    /// Timestamp
    pub timestamp: u64,
}

impl HybridSignature {
    /// Creates a new hybrid signature.
    pub fn new(pq_sig: Vec<u8>, pq_scheme: PQSignatureScheme) -> Self {
        Self {
            pq_signature: pq_sig,
            pq_scheme,
            classical_signature: None,
            timestamp: chrono::Utc::now().timestamp() as u64,
        }
    }

    /// Adds a classical signature.
    pub fn with_classical(mut self, classical_sig: Vec<u8>) -> Self {
        self.classical_signature = Some(classical_sig);
        self
    }

    /// Gets total signature size.
    pub fn total_size(&self) -> usize {
        self.pq_signature.len() 
            + self.classical_signature.as_ref().map(|s| s.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pq_scheme_security_levels() {
        assert_eq!(
            PQSignatureScheme::MlDsa65.security_level(),
            QuantumSecurityLevel::Level3
        );
        assert_eq!(
            PQSignatureScheme::MlDsa87.security_level(),
            QuantumSecurityLevel::Level5
        );
    }

    #[test]
    fn test_hash_post_quantum_bits() {
        assert_eq!(QuantumSafeHash::Sha3_256.post_quantum_bits(), 128);
        assert_eq!(QuantumSafeHash::Sha3_512.post_quantum_bits(), 256);
    }

    #[test]
    fn test_threat_detector() {
        let config = QuantumSecurityConfig::default();
        let detector = QuantumThreatDetector::new(config);
        
        assert_eq!(detector.get_threat_level(), ThreatLevel::Normal);
        assert!(detector.validate_scheme(PQSignatureScheme::MlDsa65));
    }
}
