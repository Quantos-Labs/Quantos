//! Comprehensive tests for the Security module

use quantos::security::*;
use quantos::types::*;

// ══════════════════════════════════════════════════════════
//  DDoS Protection
// ══════════════════════════════════════════════════════════

#[test]
fn test_ddos_config_defaults() {
    let config = DdosConfig::default();
    assert!(config.max_connections_per_sec > 0);
    assert!(config.max_bandwidth_per_peer > 0);
    assert!(config.max_messages_per_sec > 0);
}

#[test]
fn test_ddos_protection_creation() {
    let config = DdosConfig::default();
    let _protector = DdosProtection::new(config);
}

#[test]
fn test_ddos_stats_initial() {
    let config = DdosConfig::default();
    let protector = DdosProtection::new(config);
    let stats = protector.get_stats();
    assert_eq!(stats.connections_blocked, 0);
    assert_eq!(stats.messages_blocked, 0);
}

#[test]
fn test_ddos_banned_peers_empty() {
    let config = DdosConfig::default();
    let protector = DdosProtection::new(config);
    assert!(protector.get_banned_peers().is_empty());
}

// ══════════════════════════════════════════════════════════
//  Sybil Protection
// ══════════════════════════════════════════════════════════

#[test]
fn test_sybil_config_defaults() {
    let config = SybilConfig::default();
    assert!(config.min_stake > 0);
}

#[test]
fn test_sybil_protection_creation() {
    let config = SybilConfig::default();
    let _protector = SybilProtection::new(config);
}

// ══════════════════════════════════════════════════════════
//  Eclipse Protection
// ══════════════════════════════════════════════════════════

#[test]
fn test_eclipse_config_defaults() {
    let config = EclipseConfig::default();
    assert!(config.min_anchor_peers > 0);
    assert!(config.max_peers_per_subnet > 0);
}

#[test]
fn test_eclipse_protection_creation() {
    let config = EclipseConfig::default();
    let _protector = EclipseProtection::new(config);
}

// ══════════════════════════════════════════════════════════
//  Time Sync
// ══════════════════════════════════════════════════════════

#[test]
fn test_time_sync_config_defaults() {
    let config = TimeSyncConfig::default();
    assert!(config.max_drift_ms != 0);
    assert!(config.sync_interval_secs > 0);
}

#[test]
fn test_time_sync_creation() {
    let config = TimeSyncConfig::default();
    let _sync = TimeSync::new(config);
}

// ══════════════════════════════════════════════════════════
//  Network Security
// ══════════════════════════════════════════════════════════

#[test]
fn test_network_security_config_defaults() {
    let config = NetworkSecurityConfig::default();
    assert!(config.max_message_size > 0);
}

// ══════════════════════════════════════════════════════════
//  Quantum Security
// ══════════════════════════════════════════════════════════

#[test]
fn test_quantum_security_config_defaults() {
    let _config = QuantumSecurityConfig::default();
}

#[test]
fn test_quantum_threat_detector() {
    let config = QuantumSecurityConfig::default();
    let detector = QuantumThreatDetector::new(config);
    let level = detector.get_threat_level();
    let _ = level;
}

// ══════════════════════════════════════════════════════════
//  Transaction Security
// ══════════════════════════════════════════════════════════

#[test]
fn test_transaction_security_config_defaults() {
    let config = TransactionSecurityConfig::default();
    assert!(config.max_tx_age_slots > 0);
    assert!(config.max_nonce_gap > 0);
}

#[test]
fn test_double_spend_detector_creation() {
    let config = TransactionSecurityConfig::default();
    let _detector = DoubleSpendDetector::new(config);
}

#[test]
fn test_replay_protector_creation() {
    let config = TransactionSecurityConfig::default();
    let _protector = ReplayProtector::new(config);
}

// ══════════════════════════════════════════════════════════
//  Consensus Security
// ══════════════════════════════════════════════════════════

#[test]
fn test_consensus_security_config_defaults() {
    let _config = ConsensusSecurityConfig::default();
}

// ══════════════════════════════════════════════════════════
//  Security Error & Event
// ══════════════════════════════════════════════════════════

#[test]
fn test_severity_variants() {
    let _low = Severity::Low;
    let _medium = Severity::Medium;
    let _high = Severity::High;
    let _critical = Severity::Critical;
}
