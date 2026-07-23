// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Comprehensive tests for the Consensus module

use quantos::consensus::*;
use quantos::types::*;

// ══════════════════════════════════════════════════════════
//  Slashing Config
// ══════════════════════════════════════════════════════════

#[test]
fn test_slashing_config_defaults() {
    let config = SlashingConfig::default();
    assert!(config.double_sign_penalty_bps > 0);
    assert!(config.downtime_penalty_bps > 0);
    assert!(config.invalid_block_penalty_bps > 0);
}

#[test]
fn test_slashing_manager_creation() {
    let config = SlashingConfig::default();
    let _manager = SlashingManager::new(config);
}

// ══════════════════════════════════════════════════════════
//  Validator Registration
// ══════════════════════════════════════════════════════════

#[test]
fn test_slashing_register_validator() {
    let config = SlashingConfig::default();
    let manager = SlashingManager::new(config);
    let addr = [1u8; 32];
    let result = manager.register_validator(addr, 100_000);
    assert!(result.is_ok());
}

#[test]
fn test_slashing_register_validator_insufficient_stake() {
    let config = SlashingConfig::default();
    let manager = SlashingManager::new(config);
    let addr = [1u8; 32];
    // Minimum stake is 10_000
    let result = manager.register_validator(addr, 100);
    assert!(result.is_err());
}

#[test]
fn test_slashing_is_jailed_unregistered() {
    let config = SlashingConfig::default();
    let manager = SlashingManager::new(config);
    assert!(!manager.is_jailed(&[99u8; 32]));
}

#[test]
fn test_slashing_jail_status_none() {
    let config = SlashingConfig::default();
    let manager = SlashingManager::new(config);
    assert!(manager.get_jail_status(&[1u8; 32]).is_none());
}

#[test]
fn test_slashing_history_empty() {
    let config = SlashingConfig::default();
    let manager = SlashingManager::new(config);
    let history = manager.get_slashing_history(&[1u8; 32]);
    assert!(history.is_empty());
}

#[test]
fn test_slashing_pending_evidence_empty() {
    let config = SlashingConfig::default();
    let manager = SlashingManager::new(config);
    assert_eq!(manager.pending_evidence_count(), 0);
}

#[test]
fn test_slashing_metrics_initial() {
    let config = SlashingConfig::default();
    let manager = SlashingManager::new(config);
    let metrics = manager.get_metrics();
    assert_eq!(metrics.evidence_submitted, 0);
    assert_eq!(metrics.evidence_validated, 0);
}

#[test]
fn test_slashing_set_current_slot() {
    let config = SlashingConfig::default();
    let manager = SlashingManager::new(config);
    manager.set_current_slot(1000);
    // No panic means it worked
}

#[test]
fn test_slashing_process_evidence_empty() {
    let config = SlashingConfig::default();
    let manager = SlashingManager::new(config);
    let executions = manager.process_evidence();
    assert!(executions.is_empty());
}

// ══════════════════════════════════════════════════════════
//  Offense Types
// ══════════════════════════════════════════════════════════

#[test]
fn test_offense_type_double_signing_jails() {
    assert!(OffenseType::DoubleSigning.results_in_jail());
}

#[test]
fn test_offense_type_downtime_no_jail() {
    assert!(!OffenseType::Downtime.results_in_jail());
}

#[test]
fn test_offense_type_penalty() {
    let config = SlashingConfig::default();
    let penalty = OffenseType::DoubleSigning.base_penalty_bps(&config);
    assert!(penalty > 0);
}

// ══════════════════════════════════════════════════════════
//  Pipelining
// ══════════════════════════════════════════════════════════

#[test]
fn test_pipelined_block_creation() {
    let block = PipelinedBlock::new(
        [1u8; 32],       // hash
        [0u8; 32],       // parent
        1,               // view
        1,               // height
        [2u8; 32],       // proposer
        vec![1, 2, 3],   // payload
        [3u8; 32],       // state_root
        None,            // justify_qc
    );
    assert_eq!(block.hash, [1u8; 32]);
    assert_eq!(block.height, 1);
    assert_eq!(block.view, 1);
    assert_eq!(block.status, ProposalStatus::Proposed);
}

#[test]
fn test_proposal_status_variants() {
    assert_ne!(ProposalStatus::Proposed, ProposalStatus::Certified);
    assert_ne!(ProposalStatus::Committed, ProposalStatus::Failed);
}

// ══════════════════════════════════════════════════════════
//  View Change
// ══════════════════════════════════════════════════════════

#[test]
fn test_view_change_config_defaults() {
    let config = ViewChangeConfig::default();
    assert!(config.view_timeout.as_millis() > 0);
    assert!(config.heartbeat_interval.as_millis() > 0);
    assert!(config.max_missed_heartbeats > 0);
}

#[test]
fn test_view_change_manager_creation() {
    let config = ViewChangeConfig::default();
    let (tx, _rx) = tokio::sync::mpsc::channel(10);
    let _manager = ViewChangeManager::new([0u8; 32], 100, config, tx);
}

// ══════════════════════════════════════════════════════════
//  Dynamic Committee Optimizer
// ══════════════════════════════════════════════════════════

#[test]
fn test_dynamic_committee_optimizer_creation() {
    let optimizer = DynamicCommitteeOptimizer::new();
    let stats = optimizer.get_stats();
    assert_eq!(stats.total_decisions, 0);
}

#[test]
fn test_security_level_sizes() {
    assert!(SecurityLevel::Low.required_size() < SecurityLevel::Medium.required_size());
    assert!(SecurityLevel::Medium.required_size() < SecurityLevel::High.required_size());
}

#[test]
fn test_security_level_thresholds() {
    assert!(SecurityLevel::Low.threshold() > 0);
    assert!(SecurityLevel::High.threshold() > SecurityLevel::Low.threshold());
}
