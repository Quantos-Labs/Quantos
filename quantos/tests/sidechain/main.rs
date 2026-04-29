//! Comprehensive tests for the Sidechain module

use quantos::sidechain::*;
use quantos::types::*;
use std::sync::Arc;

// ══════════════════════════════════════════════════════════
//  Sidechain Config
// ══════════════════════════════════════════════════════════

#[test]
fn test_sidechain_config_defaults() {
    let config = SidechainConfig::default();
    assert_eq!(config.name, "Unnamed Sidechain");
    assert!(config.block_time_ms > 0);
    assert!(config.max_tx_per_block > 0);
    assert!(config.required_operators > 0);
    assert!(!config.active);
}

#[test]
fn test_sidechain_config_custom() {
    let mut config = SidechainConfig::default();
    config.name = "DeFi Chain".to_string();
    config.block_time_ms = 500;
    assert_eq!(config.name, "DeFi Chain");
    assert_eq!(config.block_time_ms, 500);
}

// ══════════════════════════════════════════════════════════
//  Sidechain Registry
// ══════════════════════════════════════════════════════════

#[test]
fn test_sidechain_registry_creation() {
    let _registry = SidechainRegistry::new(100);
}

fn deposit_stake(registry: &SidechainRegistry, creator: Address) {
    // MIN_REGISTRATION_STAKE = 100 tokens (100 * 10^18)
    registry.deposit_registration_stake(creator, Amount(200_000_000_000_000_000_000));
}

#[test]
fn test_register_sidechain() {
    let registry = SidechainRegistry::new(100);
    let creator = [1u8; 32];
    deposit_stake(&registry, creator);

    let config = SidechainConfig {
        name: "Test Sidechain".to_string(),
        ..Default::default()
    };

    let result = registry.register(config, creator);
    assert!(result.is_ok());
}

#[test]
fn test_get_sidechain() {
    let registry = SidechainRegistry::new(100);
    let creator = [1u8; 32];
    deposit_stake(&registry, creator);

    let config = SidechainConfig {
        name: "Test Sidechain".to_string(),
        ..Default::default()
    };

    let id = registry.register(config, creator).unwrap();
    let sidechain = registry.get_sidechain(&id);
    assert!(sidechain.is_some());
}

#[test]
fn test_get_nonexistent_sidechain() {
    let registry = SidechainRegistry::new(100);
    let fake_id: SidechainId = [99u8; 8];
    assert!(registry.get_sidechain(&fake_id).is_none());
}

#[test]
fn test_sidechain_count() {
    let registry = SidechainRegistry::new(100);
    assert_eq!(registry.count(), 0);
    deposit_stake(&registry, [1u8; 32]);

    let config = SidechainConfig {
        name: "Test".to_string(),
        ..Default::default()
    };
    registry.register(config, [1u8; 32]).unwrap();
    assert_eq!(registry.count(), 1);
}

#[test]
fn test_get_all_sidechains() {
    let registry = SidechainRegistry::new(100);
    assert!(registry.get_all_sidechains().is_empty());
    deposit_stake(&registry, [1u8; 32]);

    let config = SidechainConfig {
        name: "Chain A".to_string(),
        ..Default::default()
    };
    registry.register(config, [1u8; 32]).unwrap();
    assert_eq!(registry.get_all_sidechains().len(), 1);
}

#[test]
fn test_active_count_initial() {
    let registry = SidechainRegistry::new(100);
    assert_eq!(registry.active_count(), 0);
}

#[test]
fn test_sidechain_auth_token() {
    let registry = SidechainRegistry::new(100);
    let token = registry.get_auth_token();
    assert_ne!(token, [0u8; 32]);
}

// ══════════════════════════════════════════════════════════
//  State Commitments
// ══════════════════════════════════════════════════════════

#[test]
fn test_state_commitment_creation() {
    let commitment = StateCommitment {
        height: 1000,
        state_root: [1u8; 32],
        tx_root: [2u8; 32],
        signatures: vec![],
        timestamp: 1234567890,
        l1_block: 500,
    };
    assert_eq!(commitment.height, 1000);
    assert_eq!(commitment.timestamp, 1234567890);
    assert_eq!(commitment.l1_block, 500);
}

// ══════════════════════════════════════════════════════════
//  Bridge
// ══════════════════════════════════════════════════════════

#[test]
fn test_sidechain_bridge_creation() {
    let registry = Arc::new(SidechainRegistry::new(100));
    let _bridge = SidechainBridge::new(registry);
}

#[test]
fn test_transfer_status_variants() {
    assert_eq!(TransferStatus::Pending, TransferStatus::Pending);
    assert_ne!(TransferStatus::Pending, TransferStatus::Completed);
}

// ══════════════════════════════════════════════════════════
//  Asset Type
// ══════════════════════════════════════════════════════════

#[test]
fn test_asset_type_variants() {
    let _native = AssetType::Native;
    let _token = AssetType::Token { address: [1u8; 32] };
    let _nft = AssetType::NFT { address: [2u8; 32] };
}
