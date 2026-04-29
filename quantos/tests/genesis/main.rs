//! Comprehensive tests for the Genesis module

use quantos::genesis::*;
// Avoid ambiguity with genesis::GenesisConfig vs types re-exports
use quantos::types::{Address, Amount, Hash, hash_data};

// ══════════════════════════════════════════════════════════
//  Network ID
// ══════════════════════════════════════════════════════════

#[test]
fn test_network_id_chain_ids() {
    assert_eq!(NetworkId::Mainnet.chain_id(), 1);
    assert_eq!(NetworkId::Testnet.chain_id(), 2);
    assert_eq!(NetworkId::Devnet.chain_id(), 3);
}

#[test]
fn test_network_id_from_chain_id() {
    assert_eq!(NetworkId::from_chain_id(1), NetworkId::Mainnet);
    assert_eq!(NetworkId::from_chain_id(2), NetworkId::Testnet);
    assert_eq!(NetworkId::from_chain_id(3), NetworkId::Devnet);
}

#[test]
fn test_network_id_names() {
    assert_eq!(NetworkId::Mainnet.name(), "mainnet");
    assert_eq!(NetworkId::Testnet.name(), "testnet");
    assert_eq!(NetworkId::Devnet.name(), "devnet");
}

#[test]
fn test_network_id_unknown_chain_id() {
    let id = NetworkId::from_chain_id(999);
    // Unknown chain IDs return Custom variant
    assert_ne!(id, NetworkId::Mainnet);
    assert_ne!(id, NetworkId::Testnet);
    assert_ne!(id, NetworkId::Devnet);
}

// ══════════════════════════════════════════════════════════
//  Genesis Config — Testnet/Devnet
// ══════════════════════════════════════════════════════════

#[test]
fn test_genesis_testnet() {
    let config = GenesisConfig::testnet();
    assert!(config.is_ok());
    let config = config.unwrap();
    assert!(!config.validators.is_empty());
    assert!(config.chain.chain_id == 2);
}

#[test]
fn test_genesis_devnet() {
    let config = GenesisConfig::devnet();
    assert!(config.is_ok());
    let config = config.unwrap();
    assert!(!config.validators.is_empty());
    assert!(config.chain.chain_id == 3);
}

#[test]
fn test_genesis_validate() {
    let config = GenesisConfig::testnet().unwrap();
    assert!(config.validate().is_ok());
}

#[test]
fn test_genesis_hash_deterministic() {
    let config = GenesisConfig::testnet().unwrap();
    let h1 = config.genesis_hash();
    let h2 = config.genesis_hash();
    assert_eq!(h1, h2);
    assert_ne!(h1, [0u8; 32]);
}

#[test]
fn test_genesis_total_supply() {
    let config = GenesisConfig::testnet().unwrap();
    let supply = config.total_supply();
    assert!(supply.is_ok());
    assert!(supply.unwrap() > 0);
}

// ══════════════════════════════════════════════════════════
//  Genesis Builder
// ══════════════════════════════════════════════════════════

#[test]
fn test_genesis_builder() {
    let config = GenesisConfig::testnet().unwrap();
    let builder = GenesisBuilder::new(config);
    let result = builder.build();
    assert!(result.is_ok());
}

#[test]
fn test_genesis_builder_get_initial_balances() {
    let config = GenesisConfig::testnet().unwrap();
    let builder = GenesisBuilder::new(config);
    let balances = builder.get_initial_balances();
    // Testnet has allocations
    assert!(!balances.is_empty());
}

#[test]
fn test_genesis_builder_get_validators() {
    let config = GenesisConfig::testnet().unwrap();
    let builder = GenesisBuilder::new(config);
    let validators = builder.get_validators();
    assert!(!validators.is_empty());
}

// ══════════════════════════════════════════════════════════
//  Address Parsing
// ══════════════════════════════════════════════════════════

#[test]
fn test_parse_address_valid() {
    let hex = "01".repeat(32);
    let addr = GenesisConfig::parse_address(&hex);
    assert!(addr.is_ok());
    assert_eq!(addr.unwrap(), [1u8; 32]);
}

#[test]
fn test_parse_address_invalid_hex() {
    let result = GenesisConfig::parse_address("zzzz");
    assert!(result.is_err());
}

#[test]
fn test_parse_address_wrong_length() {
    let result = GenesisConfig::parse_address("0102");
    assert!(result.is_err());
}

// ══════════════════════════════════════════════════════════
//  Genesis File I/O
// ══════════════════════════════════════════════════════════

#[test]
fn test_genesis_save_and_load() {
    let config = GenesisConfig::testnet().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("genesis.json");

    config.to_file(&path).unwrap();
    let loaded = GenesisConfig::from_file(&path).unwrap();

    assert_eq!(loaded.chain.chain_id, config.chain.chain_id);
    assert_eq!(loaded.validators.len(), config.validators.len());
}

#[test]
fn test_genesis_load_nonexistent() {
    let result = GenesisConfig::from_file("/nonexistent/path/genesis.json");
    assert!(result.is_err());
}
