//! Comprehensive tests for the Sharding module

use quantos::sharding::*;
use quantos::types::*;

// ══════════════════════════════════════════════════════════
//  Dynamic Sharding
// ══════════════════════════════════════════════════════════

#[test]
fn test_sharding_config_defaults() {
    let config = ShardingConfig::default();
    assert!(config.min_shards > 0);
    assert!(config.max_shards >= config.min_shards);
    assert!(config.split_threshold_tps > 0);
}

#[test]
fn test_shard_manager_creation() {
    let config = ShardingConfig::default();
    let _manager = ShardManager::new(config);
}

#[test]
fn test_shard_manager_get_shard_map() {
    let config = ShardingConfig::default();
    let manager = ShardManager::new(config);
    let shard_map = manager.get_shard_map();
    assert!(shard_map.num_shards > 0);
}

#[test]
fn test_shard_assignment() {
    let config = ShardingConfig::default();
    let manager = ShardManager::new(config);
    let addr = [1u8; 32];
    let shard = manager.get_shard_for_address(&addr);
    let map = manager.get_shard_map();
    assert!(shard < map.num_shards);
}

#[test]
fn test_shard_assignment_deterministic() {
    let config = ShardingConfig::default();
    let manager = ShardManager::new(config);
    let addr = [42u8; 32];
    let s1 = manager.get_shard_for_address(&addr);
    let s2 = manager.get_shard_for_address(&addr);
    assert_eq!(s1, s2);
}

#[test]
fn test_shard_report_load() {
    let config = ShardingConfig::default();
    let manager = ShardManager::new(config);
    manager.report_load(0, 5000);
    let loads = manager.get_all_loads();
    assert!(!loads.is_empty());
}

#[test]
fn test_shard_check_rebalance_initial() {
    let config = ShardingConfig::default();
    let manager = ShardManager::new(config);
    // Initially no rebalance needed
    let action = manager.check_rebalance();
    // May or may not return action, just ensure no panic
    let _ = action;
}

#[test]
fn test_shard_history_initially_empty() {
    let config = ShardingConfig::default();
    let manager = ShardManager::new(config);
    let history = manager.get_history();
    assert!(history.is_empty());
}

#[test]
fn test_shard_auth_token() {
    let config = ShardingConfig::default();
    let manager = ShardManager::new(config);
    let token = manager.get_auth_token();
    assert_ne!(token, [0u8; 32]);
}

// ══════════════════════════════════════════════════════════
//  Shard Map
// ══════════════════════════════════════════════════════════

#[test]
fn test_shard_map_creation() {
    let map = ShardMap::new(100);
    assert_eq!(map.num_shards, 100);
}

#[test]
fn test_shard_map_get_shard() {
    let map = ShardMap::new(100);
    let addr = [1u8; 32];
    let shard = map.get_shard(&addr);
    assert!(shard < 100);
}

#[test]
fn test_shard_map_deterministic() {
    let map = ShardMap::new(50);
    let addr = [5u8; 32];
    assert_eq!(map.get_shard(&addr), map.get_shard(&addr));
}

// ══════════════════════════════════════════════════════════
//  Shard Load
// ══════════════════════════════════════════════════════════

#[test]
fn test_shard_load_default() {
    let load = ShardLoad::default();
    assert_eq!(load.tps, 0);
}

#[test]
fn test_shard_load_add_sample() {
    let mut load = ShardLoad::default();
    load.add_sample(1000, 10);
    assert_eq!(load.tps, 1000);
}

#[test]
fn test_shard_load_should_split() {
    let mut load = ShardLoad::default();
    load.add_sample(10000, 10);
    assert!(load.should_split(5000));
    assert!(!load.should_split(20000));
}

#[test]
fn test_shard_load_should_merge() {
    let mut load = ShardLoad::default();
    load.add_sample(100, 10);
    assert!(load.should_merge(500));
    assert!(!load.should_merge(50));
}

// ══════════════════════════════════════════════════════════
//  Cross-Shard Coordinator
// ══════════════════════════════════════════════════════════

#[test]
fn test_cross_shard_coordinator() {
    let config = ShardingConfig::default();
    let manager = std::sync::Arc::new(ShardManager::new(config));
    let coordinator = CrossShardCoordinator::new(manager);

    let tx_hash = [1u8; 32];
    let result = coordinator.initiate(tx_hash, 0, 1);
    assert!(result.is_ok());

    let status = coordinator.get_status(&tx_hash);
    assert!(status.is_some());
    assert_eq!(status.unwrap(), CrossShardPhase::Prepare);
}

#[test]
fn test_cross_shard_advance_phase() {
    let config = ShardingConfig::default();
    let manager = std::sync::Arc::new(ShardManager::new(config));
    let coordinator = CrossShardCoordinator::new(manager);

    let tx_hash = [1u8; 32];
    coordinator.initiate(tx_hash, 0, 1).unwrap();

    let next = coordinator.advance(&tx_hash);
    assert_eq!(next, Some(CrossShardPhase::Commit));
}

#[test]
fn test_cross_shard_status_unknown() {
    let config = ShardingConfig::default();
    let manager = std::sync::Arc::new(ShardManager::new(config));
    let coordinator = CrossShardCoordinator::new(manager);
    assert!(coordinator.get_status(&[99u8; 32]).is_none());
}
