// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Comprehensive tests for the Network module

use quantos::network::*;
use quantos::types::*;

// ══════════════════════════════════════════════════════════
//  Turbo Gossip Config
// ══════════════════════════════════════════════════════════

#[test]
fn test_turbo_gossip_config_defaults() {
    let config = TurboGossipConfig::default();
    assert!(config.max_queue_size > 0);
    assert!(config.bloom_filter_capacity > 0);
    assert!(config.max_gossip_peers > 0);
    assert!(config.min_critical_peers > 0);
    assert!(config.enable_lazy_push);
}

#[test]
fn test_turbo_gossip_config_custom() {
    let mut config = TurboGossipConfig::default();
    config.max_queue_size = 20_000;
    config.max_gossip_peers = 30;
    assert_eq!(config.max_queue_size, 20_000);
    assert_eq!(config.max_gossip_peers, 30);
}

// ══════════════════════════════════════════════════════════
//  Bandwidth Scheduler
// ══════════════════════════════════════════════════════════

#[test]
fn test_bandwidth_config_defaults() {
    let config = BandwidthConfig::default();
    assert!(config.total_bandwidth > 0);
    assert!(config.per_peer_rate > 0);
    assert!(config.enable_congestion_control);
}

#[test]
fn test_bandwidth_scheduler_creation() {
    let config = BandwidthConfig::default();
    let _scheduler = BandwidthScheduler::new(config);
}

// ══════════════════════════════════════════════════════════
//  Traffic Classes
// ══════════════════════════════════════════════════════════

#[test]
fn test_traffic_class_weights() {
    assert!(TrafficClass::Consensus.weight() > TrafficClass::Background.weight());
    assert!(TrafficClass::Votes.weight() > TrafficClass::Sync.weight());
}

#[test]
fn test_traffic_class_bandwidth_ratios() {
    assert!(TrafficClass::Consensus.min_bandwidth_ratio() > 0.0);
    assert!(TrafficClass::Consensus.min_bandwidth_ratio() > TrafficClass::Background.min_bandwidth_ratio());
}

#[test]
fn test_traffic_class_max_latency() {
    assert!(TrafficClass::Consensus.max_latency() < TrafficClass::Background.max_latency());
}

// ══════════════════════════════════════════════════════════
//  Token Bucket
// ══════════════════════════════════════════════════════════

#[test]
fn test_token_bucket_creation() {
    let mut bucket = TokenBucket::new(1000, 5000);
    assert!(bucket.available() > 0);
}

#[test]
fn test_token_bucket_consume() {
    let mut bucket = TokenBucket::new(1_000_000, 1_000_000);
    assert!(bucket.try_consume(100));
}

// ══════════════════════════════════════════════════════════
//  Erasure Coding
// ══════════════════════════════════════════════════════════

#[test]
fn test_erasure_config_defaults() {
    let config = ErasureCodingConfig::default();
    assert!(config.data_shards > 0);
    assert!(config.parity_shards > 0);
    assert!(config.validate().is_ok());
}

#[test]
fn test_erasure_total_shards() {
    let config = ErasureCodingConfig::default();
    assert_eq!(config.total_shards(), config.data_shards + config.parity_shards);
}

#[test]
fn test_reed_solomon_codec_creation() {
    let config = ErasureCodingConfig::default();
    let codec = ReedSolomonCodec::new(config);
    assert!(codec.is_ok());
}

#[test]
fn test_erasure_encode_decode() {
    let config = ErasureCodingConfig::default();
    let codec = ReedSolomonCodec::new(config).unwrap();

    let data = b"hello quantos erasure coding test data that is long enough for sharding";
    let block_hash = [1u8; 32];
    let shards = codec.encode(data, block_hash);
    assert!(shards.is_ok());

    let shards = shards.unwrap();
    assert!(!shards.is_empty());

    let recovered = codec.decode(&shards);
    assert!(recovered.is_ok());
    let recovered = recovered.unwrap();
    assert_eq!(&recovered[..data.len()], &data[..]);
}

#[test]
fn test_block_erasure_encoder() {
    let config = ErasureCodingConfig::default();
    let encoder = BlockErasureEncoder::new(config);
    assert!(encoder.is_ok());
}
