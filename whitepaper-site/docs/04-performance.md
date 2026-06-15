# 4. Performance

## 4.1 Throughput Targets

The "millions of TPS" claim in earlier versions has been replaced by measurable targets with explicit hardware assumptions:

| Metric | Target | Assumptions |
|--------|--------|-------------|
| Per-shard throughput | 15,000–25,000 TPS | 64-core validator, NVMe SSD, 10 Gbps NIC |
| Consensus latency | ~200 ms per slot | Δ = 100 ms, 2-round Bullshark commit |
| Finality time | ~1 second | Super-committee QC over 4–5 slots |
| Aggregate (64 shards) | ~1,000,000 TPS theoretical | Linear scaling under uniform load; real-world depends on cross-shard ratio |

**Why "theoretical" matters**: Cross-shard transactions require atomic commitment across multiple shards, which reduces effective throughput compared to intra-shard transactions. The testnet benchmark program (`quantos/benches/tps_throughput.rs`) measures both intra-shard and cross-shard throughput under controlled conditions.

## 4.2 Signature Overhead

At 20,000 ML-DSA-65 signatures/second:
- Verification: ~50 µs per signature (single-core). Parallel verification across cores handles this load.
- Bandwidth: 20,000 × 3,309 B ≈ 66 MB/s of signature data per validator. This is within 10 Gbps NIC capacity but is the dominant bandwidth consumer.
- Storage: ~5.7 TB/day of raw signatures at full load. Historical signatures are eligible for pruning after finality; only commitments are retained indefinitely.

**Batch verification**: Unlike Ed25519, ML-DSA does not have a standard batch verification algorithm that amortizes cost sub-linearly. Quantos mitigates this via (a) parallel verification across validator cores, (b) precomputed NTT tables, and (c) signature caching with SHA3-256 key deduplication.
