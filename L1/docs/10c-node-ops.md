---
sidebar_position: 28
slug: /node-operation
---

# 27. Node Operation & Validator Requirements

## 27.1 Node Software

A Quantos node is a single Rust binary (`quantos`, entry point `src/main.rs`) configurable as a full validator or a non-validating full node. It bundles the consensus engine, QuantosVM, the sharded mempool, the storage layer, the P2P stack, and the JSON-RPC server. Containerised deployment is provided via the repository `Dockerfile` and `docker-compose.yml`, with monitoring wiring under `quantos/monitoring/`.

## 27.2 Hardware Profile

The published per-shard throughput targets assume the following validator hardware profile (Performance section):

| Resource | Recommended |
|----------|-------------|
| CPU | 64 cores (parallel signature verification + parallel execution) |
| Storage | NVMe SSD (RocksDB write-heavy workload) |
| Network | 10 Gbps NIC (post-quantum signature bandwidth is the dominant consumer) |
| Memory | Sized to hold the hot working set and mempool |

The CPU and NIC requirements are driven specifically by post-quantum overhead: ML-DSA-65 verification is CPU-bound, and 3.3 KB signatures make signature data the dominant bandwidth term until aggregation compacts it.

## 27.3 Configuration

Node behaviour is set through `NodeConfig` and network config files (`quantos/config/`, `quantos/networks/`). Key parameters and their reference defaults:

```
db_path                 = "./data/quantumdag"
p2p_port                = 30303
rpc_port                = 8545
num_committees          = 1000
validators_per_committee = 21
num_shards              = 1000
committee_rotation_ms   = 100
checkpoint_interval     = 1000     # vertices per checkpoint
max_dag_parents         = 8
min_dag_parents         = 2
```

Distinct network definitions (local devnet, testnet) live under `networks/`, fixing the genesis validator set, chain id, and economic constants for each environment.

## 27.4 JSON-RPC Interface

Operators and applications interact with a node through the `qdag_*` JSON-RPC namespace (`src/rpc/`):

| Method | Purpose |
|--------|---------|
| `qdag_getBalance` / `qdag_getNonce` / `qdag_getAccount` | Account queries |
| `qdag_sendTransaction` / `qdag_getTransaction` | Submit and look up transactions |
| `qdag_getVertex` / `qdag_getDagTips` | DAG inspection |
| `qdag_getSlot` / `qdag_getEpoch` / `qdag_getFinalizedSlot` | Consensus state |
| `qdag_getMetrics` | Node and performance metrics |
| `qdag_chainId` | Chain identifier |

## 27.5 Observability

A node exposes metrics (via `qdag_getMetrics` and the monitoring stack) covering throughput, consensus latency, finalized slot, mempool depth, peer count and diversity, and rebalancing activity. These feed the sustainability and security signals described elsewhere (rent coverage, eclipse-resistance peer diversity, time-drift alerts), so operators can observe the network's health rather than infer it.

## 27.6 Benchmarking

The repository includes a benchmark suite (`quantos/benches/`, e.g. `tps_throughput.rs`) that measures intra-shard and cross-shard throughput, consensus latency, and signature-verification cost under controlled conditions. These benchmarks are the basis on which the whitepaper's performance claims are to be validated for any given configuration, consistent with the project's stated commitment to measured rather than asserted numbers.
