# Quantos

**Post-Quantum L1 Blockchain with Massive Parallelization, Dynamic Sharding & Sidechains**

Quantos is a revolutionary Layer 1 blockchain featuring high-throughput parallel DAG execution, dynamic sharding, and application-specific sidechains.

## Architecture

### Consensus: Quantos 3-Layer Hybrid

```
┌─────────────────────────────────────────────────────────────┐
│                    Layer 3: Finality Anchor                  │
│       ML-DSA-65 checkpoints every 1000 DAG vertices          │
│              Super-committee of 100 validators               │
├─────────────────────────────────────────────────────────────┤
│                 Layer 2: Quantum Committees                  │
│        1000 committees × 21 validators = 21,000 total        │
│         Hash-based VRF (SHAKE256) rotation every 100ms       │
│              ML-DSA-65 aggregated signatures                 │
├─────────────────────────────────────────────────────────────┤
│                   Layer 1: Fast Path (DAG)                   │
│          Parallel transaction inclusion & execution          │
│               2-8 parent references per vertex               │
│                 Optimistic parallel execution                │
└─────────────────────────────────────────────────────────────┘
```

### Post-Quantum Cryptography

| Algorithm | Usage | Security Level |
|-----------|-------|----------------|
| **ML-DSA-65** | Transaction, vertex & checkpoint signatures | FIPS 204, NIST level 3 |
| **ML-KEM-768** | Encrypted mempool, P2P handshake | FIPS 203, NIST level 3 |
| **Hash-based VRF** | Committee selection randomness | SHAKE256, quantum-resistant |
| **SHA3-256/SHAKE256** | Hashing | Quantum-resistant |

### Key Features

- **DAG Structure**: No sequential blocks, massive parallelization
- **1000 Shards**: Independent parallel execution
- **Optimistic Execution**: Speculative execution with rare rollbacks (<0.1%)
- **Fast Finality**: Pre-confirmation in ~50ms, finality in ~1s
- **RocksDB Storage**: High-performance persistent storage

## Project Structure

```
quantos/
├── src/
│   ├── main.rs              # Entry point & node configuration
│   ├── crypto/              # Post-quantum cryptography
│   │   ├── ml_dsa.rs        # ML-DSA-65 signatures (FIPS 204)
│   │   ├── kyber_kem.rs     # ML-KEM-768 (FIPS 203)
│   │   ├── vrf_hashbased.rs # Hash-based VRF (SHAKE256)
│   │   ├── vrf.rs           # Verifiable Random Function
│   │   ├── hash.rs          # SHA3, SHAKE256, Merkle trees
│   │   └── keypair.rs       # Key management
│   ├── types/               # Core data structures
│   │   ├── transaction.rs   # Transaction types
│   │   ├── account.rs       # Account & validator state
│   │   ├── vertex.rs        # DAG vertex structure
│   │   ├── checkpoint.rs    # Finality checkpoints
│   │   └── block.rs         # Genesis & chain params
│   ├── state/               # State management
│   │   ├── manager.rs       # Account state & validation
│   │   └── executor.rs      # Parallel & optimistic execution
│   ├── storage/             # Persistence layer
│   │   ├── rocks.rs         # RocksDB implementation
│   │   └── keys.rs          # Storage key schemas
│   ├── dag/                 # DAG structure
│   │   ├── graph.rs         # DAG graph operations
│   │   └── ordering.rs      # Topological ordering
│   ├── mempool/             # Transaction pool
│   │   └── mod.rs           # Sharded mempool
│   ├── consensus/           # QuantumDAG consensus
│   │   ├── committee.rs     # Committee management & VRF
│   │   ├── fast_path.rs     # Layer 1 fast path
│   │   ├── finality.rs      # Layer 3 finality
│   │   └── quantum_dag.rs   # Main consensus orchestrator
│   ├── network/             # P2P networking
│   │   ├── p2p.rs           # libp2p implementation
│   │   ├── gossip.rs        # Message propagation
│   │   └── sync.rs          # Chain synchronization
│   └── rpc/                 # JSON-RPC API
│       ├── server.rs        # RPC server & methods
│       └── handlers.rs      # Transaction builders
└── Cargo.toml
```

## Quick Start

### Prerequisites

- Rust 1.75+ 
- RocksDB dependencies
- OpenSSL

### Build

```bash
cd quantumdag-chain
cargo build --release
```

### Run Node

```bash
cargo run --release
```

### Configuration

Default configuration (can be overridden):

```rust
NodeConfig {
    db_path: "./data/quantumdag",
    p2p_port: 30303,
    rpc_port: 8545,
    num_committees: 1000,
    validators_per_committee: 21,
    num_shards: 1000,
    committee_rotation_ms: 100,
    checkpoint_interval: 1000,
    max_dag_parents: 8,
    min_dag_parents: 2,
}
```

## RPC API

### Endpoints

| Method | Description |
|--------|-------------|
| `qdag_getBalance` | Get account balance |
| `qdag_getNonce` | Get account nonce |
| `qdag_sendTransaction` | Submit transaction |
| `qdag_getTransaction` | Get transaction by hash |
| `qdag_getVertex` | Get DAG vertex by hash |
| `qdag_getSlot` | Get current slot |
| `qdag_getEpoch` | Get current epoch |
| `qdag_getFinalizedSlot` | Get latest finalized slot |
| `qdag_getMetrics` | Get node metrics |
| `qdag_getDagTips` | Get DAG tips for shard |
| `qdag_getAccount` | Get full account info |
| `qdag_chainId` | Get chain ID |

### Example

```bash
# Get balance
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qdag_getBalance","params":["0x..."],"id":1}'

# Get metrics
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qdag_getMetrics","params":[],"id":1}'
```

## Transaction Flow

```
1. User signs TX with ML-DSA-65
           ↓
2. TX propagated via gossip (QUIC)
           ↓
3. TX added to sharded mempool
           ↓
4. Committee creates DAG vertex (2-8 parents)
           ↓
5. Optimistic parallel execution
           ↓
6. Committee votes (14/21 threshold)
           ↓
7. Pre-confirmation (~50ms)
           ↓
8. Checkpoint finality (~1s)
```

## Security

### Post-Quantum Resistance

- All signatures use NIST-standardized post-quantum algorithms
- 128-bit security against both classical and quantum attacks
- Grover's algorithm resistance (2^128 operations)

### Byzantine Fault Tolerance

- 66% threshold in each committee (14/21 validators)
- VRF-based random committee rotation prevents targeted attacks
- Slashing: 100% stake loss for double-signing

## Development

### Run Tests

```bash
cargo test
```

### Run Benchmarks

```bash
cargo bench
```

## Roadmap

- [x] Core types & structures
- [x] Post-quantum cryptography (ML-DSA-65 FIPS 204, ML-KEM-768 FIPS 203, Hash-based VRF)
- [x] RocksDB storage
- [x] DAG structure & ordering
- [x] Sharded mempool
- [x] Committee management & VRF
- [x] 3-layer consensus (FastPath, Committees, Finality)
- [x] P2P networking (libp2p)
- [x] JSON-RPC API
- [ ] Custom VM (coming soon)
- [ ] Smart contracts
- [ ] Cross-shard transactions
- [ ] Light client support

## License

MIT License - Quantos Labs

---

**QuantumDAG Chain** - Built for the post-quantum era 🚀
