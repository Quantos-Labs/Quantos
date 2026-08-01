# Quantos

**Post-Quantum L1 Blockchain with Massive Parallelization, Dynamic Sharding & Sidechains**

Quantos is a next-generation Layer 1 blockchain designed for the post-quantum era, featuring high-throughput parallel DAG execution, dynamic sharding, application-specific sidechains, and NIST-standardized post-quantum cryptography.

## Key Features

- **Post-Quantum Cryptography** — ML-DSA-65 (FIPS 204), ML-KEM-768 (FIPS 203), hash-based VRF (Rescue-Prime + STARK), SPHINCS+, and ML-DSA-65 across all signing, encryption, and randomness operations
- **3-Layer Hybrid Consensus** — DAG fast path (~50ms pre-confirmation), quantum committees with VRF rotation (1000 committees x 21 validators), and ML-DSA-65 finality anchors (~1s finality)
- **Dynamic Sharding** — 1000 shards with cross-shard atomic transactions, self-healing, and STARK-accelerated validity proofs
- **STACC Scheduler** — Shared Transaction Access & Concurrency Control with fair queuing, anti-spam quotas, and state rent
- **Multi-VM Support** — EVM compatibility via revm, WASM runtime via wasmer with speculative execution, Solidity support via solang
- **zk-STARK Proofs** — Winterfell-based proof system for sharding, light client verification, and Layer-0 finality
- **Privacy Module** — Confidential state, shielded pools, stealth addresses, and confidential Layer-0 transactions
- **Encrypted Mempool** — Threshold ML-KEM encryption, fair ordering, proposer-builder separation (PBS), and accountable leader front-running protection
- **Layer-0 Hub** — PQC finality proofs, checkpoint pool, relayer infrastructure, and cross-chain light client verification
- **Multi-Chain Bridge** — Trustless bridges to Aptos, Solana, NEAR, SUI, Cosmos, Cardano, Polkadot, Stellar, TON, Tron, and Bitcoin/Stacks
- **PQC-Guard** — Foundry/Solidity contracts for post-quantum signature verification across chains
- **Token Standards** — QN-4 (fungible), QN-8 (non-fungible), QN-12 (multi-token)

## Architecture

### Consensus: 3-Layer Hybrid

```
┌─────────────────────────────────────────────────────────────┐
│                    Layer 3: Finality Anchor                  │
│       ML-DSA-65 checkpoints every 1000 DAG vertices          │
│              Super-committee of 100 validators               │
├─────────────────────────────────────────────────────────────┤
│                 Layer 2: Quantum Committees                  │
│        1000 committees x 21 validators = 21,000 total        │
│      Hash-based VRF (Rescue-Prime + STARK) rotation          │
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
| **ML-DSA-65** | Legacy/compatibility signatures | NIST Round 3 |
| **SPHINCS+** | Hash-based fallback signatures | NIST level 3 |
| **Hash-based VRF** | Committee selection randomness | Rescue-Prime + STARK |
| **SHA3-256/SHAKE256** | Hashing | Quantum-resistant |

### Transaction Flow

```
1. User signs TX with ML-DSA-65
           |
2. TX propagated via turbo gossip (PQ P2P)
           |
3. TX added to sharded encrypted mempool
           |
4. Committee creates DAG vertex (2-8 parents)
           |
5. Optimistic parallel execution
           |
6. Committee votes (14/21 threshold)
           |
7. Pre-confirmation (~50ms)
           |
8. Checkpoint finality (~1s)
```

## Repository Structure

```
Quantos/
├── L1/                            # Blockchain core (Rust)
│   ├── src/
│   │   ├── consensus/             # 3-layer hybrid consensus, committees, slashing, view change
│   │   ├── crypto/                # ML-DSA, ML-KEM, ML-DSA-65, SPHINCS+, VRF, NIZK, threshold
│   │   ├── network/               # PQ P2P, turbo gossip, erasure coding, NAT traversal
│   │   ├── vm/                    # EVM (revm), WASM (wasmer), MVCC, speculative exec
│   │   ├── state/                 # State manager, STM, compression, archival pruning
│   │   ├── storage/               # RocksDB persistence
│   │   ├── mempool/               # Encrypted mempool, PBS, fair ordering, accountable leader
│   │   ├── sharding/              # Cross-shard, reshard, self-healing, STARK-accelerated
│   │   ├── l0/                    # Layer-0 hub, light client, relays, checkpoints, PQC guard
│   │   ├── stacc/                 # STACC scheduler, quotas, tokenomics, state rent
│   │   ├── privacy/               # Confidential state, shielded pool, stealth addresses
│   │   ├── security/              # DDoS, eclipse, sybil, quantum, time sync
│   │   ├── dag/                   # DAG graph, ordering, ingress
│   │   ├── types/                 # Block, tx, account, checkpoint, vertex, PQC migration
│   │   ├── rpc/                   # JSON-RPC server, handlers, metrics, atomic swaps
│   │   ├── standards/             # QN-4, QN-8, QN-12 token standards
│   │   ├── sync/                  # Snapshot synchronization
│   │   ├── zk/                    # zk-STARK proof system
│   │   ├── main.rs                # Node entry point
│   │   ├── cli.rs                 # CLI tool
│   │   └── solang_cli.rs          # Solidity CLI
│   ├── tests/                     # Integration tests by module
│   ├── benches/                   # TPS, testnet TPS, PQC bloat benchmarks
│   ├── solidity-contracts/        # Solidity testnet prototypes
│   ├── sdk/                       # SDK
│   ├── scripts/                   # Deployment & utility scripts
│   ├── networks/                  # Network configurations
│   ├── config/                    # Node configurations
│   ├── monitoring/                # Monitoring setup
│   ├── docs/                      # 35 technical specification docs
│   ├── Dockerfile                 # Container build
│   └── docker-compose.yml         # Multi-node orchestration
├── base-bridge/                   # Multi-chain bridge contracts (Hardhat)
├── bridge-relayer/                # Bridge relayer service (TypeScript)
├── l0-relayer/                    # Layer-0 relayer service (TypeScript)
├── pqc-guard/                     # PQC-Guard contracts (Foundry/Solidity)
├── quantos-l0-sdk/                # Layer-0 SDK (Rust + TypeScript)
├── quantos-l0-sdk-js/             # Layer-0 SDK (JavaScript)
├── quantos-wallet-core/           # Wallet core library (Rust/WASM)
├── quantos-wallet-extension/      # Browser wallet extension (React/TypeScript)
├── quantos-wallet-server/         # Wallet backend server (Rust/Axum)
├── explorer-api/                  # Block explorer API (TypeScript/Supabase)
├── landing/                       # Landing page (React/Vite/Tailwind)
├── docs/                          # Audit scope, threat model, protocol overview
├── AUDIT_SCOPE.md                 # Audit scope definition
├── DEPLOYMENT.md                  # Deployment guide
├── Cargo.toml                     # Workspace root
└── CHANGELOG.md                   # Version history
```

## Quick Start

### Prerequisites

- Rust 1.82+ (with `cargo`)
- RocksDB dependencies (`librocksdb-dev` on Linux, `rocksdb` via Homebrew on macOS)
- Node.js 18+ (for TypeScript components)
- Docker & Docker Compose (optional, for containerized deployment)

### Build

```bash
# Build the entire Rust workspace
cargo build --release

# Build specific crate
cargo build --release -p quantos
```

### Run Node

```bash
# Run a full node
cargo run --release -p quantos

# Run with a custom config file
cargo run --release -p quantos -- --config config/testnet.toml
```

### Configuration

Default node configuration:

```rust
NodeConfig {
    db_path: "./data/quantos",
    p2p_port: 30303,
    rpc_port: 8545,
    metrics_port: 9615,
    num_committees: 1000,
    validators_per_committee: 21,
    num_shards: 1000,
    committee_rotation_ms: 100,
    checkpoint_interval: 1000,
    max_dag_parents: 8,
    min_dag_parents: 1,
    dynamic_sharding: true,
    min_shards: 100,
    max_shards: 10000,
    execution_threads: num_cpus::get(),
    sidechains_enabled: true,
    max_sidechains: 1000,
    stacc_require_activation: true,
    network_name: "testnet",
}
```

## RPC API

All methods use the `qnt_` prefix. The RPC server listens on port 8545 by default and supports both HTTP and WebSocket (for subscriptions).

### Account & State

| Method | Description |
|--------|-------------|
| `qnt_getBalance` | Get account balance (hex) |
| `qnt_getTransactionCount` | Get account nonce (hex) |
| `qnt_getAccount` | Get full account info (balance, nonce, stake, code) |
| `qnt_getCode` | Get contract bytecode at address |
| `qnt_getStorageAt` | Get storage slot at address |
| `qnt_getStateRoot` | Get current state root |

### Transactions

| Method | Description |
|--------|-------------|
| `qnt_sendRawTransaction` | Submit a pre-signed transaction (hex) |
| `qnt_sendRawTransactionBatch` | Submit a batch of signed transactions |
| `qnt_sendTransaction` | Server-side signing (private key in request) |
| `qnt_getTransactionByHash` | Get transaction by hash |
| `qnt_getTransactionReceipt` | Get transaction receipt |
| `qnt_pendingTransactions` | List pending transactions (optional limit) |
| `qnt_txPoolStatus` | Get mempool/ingress buffer status |
| `qnt_getRecentTransactions` | Get recent confirmed transactions |
| `qnt_getReceiptsSinceSlot` | Get receipts since a given slot |
| `qnt_estimateGas` | Estimate compute units for a call |

### Block & DAG

| Method | Description |
|--------|-------------|
| `qnt_blockNumber` | Get current slot (block height) |
| `qnt_chainId` | Get chain ID |
| `qnt_getSlot` | Get current slot |
| `qnt_getFinalizedSlot` | Get latest finalized slot |
| `qnt_getVertexByHash` | Get DAG vertex by hash |
| `qnt_getDagTips` | Get DAG tips for a shard |
| `qnt_getShardInfo` | Get shard info (vertices, tx count) |

### Network & Node

| Method | Description |
|--------|-------------|
| `qnt_nodeInfo` | Get node info (version, peer_id, p2p_multiaddrs, slot, state root) |
| `qnt_health` | Health check (slot lag, pending txs, active validators) |
| `qnt_syncing` | Get sync status |
| `qnt_peerCount` | Get connected peer count |
| `qnt_getPeers` | List connected peers with latency, reputation |
| `qnt_getMetrics` | Get consensus & network metrics |

### Validators

| Method | Description |
|--------|-------------|
| `qnt_getValidators` | List all active validators |
| `qnt_getValidatorByAddress` | Get validator info by address |
| `qnt_getValidatorStats` | Get validator statistics |
| `qnt_getEpochRewards` | Get epoch rewards distribution |

### Contracts

| Method | Description |
|--------|-------------|
| `qnt_call` | Read-only contract call |
| `qnt_deployContract` | Deploy a contract (WASM or EVM bytecode) |
| `qnt_getContractMetadata` | Get contract metadata |
| `qnt_verifyContract` | Verify contract bytecode |

### Tokens

| Method | Description |
|--------|-------------|
| `qnt_getNFTs` | Get NFTs owned by an address (QN-8) |
| `qnt_getTokenBalances` | Get fungible token balances (QN-4) |

### Layer-0

| Method | Description |
|--------|-------------|
| `qnt_submitExternalCheckpoint` | Submit external chain checkpoint |
| `qnt_getL0Proof` | Get L0 proof by hash |
| `qnt_getLatestL0Proof` | Get latest L0 proof |
| `qnt_getL0Metrics` | Get L0 hub metrics |
| `qnt_registerSubnet` | Register a subnet |
| `qnt_getSubnet` | Get subnet info by ID |

### Key Management

| Method | Description |
|--------|-------------|
| `qnt_generateKeyPair` | Generate a new ML-DSA-65 keypair |

### WebSocket Subscriptions

| Method | Description |
|--------|-------------|
| `qnt_subscribe` | Subscribe to events (newSlots, newTransactions, validatorChanges) |
| `qnt_unsubscribe` | Unsubscribe from a subscription |

### Example

```bash
# Get node info (including peer_id and multiaddrs)
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qnt_nodeInfo","params":[],"id":1}'

# Get balance
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qnt_getBalance","params":["QTS:ab12...ff",null],"id":1}'

# Get metrics
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qnt_getMetrics","params":[],"id":1}'

# Server-side signed transfer
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qnt_sendTransaction","params":[{"from_private_key":"QTS:...","to":"QTS:...","amount":"QTS:de0b6b3a7640000","tx_type":"transfer"}],"id":1}'
```

## CLI

The `quantos-cli` binary provides a convenient interface to the RPC API.

```bash
# Build the CLI
cargo build --release -p quantos

# Node info (shows peer_id, multiaddrs, slot, state root)
./target/release/quantos-cli node info

# Health check
./target/release/quantos-cli node health

# Account balance
./target/release/quantos-cli account balance QTS:ab12...ff

# Generate a new keypair
./target/release/quantos-cli keygen

# Transfer tokens (server-side signing)
./target/release/quantos-cli tx transfer \
  --privkey QTS:... --to QTS:... --amount QTS:de0b6b3a7640000

# Stake tokens
./target/release/quantos-cli tx stake --privkey QTS:... --amount QTS:...

# Register as a validator
./target/release/quantos-cli tx register-validator \
  --privkey QTS:... \
  --amount QTS:de0b6b3a7640000 \
  --vrf-pubkey QTS:... \
  --commission-bps 500

# Exit as a validator
./target/release/quantos-cli tx validator-exit --privkey QTS:...

# List validators
./target/release/quantos-cli validator list

# Get transaction receipt
./target/release/quantos-cli tx receipt QTS:...

# DAG tips for shard 0
./target/release/quantos-cli dag tips 0

# Mempool status
./target/release/quantos-cli mempool status

# Deploy a contract
./target/release/quantos-cli contract deploy --bytecode contract.wasm --deployer QTS:...

# JSON output
./target/release/quantos-cli --output json node info

# Connect to a remote node
./target/release/quantos-cli --rpc http://164.132.99.87:8545 node info
```

### Validator Setup

1. Generate a keypair:
   ```bash
   ./target/release/quantos-cli keygen
   ```
2. Get the bootstrap node's peer ID and multiaddr:
   ```bash
   ./target/release/quantos-cli --rpc http://<bootstrap-ip>:8545 node info
   ```
3. Start your node with the bootstrap peer:
   ```bash
   QUANTOS_BOOTSTRAP_PEERS="/ip4/<bootstrap-ip>/tcp/30303/p2p/<peer-id>" \
     cargo run --release -p quantos -- --validator
   ```
4. Register as a validator:
   ```bash
   ./target/release/quantos-cli tx register-validator \
     --privkey QTS:... \
     --amount QTS:de0b6b3a7640000 \
     --vrf-pubkey QTS:...
   ```

## Docker Deployment

```bash
cd L1
docker-compose up -d
```

See `DEPLOYMENT.md` for detailed deployment instructions.

## Security

### Post-Quantum Resistance

- All signatures use NIST-standardized post-quantum algorithms (FIPS 204, FIPS 203)
- 128-bit security against both classical and quantum attacks
- Grover's algorithm resistance (2^128 operations)
- No classical-only cryptographic assumptions in the consensus critical path

### Byzantine Fault Tolerance

- 66% threshold in each committee (14/21 validators)
- VRF-based random committee rotation prevents targeted attacks
- Slashing: 100% stake loss for double-signing
- Eclipse and sybil protection at the network layer

### Security Modules

- **DDoS Protection** — Rate limiting, reputation scoring, bandwidth scheduling
- **Eclipse Protection** — Peer diversity enforcement, outbound connection rotation
- **Sybil Protection** — Stake-based identity, PQC peer verification
- **Quantum Security** — PQC migration path, hybrid signature support
- **Time Synchronization** — Byzantine-tolerant NTP-style time sync

## Development

### Run Tests

```bash
# All workspace tests
cargo test --workspace

# Specific module
cargo test -p quantos -- consensus
```

### Run Benchmarks

```bash
cargo bench -p quantos
```

### Build Other Components

```bash
# Bridge relayer
cd bridge-relayer && npm install && npm run build

# L0 relayer
cd l0-relayer && npm install && npm run build

# Explorer API
cd explorer-api && npm install && npm run build

# Wallet extension
cd quantos-wallet-extension && npm install && npm run build

# PQC-Guard (requires Foundry)
cd pqc-guard && forge build
```

## Documentation

- `L1/docs/` — 35 technical specification documents covering protocol design, cryptography, consensus, sharding, VM, security, governance, and more
- `DEPLOYMENT.md` — Deployment guide
- `docs/THREAT_MODEL.md` — Threat model and risk assessment

## Roadmap

- [x] Core types & structures
- [x] Post-quantum cryptography (ML-DSA-65, ML-KEM-768, hash-based VRF)
- [x] RocksDB storage
- [x] DAG structure & ordering
- [x] Sharded encrypted mempool
- [x] Committee management & VRF rotation
- [x] 3-layer consensus (fast path, committees, finality)
- [x] PQ P2P networking with turbo gossip
- [x] JSON-RPC API
- [x] EVM compatibility (revm) + Solidity (solang)
- [x] WASM runtime (wasmer)
- [x] Dynamic sharding with cross-shard atomic transactions
- [x] STACC scheduler
- [x] zk-STARK proof system
- [x] Layer-0 hub with PQC finality proofs
- [x] Privacy module (confidential state, shielded pool, stealth)
- [x] Multi-chain bridge (11 chains)
- [x] PQC-Guard cross-chain verification
- [x] Token standards (QN-4, QN-8, QN-12)
- [x] Wallet core, server, and browser extension
- [x] Explorer API
- [x] Docker deployment with monitoring
- [ ] Mainnet launch
- [ ] Threshold ML-KEM encrypted mempool (research phase, behind feature flag)

## License

Business Source License 1.1 (**BUSL-1.1**) — Quantos Labs SAS

- **Licensor**: Quantos Labs SAS
- **Change Date**: 2030-07-23 (4 years after publication)
- **Change License**: Apache-2.0
- **Additional Use Grant**: Running validator nodes, full nodes, and light clients on the Quantos testnet and mainnet, and building applications, tools, and services that interact with the Quantos blockchain. Forking the software to create a competing blockchain network is prohibited until the Change Date.

See the [LICENSE](LICENSE) file for the full license text.

---

**Quantos** — Built for the post-quantum era.
