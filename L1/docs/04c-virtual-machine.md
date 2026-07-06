---
sidebar_position: 12
slug: /virtual-machine
---

# 11. Virtual Machine & Smart Contracts

## 11.1 QuantosVM: a WASM Execution Environment

Smart contracts on Quantos execute inside **QuantosVM**, a WebAssembly (WASM) runtime built on the production-grade Wasmer engine with the Cranelift compiler backend (`quantos/src/vm/runtime.rs`). WASM was chosen over a bespoke bytecode for three reasons: it has a formally specified, sandboxable execution model; it is the target of mature compilers for many high-level languages; and it admits ahead-of-time and just-in-time native compilation for performance.

Each execution runs in an isolated sandbox with hard resource limits:

```
QuantosVmConfig (defaults):
  max_memory_pages    = 1024        # 64 MB (64 KB per page)
  max_stack_size      = 1 MB
  max_compute_units   = 100,000,000 # 100M CU per execution
  debug_mode          = false
```

Because Quantos is zero-gas (STACC section), the VM does **not** meter fees. Instead it meters **Compute Units (CU)** purely as a resource-exhaustion safeguard: an execution that exceeds its CU budget is aborted with `OutOfGas`, protecting validators from unbounded or malicious contracts without charging the user a per-opcode fee.

### Host functions

Contracts interact with chain state and the environment through a namespaced host-function interface, injected into the WASM import object:

- `qnt_storage_*` — read and write contract storage slots.
- `qnt_block_*` — access block height, timestamp, and other context.
- `qnt_crypto_*` — post-quantum primitives, including native Dilithium verification (`verify_dilithium`, `verify_dilithium_batch`), exposed so contracts can themselves verify PQC signatures cheaply.

## 11.2 Bytecode-Invisible Architecture

A distinctive design choice in QuantosVM is that **contract bytecode is never publicly readable** (`vm/bytecode_protection.rs`). On most chains, deployed bytecode is fully public, which aids transparency but also hands attackers a free copy of every contract to analyse for exploits. Quantos splits a deployed contract into a public and a private part:

| Public | Private (encrypted at rest) |
|--------|------------------------------|
| Contract hash (32 bytes) | WASM bytecode (AES-256-GCM encrypted) |
| Metadata (size, deployer, timestamp) | Source maps (if provided) |
| ABI / interface definitions | Debug symbols (if provided) |

The on-chain commitment is the 32-byte contract hash; the executable bytecode is stored encrypted and decrypted only inside the sandbox at execution time, with an integrity check (`IntegrityCheckFailed`) binding the decrypted bytes to the public hash. The public ABI remains available so that wallets, explorers, and other contracts can still construct valid calls. This is a defence-in-depth measure, not a substitute for cryptographic security: the protocol's safety never depends on bytecode secrecy.

## 11.3 Multi-Language, Multi-VM Compatibility

Quantos does not ask developers to learn a new language. Two compatibility layers let existing Ethereum and Substrate toolchains target QuantosVM directly.

### Solang compatibility (Solidity → WASM)

The `vm/solang_compat.rs` layer provides production host-function shims for Solidity contracts compiled with **Solang** (the Solidity-to-WASM compiler that targets Substrate/Polkadot's `seal` ABI). Solang-emitted imports are mapped onto the QuantosVM host environment:

| Solang import | QuantosVM mapping |
|---------------|-------------------|
| `seal0::seal_input` | `HostEnv.input_data` |
| `seal0::seal_return` | `HostEnv.return_data` / revert |
| `seal0::seal_caller` | `HostEnv.caller` |
| `seal0::seal_address` | `HostEnv.contract_address` |
| `seal0::seal_block_number` | `HostEnv.block_height` |
| `seal0::seal_now` | `HostEnv.block_timestamp` |
| `seal1::set_storage` / `get_storage` | `HostEnv.storage` |
| `seal0::deposit_event` | `HostEnv.logs` |
| `seal0::hash_keccak_256` | Keccak-256 (Ethereum-compatible) |

Storage and compute operations carry fixed CU costs (e.g. `CU_SEAL_STORAGE_WRITE = 5000`, `CU_SEAL_STORAGE_READ = 1000`, `CU_SEAL_HASH_PER_BYTE = 1`), so Solidity contracts get deterministic resource accounting without any source changes.

### ERC compatibility (Ethereum ABI → native tokens)

The `vm/erc_compat.rs` router lets standard Ethereum tooling — ethers.js, wagmi, Hardhat, MetaMask — talk to native Quantos tokens. It decodes raw ERC-20/721/1155 calldata (4-byte selector + ABI-encoded parameters), maps Ethereum's 20-byte addresses to Quantos's 32-byte addresses and `uint256` to `u64` (with overflow checks), dispatches to the native QN4/QN8/QN12 token methods (Native Token Standards section), and re-encodes return values and event topics in Ethereum format so existing indexers work unchanged. Critically, every operation in this router is **purely deterministic** — no RNG, no time-dependence, no floating point — making it safe to run on the consensus path.

### EVM layer

`vm/evm.rs` provides an EVM-semantics execution path and, together with `vm/precompiles.rs`, a set of precompiled contracts for common cryptographic operations, so that contracts depending on EVM precompiles behave as expected.

## 11.4 Parallel Contract Execution

The headline scalability feature of QuantosVM is that **contract calls within a shard execute in parallel**, not sequentially. Three cooperating subsystems make this safe.

### Transaction dependency graph

`vm/tx_dependency_graph.rs` analyses the read/write sets of pending transactions and builds a dependency graph. Transactions whose access sets are disjoint are independent and can run concurrently; transactions that conflict are ordered. This converts a flat transaction list into a maximally parallel schedule.

### MVCC (Multi-Version Concurrency Control)

`vm/mvcc.rs` gives each transaction a consistent snapshot of state via versioned values, so parallel executions never block on locks:

- **Snapshot isolation**: every transaction reads a consistent version of state as of its start.
- **Optimistic concurrency**: conflicts are detected at commit time, not prevented by locking.
- **Version chains**: each value retains a chain of `Version<T>` entries (timestamp, creating txn, committed flag, link to previous), enabling historical reads and clean rollback.
- **Write-write conflict detection**: two transactions that write the same slot are detected at commit; one is re-executed.
- **Garbage collection**: obsolete versions are reclaimed once no live snapshot can observe them.

### Speculative execution

`vm/speculative_execution.rs` executes transactions *during* the consensus rounds, before final ordering is known, to hide execution latency behind consensus latency. Each speculative transaction moves through a state machine — `Pending → Executing → Speculated → Confirmed`, or `RolledBack` / `Failed` — and keeps `AccountSnapshot` and storage-slot snapshots so that, if consensus produces an ordering that invalidates the speculation, the affected transactions are cheaply rolled back and re-executed. In the common case (low conflict rate), speculation is correct and execution is effectively free; rollbacks are rare.

## 11.5 Tiered JIT Compilation

For contracts that run frequently, interpretation is wasteful. `vm/jit_compiler.rs` implements **tiered, profile-guided compilation**:

```
Interpreter  ──hot──▶  Baseline JIT  ──hotter──▶  Optimized JIT
   (slow,                (fast compile,             (slow compile,
    no compile)           moderate speed)            fastest execution)
```

- **Hot-path detection**: execution counters identify hot contract paths; cold code stays interpreted to avoid wasting compilation effort.
- **Code caching**: compiled native code is cached persistently, so a popular contract is compiled once and reused across executions and restarts.
- **Inline caching**: repeated property/method lookups are accelerated with inline caches.
- **Deoptimization**: if an assumption baked into optimised code is violated, the VM safely falls back ("deopts") to the interpreter, preserving correctness.

The compiler operates over a compact opcode set (stack ops, arithmetic, comparison, bitwise, control flow, storage), bridging WASM execution and native machine code for the hottest paths.

## 11.6 Determinism and Consensus Safety

Every component on the execution path is held to a strict determinism requirement: identical inputs must produce identical outputs on every validator, or consensus would fork. The codebase enforces this boundary explicitly — for example, the ERC router is documented as RNG-free and time-free, the adaptive-cryptography ML predictor (Post-Quantum Cryptography section) is marked advisory-only and excluded from consensus, and the JIT is required to produce results bit-identical to the interpreter. Non-deterministic optimisations are permitted only as *local hints* that never change the committed state transition.
