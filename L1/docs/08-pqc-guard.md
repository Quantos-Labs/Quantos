---
sidebar_position: 21
---

# 20. PQC-Guard: Multi-VM Smart Account

PQC-Guard is the application-layer manifestation of the Quantos L0 — a quantum-resistant smart account that any user or dApp can deploy on any supported chain. After migrating to a post-quantum key, funds are released exclusively through M-of-N attestations from the Quantos validator set, verified on-chain using a WOTS (Winternitz One-Time Signature) scheme with keccak256, requiring no lattice arithmetic on the destination chain.

## 20.1 Cryptographic Primitives

The on-chain verification relies entirely on hash operations available on all VMs:

- **WOTS (w=16, LEN=67)**: 64 message digits + 3 checksum digits in base-16. Each digit chain applied `W-1-d` times; the compressed public key is `keccak256(concat(chain_i))`.
- **Attestor Merkle tree**: `attestor_leaf = keccak256("PQCG_ATTESTOR_LEAF" ‖ id ‖ wots_root)`. A binary Merkle tree of attestor leaves; the root is anchored on-chain by the L0 oracle.
- **WOTS leaf**: `wots_leaf = keccak256("PQCG_WOTS_LEAF" ‖ wots_pub)` — domain-separated to prevent second-preimage across tree levels.
- **Authorization digest**: `keccak256(account ‖ to ‖ value ‖ data_hash ‖ nonce ‖ chain_id)` — canonical across all VMs.

## 20.2 Canonical Binary Serialization

Cross-VM attestation blobs use a chain-agnostic binary format:

```
blob := uint32(N) ‖ proof_0 ‖ … ‖ proof_{N-1}

proof_i :=
    id            [32 bytes]   attestor identifier
    wots_root     [32 bytes]   WOTS tree root
    uint64(li)    [8 bytes]    leaf index in WOTS tree
    uint32(|sig|) [4 bytes]    number of WOTS chains (LEN=67)
    sig           [67×32 bytes]
    uint32(|path|)[4 bytes]    Merkle proof depth
    path          [depth×32 bytes]
    uint64(si)    [8 bytes]    attestor index in set tree
    uint32(|sp|)  [4 bytes]    set Merkle proof depth
    sp            [depth×32 bytes]
```

The TypeScript SDK (`pqc-guard/sdk/src/canonical.ts`) implements serialization and per-chain digest computation for all seven VM families.

## 20.3 VM Ports

| Chain | Runtime | Language | Tests | Framework |
|-------|---------|----------|-------|-----------|
| Ethereum, Base, Arbitrum, Optimism, Polygon, Avalanche, BSC | EVM | Solidity | Foundry | ✅ |
| Tron | TVM (EVM) | Solidity | Foundry | ✅ |
| Solana | SVM | Rust (Anchor) | `cargo test` | ✅ 5/5 |
| Sui | Move 2024 | Move | `sui move test` | ✅ 5/5 |
| Aptos | Move | Move | `aptos move test` | ✅ 3/3 |
| NEAR | WASM | Rust (near-sdk 5.x) | `cargo test` | ✅ 4/4 |
| Stellar | Soroban | Rust (soroban-sdk) | `cargo test` | ✅ 4/4 |
| Bitcoin / Stacks | Clarity | Clarity | `clarinet test` | ✅ |
| Canton Network | DAML | DAML | `daml test` | ✅ |
| Internet Computer | WASM (canister) | Rust (ic-cdk) | `cargo test` | ✅ 4/4 |

Each port implements the same four-function interface: `migrate`, `finalize_migration`, `execute`, and `escape`/`recovery`. Non-EVM divergences are documented in `base-bridge/PQC_GUARD_PORTS.md`.

## 20.4 Guardian Escape Hatch

If the Quantos network becomes unavailable, funds are never frozen:

- After `RECOVERY_TIMEOUT` (30 days of inactivity), the guardian threshold is unlocked.
- M-of-N guardians can collectively sweep funds to a recovery address.
- The escape hatch is enforced by a block/time oracle on each VM, independently of Quantos uptime.

## 20.5 Runtime-Specific Implementation Constraints

Each non-EVM runtime imposes constraints that shaped the canonical design:

**Stellar / Soroban (Rust)**: The `soroban_sdk::Bytes` type does not expose a `to_array()` method or a generic `extend_from_slice()`. All binary encoding is done via sequential `push_back(byte)` calls with explicit bit-shifting. The `Hash<32>` return type of `soroban_sdk::env::keccak256` is wrapped in a helper `keccak_bytes(env, &Bytes) -> BytesN<32>` that converts via `.into()`, centralizing the type normalization. Because Soroban does not support multiple `#[contract]` exports from a single binary (symbol collision), the oracle's initialization function is exported as `init_oracle` rather than `init`.

**NEAR (near-sdk 5.x / Rust)**: The `near-sdk` 5.x API uses the combined `#[near]` macro applied to both the struct and its implementation block; gas is expressed as `Gas::from_tgas(u64)` and token amounts as `NearToken::from_yoctonear(u128)`. Running `cargo test` against NEAR contract crates requires the `unit-testing` feature flag declared in `[dev-dependencies]` of `Cargo.toml`. The contract's `keccak256` is provided by the `near_sdk::env::keccak256_array` host function, which returns `[u8; 32]` directly.

**Aptos (Move)**: Aptos Move uses the `aptos_framework::event::emit<T>(event: T)` function, which requires the type parameter `T` to have `has drop, store` abilities. All four event structs declare these abilities explicitly.

**Sui (Move 2024.beta)**: The Sui `Move.toml` declares `edition = "2024.beta"`, which mandates that all struct types accessible outside their defining module carry the `public` keyword. Event types are emitted via `sui::event::emit<T>()` and require `has copy, drop` abilities — no `store` is needed (unlike Aptos).

**Solana (Anchor / SVM)**: Anchor's `#[account]` macro derives `AnchorSerialize` and `AnchorDeserialize` for all state structs. PDA seeds are defined in the `#[derive(Accounts)]` context struct using `seeds = [b"...", ...]` and `bump` fields. The Solana `keccak::hash()` function operates on `&[u8]` and returns a `keccak::Hash` with a `.0: [u8; 32]` field.

**EVM / Tron (Solidity)**: Tron's TVM is byte-compatible with the EVM; the same `PQCGuard.sol` bytecode deploys on Tron without modification. The only runtime distinction is the chain ID in the authorization digest.

**Bitcoin / Stacks (Clarity)**: Clarity is a decidable, non-Turing-complete language with no loops or recursion beyond a bounded depth. WOTS chain verification (67 chains × up to 15 keccak256 iterations) is implemented via unrolled helper functions (`hash-1` through `hash-15`). State is stored in `define-data-var` and `define-map`; the authorization digest uses `keccak256(utf8(principal))` for the `toField`. The L0 anchor calls the existing `QuantosL0Verifier.clar`'s `is-proof-verified` read-only function. POC uses block-height-based delays (144 blocks ≈ 24h, 4320 blocks ≈ 30d) instead of wall-clock time.

**Canton Network (DAML)**: DAML is a functional language where smart contracts are templates with choices (actions). State is managed via template fields and the `signatory`/`controller` pattern. keccak256 is available via `DA.Hash.SHA3`. The L0 anchoring uses a separate `L0ProofRegistry` template that records verified proofs; the guard's `UpdateAttestorSet` choice checks membership. The `execute` choice performs a guarded asset transfer (Canton's atomic settlement model), not arbitrary contract calls. The authorization digest normalizes `to` as `keccak256(utf8(partyId))`.

**Internet Computer (Rust / ic-cdk)**: ICP canisters are Rust WASM modules with persistent state via `ic_cdk::storage::stable`. keccak256 is provided by the `sha3` crate (compiled to WASM). The L0 anchoring uses `call_raw` to invoke the L0 verifier canister's `is_proof_verified` method asynchronously. The `execute` function transfers e8s (1 ICP = 10^8 e8s) via the ledger canister. The authorization digest normalizes `to` as `keccak256(utf8(principal_string))`. Time-based delays use `ic_cdk::api::time_ns()` (nanosecond precision).
