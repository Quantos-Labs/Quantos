# PQC-Guard — Multi-VM Ports

Per-chain implementations of the PQC-Guard guarded account, all conformant to
[`pqc-guard/MULTIVM_SPEC.md`](../pqc-guard/MULTIVM_SPEC.md). Every port uses the
**same keccak256 encodings** (WOTS / Merkle / attestor-set) so a single
Quantos-finalized attestor set is consumable identically everywhere, and each
port anchors on that chain's existing `QuantosL0Verifier` via `is_proof_verified`.

> ⚠️ **POC / TESTNET ONLY. // AUDIT REQUIRED.** None of these are compiled in CI
> here; build each with its native toolchain (commands below). SDK/framework
> version pins may need adjustment.

## Reference (canonical)

| Layer | Path | Lang |
|-------|------|------|
| EVM (Ethereum/Base) | `pqc-guard/src/*` | Solidity |
| Quantos L1 attestor set | `quantos/src/l0/pqc_guard.rs` | Rust |
| SDK | `pqc-guard/sdk/*` | TypeScript |

## Ports

| Chain | Path | Lang / Framework | L0 anchor call |
|-------|------|------------------|----------------|
| Sui | `base-bridge/sui/sources/pqc_guard*.move` | Move | `l0_verifier::is_proof_verified` (object ref) |
| Aptos | `base-bridge/aptos/sources/pqc_guard*.move` | Move | `l0_verifier::is_proof_verified(addr, hash)` |
| Tron | `base-bridge/tron/PQCGuard.sol` | Solidity (TVM) | `isProofVerified(bytes32)` (same as EVM) |
| Stellar | `base-bridge/stellar/pqc-guard/src/lib.rs` | Rust / Soroban | cross-contract `is_proof_verified` |
| NEAR | `base-bridge/near/pqc-guard/src/lib.rs` | Rust / near-sdk | async Promise + callback |
| Solana | `base-bridge/solana/programs/quantos_pqc_guard/src/lib.rs` | Rust / Anchor | read L0 `ProofState` PDA |

## Per-chain divergences (only where the spec allows)

| Chain | `execute` semantics | `value` type | `toField` normalization | chainId |
|-------|--------------------|--------------|------------------------|---------|
| Sui | release `Coin<SUI>` to `to` | u64 → u256_be | native 32-byte address | `0x5549000000000001` |
| Aptos | release `Coin<AptosCoin>` to `to` | u64 → u256_be | `bcs(address)` (32 bytes) | `0x4150000000000001` |
| Tron | arbitrary call (full TVM) | uint256 | address left-padded 20→32 | `block.chainid` |
| Stellar | token `transfer` to `to` | i128 → u256_be | `keccak(utf8(strkey))` | `0x5354000000000001` |
| NEAR | `Promise::transfer` NEAR | u128 → u256_be | `keccak(utf8(account_id))` | `0x4e45000000000001` |
| Solana | debit vault PDA lamports | u64 → u256_be | native 32-byte pubkey | `0x534f000000000001` |

**VM capability note (spec §7):** only EVM/Tron offer arbitrary calls. Move
(Sui/Aptos), Soroban, NEAR and Solana v1 perform a guarded **asset release** to a
recipient; arbitrary protocol composition needs per-protocol adapters.

## State machine (identical everywhere)

`PreMigration → (migrate commit) → (24h delay) → (finalize reveal) → Migrated`,
with `execute` gated by M-of-N attestation over a monotonic `nonce`, and a
guardian escape hatch after 30d inactivity. See spec §7.

## Build / test commands

```bash
# Sui
cd base-bridge/sui && sui move build && sui move test

# Aptos
cd base-bridge/aptos && aptos move compile && aptos move test

# Tron (Solidity, TVM) — set evmVersion = "paris" to avoid PUSH0
#   deploy base-bridge/tron/PQCGuard.sol via TronBox or Remix/TronLink

# Stellar (Soroban)
cd base-bridge/stellar/pqc-guard && cargo build --target wasm32-unknown-unknown --release

# NEAR
cd base-bridge/near/pqc-guard && cargo build --target wasm32-unknown-unknown --release

# Solana (Anchor)
cd base-bridge/solana && anchor build
```

## Conformance checklist (per spec §9)

1. Reproduce the WOTS/Merkle/AttestorSet test vectors from
   `quantos/src/l0/pqc_guard.rs` (Sui & Aptos include native Move tests for this).
2. `verify_authorization` follows §5 (WOTS → tree root → set membership → quorum).
3. Oracle enforces §6 (monotonic epoch + verified L0 proof).
4. Lock follows the §7 state machine.

## Known POC limitations

- **Relayer-trusted root** in the oracle update (see spec §6 note); production
  binds the root into the L0 proof.
- **ECDSA/native guardians** in the escape hatch; production should use PQC
  guardians.
- **SDK** currently emits EVM ABI attestations; the canonical binary format
  (spec §4) for non-EVM targets needs a serializer (straightforward follow-up).
- Rust/Move ports are **not yet compiled in CI**; treat version pins as drafts.
