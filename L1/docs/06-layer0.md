---
sidebar_position: 19
---

# 18. Layer 0 Finality Hub

## 18.1 Trust Model: Per-Chain Cryptographic Verification

The L0 Finality Hub aggregates Quantos validator signatures into cross-chain attestations. The security of each supported chain depends on how its validator set is tracked:

| Chain | Validator Set Tracking | Trust Model | Cryptographic Verification |
|-------|------------------------|-------------|---------------------------|
| Bitcoin | SPV (full Merkle proof, tx_hash + tx_index) | Majority hashrate | ✅ BitcoinLightClient verifies Merkle path against 80-byte header |
| Ethereum | Sync committees | Ethereum consensus | ✅ Sync committee signatures (BLS) verified natively |
| Cosmos / Tendermint | IBC-compatible validator transitions | BFT consensus | ✅ Validator set transitions signed by previous validator set |
| Solana | RPC polling (`getVoteAccounts`) | RPC operator | ⚠️ Oracle attestation; no succinct light client available |
| NEAR | RPC polling (`validators`) | RPC operator | ⚠️ Oracle attestation |
| Aptos / Sui | REST API polling | RPC operator | ⚠️ Oracle attestation |
| Tron | RPC polling (`listwitnesses`) | RPC operator | ⚠️ Oracle attestation |
| TON | RPC polling (`getValidators`) | RPC operator | ⚠️ Oracle attestation |
| Polkadot | SCALE-encoded session validators | RPC operator | ⚠️ Oracle attestation |
| Stellar | Horizon API (`/quorum`) | RPC operator | ⚠️ Oracle attestation |
| Tezos | RPC polling (baking rights) | RPC operator | ⚠️ Oracle attestation |
| Cardano | db-sync API (stake distribution) | RPC operator | ⚠️ Oracle attestation |

**What this means**: For Bitcoin, Ethereum, and Cosmos, the L0 verifies validator set transitions cryptographically. For the other nine chains, the L0 relies on polled RPC data, which reduces to trusting the RPC endpoint operator. This is an honest admission of the current state of light-client technology; as succinct light clients become available for additional chains, they will be upgraded to cryptographic verification.

## 18.2 EpochWatcher

`EpochWatcher` is a background tokio service that polls each registered chain's RPC endpoints and updates the `ValidatorSetRegistry` when validator sets change. Because the registry uses `Arc<RwLock<…>>`, all live `LightClient` instances see updates immediately.

For chains with cryptographic verification (Bitcoin, Ethereum, Cosmos), `EpochWatcher` is an optimization convenience; the light client could in principle verify transitions independently. For chains relying on RPC polling, `EpochWatcher` is a trust dependency.

## 18.3 ZK-STARK Batch Aggregation

The L0 aggregates PQC validator signatures into a succinct proof:

1. Every validator signature is verified natively in Rust (ML-DSA-65).
2. For each signer, a binding commitment is computed: `sig_commitment = SHA3-256(pubkey ‖ message ‖ raw_sig)`.
3. A Winterfell STARK circuit proves: (a) each commitment is correctly embedded in the trace, (b) the accumulated signed stake is computed honestly, (c) the final `acc_stake` equals the claimed `signed_stake`.
4. The STARK proof is hashed to a 32-byte `stark_commitment`.

**On-chain footprint**: The 32-byte commitment is stored in the `QuantosStarkVerifier` contract on target chains. This is a cheap `SLOAD` (~20,000 gas on EVM). **Full STARK verification is done off-chain** by anyone who downloads the proof; the on-chain contract does not verify the STARK.

**Proof generation time**: The STARK circuit for stake aggregation is lightweight (boolean constraints + accumulator). Generation time is sub-second for committees up to 100 validators. The heavy lattice arithmetic of ML-DSA verification is done *outside* the circuit.

## 18.4 Finality Directionality

Cross-chain finality is **not symmetric**:

- **Quantos → external chain**: Quantos native finality (~1 s) plus STARK proof generation time (sub-second for stake aggregation). The proof is relayed to the target chain.
- **External chain → Quantos**: Bounded by the source chain's own finality. Bitcoin requires ~6 confirmations (~60 min). Ethereum requires ~2 epochs (~13 min). The L0 cannot compress another chain's consensus.
