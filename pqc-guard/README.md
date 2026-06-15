# PQC-Guard — Quantum-Resistant Smart Account (TESTNET POC)

> ⚠️ **POC / TESTNET ONLY.** No mainnet, no real funds. Every sensitive zone is
> annotated `// AUDIT REQUIRED`. Do not deploy with value at risk.

PQC-Guard makes EVM assets quantum-resistant by replacing **ECDSA** authorization
with **post-quantum** (SPHINCS+ / SLH-DSA) authorization — **without ever
verifying the SPHINCS+ signature on-chain** (that would blow past the block gas
limit: a SLH-DSA signature is ~17–50 KB and tens of thousands of hashes).

## The core idea: decoupled attestation

The SPHINCS+ signature is verified **off-chain** by an attestor quorum. The
chain only checks a compact, *itself quantum-safe* attestation.

```
 OFF-CHAIN                                   ON-CHAIN
 ┌──────────┐  SPHINCS+ sig (~17 KB)  ┌──────────────┐   ┌────────────────────────┐
 │  Wallet  │ ───────────────────────▶│  N attestors │──▶│  PQCGuardAccount       │
 │ (SLH-DSA)│                          │ verify SLH-DSA│   │  execute(...)          │
 └──────────┘                          │ then sign WOTS│   │      │                 │
                                       └──────────────┘   │      ▼                 │
                  hash-based M-of-N attestation (cheap)   │  IAttestationVerifier  │
                                                          └────────────────────────┘
```

`PQCGuardAccount` calls **only** `IAttestationVerifier`. That single seam lets us
swap the proving backend with zero account changes:

```
                        IAttestationVerifier (fixed interface)
                                     │
        ┌────────────────────────────┴────────────────────────────┐
        ▼                                                          ▼
 ┌───────────────────────────┐                      ┌───────────────────────────┐
 │ PHASE 1 (this MVP)         │                      │ PHASE 2 (future)           │
 │ StakeAttestationVerifier   │   ── drop-in ──▶     │ ZkStarkVerifier            │
 │ M-of-N hash-based (WOTS)   │   same account!      │ 1 STARK proof of SPHINCS+  │
 │ attestors, keccak-cheap    │                      │ verification               │
 └───────────────────────────┘                      └───────────────────────────┘
```

`PQCGuardAccount` is **byte-for-byte identical** between Phase 1 and Phase 2.
Only the address stored in `attestationVerifier` changes.

## Why this is *full PQC* (not ECDSA)

A naive design lets attestors sign with ECDSA — but then a quantum attacker who
breaks ECDSA forges the quorum and drains the account. The system would only be
as strong as ECDSA.

**The only quantum-safe primitive cheap enough for the EVM is the hash function
(`keccak256`).** So attestors sign with **Winternitz one-time signatures (WOTS)**
— the same hash-based family as SPHINCS+ itself — verified on-chain with pure
keccak hashing + Merkle membership. No ECDSA anywhere in the trust path.

## The QTS anchor — why Quantos is *required*, not optional

The attestors are **not** a local EVM registry. They **are the Quantos L1
validator set**: they stake **QTS** and are **slashed in QTS on Quantos**. Their
membership + WOTS commitment roots are finalized by Quantos consensus
(post-quantum) and exported to the target chain inside an **L0 finality proof**.

```
 QUANTOS L1 (Rust, QTS)                         TARGET CHAIN (EVM)
 ┌──────────────────────────────┐              ┌──────────────────────────────────┐
 │ l0/pqc_guard.rs::attestor_set │              │ QuantosAttestorOracle             │
 │  • {id, wotsRoot, QTS, active}│   L0 proof   │  • attestorSetRoot (from Quantos) │
 │  • merkle_root() (keccak256)  │ ───────────▶ │  • updates gated by a VERIFIED    │
 │  • slash_on_reuse() → QTS     │              │    L0 proof (QuantosL0Verifier)   │
 └──────────────────────────────┘              ├──────────────────────────────────┤
        finalized + PQC-signed                  │ StakeAttestationVerifier          │
        by Quantos validators                   │  per attestor, by keccak only:    │
                                                │   1. WOTS sig valid / digest      │
                                                │   2. WOTS pub ∈ attestor wotsRoot │
                                                │   3. {id,wotsRoot} ∈ setRoot (L0) │
                                                │  quorum M-of-N                    │
                                                └──────────────────────────────────┘
```

**Consequence:** using PQC-Guard = consuming the security of the QTS-staked
Quantos validator set. The economic security of every guarded account equals the
QTS staked behind Quantos (EigenLayer-style anchor). The Rust attestor-set
implementation and the Solidity verifier use **identical keccak256 encodings**
so the root matches bit-for-bit.

> **POC trust note (`// AUDIT REQUIRED`):** `QuantosAttestorOracle.updateAttestorSet`
> currently trusts the relayer to pass the root matching a *verified* L0 proof.
> The production design binds the root *into* the proof (header field or a
> Quantos `state_root` inclusion proof) and re-derives it on-chain, removing
> relayer trust. The consumer interface does not change.

## Repository layout

```
pqc-guard/
├── src/
│   ├── interfaces/
│   │   ├── IAttestationVerifier.sol   # the Phase-1 → Phase-2 seam
│   │   └── IAttestorSetOracle.sol     # the QTS anchor surface
│   ├── lib/
│   │   ├── WOTS.sol                   # Winternitz verify + MerkleOTS (keccak)
│   │   └── AttestorSet.sol            # attestor-set leaf encoding
│   ├── AttestorRegistry.sol           # Quantos-side logic mirror (slashing ref)
│   ├── QuantosAttestorOracle.sol      # finalized set root, fed by L0 proofs
│   ├── StakeAttestationVerifier.sol   # Phase-1 IAttestationVerifier impl
│   ├── PQCGuardAccount.sol            # the quantum-resistant account
│   └── MockERC20.sol                  # testnet stake token
├── test/
│   ├── helpers/{WOTSSigner,MockL0ProofRegistry}.sol
│   └── PQCGuard.t.sol                 # full Foundry suite
├── script/Deploy.s.sol               # Base Sepolia deployment
└── sdk/                              # TypeScript SDK (SLH-DSA + WOTS + proofs)

quantos/src/l0/pqc_guard.rs           # Quantos-side attestor set (Rust, keccak)
```

## Security model (enforced + tested)

| Property | Mechanism |
|---|---|
| No on-chain SPHINCS+ | Off-chain attestor verification; on-chain WOTS only |
| Full PQC trust path | Hash-based WOTS attestations (keccak256) |
| Anti-replay | Monotonic account `nonce` + `chainId` bound into the digest |
| Cross-account safety | `account` = `pqcCommitment` is bound into the digest |
| Migration hijack defense | Commit-delay-reveal (24h) + `cancelMigration` |
| Key reveal integrity | `keccak256(pqcPubKey) == pqcCommitment` at finalize |
| Funds never freeze | Guardian M-of-N escape hatch after 30d idle |
| One-time WOTS enforcement | Slashing on leaf reuse (Quantos, in QTS) |
| Only finalized attestors | Merkle membership against L0 `attestorSetRoot` |

## Build & test (Foundry)

```bash
cd pqc-guard
forge install foundry-rs/forge-std   # one-time
forge build
forge test -vvv
```

The suite covers (per spec): migration ok / non-owner revert; commit-delay
revert; quorum reached → success; quorum not reached → revert; replayed
attestation → revert; legacy ECDSA cannot spend post-migration; slashing on
double-sign + reporter reward; same-digest slash rejected; attestor-not-in-set
rejected; slashed-attestor-removed → no quorum; escape hatch before/after
timeout; guardian-only recovery.

## SDK demo (off-chain end-to-end)

```bash
cd pqc-guard/sdk
npm install
npm run demo
```

Generates an SLH-DSA keypair, spins up N mock attestors (Quantos validators),
signs with SPHINCS+, has the attestors verify it off-chain and emit WOTS
attestations, and ABI-encodes the exact blob `StakeAttestationVerifier` accepts.

## Deploy (Base Sepolia)

```bash
cp .env.example .env   # fill DEPLOYER_PRIVATE_KEY + L0_VERIFIER
forge script script/Deploy.s.sol:Deploy --rpc-url base_sepolia --broadcast -vvvv
```

## Parameters (MVP)

| Constant | Value | Where |
|---|---|---|
| Winternitz `w` | 16 (4 bits/digit), 67 chains | `WOTS.sol` |
| Commit delay | 24h | `PQCGuardAccount.COMMIT_DELAY` |
| Recovery timeout | 30d | `PQCGuardAccount.RECOVERY_TIMEOUT` |
| PQC scheme | SLH-DSA SHA2-128f | SDK `pqc.ts` |
| Slash reporter reward | 10% | `AttestorRegistry` |

## Roadmap to Phase 2

Implement `ZkStarkVerifier is IAttestationVerifier` that verifies a single STARK
proof attesting the SPHINCS+ verification relation (Quantos already produces
STARK batch proofs in `l0/stark_prover`). Point the account's
`attestationVerifier` at it. **No change to `PQCGuardAccount`.**
