# PQC-Guard — Canonical Multi-VM Specification (v1)

> ⚠️ **POC / TESTNET ONLY.** Normative spec for porting PQC-Guard to non-EVM
> chains (Sui, Aptos, Tron, Stellar, NEAR, Solana). Every implementation MUST
> match the byte-level encodings below so that a single Quantos-finalized
> attestor set is consumable identically on every chain.

## 0. Terminology

- **Lock / guarded account** — the on-chain object that holds a user's assets
  and releases them only against a valid post-quantum authorization.
- **Attestor** — a Quantos L1 validator (stakes QTS) that verifies the user's
  SPHINCS+/SLH-DSA signature **off-chain** and emits a hash-based WOTS attestation.
- **Attestor set** — the Quantos-finalized `{attestorId, wotsRoot}` membership,
  committed to a Merkle root and exported to each chain via an **L0 proof**.
- **L0 verifier** — the existing per-chain contract that proves a Quantos
  finality proof (`is_proof_verified(proof_hash) → bool`).

## 1. Hash function (INVARIANT)

**All hashing is `keccak256`.** No exceptions. This is the only post-quantum-safe
primitive cheap enough on every target VM, and it is what Quantos uses to build
the attestor-set root. SHA-256/Blake/Poseidon MUST NOT be used anywhere in the
trust path.

Notation: `K(x)` = `keccak256(x)`. `a ++ b` = byte concatenation. `u256_be(n)` =
32-byte big-endian encoding of unsigned integer `n`. All domain tags are ASCII
bytes with **no length prefix and no null terminator**.

## 2. Cross-VM INVARIANT encodings

These MUST be byte-identical on every chain **and** in Quantos
(`quantos/src/l0/pqc_guard.rs`). They are what make one attestor set portable.

### 2.1 Winternitz OTS (w=16, 67 chains)

```
W       = 16
LEN1    = 64      # message digits  (256 bits / 4)
LEN2    = 3       # checksum digits
LEN     = 67
```

**Digit expansion** of a 32-byte digest `d`:
```
for i in 0..32:
    digits[2i]   = d[i] >> 4         # high nibble
    digits[2i+1] = d[i] & 0x0f       # low nibble
csum = Σ (W-1 - digits[k]) for k in 0..64
digits[64] = (csum >> 8) & 0x0f
digits[65] = (csum >> 4) & 0x0f
digits[66] =  csum       & 0x0f
```

**Chain step:** `step(x) = K(x)` where `x` is exactly 32 bytes.

**Secret element** (deterministic test/keygen helper; production keys come from
the attestor's KMS):
```
sk(seed, leafIndex, chain) = K("PQCG_WOTS_SK" ++ seed[32] ++ u256_be(leafIndex) ++ u256_be(chain))
```

**Public key from signature** (verifier side):
```
pubKeyFromSig(digest, sig[67]):
    d = digits(digest)
    for i in 0..67:
        end[i] = sig[i]; for _ in d[i]..(W-1): end[i] = K(end[i])
    return K(end[0] ++ end[1] ++ ... ++ end[66])      # 67*32 bytes
```

### 2.2 One-time Merkle tree (per attestor)

```
wotsLeaf(pub)         = K("PQCG_WOTS_LEAF" ++ pub[32])
node(left, right)     = K(left[32] ++ right[32])
rootFromLeaf(leaf, index, path[]):
    h = leaf
    for sib in path:
        if index & 1 == 0: h = node(h, sib) else: h = node(sib, h)
        index >>= 1
    return h
```

### 2.3 Attestor-set tree (the Quantos anchor)

```
attestorLeaf(attestorId, wotsRoot) = K("PQCG_ATTESTOR_LEAF" ++ attestorId[32] ++ wotsRoot[32])
```
The set root is an index-addressed Merkle tree over the active attestor leaves,
**padded with `bytes32(0)` to the next power of two**, combined with `node()`.
Membership is checked with `rootFromLeaf(attestorLeaf, setIndex, setProof)`.

> Reference implementation: `quantos/src/l0/pqc_guard.rs::attestor_set` and the
> EVM `src/lib/{WOTS,AttestorSet}.sol`. New ports MUST reproduce their test vectors.

## 3. Authorization digest (per-chain, normalized)

The digest binds an action to one account on one chain and prevents replay:

```
authDigest = K( account[32]
             ++ toField[32]
             ++ u256_be(value)
             ++ K(data)
             ++ u256_be(nonce)
             ++ u256_be(chainId) )
```

Field normalization (this is the ONLY place chains differ):

| Field | Meaning | Normalization |
|-------|---------|---------------|
| `account` | the lock's `pqcCommitment` | 32 bytes as stored |
| `toField` | recipient identifier | EVM: address left-padded 20→32. Sui/Aptos/Solana: native 32-byte address. NEAR/Stellar: `K(utf8(address_string))` |
| `value` | amount of native asset moved | unsigned, `u256_be` (u64 chains zero-pad) |
| `data` | call payload / memo (may be empty) | chain-native bytes, hashed with `K` |
| `nonce` | the lock's monotonic counter | `u256_be` |
| `chainId` | canonical chain id (see §6) | `u256_be` |

The user's SLH-DSA signature and every attestor's WOTS signature are over **the
same `authDigest` bytes**. The lock recomputes `authDigest` from the call it is
asked to perform, so a signature for one action can never authorize another.

> EVM note: `abi.encode(bytes32,address,uint256,bytes32,uint256,uint256)` is
> byte-identical to the layout above (address is left-padded to 32). The existing
> `StakeAttestationVerifier.authorizationDigest` therefore already conforms.

## 4. Attestation format

Logical structure of one attestor's contribution:

```
AttestorProof {
    attestorId : bytes32       # Quantos validator id (distinctness key)
    wotsRoot   : bytes32       # attestor's committed WOTS tree root
    leafIndex  : u64           # one-time leaf used
    wotsSig    : bytes32[67]   # Winternitz signature over authDigest
    merklePath : bytes32[]     # proves wotsPub ∈ wotsRoot (len = wots tree height)
    setIndex   : u64           # leaf index in the finalized attestor set
    setProof   : bytes32[]     # proves {attestorId,wotsRoot} ∈ attestorSetRoot
}
Attestation = AttestorProof[]
```

Serialization:
- **EVM / Tron:** ABI encoding of `AttestorProof[]` (tuple as in
  `StakeAttestationVerifier`).
- **Non-EVM (canonical binary):** length-prefixed, big-endian:
  ```
  u32  count
  repeat count:
      32   attestorId
      32   wotsRoot
      u64  leafIndex
      u32  sigLen (== 67); sigLen*32 bytes
      u32  pathLen; pathLen*32 bytes
      u64  setIndex
      u32  setProofLen; setProofLen*32 bytes
  ```
  The SDK emits this format for non-EVM targets.

## 5. Verification algorithm (lock side)

`verifyAuthorization(account, to, value, data, nonce, attestation) → bool`:

```
digest    = authDigest(account, to, value, data, nonce, chainId)
threshold = oracle.threshold()
setRoot   = oracle.attestorSetRoot()
seen = {}; valid = 0
for p in decode(attestation):
    if p.attestorId in seen: continue                     # no double-count
    # (1) WOTS valid & belongs to attestor's committed tree
    pub  = pubKeyFromSig(digest, p.wotsSig)
    troot = rootFromLeaf(wotsLeaf(pub), p.leafIndex, p.merklePath)
    if troot != p.wotsRoot: continue
    # (2) attestor is in the Quantos-finalized set (the QTS anchor)
    aleaf = attestorLeaf(p.attestorId, p.wotsRoot)
    if rootFromLeaf(aleaf, p.setIndex, p.setProof) != setRoot: continue
    seen.add(p.attestorId); valid += 1
    if valid >= threshold: return true
return valid >= threshold
```

This is pure keccak hashing + comparisons — cheap and quantum-safe on every VM.

## 6. Attestor-set oracle & L0 anchoring

Each chain hosts an **attestor-set oracle** holding:
`{ attestorSetRoot: bytes32, epoch: u64, threshold: u64 }`.

`updateAttestorSet(root, epoch, threshold, proofHash)` MUST:
1. require `epoch` strictly greater than the stored epoch (monotonic);
2. require the chain's L0 verifier reports `is_proof_verified(proofHash) == true`;
3. store the new values.

> POC trust note (`// AUDIT REQUIRED`): binding `root` *into* the L0 proof (header
> field or Quantos `state_root` inclusion) and re-deriving it on-chain removes
> relayer trust. Interface unchanged.

### Canonical chain ids (`chainId` field, §3)

| Chain | chainId |
|-------|---------|
| Ethereum mainnet | `1` |
| Base Sepolia | `84532` |
| Tron mainnet | `728126428` |
| Sui | `0x5549_0000_0000_0001` (PQCG-assigned) |
| Aptos | `0x4150_0000_0000_0001` |
| Stellar | `0x5354_0000_0000_0001` |
| NEAR | `0x4e45_0000_0000_0001` |
| Solana | `0x534f_0000_0000_0001` |
| Bitcoin / Stacks | `0x5354_4B54_0000_0001` |
| Canton Network | `0x434E_0000_0000_0001` |
| Internet Computer | `0x4943_5000_0000_0001` |

(Non-EVM ids are PQCG-assigned 64-bit tags to avoid collision; they only need to
be unique and fixed per chain.)

## 7. Lock state machine (INVARIANT across VMs)

```
            migrate(commitment, verifier, guardians, gThreshold)   [owner only]
 ┌─────────────┐ ───────────────────────────────────────────────▶ ┌───────────┐
 │ PreMigration│                                                    │ Pending   │
 │ (native     │ ◀─── cancelMigration() [owner] ──────────────────  │ (commit)  │
 │  owner key) │                                                    └─────┬─────┘
 └─────────────┘                       finalizeMigration(pqcPubKey)       │ after
        ▲                              require K(pqcPubKey)==commitment    │ COMMIT_DELAY
        │ recovery rotates key                                            ▼
        │                                                          ┌───────────┐
        │                                                          │ Migrated  │
        └───────────── escape hatch (guardians, RECOVERY_TIMEOUT) ─│ PQC only  │
                                                                   └───────────┘
```

Rules:
- **execute(to, value, data, attestation):** only in `Migrated`; recompute
  `authDigest` with the current `nonce`; require `verifyAuthorization == true`;
  perform the asset movement; `nonce += 1`.
- **No native-key spend path exists in `Migrated`.** The pre-migration owner key
  cannot move funds.
- **Commit-reveal delay** (`COMMIT_DELAY`, 24h) defends against migration hijack.
- **Escape hatch:** after `RECOVERY_TIMEOUT` (30d) of inactivity, a guardian
  M-of-N quorum may sweep funds or rotate the PQC commitment so funds never freeze.

### VM capability note (important)

EVM `execute` performs an **arbitrary call** (full DeFi composability). On VMs
without generic dynamic dispatch (Move: Sui/Aptos), the v1 lock is a **guarded
vault**: `execute` releases the native asset (or a held `Coin<T>`) to `to`.
Arbitrary protocol calls require per-protocol adapters or a PTB/relayer pattern,
documented per chain. Solana/NEAR can approximate arbitrary CPI/cross-contract
calls and may expose a richer `execute` in a later version.

## 8. Parameters (defaults)

| Constant | Value |
|----------|-------|
| Winternitz `w` | 16 (4 bits/digit), 67 chains |
| `COMMIT_DELAY` | 24h |
| `RECOVERY_TIMEOUT` | 30d |
| PQC scheme | SLH-DSA SHA2-128f (off-chain) |
| Default quorum | M-of-N from the oracle (Quantos governance) |

## 9. Conformance

A port is conformant iff:
1. It reproduces the WOTS/Merkle/AttestorSet **test vectors** from
   `quantos/src/l0/pqc_guard.rs` (§2).
2. Its `verifyAuthorization` follows §5 exactly.
3. Its oracle enforces §6 (monotonic epoch + verified L0 proof).
4. Its lock follows the §7 state machine (migrate/finalize/execute/escape hatch).

The reference non-EVM implementation is **Sui** (`base-bridge/sui/sources/pqc_guard*.move`).
```
