// PQC-Guard SDK — canonical (non-EVM) attestation serializer + digest.
//
// The EVM verifier consumes `AttestorProof[]` via ABI. The Move/Soroban/NEAR/
// Solana ports instead consume the canonical big-endian binary blob defined in
// MULTIVM_SPEC.md §4, and recompute the authorization digest with per-chain
// field normalization (§3). This module produces both, so a single attestor
// pipeline drives every chain.
//
// TESTNET ONLY. // AUDIT REQUIRED.

import { keccak256 } from "ethers";
import type { AttestorProofStruct } from "./account.js";

export type ChainKind = "evm" | "tron" | "sui" | "aptos" | "solana" | "near" | "stellar";

/** Canonical PQCG chain ids (spec §6). EVM/Tron use the live network id. */
export const CHAIN_IDS: Record<Exclude<ChainKind, "evm" | "tron">, bigint> = {
  sui: 0x5549000000000001n,
  aptos: 0x4150000000000001n,
  stellar: 0x5354000000000001n,
  near: 0x4e45000000000001n,
  solana: 0x534f000000000001n,
};

// ── byte helpers ────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (h.length % 2 !== 0) throw new Error(`odd-length hex: ${hex}`);
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(b: Uint8Array): string {
  let s = "0x";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

function u32be(n: number): Uint8Array {
  if (n < 0 || n > 0xffffffff) throw new Error(`u32 out of range: ${n}`);
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

function u64be(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, false);
  return b;
}

function u256be(n: bigint): Uint8Array {
  if (n < 0n) throw new Error(`u256 must be non-negative: ${n}`);
  const b = new Uint8Array(32);
  let x = n;
  for (let i = 31; i >= 0; i--) {
    b[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new Error(`value exceeds 256 bits: ${n}`);
  return b;
}

/** Decode a hex string that MUST represent exactly 32 bytes. */
function word32(hex: string): Uint8Array {
  const b = hexToBytes(hex);
  if (b.length !== 32) throw new Error(`expected 32 bytes, got ${b.length} (${hex})`);
  return b;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

// ── canonical attestation blob (spec §4) ─────────────────────────────────────

/**
 * Serialize `AttestorProof[]` into the canonical big-endian blob consumed by
 * the Move/Soroban/NEAR/Solana verifiers.
 *
 * Layout (all integers big-endian):
 *   u32 count
 *   count × {
 *     attestorId[32], wotsRoot[32], u64 leafIndex,
 *     u32 sigLen,  sigLen × word[32],
 *     u32 pathLen, pathLen × word[32],
 *     u64 setIndex,
 *     u32 setProofLen, setProofLen × word[32]
 *   }
 */
export function encodeAttestationCanonical(proofs: AttestorProofStruct[]): Uint8Array {
  const parts: Uint8Array[] = [u32be(proofs.length)];
  for (const p of proofs) {
    parts.push(word32(p.attestorId));
    parts.push(word32(p.wotsRoot));
    parts.push(u64be(p.leafIndex));
    parts.push(u32be(p.wotsSig.length));
    for (const w of p.wotsSig) parts.push(word32(w));
    parts.push(u32be(p.merklePath.length));
    for (const w of p.merklePath) parts.push(word32(w));
    parts.push(u64be(p.setIndex));
    parts.push(u32be(p.setProof.length));
    for (const w of p.setProof) parts.push(word32(w));
  }
  return concat(parts);
}

/** Hex form of {@link encodeAttestationCanonical}. */
export function encodeAttestationCanonicalHex(proofs: AttestorProofStruct[]): string {
  return bytesToHex(encodeAttestationCanonical(proofs));
}

// ── per-chain digest (spec §3) ────────────────────────────────────────────────

/**
 * Normalize a recipient to the 32-byte `toField` used in the digest.
 *   - evm/tron : 20-byte address, left-padded to 32 (matches abi.encode(address))
 *   - sui/aptos/solana : native 32-byte address (hex)
 *   - near/stellar : keccak256(utf8(address string))
 */
export function normalizeTo(chain: ChainKind, to: string): string {
  switch (chain) {
    case "evm":
    case "tron": {
      const b = hexToBytes(to);
      if (b.length > 32) throw new Error(`address too long: ${to}`);
      const w = new Uint8Array(32);
      w.set(b, 32 - b.length);
      return bytesToHex(w);
    }
    case "sui":
    case "aptos":
    case "solana":
      return bytesToHex(word32(to)); // require canonical 32-byte hex
    case "near":
    case "stellar":
      return keccak256(new TextEncoder().encode(to));
  }
}

/**
 * Canonical authorization digest from already-normalized fields. The 192-byte
 * preimage is byte-identical to the EVM `abi.encode(...)` layout, so this also
 * reproduces the EVM digest when `toField` is the left-padded address.
 */
export function canonicalDigest(params: {
  account: string; // pqcCommitment, 32-byte hex
  toField: string; // 32-byte hex (see normalizeTo)
  value: bigint;
  data: string; // hex calldata
  nonce: bigint;
  chainId: bigint;
}): string {
  const preimage = concat([
    word32(params.account),
    word32(params.toField),
    u256be(params.value),
    word32(keccak256(params.data)),
    u256be(params.nonce),
    u256be(params.chainId),
  ]);
  return keccak256(preimage);
}

/**
 * Convenience: compute the digest for a target chain, applying the right
 * `toField` normalization and (for non-EVM) the canonical chain id.
 * For evm/tron you MUST pass the live network `chainId`.
 */
export function digestForChain(
  chain: ChainKind,
  params: { account: string; to: string; value: bigint; data: string; nonce: bigint; chainId?: bigint }
): string {
  const toField = normalizeTo(chain, params.to);
  let chainId: bigint;
  if (chain === "evm" || chain === "tron") {
    if (params.chainId === undefined) throw new Error(`${chain}: chainId is required`);
    chainId = params.chainId;
  } else {
    chainId = params.chainId ?? CHAIN_IDS[chain];
  }
  return canonicalDigest({
    account: params.account,
    toField,
    value: params.value,
    data: params.data,
    nonce: params.nonce,
    chainId,
  });
}
