// PQC-Guard SDK — Winternitz One-Time Signatures (hash-based, keccak256).
//
// Mirrors `src/lib/WOTS.sol` and `test/helpers/WOTSSigner.sol` byte-for-byte so
// signatures produced here verify on-chain. TESTNET ONLY. // AUDIT REQUIRED.

import { keccak256, solidityPacked, concat } from "ethers";

export const W = 16; // Winternitz parameter
export const LEN1 = 64; // message digits (256 / 4)
export const LEN2 = 3; // checksum digits
export const LEN = 67; // total hash chains

/** keccak256 over a 32-byte value (chain step): keccak256(abi.encodePacked(x)). */
function hashOnce(x: string): string {
  return keccak256(x);
}

/** Expand a 32-byte digest into 64 message + 3 checksum base-16 digits. */
export function digits(digest: string): number[] {
  const bytes = Buffer.from(digest.replace(/^0x/, ""), "hex");
  if (bytes.length !== 32) throw new Error("digest must be 32 bytes");
  const d: number[] = new Array(LEN).fill(0);
  let csum = 0;
  for (let i = 0; i < 32; i++) {
    const hi = bytes[i] >> 4;
    const lo = bytes[i] & 0x0f;
    d[2 * i] = hi;
    d[2 * i + 1] = lo;
    csum += W - 1 - hi;
    csum += W - 1 - lo;
  }
  d[64] = (csum >> 8) & 0x0f;
  d[65] = (csum >> 4) & 0x0f;
  d[66] = csum & 0x0f;
  return d;
}

/** Deterministic WOTS secret element (matches WOTSSigner.sk). */
export function secretElement(seed: string, leafIndex: bigint, chain: number): string {
  return keccak256(
    solidityPacked(
      ["string", "bytes32", "uint256", "uint256"],
      ["PQCG_WOTS_SK", seed, leafIndex, BigInt(chain)]
    )
  );
}

/** Compressed WOTS public key for a leaf (top of every hash chain). */
export function wotsPubKey(seed: string, leafIndex: bigint): string {
  const ends: string[] = [];
  for (let i = 0; i < LEN; i++) {
    let x = secretElement(seed, leafIndex, i);
    for (let j = 0; j < W - 1; j++) x = hashOnce(x);
    ends.push(x);
  }
  return keccak256(concat(ends));
}

/** Produce a WOTS signature over `digest` for (seed, leafIndex). */
export function wotsSign(seed: string, leafIndex: bigint, digest: string): string[] {
  const d = digits(digest);
  const sig: string[] = [];
  for (let i = 0; i < LEN; i++) {
    let x = secretElement(seed, leafIndex, i);
    for (let j = 0; j < d[i]; j++) x = hashOnce(x);
    sig.push(x);
  }
  return sig;
}

/** Recompute the compressed WOTS public key from a signature (verifier-side). */
export function pubKeyFromSig(digest: string, sig: string[]): string {
  if (sig.length !== LEN) throw new Error("bad signature length");
  const d = digits(digest);
  const ends: string[] = [];
  for (let i = 0; i < LEN; i++) {
    let x = sig[i];
    for (let j = d[i]; j < W - 1; j++) x = hashOnce(x);
    ends.push(x);
  }
  return keccak256(concat(ends));
}

/** Domain-separated WOTS Merkle leaf (mirrors MerkleOTS.leaf). */
export function wotsMerkleLeaf(wotsPub: string): string {
  return keccak256(solidityPacked(["string", "bytes32"], ["PQCG_WOTS_LEAF", wotsPub]));
}
