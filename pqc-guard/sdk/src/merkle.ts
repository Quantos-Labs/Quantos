// PQC-Guard SDK — index-addressed keccak256 Merkle trees.
//
// Two flavours, both matching the on-chain `MerkleOTS` / Rust `attestor_set`:
//   - fixed-height WOTS trees (per attestor)
//   - power-of-two padded trees over arbitrary leaves (the attestor set)
//
// TESTNET ONLY. // AUDIT REQUIRED.

import { keccak256, concat } from "ethers";
import { wotsPubKey, wotsMerkleLeaf } from "./wots.js";

const ZERO32 = "0x" + "00".repeat(32);

function node(left: string, right: string): string {
  return keccak256(concat([left, right]));
}

/** Build a full WOTS Merkle tree for one attestor and return root + a path fn. */
export function buildWotsTree(seed: string, height: number) {
  const n = 1 << height;
  let level: string[] = [];
  for (let j = 0; j < n; j++) level.push(wotsMerkleLeaf(wotsPubKey(seed, BigInt(j))));
  const leaves = [...level];

  while (level.length > 1) {
    const next: string[] = [];
    for (let j = 0; j < level.length; j += 2) next.push(node(level[j], level[j + 1]));
    level = next;
  }
  const root = level[0];

  function path(index: number): string[] {
    let lvl = [...leaves];
    const p: string[] = [];
    let idx = index;
    for (let h = 0; h < height; h++) {
      p.push(lvl[idx ^ 1]);
      const next: string[] = [];
      for (let j = 0; j < lvl.length; j += 2) next.push(node(lvl[j], lvl[j + 1]));
      lvl = next;
      idx >>= 1;
    }
    return p;
  }

  return { root, path };
}

function padPow2(leaves: string[]): string[] {
  let cap = 1;
  while (cap < leaves.length) cap <<= 1;
  const padded = [...leaves];
  while (padded.length < cap) padded.push(ZERO32);
  return padded;
}

/** Merkle root over arbitrary leaves (power-of-two zero padded). */
export function merkleRoot(leaves: string[]): string {
  let level = padPow2(leaves);
  while (level.length > 1) {
    const next: string[] = [];
    for (let j = 0; j < level.length; j += 2) next.push(node(level[j], level[j + 1]));
    level = next;
  }
  return level[0];
}

/** Merkle authentication path for `index` over arbitrary leaves. */
export function merklePath(leaves: string[], index: number): string[] {
  let level = padPow2(leaves);
  const path: string[] = [];
  let idx = index;
  while (level.length > 1) {
    path.push(level[idx ^ 1]);
    const next: string[] = [];
    for (let j = 0; j < level.length; j += 2) next.push(node(level[j], level[j + 1]));
    level = next;
    idx >>= 1;
  }
  return path;
}
