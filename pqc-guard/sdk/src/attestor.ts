// PQC-Guard SDK — mock attestor (a Quantos validator on PQC-Guard duty).
//
// In production each attestor IS a Quantos L1 validator staking QTS. Here we
// model one locally: it verifies the user's SPHINCS+ signature OFF-CHAIN, then
// emits a hash-based Winternitz attestation. The on-chain contract only ever
// sees the cheap WOTS attestation, never the ~17 KB SPHINCS+ signature.
//
// TESTNET ONLY. // AUDIT REQUIRED.

import { keccak256, solidityPacked } from "ethers";
import { wotsSign } from "./wots.js";
import { buildWotsTree } from "./merkle.js";
import { pqcVerify } from "./pqc.js";

export interface AttestorConfig {
  /** 32-byte Quantos validator id (hex). */
  id: string;
  /** Secret seed for this attestor's WOTS tree (hex, 32 bytes). */
  seed: string;
  /** WOTS tree height (number of one-time leaves = 2**height). */
  height: number;
}

/** Domain-separated attestor-set leaf (mirrors AttestorSet.leaf). */
export function attestorLeaf(id: string, wotsRoot: string): string {
  return keccak256(solidityPacked(["string", "bytes32", "bytes32"], ["PQCG_ATTESTOR_LEAF", id, wotsRoot]));
}

export class Attestor {
  readonly id: string;
  private readonly seed: string;
  readonly height: number;
  readonly wotsRoot: string;
  private readonly tree: { root: string; path: (i: number) => string[] };
  private nextLeaf = 0;

  constructor(cfg: AttestorConfig) {
    this.id = cfg.id;
    this.seed = cfg.seed;
    this.height = cfg.height;
    this.tree = buildWotsTree(cfg.seed, cfg.height);
    this.wotsRoot = this.tree.root;
  }

  /** The set leaf this attestor contributes to the Quantos attestor-set tree. */
  setLeaf(): string {
    return attestorLeaf(this.id, this.wotsRoot);
  }

  /**
   * Off-chain duty: verify the user's SPHINCS+ signature over `pqcMessage`,
   * then, if valid, sign the on-chain authorization `digest` with a fresh WOTS
   * leaf. Returns the WOTS signature + Merkle path within this attestor's tree.
   * @throws if the SPHINCS+ signature is invalid (attestor refuses to attest).
   */
  attest(params: {
    pqcPublicKey: Uint8Array;
    pqcMessage: Uint8Array;
    pqcSignature: Uint8Array;
    digest: string;
    leafIndex?: number;
  }): { leafIndex: number; wotsSig: string[]; merklePath: string[] } {
    // 1. The expensive, quantum-safe check — done here, never on-chain.
    const ok = pqcVerify(params.pqcPublicKey, params.pqcMessage, params.pqcSignature);
    if (!ok) throw new Error(`attestor ${this.id}: SPHINCS+ verification failed`);

    // 2. Consume a one-time leaf (reuse is slashable on Quantos).
    const leafIndex = params.leafIndex ?? this.nextLeaf++;
    const wotsSig = wotsSign(this.seed, BigInt(leafIndex), params.digest);
    const merklePath = this.tree.path(leafIndex);
    return { leafIndex, wotsSig, merklePath };
  }
}
