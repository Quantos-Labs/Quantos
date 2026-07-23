// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

// PQC-Guard SDK — account-side coordinator.
//
// Ties everything together: compute the authorization digest, drive migration,
// collect M-of-N attestor proofs (each gated by an OFF-CHAIN SPHINCS+ check),
// attach the Quantos attestor-set membership proofs, and ABI-encode the
// attestation blob consumed by StakeAttestationVerifier.
//
// TESTNET ONLY. // AUDIT REQUIRED.

import { AbiCoder, keccak256 } from "ethers";
import { Attestor } from "./attestor.js";
import { merkleRoot, merklePath } from "./merkle.js";
import { computeCommitment } from "./pqc.js";

const abi = AbiCoder.defaultAbiCoder();

/** Canonical authorization digest. MUST match StakeAttestationVerifier.authorizationDigest. */
export function authorizationDigest(params: {
  account: string; // pqcCommitment (bytes32)
  to: string;
  value: bigint;
  data: string; // hex
  nonce: bigint;
  chainId: bigint;
}): string {
  const encoded = abi.encode(
    ["bytes32", "address", "uint256", "bytes32", "uint256", "uint256"],
    [params.account, params.to, params.value, keccak256(params.data), params.nonce, params.chainId]
  );
  return keccak256(encoded);
}

/** Build the data needed to call PQCGuardAccount.migrate / finalizeMigration. */
export function buildMigration(pqcPublicKey: Uint8Array) {
  const commitment = computeCommitment(pqcPublicKey);
  return {
    commitment,
    // hex of the public key revealed at finalizeMigration (verified == commitment).
    pqcPublicKeyHex: "0x" + Buffer.from(pqcPublicKey).toString("hex"),
  };
}

export interface AttestorProofStruct {
  attestorId: string;
  wotsRoot: string;
  leafIndex: bigint;
  wotsSig: string[];
  merklePath: string[];
  setIndex: bigint;
  setProof: string[];
}

/**
 * Collect an M-of-N attestation for a call.
 *
 * @param attestors       The chosen attestors (subset of the finalized set).
 * @param finalizedLeaves The full ordered set leaves finalized by Quantos
 *                        (used to build each attestor's membership proof). The
 *                        Merkle root of these must equal the oracle's current
 *                        `attestorSetRoot`.
 */
export function requestAttestation(params: {
  attestors: Attestor[];
  finalizedLeaves: string[];
  pqcPublicKey: Uint8Array;
  pqcSignature: Uint8Array; // SPHINCS+ sig over `pqcMessage`
  pqcMessage: Uint8Array;
  digest: string;
}): { attestation: string; setRoot: string; proofs: AttestorProofStruct[] } {
  const proofs: AttestorProofStruct[] = [];

  for (const att of params.attestors) {
    // Each attestor independently verifies SPHINCS+ off-chain then signs.
    const { leafIndex, wotsSig, merklePath: wPath } = att.attest({
      pqcPublicKey: params.pqcPublicKey,
      pqcMessage: params.pqcMessage,
      pqcSignature: params.pqcSignature,
      digest: params.digest,
    });

    // Membership of this attestor in the Quantos-finalized set.
    const leaf = att.setLeaf();
    const setIndex = params.finalizedLeaves.findIndex((l) => l.toLowerCase() === leaf.toLowerCase());
    if (setIndex < 0) throw new Error(`attestor ${att.id} not in finalized set`);
    const setProof = merklePath(params.finalizedLeaves, setIndex);

    proofs.push({
      attestorId: att.id,
      wotsRoot: att.wotsRoot,
      leafIndex: BigInt(leafIndex),
      wotsSig,
      merklePath: wPath,
      setIndex: BigInt(setIndex),
      setProof,
    });
  }

  return {
    attestation: encodeAttestation(proofs),
    setRoot: merkleRoot(params.finalizedLeaves),
    proofs,
  };
}

/** ABI-encode AttestorProof[] exactly as StakeAttestationVerifier decodes it. */
export function encodeAttestation(proofs: AttestorProofStruct[]): string {
  const tuple = "tuple(bytes32,bytes32,uint256,bytes32[],bytes32[],uint256,bytes32[])[]";
  const arr = proofs.map((p) => [
    p.attestorId,
    p.wotsRoot,
    p.leafIndex,
    p.wotsSig,
    p.merklePath,
    p.setIndex,
    p.setProof,
  ]);
  return abi.encode([tuple], [arr]);
}
