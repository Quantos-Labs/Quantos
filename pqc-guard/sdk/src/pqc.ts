// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

// PQC-Guard SDK — post-quantum key material (SLH-DSA / SPHINCS+).
//
// We use @noble/post-quantum for the actual post-quantum primitive. We NEVER
// implement SPHINCS+ by hand. The account's `pqcCommitment` is keccak256 of the
// SLH-DSA public key; the full key is revealed only at migration finalize time.
//
// TESTNET ONLY. // AUDIT REQUIRED.

import { slh_dsa_sha2_128f } from "@noble/post-quantum/slh-dsa";
import { keccak256, hexlify, getBytes } from "ethers";

export interface PqcKeypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** Generate an SLH-DSA (SPHINCS+ SHA2-128f) keypair. */
export function genKeypair(seed?: Uint8Array): PqcKeypair {
  // @noble exposes keygen() (random) and keygen(seed) on some versions.
  const keys = seed ? slh_dsa_sha2_128f.keygen(seed) : slh_dsa_sha2_128f.keygen();
  return { publicKey: keys.publicKey, secretKey: keys.secretKey };
}

/** Sign a message with SLH-DSA. The signature is ~17 KB — far too big to verify
 *  on-chain, which is the whole reason for the attestation layer. */
export function pqcSign(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  return slh_dsa_sha2_128f.sign(secretKey, message);
}

/** Verify an SLH-DSA signature (this is what each attestor runs OFF-CHAIN). */
export function pqcVerify(publicKey: Uint8Array, message: Uint8Array, sig: Uint8Array): boolean {
  return slh_dsa_sha2_128f.verify(publicKey, message, sig);
}

/** The on-chain commitment to a PQC public key: keccak256(pubKey). */
export function computeCommitment(publicKey: Uint8Array): string {
  return keccak256(publicKey);
}

export { hexlify, getBytes };
