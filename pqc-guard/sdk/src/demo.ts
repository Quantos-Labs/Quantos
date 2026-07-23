// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

// PQC-Guard SDK — end-to-end local demo (no chain required).
//
// Run with:  npm run demo
//
// It shows the full off-chain flow:
//   1. Generate an SLH-DSA (SPHINCS+) keypair and its on-chain commitment.
//   2. Spin up N mock attestors (Quantos validators) with WOTS trees.
//   3. The user signs the authorization with SPHINCS+ (the big ~17 KB sig).
//   4. M attestors verify it OFF-CHAIN and emit cheap WOTS attestations.
//   5. We ABI-encode the attestation the on-chain verifier would accept.
//
// TESTNET ONLY. // AUDIT REQUIRED.

import { randomBytes } from "@noble/hashes/utils";
import { hexlify } from "ethers";
import { genKeypair, pqcSign, computeCommitment } from "./pqc.js";
import { Attestor } from "./attestor.js";
import { authorizationDigest, requestAttestation, buildMigration } from "./account.js";
import { merkleRoot } from "./merkle.js";

function rand32(): string {
  return hexlify(randomBytes(32));
}

async function main() {
  const N = 3;
  const THRESHOLD = 2;
  const HEIGHT = 3; // 8 one-time leaves per attestor

  // 1. User PQC key + commitment.
  const kp = genKeypair();
  const { commitment, pqcPublicKeyHex } = buildMigration(kp.publicKey);
  console.log("PQC public key bytes:", kp.publicKey.length, "(too big for on-chain verify)");
  console.log("pqcCommitment:", commitment);

  // 2. N attestors (Quantos validators), each with a WOTS tree.
  const attestors: Attestor[] = [];
  for (let i = 0; i < N; i++) {
    attestors.push(new Attestor({ id: rand32(), seed: rand32(), height: HEIGHT }));
  }
  const finalizedLeaves = attestors.map((a) => a.setLeaf());
  const setRoot = merkleRoot(finalizedLeaves);
  console.log("attestorSetRoot (published to oracle via L0):", setRoot);

  // 3. Authorization the user wants: send 1 ETH to `to`, nonce 0, chain 84532.
  const to = "0x000000000000000000000000000000000000bEEF";
  const value = 1_000_000_000_000_000_000n;
  const data = "0x";
  const nonce = 0n;
  const chainId = 84532n; // Base Sepolia

  const digest = authorizationDigest({ account: commitment, to, value, data, nonce, chainId });
  console.log("authorization digest:", digest);

  // The user's SPHINCS+ signature is over the SAME digest bytes.
  const pqcMessage = Buffer.from(digest.replace(/^0x/, ""), "hex");
  const pqcSignature = pqcSign(kp.secretKey, pqcMessage);
  console.log("SPHINCS+ signature bytes:", pqcSignature.length);

  // 4. Collect an M-of-N attestation (first THRESHOLD attestors).
  const { attestation, setRoot: rebuilt } = requestAttestation({
    attestors: attestors.slice(0, THRESHOLD),
    finalizedLeaves,
    pqcPublicKey: kp.publicKey,
    pqcSignature,
    pqcMessage,
    digest,
  });

  console.log("set root matches:", rebuilt === setRoot);
  console.log("attestation bytes:", (attestation.length - 2) / 2);
  console.log("\nReady to call:");
  console.log("  PQCGuardAccount.migrate(", commitment, ", verifier, guardians, M)");
  console.log("  ... wait 24h ...");
  console.log("  PQCGuardAccount.finalizeMigration(", pqcPublicKeyHex.slice(0, 18), "...)");
  console.log("  PQCGuardAccount.execute(to, value, data, attestation)");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
