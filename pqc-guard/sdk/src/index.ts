// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

// PQC-Guard SDK — public API. TESTNET ONLY.

export * as wots from "./wots.js";
export * as merkle from "./merkle.js";
export * as pqc from "./pqc.js";
export { Attestor, attestorLeaf, type AttestorConfig } from "./attestor.js";
export {
  authorizationDigest,
  buildMigration,
  requestAttestation,
  encodeAttestation,
  type AttestorProofStruct,
} from "./account.js";
export {
  encodeAttestationCanonical,
  encodeAttestationCanonicalHex,
  canonicalDigest,
  digestForChain,
  normalizeTo,
  CHAIN_IDS,
  type ChainKind,
} from "./canonical.js";
