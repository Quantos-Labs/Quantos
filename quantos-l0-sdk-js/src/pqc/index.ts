/**
 * Post-Quantum Cryptography (PQC) SDK for L1 chains.
 *
 * This module enables any L1 to become "PQC-ready" without modifying
 * its consensus. Users register a PQC key (Falcon-512) alongside their
 * classical address, and every sensitive action is hybrid-signed
 * (ECDSA + PQC). The PQC signature is verified by Quantos validators
 * or trusted oracles and stored on-chain as a non-repudiable proof.
 */

export { generateKeypair, sign, verify, exportKeypair, importKeypair } from "./falcon";
export type { FalconKeypair, FalconSignature } from "./falcon";

export { HybridWallet } from "./hybrid-wallet";
export type { HybridSignature, PqcIdentity, HybridWalletConfig } from "./hybrid-wallet";

export { EncryptedKeyVault, buildPqcCommitment, generateSalt } from "./encrypted-key-vault";
export type { VaultStorage, SealedVault } from "./encrypted-key-vault";
