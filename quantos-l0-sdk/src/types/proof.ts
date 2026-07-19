/**
 * Core types mirroring the Rust L0FinalityProof wire format.
 */

export enum PqcSignatureAlgo {
  MlDsa65 = 1,
  Dilithium3 = 2,
}

export interface ValidatorRecord {
  /** Validator address (hex string) */
  address: string;
  /** Stake amount (wei / lamport / raw units) */
  stake: string;
  /** PQC public key bytes (base64 or hex) */
  pubKey: string;
}

export interface ProofSignature {
  /** Index into the validators array */
  validatorIdx: number;
  /** Raw signature bytes (base64 or hex) */
  sigData: string;
  /** Algorithm used */
  algo: PqcSignatureAlgo;
}

export interface L0ProofHeader {
  /** Hash of the checkpoint this proof attests to */
  checkpointHash: string;
  /** Epoch number */
  epoch: number;
  /** Slot number */
  slot: number;
  /** Quantos state root */
  stateRoot: string;
  /** Block height */
  height: number;
  /** Unix timestamp of the proof */
  timestamp: number;
}

/**
 * L0 Finality Proof — the canonical artifact produced by FinalityHub.
 */
export interface L0FinalityProof {
  header: L0ProofHeader;
  validators: ValidatorRecord[];
  signatures: ProofSignature[];
}

/**
 * On-chain verification result returned by target-chain contracts.
 */
export interface VerificationResult {
  /** Whether the proof passed all on-chain checks */
  verified: boolean;
  /** Target chain that verified it */
  chainId: string;
  /** Transaction hash of the verify call (if applicable) */
  txHash?: string;
  /** Human-readable error if verification failed */
  error?: string;
}

/**
 * Relay outcome from RelayDispatcher.
 */
export interface RelayOutcome {
  chainId: string;
  success: boolean;
  txHash?: string;
  error?: string;
}
