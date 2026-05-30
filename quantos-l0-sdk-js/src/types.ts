export type Hash = string;

export const L0_PROOF_VERSION = 1;

export enum PqcSignatureAlgo {
  Falcon512 = 1,
  Dilithium3 = 2,
}

export interface L0ProofHeader {
  version: number;
  epoch: number;
  slot: number;
  previous_proof_hash: Hash;
  state_root: Hash;
  dag_root: Hash;
  validator_set_root: Hash;
  total_stake: number;
  stake_threshold: number;
  emitted_at_ms: number;
}

export interface ValidatorRecord {
  address: Hash;
  public_key: string;
  stake: number;
}

export interface ProofSignature {
  validator_index: number;
  algo: PqcSignatureAlgo;
  signature: string;
}

export interface L0FinalityProof {
  header: L0ProofHeader;
  validators: ValidatorRecord[];
  signatures: ProofSignature[];
}

export interface ValidatorSetSnapshot {
  root: Hash;
  validators: ValidatorRecord[];
}

export interface VerificationReport {
  signed_stake: number;
  stake_threshold: number;
  valid_signatures: number;
  invalid_signatures: number;
  is_final: boolean;
}
