export interface ExternalCheckpoint {
  chain_id: string;
  block_number: number;
  block_hash: string;
  state_root: string;
  timestamp_ms: number;
  native_finality_proof: string;
  metadata?: string;
}

export interface L0ProofResponse {
  proof_hash: string;
  status: string;
  signed_stake: string;
  required_stake: string;
}

export interface ChainConfig {
  id: string;
  rpcUrl: string;
  minConfirmations: number;
  pollInterval: number;
}

export interface BlockData {
  number: number;
  hash: string;
  stateRoot: string;
  timestamp: number;
  transactions: string[];
}
