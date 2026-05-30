/**
 * SDK configuration types.
 */

export interface QuantosNodeConfig {
  /** Quantos RPC endpoint (e.g. http://127.0.0.1:8555) */
  rpcUrl: string;
  /** Optional API key */
  apiKey?: string;
  /** Request timeout in ms */
  timeoutMs?: number;
}

export interface TargetChainConfig {
  /** Chain identifier (e.g. "ethereum", "solana", "sui") */
  chainId: string;
  /** Family: evm | svm | move | tvm | stellar | cosmos | wasm | near | ton | cardano | stacks */
  family: ChainFamily;
  /** RPC / JSON-RPC endpoint for the target chain */
  endpoint: string;
  /** Address of the QuantosL0Verifier contract / program / module */
  verifierAddress: string;
  /** Optional: account that sends verify transactions (defaults to wallet) */
  senderAddress?: string;
  /** Gas price / fee settings (chain-specific) */
  gasSettings?: Record<string, unknown>;
}

export enum ChainFamily {
  Evm = 'evm',
  Svm = 'svm',
  Move = 'move',
  Tvm = 'tvm',
  Stellar = 'stellar',
  Cosmos = 'cosmos',
  Wasm = 'wasm',
  Near = 'near',
  Ton = 'ton',
  Cardano = 'cardano',
  Stacks = 'stacks',
}

export interface L0SdkConfig {
  quantos: QuantosNodeConfig;
  targets: TargetChainConfig[];
  /** Whether to archive fetched proofs locally */
  archiveProofs?: boolean;
}
