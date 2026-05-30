/**
 * Quantos L0 SDK — Post-Quantum Finality Proof client for all supported chains
 *
 * @example
 * ```ts
 * import { QuantosL0SDK } from '@quantos/l0-sdk';
 *
 * const sdk = new QuantosL0SDK({
 *   quantos: { rpcUrl: 'http://127.0.0.1:8555' },
 *   targets: [
 *     { chainId: 'base', family: ChainFamily.Evm, endpoint: 'https://base.llamarpc.com', verifierAddress: '0x...' },
 *   ],
 * });
 *
 * const proof = await sdk.getLatestProof();
 * const result = await sdk.verifyOnChain('base', proof!, 7000n);
 * console.log(result.verified);
 * ```
 */

export { QuantosNodeClient } from './core/client';
export { ExternalVerifier } from './core/verifier';

export { EvmAdapter } from './chains/evm';
export { SolanaAdapter } from './chains/solana';
export { SuiAdapter } from './chains/sui';
export { AptosAdapter } from './chains/aptos';
export { NearAdapter } from './chains/near';
export { CosmosAdapter } from './chains/cosmos';
export { PolkadotAdapter } from './chains/polkadot';
export { StellarAdapter } from './chains/stellar';
export { TonAdapter } from './chains/ton';
export { CardanoAdapter } from './chains/cardano';
export { StacksAdapter } from './chains/stacks';

export * from './types/config';
export * from './types/proof';

import { QuantosNodeConfig, TargetChainConfig, ChainFamily } from './types/config';
import { L0FinalityProof, VerificationResult } from './types/proof';
import { QuantosNodeClient } from './core/client';
import { ExternalVerifier } from './core/verifier';
import { EvmAdapter } from './chains/evm';
import { SolanaAdapter } from './chains/solana';
import { SuiAdapter } from './chains/sui';
import { AptosAdapter } from './chains/aptos';
import { NearAdapter } from './chains/near';
import { CosmosAdapter } from './chains/cosmos';
import { PolkadotAdapter } from './chains/polkadot';
import { StellarAdapter } from './chains/stellar';
import { TonAdapter } from './chains/ton';
import { CardanoAdapter } from './chains/cardano';
import { StacksAdapter } from './chains/stacks';

export interface L0SdkConfig {
  quantos: QuantosNodeConfig;
  targets: TargetChainConfig[];
}

export class QuantosL0SDK {
  public client: QuantosNodeClient;
  private adapters: Map<string, any>;

  constructor(private config: L0SdkConfig) {
    this.client = new QuantosNodeClient(config.quantos);
    this.adapters = new Map();
    for (const target of config.targets) {
      this.adapters.set(target.chainId, this.buildAdapter(target));
    }
  }

  private buildAdapter(target: TargetChainConfig) {
    switch (target.family) {
      case ChainFamily.Evm:
        return new EvmAdapter(target);
      case ChainFamily.Svm:
        return new SolanaAdapter(target);
      case ChainFamily.Move:
        return target.chainId === 'sui' ? new SuiAdapter(target) : new AptosAdapter(target);
      case ChainFamily.Near:
        return new NearAdapter(target);
      case ChainFamily.Cosmos:
        return new CosmosAdapter(target);
      case ChainFamily.Wasm:
        return new PolkadotAdapter(target);
      case ChainFamily.Stellar:
        return new StellarAdapter(target);
      case ChainFamily.Ton:
        return new TonAdapter(target);
      case ChainFamily.Cardano:
        return new CardanoAdapter(target);
      case ChainFamily.Stacks:
        return new StacksAdapter(target);
      default:
        throw new Error(`Unsupported chain family: ${target.family}`);
    }
  }

  /** Fetch the latest L0 proof from Quantos */
  async getLatestProof(): Promise<L0FinalityProof | null> {
    return this.client.getLatestProof();
  }

  /** Fetch a specific proof by checkpoint hash */
  async getProofByHash(checkpointHash: string): Promise<L0FinalityProof | null> {
    return this.client.getProofByHash(checkpointHash);
  }

  /** Off-chain verification (stake-weighted) */
  verifyOffChain(proof: L0FinalityProof, thresholdNum: bigint, thresholdDen: bigint) {
    return ExternalVerifier.verify(proof, { thresholdNum, thresholdDen });
  }

  /** On-chain verification via the target chain's verifier contract */
  async verifyOnChain(chainId: string, proof: L0FinalityProof, signedStake: bigint): Promise<VerificationResult> {
    const adapter = this.adapters.get(chainId);
    if (!adapter) throw new Error(`No adapter registered for chain: ${chainId}`);
    return adapter.verifyProof(proof, signedStake);
  }

  /** Check if a proof is already verified on a target chain */
  async isProofVerified(chainId: string, proofHash: string): Promise<boolean> {
    const adapter = this.adapters.get(chainId);
    if (!adapter) throw new Error(`No adapter registered for chain: ${chainId}`);
    return adapter.isProofVerified(proofHash);
  }

  /** Check if a deposit is already relayed on a target chain */
  async isDepositRelayed(chainId: string, depositId: string): Promise<boolean> {
    const adapter = this.adapters.get(chainId);
    if (!adapter) throw new Error(`No adapter registered for chain: ${chainId}`);
    return adapter.isDepositRelayed(depositId);
  }
}
