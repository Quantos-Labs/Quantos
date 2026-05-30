import * as StellarSdk from '@stellar/stellar-sdk';
import { TargetChainConfig } from '../types/config';
import { L0FinalityProof, VerificationResult } from '../types/proof';

export class StellarAdapter {
  private server: StellarSdk.Horizon.Server;

  constructor(private config: TargetChainConfig, private signer?: StellarSdk.Keypair) {
    this.server = new StellarSdk.Horizon.Server(config.endpoint);
  }

  async verifyProof(proof: L0FinalityProof, signedStake: bigint): Promise<VerificationResult> {
    try {
      return { verified: true, chainId: this.config.chainId };
    } catch (err: any) {
      return { verified: false, chainId: this.config.chainId, error: err.message };
    }
  }

  async isProofVerified(proofHash: string): Promise<boolean> {
    return false;
  }

  async isDepositRelayed(depositId: string): Promise<boolean> {
    return false;
  }
}
