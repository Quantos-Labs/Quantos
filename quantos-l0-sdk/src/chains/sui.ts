import { SuiClient } from '@mysten/sui.js/client';
import { TransactionBlock } from '@mysten/sui.js/transactions';
import { TargetChainConfig } from '../types/config';
import { L0FinalityProof, VerificationResult } from '../types/proof';

export class SuiAdapter {
  private client: SuiClient;

  constructor(private config: TargetChainConfig, private signer?: any) {
    this.client = new SuiClient({ url: config.endpoint });
  }

  async verifyProof(proof: L0FinalityProof, signedStake: bigint): Promise<VerificationResult> {
    try {
      const txb = new TransactionBlock();
      txb.moveCall({
        target: `${this.config.verifierAddress}::l0_verifier::verify_proof`,
        arguments: [
          txb.object(this.config.verifierAddress), // registry
          txb.pure(proof.header.stateRoot),          // state_root
          txb.pure(Array.from(Buffer.from(proof.header.checkpointHash, 'hex'))),
          txb.pure(proof.header.epoch),
          txb.pure(proof.header.slot),
          txb.pure(proof.header.stateRoot),
          txb.pure(signedStake.toString()),
        ],
      });
      // Sign and execute omitted for brevity
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
