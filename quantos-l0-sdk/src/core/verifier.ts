import { L0FinalityProof, ValidatorRecord, ProofSignature } from '../types/proof';
import { createHash } from 'crypto';

export interface VerifyOptions {
  thresholdNum: bigint;
  thresholdDen: bigint;
}

export interface VerifyResult {
  valid: boolean;
  signedStake: bigint;
  totalStake: bigint;
  fraction: number;
  reason?: string;
}

export class ExternalVerifier {
  static proofDigest(proof: L0FinalityProof): string {
    const canonical = JSON.stringify(proof, Object.keys(proof).sort());
    return '0x' + createHash('sha256').update(canonical).digest('hex');
  }

  static verify(proof: L0FinalityProof, options: VerifyOptions): VerifyResult {
    const totalStake = proof.validators.reduce((sum, v) => sum + BigInt(v.stake), 0n);
    const uniqueValidators = new Set<number>();
    let signedStake = 0n;

    for (const sig of proof.signatures) {
      if (sig.validatorIdx >= proof.validators.length) {
        return { valid: false, signedStake: 0n, totalStake, fraction: 0, reason: 'Invalid validator index' };
      }
      if (uniqueValidators.has(sig.validatorIdx)) {
        return { valid: false, signedStake: 0n, totalStake, fraction: 0, reason: 'Duplicate validator signature' };
      }
      uniqueValidators.add(sig.validatorIdx);
      signedStake += BigInt(proof.validators[sig.validatorIdx].stake);
    }

    const fraction = totalStake > 0n ? Number(signedStake) / Number(totalStake) : 0;
    const required = (options.thresholdNum * totalStake) / options.thresholdDen;

    if (signedStake < required) {
      return { valid: false, signedStake, totalStake, fraction, reason: 'Insufficient signed stake' };
    }

    return { valid: true, signedStake, totalStake, fraction };
  }
}
