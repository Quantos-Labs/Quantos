import { ethers, Contract, Interface, JsonRpcProvider, Wallet } from 'ethers';
import { TargetChainConfig } from '../types/config';
import { L0FinalityProof, VerificationResult } from '../types/proof';

const VERIFIER_ABI = [
  'function verifyProof(bytes32 proofHash, bytes32 validatorSetRoot, uint64 epoch, uint64 slot, bytes32 stateRoot, uint128 signedStake) external',
  'function authorizeRelay(bytes32 proofHash, bytes32 quantosDepositId, uint64 amount) external',
  'function isProofVerified(bytes32 proofHash) external view returns (bool)',
  'function isDepositRelayed(bytes32 depositId) external view returns (bool)',
  'function registerValidatorSet(bytes32 root, uint128 totalStake, uint128 threshold) external',
  'event ProofVerified(bytes32 indexed proofHash, bytes32 indexed validatorSetRoot, uint64 epoch, uint64 slot)',
];

export class EvmAdapter {
  private provider: JsonRpcProvider;
  private contract: Contract;

  constructor(private config: TargetChainConfig, private signer?: Wallet) {
    this.provider = new JsonRpcProvider(config.endpoint);
    this.contract = new Contract(config.verifierAddress, VERIFIER_ABI, this.provider);
  }

  async verifyProof(proof: L0FinalityProof, signedStake: bigint): Promise<VerificationResult> {
    try {
      const proofHash = ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(proof)));
      const stateRoot = proof.header.stateRoot;
      const validatorSetRoot = proof.validators.length > 0 ? ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(proof.validators))) : ethers.ZeroHash;

      const tx = await this.contract.verifyProof(
        proofHash,
        validatorSetRoot,
        proof.header.epoch,
        proof.header.slot,
        stateRoot,
        signedStake,
        { gasLimit: 500000 }
      );
      const receipt = await tx.wait();
      return { verified: true, chainId: this.config.chainId, txHash: receipt.hash };
    } catch (err: any) {
      return { verified: false, chainId: this.config.chainId, error: err.message || String(err) };
    }
  }

  async isProofVerified(proofHash: string): Promise<boolean> {
    return this.contract.isProofVerified(proofHash);
  }

  async isDepositRelayed(depositId: string): Promise<boolean> {
    return this.contract.isDepositRelayed(depositId);
  }

  async authorizeRelay(proofHash: string, depositId: string, amount: bigint): Promise<string> {
    const tx = await this.contract.authorizeRelay(proofHash, depositId, amount, { gasLimit: 300000 });
    const receipt = await tx.wait();
    return receipt.hash;
  }
}
