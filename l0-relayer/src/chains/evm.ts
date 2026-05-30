import { ethers } from 'ethers';
import { BlockData } from '../types';

export class EVMChainMonitor {
  private provider: ethers.JsonRpcProvider;
  private chainId: string;
  private lastProcessedBlock: number = 0;

  constructor(chainId: string, rpcUrl: string) {
    this.chainId = chainId;
    this.provider = new ethers.JsonRpcProvider(rpcUrl);
  }

  async getLatestBlock(): Promise<BlockData> {
    const block = await this.provider.getBlock('latest');
    if (!block) {
      throw new Error('Failed to fetch latest block');
    }

    return {
      number: block.number,
      hash: block.hash || '',
      stateRoot: block.stateRoot || '',
      timestamp: block.timestamp * 1000, // Convert to milliseconds
      transactions: block.transactions as string[],
    };
  }

  async getBlock(blockNumber: number): Promise<BlockData> {
    const block = await this.provider.getBlock(blockNumber);
    if (!block) {
      throw new Error(`Block ${blockNumber} not found`);
    }

    return {
      number: block.number,
      hash: block.hash || '',
      stateRoot: block.stateRoot || '',
      timestamp: block.timestamp * 1000,
      transactions: block.transactions as string[],
    };
  }

  async waitForConfirmations(blockNumber: number, confirmations: number): Promise<boolean> {
    const latestBlock = await this.provider.getBlockNumber();
    return latestBlock >= blockNumber + confirmations;
  }

  getChainId(): string {
    return this.chainId;
  }

  setLastProcessedBlock(blockNumber: number): void {
    this.lastProcessedBlock = blockNumber;
  }

  getLastProcessedBlock(): number {
    return this.lastProcessedBlock;
  }
}
