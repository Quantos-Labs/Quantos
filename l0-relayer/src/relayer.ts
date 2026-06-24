import { EVMChainMonitor } from './chains/evm';
import { QuantosL0Client } from './quantos';
import { ExternalCheckpoint, ChainConfig } from './types';

export class L0Relayer {
  private quantosClient: QuantosL0Client;
  private monitors: Map<string, EVMChainMonitor> = new Map();
  private configs: Map<string, ChainConfig> = new Map();
  private running: boolean = false;

  constructor(quantosRpcUrl: string) {
    this.quantosClient = new QuantosL0Client(quantosRpcUrl);
  }

  addChain(config: ChainConfig): void {
    console.log(`Adding chain: ${config.id}`);
    this.configs.set(config.id, config);
    
    // For now, only EVM chains are supported
    const monitor = new EVMChainMonitor(config.id, config.rpcUrl);
    this.monitors.set(config.id, monitor);
  }

  async start(): Promise<void> {
    this.running = true;
    console.log('L0 Relayer started');

    // Start monitoring all chains
    const promises = Array.from(this.configs.entries()).map(([chainId, config]) =>
      this.monitorChain(chainId, config)
    );

    await Promise.all(promises);
  }

  stop(): void {
    this.running = false;
    console.log('L0 Relayer stopped');
  }

  private async monitorChain(chainId: string, config: ChainConfig): Promise<void> {
    const monitor = this.monitors.get(chainId);
    if (!monitor) {
      console.error(`No monitor found for chain ${chainId}`);
      return;
    }

    console.log(`Monitoring chain: ${chainId}`);

    while (this.running) {
      try {
        const latestBlock = await monitor.getLatestBlock();
        const lastProcessed = monitor.getLastProcessedBlock();

        // Check if we have a new block with enough confirmations
        if (latestBlock.number > lastProcessed) {
          const targetBlock = latestBlock.number - config.minConfirmations;
          
          if (targetBlock > lastProcessed) {
            const block = await monitor.getBlock(targetBlock);
            await this.submitCheckpoint(chainId, block);
            monitor.setLastProcessedBlock(targetBlock);
          }
        }
      } catch (error) {
        console.error(`Error monitoring chain ${chainId}:`, error);
      }

      // Wait for next poll interval
      await new Promise(resolve => setTimeout(resolve, config.pollInterval * 1000));
    }
  }

  private async submitCheckpoint(chainId: string, block: any): Promise<void> {
    try {
      console.log(`Submitting checkpoint for ${chainId} block ${block.number}`);

      const checkpoint: ExternalCheckpoint = {
        chain_id: chainId,
        block_number: block.number,
        block_hash: block.hash,
        state_root: block.stateRoot,
        timestamp_ms: block.timestamp,
        native_finality_proof: '0x', // finality proof from source chain (attached by relay node)
        metadata: JSON.stringify({
          tx_count: block.transactions.length,
          submitted_at: Date.now(),
        }),
      };

      const response = await this.quantosClient.submitCheckpoint(checkpoint);
      console.log(`Checkpoint submitted for ${chainId} block ${block.number}:`, response);
    } catch (error) {
      console.error(`Failed to submit checkpoint for ${chainId} block ${block.number}:`, error);
      throw error;
    }
  }

  async getMetrics(): Promise<any> {
    return this.quantosClient.getL0Metrics();
  }
}
