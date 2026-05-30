import * as dotenv from 'dotenv';
import * as http from 'http';
import { L0Relayer } from './relayer';
import { ChainConfig } from './types';

dotenv.config();

const QUANTOS_RPC_URL = process.env.QUANTOS_RPC_URL || 'http://localhost:8545';
const SOURCE_CHAINS = (process.env.SOURCE_CHAINS || 'ethereum-sepolia').split(',');
const POLL_INTERVAL = parseInt(process.env.POLL_INTERVAL || '12');
const MIN_CONFIRMATIONS = parseInt(process.env.MIN_CONFIRMATIONS || '6');
const HEALTH_PORT = parseInt(process.env.HEALTH_PORT || '3200');

async function main() {
  console.log('Starting Quantos L0 Relayer...');
  console.log(`Quantos RPC: ${QUANTOS_RPC_URL}`);
  console.log(`Source chains: ${SOURCE_CHAINS.join(', ')}`);

  const relayer = new L0Relayer(QUANTOS_RPC_URL);

  // Add all configured chains
  for (const chainId of SOURCE_CHAINS) {
    const rpcUrlKey = `${chainId.toUpperCase().replace(/-/g, '_')}_RPC_URL`;
    const rpcUrl = process.env[rpcUrlKey];

    if (!rpcUrl) {
      console.warn(`No RPC URL configured for ${chainId} (${rpcUrlKey}), skipping`);
      continue;
    }

    const config: ChainConfig = {
      id: chainId,
      rpcUrl,
      minConfirmations: MIN_CONFIRMATIONS,
      pollInterval: POLL_INTERVAL,
    };

    relayer.addChain(config);
  }

  // Start health check server
  const server = http.createServer(async (req, res) => {
    if (req.url === '/health') {
      try {
        const metrics = await relayer.getMetrics();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'ok',
          timestamp: new Date().toISOString(),
          chains: SOURCE_CHAINS,
          l0_metrics: metrics,
        }));
      } catch (error) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'error',
          error: error instanceof Error ? error.message : 'Unknown error',
        }));
      }
    } else {
      res.writeHead(404);
      res.end('Not found');
    }
  });

  server.listen(HEALTH_PORT, () => {
    console.log(`Health check server listening on port ${HEALTH_PORT}`);
  });

  // Start relayer
  await relayer.start();
}

main().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});
