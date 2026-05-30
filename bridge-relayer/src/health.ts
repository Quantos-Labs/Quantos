import express from 'express'
import { config } from './config.js'
import { db } from './db.js'
import { base } from './base.js'
import { logger } from './logger.js'
import type { BridgeRelayer } from './relayer.js'

export function startHealthServer(relayer: BridgeRelayer): void {
  const app = express()
  app.use(express.json())

  // Health check
  app.get('/health', (_req, res) => {
    const status = relayer.getStatus()
    res.json({
      ok: status.running,
      ...status,
    })
  })

  // Detailed stats
  app.get('/stats', async (_req, res) => {
    try {
      const [dbStats, relayerBalance, wqtestSupply] = await Promise.all([
        db.getStats(),
        base.getRelayerBalance(),
        base.getWQtestTotalSupply(),
      ])

      res.json({
        relayer: relayer.getStatus(),
        database: dbStats,
        base: {
          relayerBalance: relayerBalance + ' ETH',
          wqtestTotalSupply: wqtestSupply + ' wQTEST',
          gatewayAddress: config.baseBridgeGatewayAddress,
          wrappedQtestAddress: config.baseWrappedQtestAddress,
        },
      })
    } catch (err: any) {
      res.status(500).json({ error: err.message })
    }
  })

  // Recent deposits
  app.get('/deposits', async (_req, res) => {
    try {
      const limit = Number(_req.query.limit) || 50
      const deposits = await db.getRecentDeposits(limit)
      res.json({ count: deposits.length, deposits })
    } catch (err: any) {
      res.status(500).json({ error: err.message })
    }
  })

  // Lookup deposit by Quantos tx hash
  app.get('/deposit/:txHash', async (req, res) => {
    try {
      const deposit = await db.getDepositByQuantosTxHash(req.params.txHash)
      if (!deposit) {
        res.status(404).json({ error: 'Deposit not found' })
        return
      }
      res.json(deposit)
    } catch (err: any) {
      res.status(500).json({ error: err.message })
    }
  })

  // Check wQTEST balance for an address
  app.get('/balance/:address', async (req, res) => {
    try {
      const balance = await base.getWQtestBalance(req.params.address)
      res.json({ address: req.params.address, balance: balance + ' wQTEST' })
    } catch (err: any) {
      res.status(500).json({ error: err.message })
    }
  })

  app.listen(config.healthPort, () => {
    logger.info(`Health server listening on http://localhost:${config.healthPort}`)
    logger.info(`  GET /health       - relayer status`)
    logger.info(`  GET /stats        - detailed stats`)
    logger.info(`  GET /deposits     - recent deposits`)
    logger.info(`  GET /deposit/:tx  - lookup by Quantos tx hash`)
    logger.info(`  GET /balance/:addr - wQTEST balance`)
  })
}
