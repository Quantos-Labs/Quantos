import { config } from './config.js'
import { setLogLevel } from './logger.js'
import { logger } from './logger.js'
import { BridgeRelayer } from './relayer.js'
import { startHealthServer } from './health.js'

setLogLevel(config.logLevel as any)

const relayer = new BridgeRelayer()

// Graceful shutdown
function shutdown(signal: string): void {
  logger.info(`Received ${signal}, shutting down...`)
  relayer.stop()
  setTimeout(() => {
    logger.info('Force exit')
    process.exit(0)
  }, 10_000)
}

process.on('SIGINT', () => shutdown('SIGINT'))
process.on('SIGTERM', () => shutdown('SIGTERM'))

// Start health server first
startHealthServer(relayer)

// Start relayer
relayer.start().catch(err => {
  logger.error('Fatal relayer error:', err)
  process.exit(1)
})
