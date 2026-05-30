import { ethers } from 'ethers'
import { config } from './config.js'
import { db, BridgeDeposit } from './db.js'
import { quantos } from './quantos.js'
import { base } from './base.js'
import { awardBridgePoints } from './rewards.js'
import { logger } from './logger.js'

// Convert a Quantos tx hash to a bytes32 deposit ID for the Base gateway contract
function quantosTxHashToDepositId(txHash: string): string {
  const raw = txHash.replace(/^QTS:/, '').replace(/^0x/i, '')
  // Pad or truncate to 32 bytes (64 hex chars)
  const padded = raw.padStart(64, '0').slice(0, 64)
  return '0x' + padded
}

// Convert a QTS address to bytes32 for the quantosSender param
function qtsAddressToBytes32(address: string): string {
  const raw = address.replace(/^QTS:/, '').replace(/^0x/i, '')
  const padded = raw.padStart(64, '0').slice(0, 64)
  return '0x' + padded
}

// Convert human-readable amount (e.g. "10") to wei bigint (18 decimals)
function amountToWei(amount: string): bigint {
  return ethers.parseEther(amount)
}

// Extract EVM address from a bytes32 encoded address (last 20 bytes)
function bytes32ToEvmAddress(bytes32: string): string {
  const raw = bytes32.replace(/^0x/i, '').padStart(64, '0')
  return ethers.getAddress('0x' + raw.slice(24))
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

export class BridgeRelayer {
  private running = false
  private processedCount = 0
  private failedCount = 0
  private skippedCount = 0
  private lastPollAt: Date | null = null
  private startedAt: Date | null = null

  async start(): Promise<void> {
    this.running = true
    this.startedAt = new Date()
    logger.info('=== Bridge Relayer Starting ===')

    // Initialize Base provider/wallet/contracts
    base.init()

    // Verify configuration
    await this.verifySetup()

    logger.info(`Polling every ${config.pollIntervalMs}ms`)
    logger.info('=== Bridge Relayer Running ===')

    while (this.running) {
      try {
        await this.pollAndProcess()
      } catch (err) {
        logger.error('Poll cycle error:', err)
      }
      await sleep(config.pollIntervalMs)
    }

    logger.info('=== Bridge Relayer Stopped ===')
  }

  stop(): void {
    this.running = false
    logger.info('Bridge relayer stopping gracefully...')
  }

  getStatus() {
    return {
      running: this.running,
      startedAt: this.startedAt?.toISOString() || null,
      processedCount: this.processedCount,
      failedCount: this.failedCount,
      skippedCount: this.skippedCount,
      lastPollAt: this.lastPollAt?.toISOString() || null,
      relayerAddress: base.getRelayerAddress(),
      gatewayAddress: config.baseBridgeGatewayAddress,
      wrappedQtestAddress: config.baseWrappedQtestAddress,
      vaultAddress: config.bridgeVaultAddress,
    }
  }

  private async verifySetup(): Promise<void> {
    // 1. Check Quantos node
    try {
      const nodeInfo = await quantos.getNodeInfo() as any
      logger.info(`Quantos node connected: chain_id=${nodeInfo.chain_id}, slot=${nodeInfo.current_slot}`)
    } catch (err) {
      throw new Error(`Cannot reach Quantos node at ${config.quantosRpcUrl}: ${err}`)
    }

    // 2. Check Base connection
    try {
      const network = await new ethers.JsonRpcProvider(config.baseRpcUrl).getNetwork()
      logger.info(`Base network connected: chainId=${network.chainId}`)
    } catch (err) {
      throw new Error(`Cannot reach Base RPC at ${config.baseRpcUrl}: ${err}`)
    }

    // 3. Check relayer is authorized on gateway
    const isRelayer = await base.isAuthorizedRelayer()
    if (!isRelayer) {
      throw new Error(
        `FATAL: Relayer ${base.getRelayerAddress()} is NOT authorized on gateway ${config.baseBridgeGatewayAddress}. ` +
        `The gateway owner must call setRelayer(${base.getRelayerAddress()}, true).`
      )
    }
    logger.info(`Relayer ${base.getRelayerAddress()} is authorized on gateway`)

    // 4. Check gateway is not paused
    const paused = await base.isPaused()
    if (paused) {
      logger.warn('WARNING: Gateway contract is PAUSED. No mints will succeed until unpaused.')
    }

    // 5. Check relayer has ETH for gas
    const balance = await base.getRelayerBalance()
    logger.info(`Relayer Base ETH balance: ${balance}`)
    if (parseFloat(balance) < 0.001) {
      logger.warn('WARNING: Low relayer ETH balance on Base! Fund it to pay for gas.')
    }

    // 6. Check Supabase
    const stats = await db.getStats()
    logger.info(`Supabase stats: total=${stats.total}, pending=${stats.pending}, completed=${stats.completed}, failed=${stats.failed}`)
  }

  private async pollAndProcess(): Promise<void> {
    this.lastPollAt = new Date()

    // Get pending deposits
    const pending = await db.getPendingDeposits()

    // Also recover stuck "relaying" deposits (older than 2 min)
    const stuck = await db.getFailedRetryable()

    const allDeposits = [...pending, ...stuck]
    if (allDeposits.length === 0) return

    logger.info(`Processing ${allDeposits.length} deposits (${pending.length} pending, ${stuck.length} stuck)`)

    for (const deposit of allDeposits) {
      if (!this.running) break

      try {
        await this.processDeposit(deposit)
      } catch (err: any) {
        const errMsg = err?.message || String(err)
        const errStack = err?.stack || ''
        logger.error(`=== DEPOSIT FAILED === id=${deposit.id}`)
        logger.error(`  quantos_tx  = ${deposit.quantos_tx_hash}`)
        logger.error(`  recipient   = ${deposit.base_recipient}`)
        logger.error(`  amount      = ${deposit.amount}`)
        logger.error(`  error       = ${errMsg}`)
        if (err?.code) logger.error(`  error.code  = ${err.code}`)
        if (err?.data) logger.error(`  error.data  = ${err.data}`)
        logger.debug(`  stack       = ${errStack}`)

        const newRetry = (deposit.retry_count || 0) + 1
        await db.updateDeposit(deposit.id, {
          status: newRetry >= config.maxRetries ? 'failed' : 'pending',
          error_message: errMsg.slice(0, 1000),
          retry_count: newRetry,
        })

        if (newRetry >= config.maxRetries) {
          this.failedCount++
          logger.error(`Deposit ${deposit.id} permanently failed after ${newRetry} retries`)
        }
      }

      // Small delay between deposits to avoid nonce issues
      await sleep(500)
    }
  }

  private async processDeposit(deposit: BridgeDeposit): Promise<void> {
    const tag = `[${deposit.id.slice(0, 8)}]`
    logger.info(`${tag} Processing: tx=${deposit.quantos_tx_hash}, amount=${deposit.amount}, to=${deposit.base_recipient}`)

    // Mark as relaying
    await db.updateDeposit(deposit.id, { status: 'relaying' })

    // 1. Verify Quantos receipt on-chain
    const verification = await quantos.verifyBridgeDeposit(deposit.quantos_tx_hash)
    if (!verification.valid) {
      await db.updateDeposit(deposit.id, {
        status: 'failed',
        error_message: `Quantos verification failed: ${verification.error}`,
      })
      this.failedCount++
      logger.error(`${tag} Quantos verification failed: ${verification.error}`)
      return
    }

    logger.info(`${tag} Quantos receipt verified: from=${verification.from}, amount=${verification.amount}, method=${verification.method || 'unknown'}`)

    // 2. Build deposit ID from Quantos tx hash
    const depositIdHex = quantosTxHashToDepositId(deposit.quantos_tx_hash)

    // 3. Check if already processed on Base (idempotency)
    const alreadyProcessed = await base.isDepositProcessed(depositIdHex)
    if (alreadyProcessed) {
      logger.info(`${tag} Already processed on Base, marking completed`)
      await db.updateDeposit(deposit.id, {
        status: 'completed',
        deposit_id_hex: depositIdHex,
      })
      try {
        await awardBridgePoints({
          ...deposit,
          status: 'completed',
          deposit_id_hex: depositIdHex,
        })
      } catch (err) {
        logger.error(`${tag} Bridge points award failed:`, err)
      }
      this.skippedCount++
      return
    }

    // 4. Parse amounts
    // Use the on-chain verified amount, not the user-submitted one
    const amountWei = verification.amount
    if (amountWei === 0n) {
      await db.updateDeposit(deposit.id, {
        status: 'failed',
        error_message: 'On-chain amount is 0',
      })
      this.failedCount++
      return
    }

    // 5. Resolve base_recipient
    // Prefer the on-chain recipient from QuantosBridgeVault.deposit when available.
    let baseRecipient = deposit.base_recipient
    if (verification.baseRecipientBytes32) {
      const onChainRecipient = bytes32ToEvmAddress(verification.baseRecipientBytes32)
      logger.info(`${tag} On-chain base recipient verified: ${onChainRecipient}`)

      if (baseRecipient.length === 66) {
        baseRecipient = bytes32ToEvmAddress(baseRecipient)
      }

      if (baseRecipient.toLowerCase() !== onChainRecipient.toLowerCase()) {
        logger.warn(`${tag} Supabase recipient ${baseRecipient} differs from on-chain recipient ${onChainRecipient}; using on-chain recipient`)
      }

      baseRecipient = onChainRecipient
    } else if (baseRecipient.length === 66) {
      // Legacy flow stored a bytes32 recipient in the deposit record.
      baseRecipient = bytes32ToEvmAddress(baseRecipient)
    }

    // 6. Build quantosSender as bytes32
    const quantosSenderBytes32 = qtsAddressToBytes32(deposit.quantos_sender)

    // 7. Send mintFromQuantos on Base
    logger.info(`${tag} Sending mintFromQuantos on Base...`)
    logger.info(`${tag}   depositIdHex       = ${depositIdHex}`)
    logger.info(`${tag}   verification.nonce  = ${verification.nonce}`)
    logger.info(`${tag}   quantosSenderBytes32= ${quantosSenderBytes32}`)
    logger.info(`${tag}   baseRecipient       = ${baseRecipient}`)
    logger.info(`${tag}   amountWei           = ${amountWei} (${ethers.formatEther(amountWei)} wQTEST)`)

    const baseTx = await base.mintFromQuantos(
      depositIdHex,
      verification.nonce,
      quantosSenderBytes32,
      baseRecipient,
      amountWei,
    )

    logger.info(`${tag} Base tx sent: ${baseTx.hash}`)
    await db.updateDeposit(deposit.id, { base_tx_hash: baseTx.hash })

    // 8. Wait for confirmation (2 block confirmations)
    logger.info(`${tag} Waiting for Base confirmation...`)
    const receipt = await baseTx.wait(2)

    if (!receipt || receipt.status !== 1) {
      logger.error(`${tag} BASE TX REVERTED on-chain!`)
      logger.error(`${tag}   tx hash     = ${baseTx.hash}`)
      logger.error(`${tag}   status      = ${receipt?.status}`)
      logger.error(`${tag}   gasUsed     = ${receipt?.gasUsed}`)
      logger.error(`${tag}   blockNumber = ${receipt?.blockNumber}`)
      logger.error(`${tag}   logs count  = ${receipt?.logs?.length || 0}`)
      throw new Error(`Base tx reverted on-chain: ${baseTx.hash} (status=${receipt?.status}, gasUsed=${receipt?.gasUsed})`)
    }

    // 9. Mark completed
    const relayedAt = new Date().toISOString()
    await db.updateDeposit(deposit.id, {
      status: 'completed',
      deposit_id_hex: depositIdHex,
      base_tx_hash: baseTx.hash,
      relayed_at: relayedAt,
    })
    try {
      await awardBridgePoints({
        ...deposit,
        status: 'completed',
        deposit_id_hex: depositIdHex,
        base_tx_hash: baseTx.hash,
        relayed_at: relayedAt,
      })
    } catch (err) {
      logger.error(`${tag} Bridge points award failed:`, err)
    }

    this.processedCount++
    logger.info(`${tag} COMPLETED | Base tx: ${baseTx.hash} | wQTEST minted: ${ethers.formatEther(amountWei)} to ${baseRecipient}`)
  }
}
