import { ethers } from 'ethers'
import { config } from './config.js'
import { logger } from './logger.js'

// Full ABI for BaseBridgeGateway including custom errors
const GATEWAY_ABI = [
  'function mintFromQuantos(bytes32 quantosDepositId, uint256 quantosDepositNonce, bytes32 quantosSender, address recipient, uint256 amount) external',
  'function processedQuantosDeposits(bytes32) view returns (bool)',
  'function relayers(address) view returns (bool)',
  'function paused() view returns (bool)',
  'function owner() view returns (address)',
  'function burnNonce() view returns (uint256)',
  // Custom errors for revert reason decoding
  'error ZeroAddress()',
  'error InvalidAmount()',
  'error InvalidId()',
  'error InvalidRecipient()',
  'error Unauthorized()',
  'error DepositAlreadyProcessed()',
]

const WRAPPED_QTEST_ERRORS = [
  'error ZeroAddress()',
  'error Unauthorized()',
]

const WRAPPED_QTEST_ABI = [
  'function balanceOf(address) view returns (uint256)',
  'function totalSupply() view returns (uint256)',
  'function bridgeGateway() view returns (address)',
]

let provider: ethers.JsonRpcProvider
let wallet: ethers.Wallet
let gateway: ethers.Contract
let wrappedQtest: ethers.Contract
let relayerAddress: string

// ── Revert reason decoder ──
const gatewayInterface = new ethers.Interface(GATEWAY_ABI)

function decodeRevertReason(err: any): string {
  // 1. ethers already decoded it
  if (err?.reason) return `reason: ${err.reason}`

  // 2. Try to decode from error data
  const data = err?.data || err?.error?.data || err?.info?.error?.data
  if (data && typeof data === 'string' && data.length > 2) {
    try {
      const parsed = gatewayInterface.parseError(data)
      if (parsed) return `custom error: ${parsed.name}(${parsed.args.join(', ')})`
    } catch { /* not a known custom error */ }

    // 3. Try standard string revert  "08c379a2" = Error(string)
    if (data.startsWith('0x08c379a2')) {
      try {
        const msg = ethers.AbiCoder.defaultAbiCoder().decode(['string'], '0x' + data.slice(10))
        return `Error("${msg[0]}")`
      } catch { /* ignore */ }
    }

    return `raw revert data: ${data.slice(0, 138)}`
  }

  // 4. Extract from nested error message
  const msg = err?.message || err?.error?.message || ''
  const match = msg.match(/reverted with reason string '([^']+)'/)
  if (match) return `reason: ${match[1]}`

  const customMatch = msg.match(/reverted with custom error '([^']+)'/)
  if (customMatch) return `custom error: ${customMatch[1]}`

  // 5. Check for execution reverted
  if (msg.includes('execution reverted')) {
    return `execution reverted (no decoded reason — check contract state & params)`
  }

  return err?.message?.slice(0, 300) || 'unknown error'
}

function init(): void {
  provider = new ethers.JsonRpcProvider(config.baseRpcUrl)
  wallet = new ethers.Wallet(config.relayerPrivateKey, provider)
  relayerAddress = wallet.address
  gateway = new ethers.Contract(config.baseBridgeGatewayAddress, GATEWAY_ABI, wallet)
  wrappedQtest = new ethers.Contract(config.baseWrappedQtestAddress, WRAPPED_QTEST_ABI, provider)

  logger.info(`Base relayer address: ${relayerAddress}`)
  logger.info(`Base gateway: ${config.baseBridgeGatewayAddress}`)
  logger.info(`Base wQTEST: ${config.baseWrappedQtestAddress}`)
}

export const base = {
  init,

  getRelayerAddress(): string {
    return relayerAddress
  },

  async isAuthorizedRelayer(): Promise<boolean> {
    try {
      return await gateway.relayers(relayerAddress)
    } catch (err) {
      logger.error('Failed to check relayer status:', err)
      return false
    }
  },

  async isPaused(): Promise<boolean> {
    try {
      return await gateway.paused()
    } catch (err) {
      logger.error('Failed to check paused status:', err)
      return false
    }
  },

  async getRelayerBalance(): Promise<string> {
    const bal = await provider.getBalance(relayerAddress)
    return ethers.formatEther(bal)
  },

  async isDepositProcessed(depositIdHex: string): Promise<boolean> {
    try {
      return await gateway.processedQuantosDeposits(depositIdHex)
    } catch (err) {
      logger.error(`Failed to check deposit processed status for ${depositIdHex}:`, err)
      return false
    }
  },

  async mintFromQuantos(
    depositIdHex: string,
    depositNonce: number,
    quantosSenderBytes32: string,
    baseRecipient: string,
    amountWei: bigint,
  ): Promise<ethers.TransactionResponse> {
    // ── Detailed pre-flight parameter logging ──
    logger.info(`mintFromQuantos PARAMS:`)
    logger.info(`  depositId        = ${depositIdHex} (length=${depositIdHex.length})`)
    logger.info(`  depositNonce     = ${depositNonce}`)
    logger.info(`  quantosSender    = ${quantosSenderBytes32} (length=${quantosSenderBytes32.length})`)
    logger.info(`  baseRecipient    = ${baseRecipient}`)
    logger.info(`  amountWei        = ${amountWei} (${ethers.formatEther(amountWei)} ETH-equiv)`)
    logger.info(`  relayerAddress   = ${relayerAddress}`)
    logger.info(`  gateway          = ${config.baseBridgeGatewayAddress}`)

    // ── Pre-flight validation ──
    if (depositIdHex === ethers.ZeroHash) {
      throw new Error(`PRE-FLIGHT FAIL: depositId is bytes32(0)  → contract would revert InvalidId()`)
    }
    if (baseRecipient === ethers.ZeroAddress) {
      throw new Error(`PRE-FLIGHT FAIL: recipient is address(0)  → contract would revert InvalidRecipient()`)
    }
    if (quantosSenderBytes32 === ethers.ZeroHash) {
      throw new Error(`PRE-FLIGHT FAIL: quantosSender is bytes32(0)  → contract would revert InvalidRecipient()`)
    }
    if (amountWei === 0n) {
      throw new Error(`PRE-FLIGHT FAIL: amount is 0  → contract would revert InvalidAmount()`)
    }

    // ── Pre-flight on-chain checks ──
    try {
      const [isRelayer, isPaused, alreadyProcessed] = await Promise.all([
        gateway.relayers(relayerAddress),
        gateway.paused(),
        gateway.processedQuantosDeposits(depositIdHex),
      ])
      logger.info(`  on-chain checks: isRelayer=${isRelayer}, isPaused=${isPaused}, alreadyProcessed=${alreadyProcessed}`)

      if (!isRelayer) {
        throw new Error(`PRE-FLIGHT FAIL: relayer ${relayerAddress} is NOT authorized on gateway → contract would revert Unauthorized()`)
      }
      if (isPaused) {
        throw new Error(`PRE-FLIGHT FAIL: gateway is PAUSED → contract would revert EnforcedPause()`)
      }
      if (alreadyProcessed) {
        throw new Error(`PRE-FLIGHT FAIL: deposit ${depositIdHex} already processed → contract would revert DepositAlreadyProcessed()`)
      }
    } catch (err: any) {
      if (err.message.startsWith('PRE-FLIGHT FAIL')) throw err
      logger.warn(`Pre-flight on-chain checks failed (non-fatal): ${err.message}`)
    }

    // ── Gas estimation ──
    let gasEstimate: bigint
    try {
      gasEstimate = await gateway.mintFromQuantos.estimateGas(
        depositIdHex,
        depositNonce,
        quantosSenderBytes32,
        baseRecipient,
        amountWei,
      )
      logger.info(`Gas estimate: ${gasEstimate}`)
    } catch (err: any) {
      // Attempt to decode the revert reason from error data
      const decoded = decodeRevertReason(err)
      logger.error(`Gas estimation FAILED — tx WILL revert`)
      logger.error(`  raw error.code    = ${err?.code}`)
      logger.error(`  raw error.reason  = ${err?.reason}`)
      logger.error(`  raw error.message = ${err?.message?.slice(0, 500)}`)
      logger.error(`  decoded revert    = ${decoded}`)
      if (err?.data) logger.error(`  error.data        = ${err.data}`)
      if (err?.transaction) {
        logger.error(`  error.transaction = ${JSON.stringify({
          to: err.transaction.to,
          from: err.transaction.from,
          data: err.transaction.data?.slice(0, 74) + '...',
        })}`)
      }
      throw new Error(`Gas estimation failed (tx will revert): ${decoded}`)
    }

    // ── Send with 20% gas buffer ──
    const gasLimit = (gasEstimate * 120n) / 100n
    logger.info(`Sending tx with gasLimit=${gasLimit}`)
    const tx = await gateway.mintFromQuantos(
      depositIdHex,
      depositNonce,
      quantosSenderBytes32,
      baseRecipient,
      amountWei,
      { gasLimit },
    )

    return tx
  },

  async getWQtestBalance(address: string): Promise<string> {
    const bal = await wrappedQtest.balanceOf(address)
    return ethers.formatEther(bal)
  },

  async getWQtestTotalSupply(): Promise<string> {
    const supply = await wrappedQtest.totalSupply()
    return ethers.formatEther(supply)
  },

  async getGatewayOwner(): Promise<string> {
    return await gateway.owner()
  },

  async getBurnNonce(): Promise<number> {
    const n = await gateway.burnNonce()
    return Number(n)
  },
}
