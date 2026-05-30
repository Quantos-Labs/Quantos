import { config } from './config.js'
import { logger } from './logger.js'

interface QuantosReceipt {
  transaction_hash: string
  block_number: string
  from: string
  to: string
  gas_used: string
  status: string
  logs: Array<{
    address: string
    topics: string[]
    data: string
  }>
  revert_reason?: string
}

interface QuantosTransaction {
  hash: string
  from: string
  to: string
  value: string
  nonce: number | string
  gas: string
  input: string
}

async function rpcCall<T>(method: string, params: unknown[] = []): Promise<T> {
  const res = await fetch(config.quantosRpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: Date.now(), method, params }),
  })

  if (!res.ok) {
    throw new Error(`Quantos RPC HTTP error: ${res.status} ${res.statusText}`)
  }

  const json = await res.json() as any
  if (json.error) {
    throw new Error(`Quantos RPC error: ${json.error.message || JSON.stringify(json.error)}`)
  }

  return json.result as T
}

function parseQtsHex(value: string | number | null | undefined): number {
  if (typeof value === 'number') return value
  if (!value) return 0
  const raw = String(value).replace(/^QTS:/, '').replace(/^0x/i, '')
  if (!raw || raw === '0') return 0
  return parseInt(raw, 16) || 0
}

function parseQtsHexBigInt(value: string | number | null | undefined): bigint {
  if (typeof value === 'number') return BigInt(value)
  if (!value) return 0n
  const raw = String(value).replace(/^QTS:/, '').replace(/^0x/i, '')
  if (!raw || raw === '0') return 0n
  return BigInt('0x' + raw)
}

// Quantos uses little-endian uint256 in calldata. Convert LE hex bytes to bigint.
function leHexToBigInt(hex: string): bigint {
  const clean = hex.replace(/^(QTS:|0x)/i, '')
  const bytes = Buffer.from(clean, 'hex')
  let result = 0n
  for (let i = 0; i < bytes.length; i++) {
    result += BigInt(bytes[i]) << BigInt(i * 8)
  }
  return result
}

export const quantos = {
  async getNodeInfo(): Promise<Record<string, unknown>> {
    return rpcCall('qnt_nodeInfo')
  },

  async getTransactionReceipt(txHash: string): Promise<QuantosReceipt | null> {
    try {
      return await rpcCall<QuantosReceipt>('qnt_getTransactionReceipt', [txHash])
    } catch (err) {
      logger.error(`Failed to get receipt for ${txHash}:`, err)
      return null
    }
  },

  async getTransaction(txHash: string): Promise<QuantosTransaction | null> {
    try {
      return await rpcCall<QuantosTransaction>('qnt_getTransactionByHash', [txHash])
    } catch (err) {
      logger.error(`Failed to get tx for ${txHash}:`, err)
      return null
    }
  },

  async getRecentTransactions(limit = 200): Promise<any[]> {
    return rpcCall('qnt_getRecentTransactions', [limit])
  },

  // Verify a bridge deposit. Supports both legacy token transfer-to-vault
  // and the current vault.deposit(bytes32,uint256) flow.
  async verifyBridgeDeposit(txHash: string): Promise<{
    valid: boolean
    from: string
    amount: bigint
    nonce: number
    baseRecipientBytes32?: string
    method?: 'token_transfer' | 'vault_deposit'
    error?: string
  }> {
    const receipt = await this.getTransactionReceipt(txHash)
    if (!receipt) {
      return { valid: false, from: '', amount: 0n, nonce: 0, error: 'Receipt not found' }
    }

    // Check status = QTS:1 (success)
    if (receipt.status !== 'QTS:1') {
      return {
        valid: false,
        from: receipt.from,
        amount: 0n,
        nonce: 0,
        error: `Tx failed: status=${receipt.status}, revert=${receipt.revert_reason || 'none'}`,
      }
    }

    // Get the full transaction to read calldata
    const tx = await this.getTransaction(txHash)
    if (!tx) {
      return { valid: false, from: receipt.from, amount: 0n, nonce: 0, error: 'Transaction not found' }
    }

    const input = String(tx.input).replace(/^QTS:/, '').replace(/^0x/i, '')
    if (input.length < 8) {
      return { valid: false, from: receipt.from, amount: 0n, nonce: 0, error: 'Calldata too short' }
    }

    const selector = input.slice(0, 8)

    // Legacy flow: QTEST.transfer(vault, amount)
    if (selector === 'a9059cbb') {
      if (input.length < 136) {
        return { valid: false, from: receipt.from, amount: 0n, nonce: 0, error: 'Transfer calldata too short' }
      }

      if (String(tx.to).toLowerCase() !== config.qtestContractAddress.toLowerCase()) {
        return {
          valid: false,
          from: receipt.from,
          amount: 0n,
          nonce: parseQtsHex(tx.nonce),
          error: `Legacy transfer target ${tx.to} != QTEST contract ${config.qtestContractAddress}`,
        }
      }

      const toAddress = 'QTS:' + input.slice(8, 72)
      const amountHex = input.slice(72, 136)
      const amount = leHexToBigInt(amountHex)

      if (toAddress.toLowerCase() !== config.bridgeVaultAddress.toLowerCase()) {
        return {
          valid: false,
          from: receipt.from,
          amount,
          nonce: parseQtsHex(tx.nonce),
          error: `Transfer target ${toAddress} != vault ${config.bridgeVaultAddress}`,
        }
      }

      return {
        valid: true,
        from: receipt.from,
        amount,
        nonce: parseQtsHex(tx.nonce),
        method: 'token_transfer',
      }
    }

    // Current flow: QuantosBridgeVault.deposit(bytes32 baseRecipient, uint256 amount)
    if (selector === '1de26e16') {
      if (input.length < 136) {
        return { valid: false, from: receipt.from, amount: 0n, nonce: 0, error: 'Vault deposit calldata too short' }
      }

      if (String(tx.to).toLowerCase() !== config.bridgeVaultAddress.toLowerCase()) {
        return {
          valid: false,
          from: receipt.from,
          amount: 0n,
          nonce: parseQtsHex(tx.nonce),
          error: `Vault deposit target ${tx.to} != vault ${config.bridgeVaultAddress}`,
        }
      }

      const baseRecipientBytes32 = '0x' + input.slice(8, 72)
      const amountHex = input.slice(72, 136)
      const amount = leHexToBigInt(amountHex)

      if (/^0x0{64}$/i.test(baseRecipientBytes32)) {
        return {
          valid: false,
          from: receipt.from,
          amount,
          nonce: parseQtsHex(tx.nonce),
          error: 'Vault deposit baseRecipient is zero',
        }
      }

      return {
        valid: true,
        from: receipt.from,
        amount,
        nonce: parseQtsHex(tx.nonce),
        baseRecipientBytes32,
        method: 'vault_deposit',
      }
    }

    return {
      valid: false,
      from: receipt.from,
      amount: 0n,
      nonce: parseQtsHex(tx.nonce),
      error: `Unsupported bridge selector: ${selector}`,
    }
  },

  parseQtsHex,
  parseQtsHexBigInt,
  leHexToBigInt,
}
