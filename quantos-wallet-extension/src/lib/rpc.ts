// ── Quantos Node RPC Client ──
// Communicates with the Quantos node via JSON-RPC.
// All values use QTS: prefix (e.g. "QTS:1a4" for hex amounts).

const DEFAULT_RPC_URL = 'http://localhost:8545'

interface RpcResponse<T = unknown> {
  jsonrpc: string
  id: number
  result?: T
  error?: { code: number; message: string; data?: string }
}

let rpcUrl = DEFAULT_RPC_URL
let requestId = 1

export function setRpcUrl(url: string) {
  rpcUrl = url
}

export function getRpcUrl(): string {
  return rpcUrl
}

async function rpcCall<T>(method: string, params: unknown[] = []): Promise<T> {
  const id = requestId++
  const response = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', method, params, id }),
  })

  if (!response.ok) {
    throw new Error(`RPC HTTP ${response.status}: ${response.statusText}`)
  }

  const data: RpcResponse<T> = await response.json()

  if (data.error) {
    throw new Error(`RPC error ${data.error.code}: ${data.error.message}`)
  }

  return data.result as T
}

// ── QTS format helpers ──────────────────────────────────────

/** Parse "QTS:1a4" → BigInt (hex value) */
export function parseQtsHex(s: string): bigint {
  const hex = s.replace(/^QTS:/i, '').replace(/^0x/i, '')
  return hex ? BigInt('0x' + hex) : 0n
}

/** Parse "QTS:<64-char-hex>" → raw hex string */
export function parseQtsRaw(s: string): string {
  return s.replace(/^QTS:/i, '').replace(/^0x/i, '')
}

/** Format address for RPC: "QTS:<hex>" */
export function formatRpcAddress(addressHex: string): string {
  const hex = addressHex.replace(/^QTS:/i, '').replace(/^0x/i, '')
  return `QTS:${hex}`
}

// ── Account ─────────────────────────────────────────────────

/** Returns balance as QTS:hex string. Use parseQtsHex() to get BigInt. */
export async function getBalance(address: string): Promise<string> {
  return rpcCall<string>('qnt_getBalance', [address])
}

/** Returns nonce as QTS:hex string. Use parseQtsHex() to get number. */
export async function getTransactionCount(address: string): Promise<string> {
  return rpcCall<string>('qnt_getTransactionCount', [address])
}

/** Get nonce as a number (convenience wrapper). */
export async function getNonce(address: string): Promise<number> {
  const raw = await getTransactionCount(address)
  return Number(parseQtsHex(raw))
}

// Response types match quantos/src/rpc/server.rs exactly
export interface AccountInfo {
  address: string       // "QTS:<hex>"
  balance: string       // "QTS:<hex>"
  nonce: string         // "QTS:<hex>"
  code_hash: string | null
  storage_root: string
  stake: string         // "QTS:<hex>"
  is_validator: boolean
  is_contract: boolean
}

export async function getAccount(address: string): Promise<AccountInfo> {
  return rpcCall<AccountInfo>('qnt_getAccount', [address])
}

// ── Transaction ─────────────────────────────────────────────

/**
 * Send a bincode-serialized signed transaction (hex).
 * The txHex comes directly from quantos-wallet-core's buildSignedTransfer().
 * Returns tx hash as "QTS:<hex>".
 */
export async function sendRawTransaction(txHex: string): Promise<string> {
  return rpcCall<string>('qnt_sendRawTransaction', [txHex])
}

export interface TransactionInfo {
  hash: string    // "QTS:<hex>"
  from: string    // "QTS:<hex>"
  to: string      // "QTS:<hex>"
  value: string   // "QTS:<hex>"
  nonce: string   // "QTS:<hex>"
  gas: string     // "QTS:<hex>"
  input: string   // "QTS:<hex>"
}

export async function getTransactionByHash(hash: string): Promise<TransactionInfo | null> {
  return rpcCall<TransactionInfo | null>('qnt_getTransactionByHash', [hash])
}

export interface ReceiptInfo {
  transaction_hash: string
  block_number: string
  from: string
  to: string
  gas_used: string
  status: string   // "QTS:1" = success, "QTS:0" = fail
  logs: Array<{ address: string; topics: string[]; data: string }>
}

export async function getTransactionReceipt(hash: string): Promise<ReceiptInfo | null> {
  return rpcCall<ReceiptInfo | null>('qnt_getTransactionReceipt', [hash])
}

// ── Chain ───────────────────────────────────────────────────

export async function getChainId(): Promise<string> {
  return rpcCall<string>('qnt_chainId')
}

/** Returns chain ID as number. */
export async function getChainIdNumber(): Promise<number> {
  const raw = await getChainId()
  return Number(parseQtsHex(raw))
}

export async function getBlockNumber(): Promise<string> {
  return rpcCall<string>('qnt_blockNumber')
}

export async function getSlot(): Promise<number> {
  return rpcCall<number>('qnt_getSlot')
}

export async function getFinalizedSlot(): Promise<number> {
  return rpcCall<number>('qnt_getFinalizedSlot')
}

export async function estimateGas(): Promise<string> {
  // Quantos is gasless — always returns "qts:0"
  return rpcCall<string>('qnt_estimateGas', [{ to: '', data: '' }])
}

// ── Network ─────────────────────────────────────────────────

export interface HealthResponse {
  healthy: boolean
  current_slot: number
  finalized_slot: number
  slot_lag: number
  pending_transactions: number
  validators_active: number
}

export async function health(): Promise<HealthResponse> {
  return rpcCall<HealthResponse>('qnt_health')
}

export interface NodeInfoResponse {
  version: string
  protocol_version: number
  chain_id: number
  current_slot: number
  current_epoch: number
  finalized_slot: number
  state_root: string
  num_shards: number
  uptime_seconds: number
}

export async function nodeInfo(): Promise<NodeInfoResponse> {
  return rpcCall<NodeInfoResponse>('qnt_nodeInfo')
}

export async function peerCount(): Promise<string> {
  return rpcCall<string>('qnt_peerCount')
}

// ── Metrics ─────────────────────────────────────────────────

export interface MetricsInfo {
  current_slot: number
  current_epoch: number
  finalized_slot: number
  pending_transactions: number
  pending_vertices: number
  confirmed_vertices: number
  total_validators: number
}

export async function getMetrics(): Promise<MetricsInfo> {
  return rpcCall<MetricsInfo>('qnt_getMetrics')
}

// ── Validators ──────────────────────────────────────────────

export interface ValidatorInfo {
  address: string
  stake: string
  commission_rate: number
  active: boolean
  jailed: boolean
  slash_count: number
  last_active_slot: number
}

export interface ValidatorsResponse {
  validators: ValidatorInfo[]
  total_stake: string
  total_active: number
  epoch: number
}

export async function getValidators(): Promise<ValidatorsResponse> {
  return rpcCall<ValidatorsResponse>('qnt_getValidators')
}

// ── NFTs (QN8) ──────────────────────────────────────────

export interface NFTInfo {
  token_id: number
  collection_address: string
  collection_name: string
  collection_symbol: string
  owner: string
  token_uri: string
}

export async function getNFTs(ownerAddress: string, collectionAddress?: string): Promise<NFTInfo[]> {
  return rpcCall<NFTInfo[]>('qnt_getNFTs', [ownerAddress, collectionAddress ?? null])
}

// ── Mempool ─────────────────────────────────────────────

export async function pendingTransactions(limit?: number): Promise<TransactionInfo[]> {
  return rpcCall<TransactionInfo[]>('qnt_pendingTransactions', limit ? [limit] : [])
}
