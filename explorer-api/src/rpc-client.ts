import { config } from './config.js'

let rpcId = 0

interface RpcResponse<T> {
  jsonrpc: string
  id: number
  result?: T
  error?: { code: number; message: string }
}

export async function rpcCall<T>(method: string, params: unknown[] = []): Promise<T> {
  const id = ++rpcId
  const res = await fetch(config.quantos.rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
  })

  if (!res.ok) {
    throw new Error(`RPC HTTP error: ${res.status}`)
  }

  const data: RpcResponse<T> = await res.json()

  if (data.error) {
    throw new Error(`RPC error [${data.error.code}]: ${data.error.message}`)
  }

  return data.result as T
}

// ── Typed RPC methods ──

export interface NodeInfo {
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

export interface TransactionInfo {
  hash: string
  from: string
  to: string
  value: string
  nonce: string
  gas: string
  input: string
}

export interface ReceiptInfo {
  transaction_hash: string
  block_number: string
  from: string
  to: string
  gas_used: string
  status: string
  logs: unknown[]
}

export interface AccountInfo {
  address: string
  balance: string
  nonce: string
  code_hash: string | null
  storage_root: string
  stake: string
  is_validator: boolean
  is_contract: boolean
}

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

export interface MetricsInfo {
  current_slot: number
  current_epoch: number
  finalized_slot: number
  pending_transactions: number
  pending_vertices: number
  confirmed_vertices: number
  total_validators: number
}

export interface ContractMetadataInfo {
  address: string
  bytecode_hash: string
  deployer: string
  deployed_at: number
  deployed_height: number
  bytecode_size: number
  version: string
}

export interface ConfirmedTransactionInfo {
  hash: string
  from: string
  to: string
  value: string
  nonce: number
  gas_used: number
  tx_type: string
  status: string
  success: boolean
  slot: number
  shard_id: number
  timestamp: number
  logs: { address: string; topics: string[]; data: string }[]
  revert_reason?: string
}

export interface VertexInfo {
  hash: string
  parents: string[]
  tx_count: number
  timestamp: number
  shard_id: number
  creator: string
  height: number
  status: string
  state_root: string
}

export interface CallRequest {
  from?: string
  to: string
  data?: string
  gas?: string
  value?: string
}

export interface TokenBalanceInfo {
  token_address: string
  name: string
  symbol: string
  decimals: number
  balance: number
  balance_formatted: string
}

export interface NFTInfo {
  token_id: number
  collection_address: string
  collection_name: string
  collection_symbol: string
  owner: string
  token_uri: string
}

export interface ValidatorStatsResponse {
  address: string
  current_epoch: number
  current_blocks_proposed: number
  current_votes_cast: number
  current_votes_expected: number
  current_checkpoint_signatures: number
  current_performance_score: number
  current_uptime: number
  total_blocks_proposed: number
  total_votes_cast: number
  total_checkpoint_signatures: number
  avg_performance_score: number
  avg_uptime: number
  total_rewards_earned: number
  history: unknown[]
}

export const rpc = {
  getBlockNumber: () => rpcCall<string>('qnt_blockNumber'),
  getChainId: () => rpcCall<string>('qnt_chainId'),
  getSlot: () => rpcCall<number>('qnt_getSlot'),
  getFinalizedSlot: () => rpcCall<number>('qnt_getFinalizedSlot'),
  getMetrics: () => rpcCall<MetricsInfo>('qnt_getMetrics'),
  getNodeInfo: () => rpcCall<NodeInfo>('qnt_nodeInfo'),
  getHealth: () => rpcCall<{ healthy: boolean; current_slot: number; finalized_slot: number; slot_lag: number; pending_transactions: number; validators_active: number }>('qnt_health'),
  getBalance: (address: string) => rpcCall<string>('qnt_getBalance', [address, 'latest']),
  getAccount: (address: string) => rpcCall<AccountInfo>('qnt_getAccount', [address]),
  getTransactionByHash: (hash: string) => rpcCall<TransactionInfo | null>('qnt_getTransactionByHash', [hash]),
  getTransactionReceipt: (hash: string) => rpcCall<ReceiptInfo | null>('qnt_getTransactionReceipt', [hash]),
  getContractMetadata: (address: string) => rpcCall<ContractMetadataInfo | null>('qnt_getContractMetadata', [address]),
  verifyContract: (address: string) => rpcCall<boolean>('qnt_verifyContract', [address]),
  callContract: (request: CallRequest) => rpcCall<string>('qnt_call', [request, 'latest']),
  getValidators: () => rpcCall<ValidatorsResponse>('qnt_getValidators'),
  getValidatorByAddress: (address: string) => rpcCall<ValidatorInfo | null>('qnt_getValidatorByAddress', [address]),
  getValidatorStats: (address: string) => rpcCall<ValidatorStatsResponse | null>('qnt_getValidatorStats', [address]),
  getPendingTransactions: (limit?: number) => rpcCall<TransactionInfo[]>('qnt_pendingTransactions', [limit ?? 100]),
  getRecentTransactions: (limit?: number) => rpcCall<ConfirmedTransactionInfo[]>('qnt_getRecentTransactions', [limit ?? 50]),
  getReceiptsSinceSlot: (sinceSlot: number, limit?: number) => rpcCall<ConfirmedTransactionInfo[]>('qnt_getReceiptsSinceSlot', [sinceSlot, limit ?? 200]),
  getTokenBalances: (ownerAddress: string) => rpcCall<TokenBalanceInfo[]>('qnt_getTokenBalances', [ownerAddress]),
  getNfts: (ownerAddress: string, collectionAddress?: string) => rpcCall<NFTInfo[]>('qnt_getNFTs', [ownerAddress, collectionAddress ?? null]),
  getDagTips: (shardId: number) => rpcCall<string[]>('qnt_getDagTips', [shardId]),
  getVertexByHash: (hash: string) => rpcCall<VertexInfo | null>('qnt_getVertexByHash', [hash]),
}
