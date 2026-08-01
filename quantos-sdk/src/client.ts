// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1

// ============================================================================
// Quantos L1 — JSON-RPC client (HTTP).
// Talks the native qnt_* namespace. See docs/RPC_SPEC.md.
// ============================================================================

import type {
  AccountInfo,
  Address,
  Amount,
  CallRequest,
  ConfirmedTransactionInfo,
  ContractMetadataInfo,
  ExternalCheckpointRequest,
  ExternalCheckpointResponse,
  Hash,
  HealthResponse,
  KeyPairResponse,
  L0MetricsInfo,
  L0ProofInfo,
  LogInfo,
  MetricsInfo,
  NFTInfo,
  NodeInfoResponse,
  PeerInfoResponse,
  QtsHex,
  ReceiptInfo,
  RegisterSubnetRequest,
  SendTransactionRequest,
  ShardInfo,
  SubnetInfo,
  SyncStatus,
  TokenBalanceInfo,
  TransactionInfo,
  TxPoolStatusResponse,
  ValidatorsResponse,
  ValidatorInfoResponse,
  ValidatorStatsResponse,
  EpochRewardsResponse,
  VertexInfo,
} from './types.js'
import { QuantosRpcError, type RpcError } from './types.js'

export interface QuantosClientOptions {
  /** RPC endpoint URL (default: http://127.0.0.1:8545). */
  rpcUrl?: string
  /** Optional API key sent as `Authorization: Bearer <key>`. */
  apiKey?: string
  /** Request timeout in ms (default: 30 000). */
  timeoutMs?: number
  /** Custom fetch implementation (default: global fetch). */
  fetch?: typeof fetch
  /** Custom headers to merge into every request. */
  headers?: Record<string, string>
}

interface RpcResponse<T> {
  jsonrpc: string
  id: number
  result?: T
  error?: RpcError
}

let nextId = 0

export class QuantosClient {
  private readonly rpcUrl: string
  private readonly apiKey?: string
  private readonly timeoutMs: number
  private readonly fetchFn: typeof fetch
  private readonly extraHeaders: Record<string, string>

  constructor(options: QuantosClientOptions = {}) {
    this.rpcUrl = options.rpcUrl ?? 'http://127.0.0.1:8545'
    this.apiKey = options.apiKey
    this.timeoutMs = options.timeoutMs ?? 30_000
    this.fetchFn = options.fetch ?? globalThis.fetch
    this.extraHeaders = options.headers ?? {}
  }

  /** Low-level: send a raw JSON-RPC call. */
  async call<T>(method: string, params: unknown[] = []): Promise<T> {
    const id = ++nextId
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...this.extraHeaders,
    }
    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`
    }

    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), this.timeoutMs)

    let res: Response
    try {
      res = await this.fetchFn(this.rpcUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
        signal: controller.signal,
      })
    } catch (err) {
      clearTimeout(timer)
      if (err instanceof Error && err.name === 'AbortError') {
        throw new QuantosRpcError({ code: -32000, message: `Request timeout after ${this.timeoutMs}ms` })
      }
      throw err
    }
    clearTimeout(timer)

    if (res.status === 429) {
      throw new QuantosRpcError({ code: -32000, message: 'Rate limit exceeded' })
    }
    if (!res.ok) {
      throw new QuantosRpcError({ code: -32000, message: `HTTP ${res.status}` })
    }

    const data = (await res.json()) as RpcResponse<T>
    if (data.error) {
      throw new QuantosRpcError(data.error)
    }
    return data.result as T
  }

  // ── Account & State ────────────────────────────────────────────────────────

  getBalance(address: Address, block?: string): Promise<Amount> {
    return this.call('qnt_getBalance', [address, block ?? 'latest'])
  }

  getTransactionCount(address: Address, block?: string): Promise<QtsHex> {
    return this.call('qnt_getTransactionCount', [address, block ?? 'latest'])
  }

  getAccount(address: Address): Promise<AccountInfo> {
    return this.call('qnt_getAccount', [address])
  }

  getStateRoot(): Promise<Hash> {
    return this.call('qnt_getStateRoot', [])
  }

  getCode(address: Address, block?: string): Promise<QtsHex> {
    return this.call('qnt_getCode', [address, block ?? 'latest'])
  }

  getStorageAt(address: Address, position: Hash, block?: string): Promise<QtsHex> {
    return this.call('qnt_getStorageAt', [address, position, block ?? 'latest'])
  }

  // ── Transactions ───────────────────────────────────────────────────────────

  sendRawTransaction(txHex: QtsHex): Promise<Hash> {
    return this.call('qnt_sendRawTransaction', [txHex])
  }

  sendRawTransactionBatch(txsHex: QtsHex[]): Promise<string[]> {
    return this.call('qnt_sendRawTransactionBatch', [txsHex])
  }

  getTransactionByHash(hash: Hash): Promise<TransactionInfo | null> {
    return this.call('qnt_getTransactionByHash', [hash])
  }

  getTransactionReceipt(hash: Hash): Promise<ReceiptInfo | null> {
    return this.call('qnt_getTransactionReceipt', [hash])
  }

  callContract(request: CallRequest, block?: string): Promise<QtsHex> {
    return this.call('qnt_call', [request, block ?? 'latest'])
  }

  estimateGas(request: CallRequest): Promise<QtsHex> {
    return this.call('qnt_estimateGas', [request])
  }

  // ── Block / Slot ───────────────────────────────────────────────────────────

  blockNumber(): Promise<QtsHex> {
    return this.call('qnt_blockNumber', [])
  }

  chainId(): Promise<QtsHex> {
    return this.call('qnt_chainId', [])
  }

  getSlot(): Promise<number> {
    return this.call('qnt_getSlot', [])
  }

  getFinalizedSlot(): Promise<number> {
    return this.call('qnt_getFinalizedSlot', [])
  }

  getMetrics(): Promise<MetricsInfo> {
    return this.call('qnt_getMetrics', [])
  }

  getShardInfo(shardId: number): Promise<ShardInfo> {
    return this.call('qnt_getShardInfo', [shardId])
  }

  // ── Node & Network ─────────────────────────────────────────────────────────

  nodeInfo(): Promise<NodeInfoResponse> {
    return this.call('qnt_nodeInfo', [])
  }

  health(): Promise<HealthResponse> {
    return this.call('qnt_health', [])
  }

  syncing(): Promise<SyncStatus> {
    return this.call('qnt_syncing', [])
  }

  peerCount(): Promise<QtsHex> {
    return this.call('qnt_peerCount', [])
  }

  getPeers(): Promise<PeerInfoResponse[]> {
    return this.call('qnt_getPeers', [])
  }

  // ── Validators ─────────────────────────────────────────────────────────────

  getValidators(): Promise<ValidatorsResponse> {
    return this.call('qnt_getValidators', [])
  }

  getValidatorByAddress(address: Address): Promise<ValidatorInfoResponse | null> {
    return this.call('qnt_getValidatorByAddress', [address])
  }

  getValidatorStats(address: Address): Promise<ValidatorStatsResponse | null> {
    return this.call('qnt_getValidatorStats', [address])
  }

  getEpochRewards(epoch: number): Promise<EpochRewardsResponse> {
    return this.call('qnt_getEpochRewards', [epoch])
  }

  // ── DAG ────────────────────────────────────────────────────────────────────

  getVertexByHash(hash: Hash): Promise<VertexInfo | null> {
    return this.call('qnt_getVertexByHash', [hash])
  }

  getDagTips(shardId: number): Promise<Hash[]> {
    return this.call('qnt_getDagTips', [shardId])
  }

  // ── Mempool / Ingress ──────────────────────────────────────────────────────

  pendingTransactions(limit?: number): Promise<TransactionInfo[]> {
    return this.call('qnt_pendingTransactions', [limit ?? 100])
  }

  txPoolStatus(): Promise<TxPoolStatusResponse> {
    return this.call('qnt_txPoolStatus', [])
  }

  // ── Contracts ──────────────────────────────────────────────────────────────

  getContractMetadata(address: Address): Promise<ContractMetadataInfo | null> {
    return this.call('qnt_getContractMetadata', [address])
  }

  verifyContract(address: Address): Promise<boolean> {
    return this.call('qnt_verifyContract', [address])
  }

  // ── Tokens (QN4 / QN8) ─────────────────────────────────────────────────────

  getNfts(ownerAddress: Address, collectionAddress?: Address): Promise<NFTInfo[]> {
    return this.call('qnt_getNFTs', [ownerAddress, collectionAddress ?? null])
  }

  getTokenBalances(ownerAddress: Address): Promise<TokenBalanceInfo[]> {
    return this.call('qnt_getTokenBalances', [ownerAddress])
  }

  // ── Explorer Indexing ──────────────────────────────────────────────────────

  getRecentTransactions(limit?: number): Promise<ConfirmedTransactionInfo[]> {
    return this.call('qnt_getRecentTransactions', [limit ?? 50])
  }

  getReceiptsSinceSlot(sinceSlot: number, limit?: number): Promise<ConfirmedTransactionInfo[]> {
    return this.call('qnt_getReceiptsSinceSlot', [sinceSlot, limit ?? 200])
  }

  // ── L0 Finality Hub ────────────────────────────────────────────────────────

  submitExternalCheckpoint(request: ExternalCheckpointRequest): Promise<ExternalCheckpointResponse> {
    return this.call('qnt_submitExternalCheckpoint', [request])
  }

  getL0Proof(proofHash: Hash): Promise<L0ProofInfo | null> {
    return this.call('qnt_getL0Proof', [proofHash])
  }

  getLatestL0Proof(): Promise<L0ProofInfo | null> {
    return this.call('qnt_getLatestL0Proof', [])
  }

  getL0Metrics(): Promise<L0MetricsInfo> {
    return this.call('qnt_getL0Metrics', [])
  }

  // ── Subnets ────────────────────────────────────────────────────────────────

  registerSubnet(request: RegisterSubnetRequest): Promise<boolean> {
    return this.call('qnt_registerSubnet', [request])
  }

  getSubnet(id: string): Promise<SubnetInfo | null> {
    return this.call('qnt_getSubnet', [id])
  }

  // ── Server-side signing (custodial — disable on public providers) ──────────

  sendTransaction(request: SendTransactionRequest): Promise<Hash> {
    return this.call('qnt_sendTransaction', [request])
  }

  generateKeyPair(): Promise<KeyPairResponse> {
    return this.call('qnt_generateKeyPair', [])
  }
}
