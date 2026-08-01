// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1

// ============================================================================
// Quantos L1 SDK — public API.
//
// PQC-native RPC client for the Quantos L1 blockchain.
// Signatures are ML-DSA-65 (FIPS 204), addresses are 32 bytes,
// all hex values use the QTS: prefix.
//
// @example
// ```ts
// import { Quantos, formatQts } from '@quantos/sdk'
//
// const q = new Quantos({ rpcUrl: 'https://rpc.quantos.io', apiKey: 'qnt_xxx' })
// const balance = await q.getBalance('QTS:0102…ff')
// console.log(formatQts(balance))
//
// const unsub = await q.subscriptions.subscribeNewHeads((head) => {
//   console.log('new slot:', head.slot)
// })
// ```
// ============================================================================

export { QuantosClient, type QuantosClientOptions } from './client.js'
export { QuantosSubscriptions, type QuantosSubscriptionOptions } from './subscriptions.js'
export {
  stripPrefix,
  withPrefix,
  qtsToBigInt,
  bigIntToQts,
  qtsToNumber,
  numberToQts,
  formatQts,
  QTS_DECIMALS,
  ONE_QTS,
} from './utils.js'

export type {
  QtsHex,
  Address,
  Hash,
  Amount,
  AccountInfo,
  TransactionType,
  TransactionInfo,
  LogInfo,
  ReceiptInfo,
  ConfirmedTransactionInfo,
  CallRequest,
  SendTransactionRequest,
  KeyPairResponse,
  NodeInfoResponse,
  HealthResponse,
  SyncStatus,
  PeerInfoResponse,
  MetricsInfo,
  ShardInfo,
  ValidatorInfoResponse,
  ValidatorsResponse,
  ValidatorEpochHistoryEntry,
  ValidatorStatsResponse,
  EpochRewardEntry,
  EpochRewardsResponse,
  VertexInfo,
  VertexStatus,
  TxPoolStatusResponse,
  ContractMetadataInfo,
  NFTInfo,
  TokenBalanceInfo,
  L0ProofInfo,
  L0MetricsInfo,
  ExternalCheckpointRequest,
  ExternalCheckpointResponse,
  SubnetValidatorInfo,
  RegisterSubnetRequest,
  SubnetInfo,
  NewHeadsNotification,
  NewPendingTransactionsNotification,
  SubscriptionKind,
  RpcError,
} from './types.js'
export { QuantosRpcError, ChainId } from './types.js'

import { QuantosClient, type QuantosClientOptions } from './client.js'
import { QuantosSubscriptions } from './subscriptions.js'

export interface QuantosOptions extends QuantosClientOptions {
  /** WebSocket URL for subscriptions (defaults to rpcUrl with ws:// scheme). */
  wsUrl?: string
}

/**
 * High-level facade combining the RPC client and WebSocket subscriptions.
 *
 * All RPC methods from {@link QuantosClient} are available directly on this
 * object. WebSocket subscriptions are available via `.subscriptions`.
 */
export class Quantos {
  /** The underlying RPC client. */
  readonly client: QuantosClient
  /** WebSocket subscription manager (lazily initialized). */
  private _subscriptions: QuantosSubscriptions | null = null
  private readonly wsUrl?: string

  constructor(options: QuantosOptions = {}) {
    this.client = new QuantosClient(options)
    this.wsUrl = options.wsUrl
  }

  /** WebSocket subscriptions (lazily creates the connection on first access). */
  get subscriptions(): QuantosSubscriptions {
    if (!this._subscriptions) {
      const wsUrl = this.wsUrl ?? this.deriveWsUrl()
      this._subscriptions = new QuantosSubscriptions({
        wsUrl,
        apiKey: (this.client as unknown as { apiKey?: string }).apiKey,
      })
    }
    return this._subscriptions
  }

  private deriveWsUrl(): string {
    try {
      const url = new URL(this.client['rpcUrl'] as string)
      if (url.protocol === 'https:') return `wss://${url.host}`
      return `ws://${url.host}`
    } catch {
      return 'ws://127.0.0.1:8545'
    }
  }

  /** Close any open WebSocket connection. */
  close(): void {
    this._subscriptions?.close()
    this._subscriptions = null
  }
}

// Re-export all client methods on Quantos via prototype delegation
// (done at runtime to avoid duplicating 40+ method signatures)
const clientProto = QuantosClient.prototype
const methodNames = Object.getOwnPropertyNames(clientProto).filter(
  (name) => name !== 'constructor' && typeof (clientProto as unknown as Record<string, unknown>)[name] === 'function'
)
for (const name of methodNames) {
  Object.defineProperty(Quantos.prototype, name, {
    value: function (this: Quantos, ...args: unknown[]) {
      return (this.client as unknown as Record<string, (...a: unknown[]) => unknown>)[name](...args)
    },
    writable: true,
    enumerable: false,
    configurable: true,
  })
}
