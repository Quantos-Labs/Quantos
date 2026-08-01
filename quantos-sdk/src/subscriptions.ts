// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1

// ============================================================================
// Quantos L1 — WebSocket subscriptions (qnt_subscribe / qnt_unsubscribe).
// ============================================================================

import type {
  NewHeadsNotification,
  NewPendingTransactionsNotification,
  SubscriptionKind,
} from './types.js'

export interface QuantosSubscriptionOptions {
  /** WebSocket endpoint URL (default: ws://127.0.0.1:8545). */
  wsUrl?: string
  /** Optional API key sent as a query param `?api_key=…`. */
  apiKey?: string
  /** Reconnect delay in ms (default: 3 000). Set to 0 to disable auto-reconnect. */
  reconnectDelayMs?: number
  /** Custom WebSocket implementation (default: global WebSocket). */
  WebSocketCtor?: typeof WebSocket
}

interface SubscriptionEntry {
  kind: SubscriptionKind
  id: string
  callback: (data: unknown) => void
}

interface JsonRpcNotification {
  jsonrpc: string
  method: string
  params: {
    subscription: string
    result: unknown
  }
}

interface JsonRpcResponse {
  jsonrpc: string
  id: number
  result?: string
  error?: { code: number; message: string }
}

let nextWsId = 0

/**
 * Manages a single WebSocket connection to a Quantos node and multiplexes
 * subscriptions over it. Auto-reconnects on disconnect and re-subscribes.
 */
export class QuantosSubscriptions {
  private readonly wsUrl: string
  private readonly apiKey?: string
  private readonly reconnectDelayMs: number
  private readonly WebSocketCtor: typeof WebSocket
  private ws: WebSocket | null = null
  private subscriptions: Map<string, SubscriptionEntry> = new Map()
  private pendingRequests: Map<number, { resolve: (v: string) => void; reject: (e: Error) => void }> = new Map()
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private closed = false

  constructor(options: QuantosSubscriptionOptions = {}) {
    let url = options.wsUrl ?? 'ws://127.0.0.1:8545'
    if (options.apiKey) {
      url += (url.includes('?') ? '&' : '?') + `api_key=${encodeURIComponent(options.apiKey)}`
    }
    this.wsUrl = url
    this.apiKey = options.apiKey
    this.reconnectDelayMs = options.reconnectDelayMs ?? 3_000
    this.WebSocketCtor = options.WebSocketCtor ?? globalThis.WebSocket
  }

  private connect(): void {
    if (this.closed) return
    this.ws = new this.WebSocketCtor(this.wsUrl)

    this.ws.onopen = () => {
      // Re-subscribe to all active subscriptions after (re)connect
      for (const entry of this.subscriptions.values()) {
        this.sendSubscribe(entry).catch(() => {})
      }
    }

    this.ws.onmessage = (event: MessageEvent) => {
      try {
        const msg = JSON.parse(event.data as string)
        // Subscription notification
        if (msg.method === 'qnt_subscribe' && msg.params?.subscription) {
          const subId = msg.params.subscription as string
          const entry = this.subscriptions.get(subId)
          if (entry) {
            entry.callback(msg.params.result)
          }
          return
        }
        // Response to a subscribe/unsubscribe request
        if (msg.id !== undefined) {
          const pending = this.pendingRequests.get(msg.id)
          if (pending) {
            this.pendingRequests.delete(msg.id)
            if (msg.error) {
              pending.reject(new Error(`[${msg.error.code}] ${msg.error.message}`))
            } else {
              pending.resolve(msg.result as string)
            }
          }
        }
      } catch {
        // Ignore malformed messages
      }
    }

    this.ws.onclose = () => {
      this.ws = null
      // Invalidate all subscription IDs (they'll be re-established on reconnect)
      for (const entry of this.subscriptions.values()) {
        entry.id = ''
      }
      if (this.reconnectDelayMs > 0 && !this.closed) {
        this.reconnectTimer = setTimeout(() => this.connect(), this.reconnectDelayMs)
      }
    }

    this.ws.onerror = () => {
      // onclose will handle reconnect
    }
  }

  private ensureConnected(): Promise<void> {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) return Promise.resolve()
    if (!this.ws) this.connect()
    return new Promise((resolve, reject) => {
      if (!this.ws) return reject(new Error('WebSocket not initialized'))
      if (this.ws.readyState === WebSocket.OPEN) return resolve()
      const onOpen = () => { cleanup(); resolve() }
      const onError = () => { cleanup(); reject(new Error('WebSocket connection failed')) }
      const cleanup = () => {
        this.ws?.removeEventListener('open', onOpen)
        this.ws?.removeEventListener('error', onError)
      }
      this.ws.addEventListener('open', onOpen)
      this.ws.addEventListener('error', onError)
    })
  }

  private async sendSubscribe(entry: SubscriptionEntry): Promise<string> {
    await this.ensureConnected()
    const id = ++nextWsId
    return new Promise<string>((resolve, reject) => {
      this.pendingRequests.set(id, { resolve, reject })
      const payload = JSON.stringify({
        jsonrpc: '2.0',
        id,
        method: 'qnt_subscribe',
        params: [entry.kind, null],
      })
      this.ws?.send(payload)
      // Timeout: reject if no response in 10s
      setTimeout(() => {
        if (this.pendingRequests.has(id)) {
          this.pendingRequests.delete(id)
          reject(new Error('Subscribe timeout'))
        }
      }, 10_000)
    })
  }

  private async sendUnsubscribe(subId: string): Promise<void> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return
    const id = ++nextWsId
    return new Promise<void>((resolve, reject) => {
      this.pendingRequests.set(id, { resolve: () => resolve(), reject })
      this.ws?.send(JSON.stringify({
        jsonrpc: '2.0',
        id,
        method: 'qnt_unsubscribe',
        params: [subId],
      }))
    })
  }

  /**
   * Subscribe to new heads (slot finalization events).
   * Returns an unsubscribe function.
   */
  subscribeNewHeads(callback: (notification: NewHeadsNotification) => void): Promise<() => Promise<void>> {
    return this.subscribe('newHeads', callback as (data: unknown) => void)
  }

  /**
   * Subscribe to pending transaction count changes per shard.
   * Returns an unsubscribe function.
   */
  subscribeNewPendingTransactions(callback: (notification: NewPendingTransactionsNotification) => void): Promise<() => Promise<void>> {
    return this.subscribe('newPendingTransactions', callback as (data: unknown) => void)
  }

  /**
   * Generic subscribe. Returns an unsubscribe function.
   */
  async subscribe(kind: SubscriptionKind, callback: (data: unknown) => void): Promise<() => Promise<void>> {
    const entry: SubscriptionEntry = { kind, id: '', callback }
    const subId = await this.sendSubscribe(entry)
    entry.id = subId
    this.subscriptions.set(subId, entry)

    return async () => {
      await this.sendUnsubscribe(subId)
      this.subscriptions.delete(subId)
    }
  }

  /** Close the WebSocket connection and stop reconnecting. */
  close(): void {
    this.closed = true
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer)
    this.ws?.close()
    this.ws = null
    this.subscriptions.clear()
    this.pendingRequests.clear()
  }
}
