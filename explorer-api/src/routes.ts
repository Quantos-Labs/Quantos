// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1

// ============================================================================
// Enhanced API routes — paginated historical queries from Supabase +
// live state proxy from the Quantos RPC node.
// ============================================================================

import { Hono, type Context } from 'hono'
import type { ContentfulStatusCode } from 'hono/utils/http-status'
import { supabasePublic } from './db.js'
import { rpc } from './rpc-client.js'

// Helper: parse pagination params
function pagination(c: Context): { page: number; limit: number; offset: number } {
  const page = Math.max(1, Number(c.req.query('page') ?? 1))
  const limit = Math.min(100, Math.max(1, Number(c.req.query('limit') ?? 20)))
  return { page, limit, offset: (page - 1) * limit }
}

// Helper: standard error response
function errorResponse(c: Context, status: ContentfulStatusCode, message: string) {
  return c.json({ error: message }, status)
}

// ============================================================================
// Health & Info
// ============================================================================

export const healthRoutes = new Hono()

healthRoutes.get('/health', async (c) => {
  try {
    const health = await rpc.getHealth()
    return c.json(health)
  } catch {
    return c.json({ healthy: false, error: 'RPC node unreachable' }, 503)
  }
})

healthRoutes.get('/info', async (c) => {
  try {
    const info = await rpc.getNodeInfo()
    return c.json(info)
  } catch (err) {
    return errorResponse(c, 503, `Node unreachable: ${err}`)
  }
})

healthRoutes.get('/metrics', async (c) => {
  try {
    const metrics = await rpc.getMetrics()
    return c.json(metrics)
  } catch (err) {
    return errorResponse(c, 503, `Node unreachable: ${err}`)
  }
})

// ============================================================================
// Accounts
// ============================================================================

export const accountRoutes = new Hono()

// GET /v1/accounts/:address — live account state from RPC
accountRoutes.get('/:address', async (c) => {
  const address = c.req.param('address')
  try {
    const account = await rpc.getAccount(address)
    return c.json(account)
  } catch (err) {
    return errorResponse(c, 404, `Account not found: ${err}`)
  }
})

// GET /v1/accounts/:address/balance — live balance
accountRoutes.get('/:address/balance', async (c) => {
  const address = c.req.param('address')
  try {
    const balance = await rpc.getBalance(address)
    return c.json({ address, balance })
  } catch (err) {
    return errorResponse(c, 500, `Failed: ${err}`)
  }
})

// GET /v1/accounts/:address/transactions — paginated tx history from indexer
accountRoutes.get('/:address/transactions', async (c) => {
  const address = c.req.param('address')
  const { page, limit, offset } = pagination(c)

  const [fromRes, toRes] = await Promise.all([
    supabasePublic
      .from('transactions')
      .select('*', { count: 'exact' })
      .eq('from_address', address)
      .order('timestamp', { ascending: false })
      .range(offset, offset + limit - 1),
    supabasePublic
      .from('transactions')
      .select('*', { count: 'exact' })
      .eq('to_address', address)
      .order('timestamp', { ascending: false })
      .range(offset, offset + limit - 1),
  ])

  if (fromRes.error || toRes.error) {
    return errorResponse(c, 500, fromRes.error?.message ?? toRes.error?.message ?? 'DB error')
  }

  // Merge, dedupe by hash, sort by timestamp desc
  const seen = new Set<string>()
  const txs = [...(fromRes.data ?? []), ...(toRes.data ?? [])]
    .filter((tx: { hash: string }) => {
      if (seen.has(tx.hash)) return false
      seen.add(tx.hash)
      return true
    })
    .sort((a: { timestamp: string }, b: { timestamp: string }) =>
      b.timestamp > a.timestamp ? 1 : b.timestamp < a.timestamp ? -1 : 0
    )

  const total = (fromRes.count ?? 0) + (toRes.count ?? 0)
  return c.json({
    data: txs,
    pagination: { page, limit, total, total_pages: Math.ceil(total / limit) },
  })
})

// GET /v1/accounts/:address/tokens — QN4 token balances (live)
accountRoutes.get('/:address/tokens', async (c) => {
  const address = c.req.param('address')
  try {
    const balances = await rpc.getTokenBalances(address)
    return c.json({ data: balances })
  } catch (err) {
    return errorResponse(c, 500, `Failed: ${err}`)
  }
})

// GET /v1/accounts/:address/nfts — QN8 NFTs (live)
accountRoutes.get('/:address/nfts', async (c) => {
  const address = c.req.param('address')
  const collection = c.req.query('collection') ?? undefined
  try {
    const nfts = await rpc.getNfts(address, collection)
    return c.json({ data: nfts })
  } catch (err) {
    return errorResponse(c, 500, `Failed: ${err}`)
  }
})

// ============================================================================
// Transactions
// ============================================================================

export const txRoutes = new Hono()

// GET /v1/transactions — paginated recent transactions (from indexer)
txRoutes.get('/', async (c) => {
  const { page, limit, offset } = pagination(c)
  const { data, error, count } = await supabasePublic
    .from('transactions')
    .select('*', { count: 'exact' })
    .order('timestamp', { ascending: false })
    .range(offset, offset + limit - 1)

  if (error) return errorResponse(c, 500, error.message)
  return c.json({
    data: data ?? [],
    pagination: { page, limit, total: count ?? 0, total_pages: Math.ceil((count ?? 0) / limit) },
  })
})

// GET /v1/transactions/:hash — live tx + receipt from RPC
txRoutes.get('/:hash', async (c) => {
  const hash = c.req.param('hash')
  try {
    const [tx, receipt] = await Promise.all([
      rpc.getTransactionByHash(hash),
      rpc.getTransactionReceipt(hash),
    ])
    if (!tx && !receipt) return errorResponse(c, 404, 'Transaction not found')
    return c.json({ transaction: tx, receipt })
  } catch (err) {
    return errorResponse(c, 500, `Failed: ${err}`)
  }
})

// ============================================================================
// Blocks (slots)
// ============================================================================

export const blockRoutes = new Hono()

// GET /v1/blocks — paginated blocks (from indexer)
blockRoutes.get('/', async (c) => {
  const { page, limit, offset } = pagination(c)
  const { data, error, count } = await supabasePublic
    .from('blocks')
    .select('*', { count: 'exact' })
    .order('height', { ascending: false })
    .range(offset, offset + limit - 1)

  if (error) return errorResponse(c, 500, error.message)
  return c.json({
    data: data ?? [],
    pagination: { page, limit, total: count ?? 0, total_pages: Math.ceil((count ?? 0) / limit) },
  })
})

// GET /v1/blocks/:height — single block (from indexer)
blockRoutes.get('/:height', async (c) => {
  const height = Number(c.req.param('height'))
  if (isNaN(height)) return errorResponse(c, 400, 'Invalid block height')

  const { data, error } = await supabasePublic
    .from('blocks')
    .select('*')
    .eq('height', height)
    .single()

  if (error || !data) return errorResponse(c, 404, 'Block not found')
  return c.json(data)
})

// GET /v1/blocks/:height/transactions — transactions in a block
blockRoutes.get('/:height/transactions', async (c) => {
  const height = Number(c.req.param('height'))
  if (isNaN(height)) return errorResponse(c, 400, 'Invalid block height')
  const { page, limit, offset } = pagination(c)

  const { data, error, count } = await supabasePublic
    .from('transactions')
    .select('*', { count: 'exact' })
    .eq('block_height', height)
    .order('nonce', { ascending: true })
    .range(offset, offset + limit - 1)

  if (error) return errorResponse(c, 500, error.message)
  return c.json({
    data: data ?? [],
    pagination: { page, limit, total: count ?? 0, total_pages: Math.ceil((count ?? 0) / limit) },
  })
})

// ============================================================================
// Validators
// ============================================================================

export const validatorRoutes = new Hono()

// GET /v1/validators — paginated validators (from indexer, sorted by stake)
validatorRoutes.get('/', async (c) => {
  const { page, limit, offset } = pagination(c)
  const { data, error, count } = await supabasePublic
    .from('validators')
    .select('*', { count: 'exact' })
    .order('rank', { ascending: true })
    .range(offset, offset + limit - 1)

  if (error) return errorResponse(c, 500, error.message)
  return c.json({
    data: data ?? [],
    pagination: { page, limit, total: count ?? 0, total_pages: Math.ceil((count ?? 0) / limit) },
  })
})

// GET /v1/validators/:address — single validator (indexer + live stats)
validatorRoutes.get('/:address', async (c) => {
  const address = c.req.param('address')

  const [indexedRes, liveRes] = await Promise.all([
    supabasePublic.from('validators').select('*').eq('address', address).single(),
    rpc.getValidatorByAddress(address).catch(() => null),
  ])

  if (indexedRes.error && !liveRes) {
    return errorResponse(c, 404, 'Validator not found')
  }

  return c.json({
    indexed: indexedRes.data ?? null,
    live: liveRes,
  })
})

// GET /v1/validators/:address/stats — live validator stats from RPC
validatorRoutes.get('/:address/stats', async (c) => {
  const address = c.req.param('address')
  try {
    const stats = await rpc.getValidatorStats(address)
    if (!stats) return errorResponse(c, 404, 'Validator not found')
    return c.json(stats)
  } catch (err) {
    return errorResponse(c, 500, `Failed: ${err}`)
  }
})

// ============================================================================
// Contracts
// ============================================================================

export const contractRoutes = new Hono()

// GET /v1/contracts/:address — contract metadata (live from RPC)
contractRoutes.get('/:address', async (c) => {
  const address = c.req.param('address')
  try {
    const meta = await rpc.getContractMetadata(address)
    if (!meta) return errorResponse(c, 404, 'Contract not found')
    return c.json(meta)
  } catch (err) {
    return errorResponse(c, 500, `Failed: ${err}`)
  }
})

// GET /v1/contracts/:address/verify — check if contract exists
contractRoutes.get('/:address/verify', async (c) => {
  const address = c.req.param('address')
  try {
    const exists = await rpc.verifyContract(address)
    return c.json({ address, exists })
  } catch (err) {
    return errorResponse(c, 500, `Failed: ${err}`)
  }
})

// POST /v1/contracts/call — read-only contract call (proxy to qnt_call)
contractRoutes.post('/call', async (c) => {
  const body = await c.req.json()
  try {
    const result = await rpc.callContract(body)
    return c.json({ result })
  } catch (err) {
    return errorResponse(c, 500, `Call failed: ${err}`)
  }
})

// ============================================================================
// Network Stats
// ============================================================================

export const statsRoutes = new Hono()

// GET /v1/stats — all network stats from indexer
statsRoutes.get('/', async (c) => {
  const { data, error } = await supabasePublic
    .from('network_stats')
    .select('*')
    .order('key', { ascending: true })

  if (error) return errorResponse(c, 500, error.message)

  // Convert to key-value object
  const stats: Record<string, string> = {}
  for (const row of data ?? []) {
    stats[row.key] = row.value
  }
  return c.json(stats)
})

// GET /v1/stats/:key — single stat
statsRoutes.get('/:key', async (c) => {
  const key = c.req.param('key')
  const { data, error } = await supabasePublic
    .from('network_stats')
    .select('*')
    .eq('key', key)
    .single()

  if (error || !data) return errorResponse(c, 404, 'Stat not found')
  return c.json({ key: data.key, value: data.value, updated_at: data.updated_at })
})

// ============================================================================
// DAG
// ============================================================================

export const dagRoutes = new Hono()

// GET /v1/dag/tips/:shardId — DAG tips for a shard (live)
dagRoutes.get('/tips/:shardId', async (c) => {
  const shardId = Number(c.req.param('shardId'))
  if (isNaN(shardId)) return errorResponse(c, 400, 'Invalid shard ID')
  try {
    const tips = await rpc.getDagTips(shardId)
    return c.json({ shard_id: shardId, tips })
  } catch (err) {
    return errorResponse(c, 500, `Failed: ${err}`)
  }
})

// GET /v1/dag/vertices/:hash — vertex info (live)
dagRoutes.get('/vertices/:hash', async (c) => {
  const hash = c.req.param('hash')
  try {
    const vertex = await rpc.getVertexByHash(hash)
    if (!vertex) return errorResponse(c, 404, 'Vertex not found')
    return c.json(vertex)
  } catch (err) {
    return errorResponse(c, 500, `Failed: ${err}`)
  }
})
