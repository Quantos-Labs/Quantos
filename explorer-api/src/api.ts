// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1

// ============================================================================
// Quantos Enhanced API — public REST API server.
//
// Provides paginated historical queries (from Supabase indexer) and live
// state proxying (from the Quantos RPC node), behind API key auth + rate
// limiting.
//
// Run: npm run dev:api  (or npm run start:api in production)
// ============================================================================

import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { config } from './config.js'
import { authMiddleware, rateLimitMiddleware, corsMiddleware } from './middleware.js'
import {
  healthRoutes,
  accountRoutes,
  txRoutes,
  blockRoutes,
  validatorRoutes,
  contractRoutes,
  statsRoutes,
  dagRoutes,
} from './routes.js'

const app = new Hono()

// ── Global middleware ────────────────────────────────────────────────────────
app.use('*', corsMiddleware)
app.use('*', authMiddleware)
app.use('*', rateLimitMiddleware)

// ── API versioning ───────────────────────────────────────────────────────────
app.route('/v1/health', healthRoutes)
app.route('/v1/info', healthRoutes) // alias
app.route('/v1/metrics', healthRoutes) // alias
app.route('/v1/accounts', accountRoutes)
app.route('/v1/transactions', txRoutes)
app.route('/v1/blocks', blockRoutes)
app.route('/v1/validators', validatorRoutes)
app.route('/v1/contracts', contractRoutes)
app.route('/v1/stats', statsRoutes)
app.route('/v1/dag', dagRoutes)

// ── Root ─────────────────────────────────────────────────────────────────────
app.get('/', (c) => c.json({
  name: 'Quantos Enhanced API',
  version: '1.0.0',
  docs: '/v1/health',
  endpoints: [
    'GET  /v1/health',
    'GET  /v1/info',
    'GET  /v1/metrics',
    'GET  /v1/accounts/:address',
    'GET  /v1/accounts/:address/balance',
    'GET  /v1/accounts/:address/transactions',
    'GET  /v1/accounts/:address/tokens',
    'GET  /v1/accounts/:address/nfts',
    'GET  /v1/transactions',
    'GET  /v1/transactions/:hash',
    'GET  /v1/blocks',
    'GET  /v1/blocks/:height',
    'GET  /v1/blocks/:height/transactions',
    'GET  /v1/validators',
    'GET  /v1/validators/:address',
    'GET  /v1/validators/:address/stats',
    'GET  /v1/contracts/:address',
    'GET  /v1/contracts/:address/verify',
    'POST /v1/contracts/call',
    'GET  /v1/stats',
    'GET  /v1/stats/:key',
    'GET  /v1/dag/tips/:shardId',
    'GET  /v1/dag/vertices/:hash',
  ],
}))

// ── 404 fallback ─────────────────────────────────────────────────────────────
app.notFound((c) => c.json({ error: 'Not found' }, 404))
app.onError((err, c) => {
  console.error('[api] unhandled error:', err)
  return c.json({ error: 'Internal server error' }, 500)
})

// ── Start server ─────────────────────────────────────────────────────────────
const port = config.api.port

serve({ fetch: app.fetch, port }, (info) => {
  const authMode = config.api.apiKeys || config.api.masterKey ? 'enabled' : 'disabled (dev mode)'
  console.log(`[api] Quantos Enhanced API listening on http://0.0.0.0:${info.port}`)
  console.log(`[api] Auth: ${authMode}`)
  console.log(`[api] Rate limit: ${config.api.rateLimitPerMinute}/min + ${config.api.rateLimitBurst} burst`)
  console.log(`[api] CORS origin: ${config.api.corsOrigin}`)
})
