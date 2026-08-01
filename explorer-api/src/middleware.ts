// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1

// ============================================================================
// API middleware — API key authentication + per-key rate limiting.
// ============================================================================

import type { Context, Next } from 'hono'
import { config } from './config.js'

// ── API key validation ───────────────────────────────────────────────────────

const validKeys = new Set(
  config.api.apiKeys
    .split(',')
    .map((k) => k.trim())
    .filter(Boolean)
)
const masterKey = config.api.masterKey.trim()

export interface AuthInfo {
  apiKey: string
  isMaster: boolean
}

/**
 * Extracts and validates the API key from the `Authorization: Bearer <key>`
 * header or `?api_key=<key>` query param. Attaches `auth` to the context.
 *
 * If no API keys are configured (dev mode), auth is skipped.
 */
export async function authMiddleware(c: Context, next: Next): Promise<Response | void> {
  // Dev mode: no keys configured → open access
  if (validKeys.size === 0 && !masterKey) {
    c.set('auth', { apiKey: 'dev', isMaster: true } satisfies AuthInfo)
    await next()
    return
  }

  // Extract key from Authorization header or query param
  let key: string | undefined
  const authHeader = c.req.header('Authorization')
  if (authHeader?.startsWith('Bearer ')) {
    key = authHeader.slice(7).trim()
  }
  if (!key) {
    key = c.req.query('api_key')
  }

  if (!key) {
    return c.json({ error: 'Missing API key. Provide Authorization: Bearer <key> or ?api_key=<key>' }, 401)
  }

  const isMaster = masterKey !== '' && key === masterKey
  if (!isMaster && !validKeys.has(key)) {
    return c.json({ error: 'Invalid API key' }, 403)
  }

  c.set('auth', { apiKey: key, isMaster } satisfies AuthInfo)
  await next()
}

// ── Rate limiting (in-memory, per API key) ───────────────────────────────────

interface RateLimitEntry {
  count: number
  windowStart: number
}

const rateLimitMap = new Map<string, RateLimitEntry>()
const perMinute = config.api.rateLimitPerMinute
const burst = config.api.rateLimitBurst

// Cleanup old entries every 5 minutes
setInterval(() => {
  const now = Date.now()
  for (const [key, entry] of rateLimitMap) {
    if (now - entry.windowStart > 120_000) {
      rateLimitMap.delete(key)
    }
  }
}, 300_000)

export async function rateLimitMiddleware(c: Context, next: Next): Promise<Response | void> {
  const auth = c.get('auth') as AuthInfo | undefined
  const key = auth?.apiKey ?? 'anonymous'

  // Master key bypasses rate limiting
  if (auth?.isMaster) {
    await next()
    return
  }

  const now = Date.now()
  let entry = rateLimitMap.get(key)
  if (!entry || now - entry.windowStart > 60_000) {
    entry = { count: 0, windowStart: now }
    rateLimitMap.set(key, entry)
  }

  entry.count++

  const limit = perMinute + burst
  const remaining = Math.max(0, limit - entry.count)
  c.header('X-RateLimit-Limit', String(perMinute))
  c.header('X-RateLimit-Remaining', String(remaining))
  c.header('X-RateLimit-Reset', String(Math.ceil(entry.windowStart / 1000) + 60))

  if (entry.count > limit) {
    return c.json({ error: 'Rate limit exceeded. Retry after a minute.' }, 429)
  }

  await next()
}

// ── CORS ─────────────────────────────────────────────────────────────────────

export function corsMiddleware(c: Context, next: Next): Promise<Response | void> {
  const origin = c.req.header('Origin')
  if (origin) {
    c.header('Access-Control-Allow-Origin', config.api.corsOrigin)
    c.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    c.header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
    c.header('Access-Control-Max-Age', '86400')
  }
  if (c.req.method === 'OPTIONS') {
    return Promise.resolve(c.body(null, 204))
  }
  return next()
}
