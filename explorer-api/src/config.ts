import 'dotenv/config'

function required(key: string): string {
  const val = process.env[key]
  if (!val) throw new Error(`Missing required env var: ${key}`)
  return val
}

function optional(key: string, fallback: string): string {
  return process.env[key] ?? fallback
}

export const config = {
  supabase: {
    url: required('SUPABASE_URL'),
    serviceRoleKey: required('SUPABASE_SERVICE_ROLE_KEY'),
    anonKey: required('SUPABASE_ANON_KEY'),
  },
  quantos: {
    rpcUrl: optional('QUANTOS_RPC_URL', 'http://localhost:8545'),
  },
  indexer: {
    pollIntervalMs: Number(process.env.POLL_INTERVAL_MS) || 2000,
  },
  api: {
    port: Number(process.env.API_PORT) || 3000,
    /** Comma-separated list of valid API keys. If empty, auth is disabled (dev mode). */
    apiKeys: process.env.QUANTOS_API_KEYS ?? '',
    /** Master key with unlimited rate limit. */
    masterKey: process.env.QUANTOS_MASTER_KEY ?? '',
    /** Requests per minute per API key (default 600). */
    rateLimitPerMinute: Number(process.env.API_RATE_LIMIT_PER_MINUTE) || 600,
    /** Burst allowance (default 100). */
    rateLimitBurst: Number(process.env.API_RATE_LIMIT_BURST) || 100,
    /** CORS origin (default *). */
    corsOrigin: optional('API_CORS_ORIGIN', '*'),
  },
}
