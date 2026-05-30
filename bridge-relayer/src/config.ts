import 'dotenv/config'

function required(key: string): string {
  const v = process.env[key]
  if (!v) throw new Error(`Missing required env var: ${key}`)
  return v
}

function optional(key: string, fallback: string): string {
  return process.env[key] || fallback
}

export const config = {
  // Quantos
  quantosRpcUrl: optional('QUANTOS_RPC_URL', 'http://127.0.0.1:8545'),
  quantosChainId: Number(optional('QUANTOS_CHAIN_ID', '1')),
  qtestContractAddress: required('QTEST_CONTRACT_ADDRESS'),
  bridgeVaultAddress: required('BRIDGE_VAULT_ADDRESS'),

  // Base
  baseRpcUrl: optional('BASE_RPC_URL', 'https://sepolia.base.org'),
  baseBridgeGatewayAddress: required('BASE_BRIDGE_GATEWAY_ADDRESS'),
  baseWrappedQtestAddress: required('BASE_WRAPPED_QTEST_ADDRESS'),
  relayerPrivateKey: required('RELAYER_PRIVATE_KEY'),

  // Supabase
  supabaseUrl: required('SUPABASE_URL'),
  supabaseServiceRoleKey: required('SUPABASE_SERVICE_ROLE_KEY'),

  // Settings
  pollIntervalMs: Number(optional('POLL_INTERVAL_MS', '5000')),
  maxRetries: Number(optional('MAX_RETRIES', '10')),
  healthPort: Number(optional('HEALTH_PORT', '3100')),
  logLevel: optional('LOG_LEVEL', 'info'),
}

export type Config = typeof config
