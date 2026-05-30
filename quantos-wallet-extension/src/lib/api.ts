// ── Wallet Server API Client ──
// HTTP client that calls the wallet-server endpoints (same as the web wallet).
// Replaces WASM-based signing with server-side signing via the proven wallet-server.

const DEFAULT_SERVER_URL = 'http://localhost:3001'

let serverUrl = DEFAULT_SERVER_URL

// ── Configuration ─────────────────────────────────────────────

export function setServerUrl(url: string) {
  serverUrl = url.replace(/\/+$/, '')
}

export function getServerUrl(): string {
  return serverUrl
}

export async function loadServerUrl(): Promise<string> {
  try {
    const result = await chrome.storage.local.get(['quantos_server_url'])
    if (result.quantos_server_url) {
      serverUrl = result.quantos_server_url
    }
  } catch {
    // Not in extension context, use default
  }
  return serverUrl
}

export async function saveServerUrl(url: string): Promise<void> {
  serverUrl = url.replace(/\/+$/, '')
  try {
    await chrome.storage.local.set({ quantos_server_url: serverUrl })
  } catch {
    // Not in extension context
  }
}

// ── HTTP helpers ──────────────────────────────────────────────

async function apiPost<T>(path: string, body: Record<string, unknown>): Promise<T> {
  const response = await fetch(`${serverUrl}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })

  const data = await response.json()

  if (!response.ok) {
    const errMsg = typeof data?.error === 'string'
      ? data.error
      : data?.error?.message || data?.message || `HTTP ${response.status}`
    throw new Error(errMsg)
  }

  return data as T
}

async function apiGet<T>(path: string): Promise<T> {
  const response = await fetch(`${serverUrl}${path}`)

  const data = await response.json()

  if (!response.ok) {
    const errMsg = typeof data?.error === 'string'
      ? data.error
      : data?.error?.message || data?.message || `HTTP ${response.status}`
    throw new Error(errMsg)
  }

  return data as T
}

// ── Response Types ────────────────────────────────────────────

export interface WalletInfo {
  address: string
  qts_address: string
  rpc_address: string
  public_key: string
  label: string | null
  created_at: number
}

export interface CreateWalletResponse {
  wallet: WalletInfo
  encrypted_key: string
}

export interface UnlockResponse {
  session_token: string
  expires_at: number
  address: string
}

export interface BalanceResponse {
  address: string
  qts_address: string
  balance: string
  stake: string
  nonce: number
  is_validator: boolean
  balance_formatted: string
  stake_formatted: string
  qtest_balance: string
  qtest_balance_formatted: string
  sqtest_balance: string
  sqtest_balance_formatted: string
}

export interface TxResponse {
  tx_hash: string
  status: string
  token?: string
  amount?: string
  error?: string
}

export interface SignResponse {
  message: string
  signature_hex: string
  public_key_hex: string
  address: string
}

export interface FaucetStatusResponse {
  contract_address: string
  token: string
  symbol: string
  decimals: number
  claim_amount: string
  claim_amount_formatted: string
  cooldown_seconds: number
}

export interface HealthResponse {
  status: string
  version: string
  node_connected: boolean
  node_rpc_url: string
}

// ── Wallet Lifecycle ──────────────────────────────────────────

export async function createWallet(pin: string, label?: string): Promise<CreateWalletResponse> {
  return apiPost<CreateWalletResponse>('/wallet/create', { pin, label: label || null })
}

export async function importWallet(secretKeyHex: string, pin: string, label?: string): Promise<CreateWalletResponse> {
  return apiPost<CreateWalletResponse>('/wallet/import', { secret_key_hex: secretKeyHex, pin, label: label || null })
}

export async function unlockWallet(address: string, encryptedKey: string, pin: string): Promise<UnlockResponse> {
  return apiPost<UnlockResponse>('/wallet/unlock', { address, encrypted_key: encryptedKey, pin })
}

export async function lockWallet(sessionToken: string): Promise<void> {
  await apiPost('/wallet/lock', { session_token: sessionToken })
}

// ── Read (no session) ─────────────────────────────────────────

export async function getBalance(address: string): Promise<BalanceResponse> {
  return apiGet<BalanceResponse>(`/wallet/${address}/balance`)
}

export async function getAccountInfo(address: string): Promise<unknown> {
  return apiGet(`/wallet/${address}/info`)
}

export async function getTokenBalances(address: string): Promise<unknown> {
  return apiGet(`/wallet/${address}/tokens`)
}

export async function getNFTs(address: string): Promise<unknown> {
  return apiGet(`/wallet/${address}/nfts`)
}

// ── Transactions (session required) ───────────────────────────

export async function sendTransfer(sessionToken: string, to: string, amount: string): Promise<TxResponse> {
  return apiPost<TxResponse>('/wallet/send', { session_token: sessionToken, to, amount })
}

export async function transferToken(sessionToken: string, to: string, amount: string): Promise<TxResponse> {
  return apiPost<TxResponse>('/wallet/transfer-token', { session_token: sessionToken, to, amount })
}

export async function deployContract(sessionToken: string, bytecodeHex: string, constructorDataHex?: string): Promise<TxResponse> {
  return apiPost<TxResponse>('/wallet/deploy', {
    session_token: sessionToken,
    bytecode_hex: bytecodeHex,
    constructor_data_hex: constructorDataHex || null,
  })
}

export async function callContract(sessionToken: string, contractAddress: string, calldataHex: string, amount?: string): Promise<TxResponse> {
  return apiPost<TxResponse>('/wallet/call', {
    session_token: sessionToken,
    contract_address: contractAddress,
    calldata_hex: calldataHex,
    amount: amount || null,
  })
}

export async function signMessage(sessionToken: string, message: string): Promise<SignResponse> {
  return apiPost<SignResponse>('/wallet/sign', { session_token: sessionToken, message })
}

export async function bridgeApprove(sessionToken: string, amount: string, vaultAddress?: string): Promise<TxResponse> {
  return apiPost<TxResponse>('/bridge/approve', {
    session_token: sessionToken,
    amount,
    vault_address: vaultAddress || null,
  })
}

export async function bridgeDeposit(sessionToken: string, amount: string, baseRecipient: string, vaultAddress?: string): Promise<TxResponse & { vault_address?: string; base_recipient?: string }> {
  return apiPost<TxResponse & { vault_address?: string; base_recipient?: string }>('/bridge/deposit', {
    session_token: sessionToken,
    amount,
    base_recipient: baseRecipient,
    vault_address: vaultAddress || null,
  })
}

export async function bridgeRelease(sessionToken: string, releaseId: string, to: string, amount: string, vaultAddress?: string): Promise<TxResponse & { vault_address?: string }> {
  return apiPost<TxResponse & { vault_address?: string }>('/bridge/release', {
    session_token: sessionToken,
    release_id: releaseId,
    to,
    amount,
    vault_address: vaultAddress || null,
  })
}

// ── Faucet ────────────────────────────────────────────────────

export async function claimFaucet(sessionToken: string): Promise<TxResponse> {
  return apiPost<TxResponse>('/faucet/claim', { session_token: sessionToken })
}

export async function getFaucetStatus(address: string): Promise<FaucetStatusResponse> {
  return apiGet<FaucetStatusResponse>(`/faucet/status/${address}`)
}

// ── Health ────────────────────────────────────────────────────

export async function health(): Promise<HealthResponse> {
  return apiGet<HealthResponse>('/health')
}

export async function nodeInfo(): Promise<unknown> {
  return apiGet('/node/info')
}
