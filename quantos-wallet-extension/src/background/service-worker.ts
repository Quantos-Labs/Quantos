// ── Quantos Wallet Service Worker ──
// Manages wallet state, handles dApp requests via wallet-server API.
// Sensitive methods open a popup for user approval before executing.

import * as api from '../lib/api'

// ── Types ─────────────────────────────────────────────────────

interface StoredWalletInfo {
  address: string
  qtsAddress: string
  rpcAddress: string
  publicKey: string
  encryptedKey: string
}

interface WalletState {
  isUnlocked: boolean
  activeAddress: string | null
  wallets: StoredWalletInfo[]
  connectedOrigins: string[]
  serverUrl: string
}

interface PendingRequest {
  id: string
  method: string
  params: Record<string, unknown>
  origin: string
  tabId: number | null
  messageId: string | null
  resolve: (value: unknown) => void
  reject: (reason: Error) => void
}

// ── State ─────────────────────────────────────────────────────

let walletState: WalletState = {
  isUnlocked: false,
  activeAddress: null,
  wallets: [],
  connectedOrigins: [],
  serverUrl: 'http://localhost:3001',
}

// Session token kept in memory only (never persisted)
let sessionToken: string | null = null
let sessionAddress: string | null = null

// Pending approval requests: Map<requestId, PendingRequest>
const pendingRequests = new Map<string, PendingRequest>()

// ── Storage ───────────────────────────────────────────────────

const STORAGE_KEY = 'quantos_wallet_state'

async function loadState(): Promise<void> {
  const result = await chrome.storage.local.get([STORAGE_KEY])
  if (result[STORAGE_KEY]) {
    walletState = { ...walletState, ...result[STORAGE_KEY] }
  }
  api.setServerUrl(walletState.serverUrl)
}

async function saveState(): Promise<void> {
  await chrome.storage.local.set({
    [STORAGE_KEY]: {
      wallets: walletState.wallets,
      activeAddress: walletState.activeAddress,
      connectedOrigins: walletState.connectedOrigins,
      serverUrl: walletState.serverUrl,
    },
  })
}

// ── Popup Approval Flow ───────────────────────────────────────

// Methods that require popup approval
const SENSITIVE_METHODS = new Set([
  'qnt_sendTransfer',
  'qnt_transferToken',
  'qnt_callContract',
  'qnt_bridgeApprove',
  'qnt_bridgeDeposit',
  'qnt_bridgeRelease',
  'qnt_deployContract',
  'qnt_signMessage',
  'qnt_claimFaucet',
])

function generateRequestId(): string {
  return `req_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`
}

async function openApprovalPopup(requestId: string): Promise<void> {
  // Send message to the active tab's content script to inject the popup overlay
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true })
  if (tab?.id) {
    chrome.tabs.sendMessage(tab.id, {
      type: 'QUANTOS_SHOW_POPUP',
      requestId,
    })
  }
}

async function requestApproval(
  method: string,
  params: Record<string, unknown>,
  origin: string,
  tabId: number | null = null,
  messageId: string | null = null,
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const requestId = generateRequestId()

    const pending: PendingRequest = {
      id: requestId,
      method,
      params,
      origin,
      tabId,
      messageId,
      resolve,
      reject,
    }

    pendingRequests.set(requestId, pending)

    chrome.storage.session.set({
      [`pending_${requestId}`]: {
        id: requestId,
        method,
        params,
        origin,
      },
    }).then(() => {
      openApprovalPopup(requestId).catch((err) => {
        pendingRequests.delete(requestId)
        reject(new Error(`Failed to open approval popup: ${err.message}`))
      })
    })

    // Timeout after 5 minutes
    setTimeout(() => {
      if (pendingRequests.has(requestId)) {
        pendingRequests.delete(requestId)
        chrome.storage.session.remove(`pending_${requestId}`)
        reject(new Error('Approval request timed out'))
      }
    }, 300_000)
  })
}

// Send result/error directly to the tab's content script
function sendResponseToTab(tabId: number | null, messageId: string | null, result: unknown, error?: string) {
  if (!tabId || !messageId) return
  chrome.tabs.sendMessage(tabId, {
    type: 'QUANTOS_APPROVAL_RESPONSE',
    id: messageId,
    result: error ? undefined : result,
    error: error || undefined,
  })
}

// ── Execute Approved Transaction ──────────────────────────────

async function executeApprovedRequest(method: string, params: Record<string, unknown>): Promise<unknown> {
  // Use session token from params (passed by dApp) or extension's own session
  const token = (params.sessionToken as string) || sessionToken
  if (!token) {
    throw new Error('No session token available')
  }

  switch (method) {
    case 'qnt_sendTransfer':
      return await api.sendTransfer(token, params.to as string, params.amount as string)

    case 'qnt_transferToken':
      return await api.transferToken(token, params.to as string, params.amount as string)

    case 'qnt_callContract':
      return await api.callContract(
        token,
        params.contractAddress as string,
        params.calldataHex as string,
        params.amount as string | undefined,
      )

    case 'qnt_bridgeApprove':
      return await api.bridgeApprove(
        token,
        params.amount as string,
        params.vaultAddress as string | undefined,
      )

    case 'qnt_bridgeDeposit':
      return await api.bridgeDeposit(
        token,
        params.amount as string,
        params.baseRecipient as string,
        params.vaultAddress as string | undefined,
      )

    case 'qnt_bridgeRelease':
      return await api.bridgeRelease(
        token,
        params.releaseId as string,
        params.to as string,
        params.amount as string,
        params.vaultAddress as string | undefined,
      )

    case 'qnt_deployContract':
      return await api.deployContract(
        token,
        params.bytecodeHex as string,
        params.constructorDataHex as string | undefined,
      )

    case 'qnt_signMessage':
      return await api.signMessage(token, params.message as string)

    case 'qnt_claimFaucet':
      return await api.claimFaucet(token)

    default:
      throw new Error(`Unknown sensitive method: ${method}`)
  }
}

// ── Message Handlers ───────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab?.id ?? null
  const messageId = message.id || null

  handleMessage(message, sender, tabId, messageId)
    .then((result) => sendResponse({ result }))
    .catch((error) => {
      console.error('Service worker error:', error)
      sendResponse({ error: error.message || 'Unknown error' })
    })
  return true // Keep message channel open for async response
})

async function handleMessage(message: any, sender: chrome.runtime.MessageSender, tabId: number | null = null, messageId: string | null = null): Promise<unknown> {
  // Handle internal messages from the popup (approve/reject)
  if (message.type === 'POPUP_APPROVE') {
    return handlePopupApprove(message.requestId)
  }
  if (message.type === 'POPUP_REJECT') {
    return handlePopupReject(message.requestId)
  }
  if (message.type === 'POPUP_UNLOCK_AND_APPROVE') {
    return handlePopupUnlockAndApprove(message.requestId, message.address, message.pin)
  }
  if (message.type === 'GET_PENDING_REQUEST') {
    return getPendingRequestDetails(message.requestId)
  }
  if (message.type === 'GET_WALLET_STATUS') {
    return {
      isUnlocked: walletState.isUnlocked,
      activeAddress: walletState.activeAddress,
      wallets: walletState.wallets.map((w) => ({
        address: w.address,
        qtsAddress: w.qtsAddress,
      })),
    }
  }

  // Determine if message is from the popup (trusted) or a dApp content script
  // Popup messages have no sender.tab; content script messages have sender.tab
  const isFromPopup = !sender.tab
  const isFromContentScript = !!sender.tab

  // Handle dApp requests (from content script or popup)
  const { method, params = {} } = message
  const origin = message.origin || sender.origin || sender.tab?.url || 'extension'

  await loadState()

  switch (method) {
    // ── Wallet Lifecycle (popup-initiated, no approval needed) ──
    case 'qnt_createWallet':
      return await handleCreateWallet(params.pin, params.label)

    case 'qnt_importWallet':
      return await handleImportWallet(params.secretKeyHex, params.pin, params.label)

    case 'qnt_unlockWallet':
      return await handleUnlockWallet(params.address, params.pin)

    case 'qnt_lockWallet':
      return await handleLockWallet()

    case 'qnt_getWallets':
      return walletState.wallets.map((w) => ({
        address: w.address,
        qtsAddress: w.qtsAddress,
        rpcAddress: w.rpcAddress,
      }))

    case 'qnt_getSelectedAccount':
      return walletState.activeAddress || walletState.wallets[0]?.address || null

    case 'qnt_setSelectedAccount':
      return await handleSetSelectedAccount(params.address)

    // ── Passive reads (no popup) ──
    case 'qnt_requestAccounts': {
      const addr = walletState.activeAddress || walletState.wallets[0]?.address || (params.webWalletAddress as string)
      if (!addr) throw new Error('No wallet found. Create a wallet first.')

      if (walletState.connectedOrigins.includes(origin)) {
        return [addr]
      }

      // Require approval once per origin, even if wallet is locked
      return await requestApproval(
        'qnt_requestAccounts',
        { address: addr },
        origin,
        tabId,
        messageId,
      )
    }

    case 'qnt_getBalance': {
      const addr = walletState.activeAddress || walletState.wallets[0]?.address
      if (!addr) throw new Error('No wallet')
      return await api.getBalance(addr)
    }

    case 'qnt_getChainId':
      return 'quantos:testnet'

    case 'qnt_isConnected':
      return walletState.isUnlocked && walletState.connectedOrigins.includes(origin)

    case 'qnt_disconnect':
      walletState.connectedOrigins = walletState.connectedOrigins.filter((o) => o !== origin)
      await saveState()
      return true

    case 'qnt_getAccountInfo': {
      const addr = walletState.activeAddress || walletState.wallets[0]?.address
      if (!addr) throw new Error('No wallet')
      return await api.getAccountInfo(addr)
    }

    case 'qnt_getNFTs': {
      const addr = walletState.activeAddress || walletState.wallets[0]?.address
      if (!addr) throw new Error('No wallet')
      return await api.getNFTs(addr)
    }

    case 'qnt_nodeInfo':
      return await api.nodeInfo()

    case 'qnt_health':
      return await api.health()

    case 'qnt_setServerUrl':
      walletState.serverUrl = params.url
      api.setServerUrl(params.url)
      await saveState()
      return { ok: true }

    // ── Sensitive methods ──
    // From popup: execute directly (user is already interacting with the extension)
    // From dApp content script: require popup approval
    case 'qnt_sendTransfer':
    case 'qnt_transferToken':
    case 'qnt_callContract':
    case 'qnt_bridgeApprove':
    case 'qnt_bridgeDeposit':
    case 'qnt_bridgeRelease':
    case 'qnt_deployContract':
    case 'qnt_signMessage':
    case 'qnt_claimFaucet':
      if (isFromPopup) {
        // Trusted: user initiated from popup, execute directly
        return await executeApprovedRequest(method, params)
      }
      // Untrusted: dApp request, require approval popup
      return await requestApproval(method, params, origin, tabId, messageId)

    default:
      throw new Error(`Unknown method: ${method}`)
  }
}

// ── Popup Handlers ────────────────────────────────────────────

async function handlePopupApprove(requestId: string): Promise<unknown> {
  const pending = pendingRequests.get(requestId)
  if (!pending) throw new Error('Request not found or expired')

  try {
    let result: unknown

    // Special case: qnt_requestAccounts just needs to connect
    if (pending.method === 'qnt_requestAccounts') {
      const addr =
        (pending.params.address as string | undefined) ||
        walletState.activeAddress ||
        walletState.wallets[0]?.address ||
        (pending.params.webWalletAddress as string | undefined)

      if (!addr) {
        throw new Error('No wallet available')
      }

      if (!walletState.connectedOrigins.includes(pending.origin)) {
        walletState.connectedOrigins.push(pending.origin)
        await saveState()
      }

      result = [addr]
    } else {
      result = await executeApprovedRequest(pending.method, pending.params)
    }

    // Resolve the original Promise (fires sendResponse chain if still alive)
    pending.resolve(result)
    // Backup: send directly to tab (bypasses expired sendResponse)
    sendResponseToTab(pending.tabId, pending.messageId, result)
    return result
  } catch (err: any) {
    pending.reject(err)
    sendResponseToTab(pending.tabId, pending.messageId, null, err.message)
    throw err
  } finally {
    pendingRequests.delete(requestId)
    chrome.storage.session.remove(`pending_${requestId}`)
  }
}

async function handlePopupReject(requestId: string): Promise<unknown> {
  const pending = pendingRequests.get(requestId)
  if (!pending) throw new Error('Request not found or expired')

  pendingRequests.delete(requestId)
  chrome.storage.session.remove(`pending_${requestId}`)

  // Reject the original Promise + send directly to tab
  pending.reject(new Error('User rejected the request'))
  sendResponseToTab(pending.tabId, pending.messageId, null, 'User rejected the request')
  return { rejected: true }
}

async function handlePopupUnlockAndApprove(requestId: string, address: string, pin: string): Promise<unknown> {
  // If extension has no wallets, try using web wallet's encrypted key from the pending request
  const pending = pendingRequests.get(requestId)
  if (pending?.params?.sessionToken) {
    return handlePopupApprove(requestId)
  }
  const webEncryptedKey = pending?.params?.webWalletEncryptedKey as string | undefined

  // First unlock the wallet
  await handleUnlockWallet(address, pin, webEncryptedKey)

  // Then approve the request
  return handlePopupApprove(requestId)
}

async function getPendingRequestDetails(requestId: string): Promise<unknown> {
  const result = await chrome.storage.session.get(`pending_${requestId}`)
  const data = result[`pending_${requestId}`]
  if (!data) return null

  // Use web wallet address as fallback if extension has no wallets
  const webAddr = data.params?.webWalletAddress
  const effectiveAddress = walletState.activeAddress || webAddr || null
  const effectiveWallets = walletState.wallets.length > 0
    ? walletState.wallets.map((w) => ({ address: w.address, qtsAddress: w.qtsAddress }))
    : webAddr ? [{ address: webAddr, qtsAddress: '' }] : []

  return {
    ...data,
    isUnlocked: walletState.isUnlocked,
    activeAddress: effectiveAddress,
    wallets: effectiveWallets,
  }
}

// ── Wallet Operations ─────────────────────────────────────────

async function handleCreateWallet(pin: string, label?: string): Promise<unknown> {
  const result = await api.createWallet(pin, label)

  const walletInfo: StoredWalletInfo = {
    address: result.wallet.address,
    qtsAddress: result.wallet.qts_address,
    rpcAddress: result.wallet.rpc_address,
    publicKey: result.wallet.public_key,
    encryptedKey: result.encrypted_key,
  }

  walletState.wallets.push(walletInfo)
  if (!walletState.activeAddress) {
    walletState.activeAddress = walletInfo.address
  }
  await saveState()

  // Auto-unlock after creation
  await handleUnlockWallet(walletInfo.address, pin)

  return {
    address: walletInfo.address,
    qtsAddress: walletInfo.qtsAddress,
  }
}

async function handleImportWallet(secretKeyHex: string, pin: string, label?: string): Promise<unknown> {
  const result = await api.importWallet(secretKeyHex, pin, label)

  // Check for duplicate
  if (walletState.wallets.find((w) => w.address === result.wallet.address)) {
    throw new Error('Wallet already exists')
  }

  const walletInfo: StoredWalletInfo = {
    address: result.wallet.address,
    qtsAddress: result.wallet.qts_address,
    rpcAddress: result.wallet.rpc_address,
    publicKey: result.wallet.public_key,
    encryptedKey: result.encrypted_key,
  }

  walletState.wallets.push(walletInfo)
  if (!walletState.activeAddress) {
    walletState.activeAddress = walletInfo.address
  }
  await saveState()

  return {
    address: walletInfo.address,
    qtsAddress: walletInfo.qtsAddress,
  }
}

async function handleUnlockWallet(address: string, pin: string, fallbackEncryptedKey?: string): Promise<unknown> {
  const wallet = walletState.wallets.find((w) => w.address === address)
  const encryptedKey = wallet?.encryptedKey || fallbackEncryptedKey
  if (!encryptedKey) throw new Error('Wallet not found')

  const result = await api.unlockWallet(address, encryptedKey, pin)

  sessionToken = result.session_token
  sessionAddress = result.address
  walletState.isUnlocked = true
  walletState.activeAddress = result.address
  await saveState()

  return {
    address: wallet?.address || result.address,
    qtsAddress: wallet?.qtsAddress || '',
  }
}

async function handleLockWallet(): Promise<unknown> {
  if (sessionToken) {
    try {
      await api.lockWallet(sessionToken)
    } catch {
      // Ignore — server session may have already expired
    }
  }

  sessionToken = null
  sessionAddress = null
  walletState.isUnlocked = false
  await saveState()

  return { locked: true }
}

async function handleSetSelectedAccount(address: string): Promise<unknown> {
  const wallet = walletState.wallets.find((w) => w.address === address)
  if (!wallet) throw new Error('Wallet not found')

  walletState.activeAddress = address
  await saveState()

  return { address }
}

// ── Initialization ───────────────────────────────────────────

loadState().catch(console.error)
