// ── Quantos Provider (injected into page as window.quantos) ──
// This is the equivalent of window.ethereum for MetaMask

interface QuantosProvider {
  isQuantos: boolean
  version: string
  chainId: string
  selectedAddress: string | null
  isConnected: () => boolean
  request: (args: { method: string; params?: Record<string, unknown> }) => Promise<unknown>
  requestAccounts: () => Promise<string[]>
  sendTransfer: (to: string, amount: string) => Promise<unknown>
  transferToken: (to: string, amount: string) => Promise<unknown>
  getBalance: () => Promise<unknown>
  disconnect: () => Promise<boolean>
  on: (event: string, handler: (...args: unknown[]) => void) => void
  removeListener: (event: string, handler: (...args: unknown[]) => void) => void
}

const listeners: Record<string, Array<(...args: unknown[]) => void>> = {}

let _isConnected = false
let _selectedAddress: string | null = null
let _chainId = 'quantos:mainnet'

const quantosProvider: QuantosProvider = {
  isQuantos: true,
  version: '1.0.0',
  chainId: _chainId,
  selectedAddress: _selectedAddress,

  isConnected: () => _isConnected,

  request: async ({ method, params = {} }) => {
    return new Promise((resolve, reject) => {
      const id = `qnt_${Date.now()}_${Math.random().toString(36).slice(2)}`

      const handler = (event: MessageEvent) => {
        if (event.data?.type !== 'QUANTOS_RESPONSE' || event.data?.id !== id) return
        window.removeEventListener('message', handler)

        if (event.data.error) {
          reject(new Error(event.data.error))
        } else {
          // Update internal state based on method
          if (method === 'qnt_requestAccounts' && Array.isArray(event.data.result)) {
            _selectedAddress = event.data.result[0] || null
            _isConnected = !!_selectedAddress
            quantosProvider.selectedAddress = _selectedAddress
            emit('accountsChanged', event.data.result)
          }
          if (method === 'qnt_disconnect') {
            _selectedAddress = null
            _isConnected = false
            quantosProvider.selectedAddress = null
            emit('accountsChanged', [])
            emit('disconnect')
          }
          if (method === 'qnt_getChainId') {
            _chainId = event.data.result as string
            quantosProvider.chainId = _chainId
          }
          resolve(event.data.result)
        }
      }

      window.addEventListener('message', handler)

      // Send request to content script
      window.postMessage({
        type: 'QUANTOS_REQUEST',
        id,
        method,
        params,
      }, '*')

      // Timeout after 5 minutes (approval popups may take time)
      setTimeout(() => {
        window.removeEventListener('message', handler)
        reject(new Error('Request timed out'))
      }, 300_000)
    })
  },

  // ── Convenience methods ──

  requestAccounts: async () => {
    return quantosProvider.request({ method: 'qnt_requestAccounts' }) as Promise<string[]>
  },

  sendTransfer: async (to: string, amount: string) => {
    return quantosProvider.request({ method: 'qnt_sendTransfer', params: { to, amount } })
  },

  transferToken: async (to: string, amount: string) => {
    return quantosProvider.request({ method: 'qnt_transferToken', params: { to, amount } })
  },

  getBalance: async () => {
    return quantosProvider.request({ method: 'qnt_getBalance' })
  },

  disconnect: async () => {
    return quantosProvider.request({ method: 'qnt_disconnect' }) as Promise<boolean>
  },

  on: (event: string, handler: (...args: unknown[]) => void) => {
    if (!listeners[event]) listeners[event] = []
    listeners[event].push(handler)
  },

  removeListener: (event: string, handler: (...args: unknown[]) => void) => {
    if (!listeners[event]) return
    listeners[event] = listeners[event].filter((h) => h !== handler)
  },
}

function emit(event: string, ...args: unknown[]) {
  if (!listeners[event]) return
  listeners[event].forEach((handler) => handler(...args))
}

// Listen for events from content script
window.addEventListener('message', (event) => {
  if (event.data?.type === 'QUANTOS_EVENT') {
    emit(event.data.event, ...(event.data.args || []))
  }
})

// Inject provider
Object.defineProperty(window, 'quantos', {
  value: quantosProvider,
  writable: false,
  configurable: false,
})

// Announce provider
window.dispatchEvent(new CustomEvent('quantos#initialized'))
