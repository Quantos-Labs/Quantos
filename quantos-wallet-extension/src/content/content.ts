// ── Content Script ──
// Bridges messages between the injected inpage.js and the background service worker.

// Inject the inpage script into the page
const script = document.createElement('script')
script.src = chrome.runtime.getURL('inpage.js')
script.onload = () => script.remove()
;(document.head || document.documentElement).appendChild(script)

// Forward requests from page to background
window.addEventListener('message', (event) => {
  if (event.source !== window) return
  if (event.data?.type !== 'QUANTOS_REQUEST') return

  // Build message
  const msg: any = {
    type: 'QUANTOS_REQUEST',
    id: event.data.id,
    method: event.data.method,
    params: { ...(event.data.params || {}) },
    origin: window.location.origin,
  }

  // Attach web wallet data from localStorage as fallback for all methods
  try {
    const raw = localStorage.getItem('quantos_wallets')
    if (raw) {
      const data = JSON.parse(raw)
      const wallets = Array.isArray(data.wallets) ? data.wallets : []
      const activeWallet = wallets.find((w: any) => w.address === data.activeAddress)
      const wallet = activeWallet || wallets[0]
      if (wallet?.address) {
        msg.params.webWalletAddress = wallet.address
        if (wallet.encrypted_key) msg.params.webWalletEncryptedKey = wallet.encrypted_key
        if (wallet.public_key) msg.params.webWalletPublicKey = wallet.public_key
      }
    }
  } catch { /* ignore */ }

  chrome.runtime.sendMessage(
    msg,
    (response) => {
      window.postMessage(
        {
          type: 'QUANTOS_RESPONSE',
          id: event.data.id,
          result: response?.result,
          error: response?.error,
        },
        '*'
      )
    }
  )
})

// Forward events from background to page
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'QUANTOS_EVENT') {
    window.postMessage(
      {
        type: 'QUANTOS_EVENT',
        event: message.event,
        args: message.args,
      },
      '*'
    )
  }

  // Show approval popup overlay
  if (message.type === 'QUANTOS_SHOW_POPUP') {
    showPopupOverlay(message.requestId)
  }

  // Receive approval/rejection result directly from service worker
  if (message.type === 'QUANTOS_APPROVAL_RESPONSE') {
    window.postMessage(
      {
        type: 'QUANTOS_RESPONSE',
        id: message.id,
        result: message.result,
        error: message.error,
      },
      '*'
    )
  }
})

// ── Popup Overlay ──

let overlayContainer: HTMLDivElement | null = null

function showPopupOverlay(requestId: string) {
  // Remove any existing overlay
  removePopupOverlay()

  const popupUrl = chrome.runtime.getURL(`popup.html#approve/${requestId}`)

  // Create overlay container
  overlayContainer = document.createElement('div')
  overlayContainer.id = 'quantos-wallet-overlay'
  overlayContainer.style.cssText = `
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    z-index: 2147483647;
    background: rgba(0, 0, 0, 0.4);
    backdrop-filter: blur(2px);
    display: flex;
    justify-content: flex-end;
    align-items: flex-start;
    padding: 16px;
    font-family: system-ui, -apple-system, sans-serif;
  `

  // Create iframe
  const iframe = document.createElement('iframe')
  iframe.src = popupUrl
  iframe.id = 'quantos-wallet-popup'
  iframe.allow = 'clipboard-write'
  iframe.style.cssText = `
    width: 375px;
    height: 600px;
    border: none;
    border-radius: 16px;
    box-shadow: 0 25px 60px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(255, 255, 255, 0.08);
    margin-top: 60px;
  `

  // Click backdrop to close (reject)
  overlayContainer.addEventListener('click', (e) => {
    if (e.target === overlayContainer) {
      chrome.runtime.sendMessage({ type: 'POPUP_REJECT', requestId })
      removePopupOverlay()
    }
  })

  overlayContainer.appendChild(iframe)
  document.body.appendChild(overlayContainer)
}

function removePopupOverlay() {
  if (overlayContainer) {
    overlayContainer.remove()
    overlayContainer = null
  }
}

// Listen for close message from popup iframe
window.addEventListener('message', (event) => {
  if (event.data?.type === 'QUANTOS_CLOSE_POPUP') {
    removePopupOverlay()
  }
})
