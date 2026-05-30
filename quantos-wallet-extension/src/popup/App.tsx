import { useState, useEffect, useCallback } from 'react'
import { cn } from '@/lib/utils'
import {
  Copy, Send, ArrowDownLeft, Shield, Fingerprint,
  Lock, CheckCircle, Droplet,
  Zap, Sparkles, Download, ArrowLeft, Wallet,
  Globe, X, Loader2, AlertTriangle, FileCode, PenTool, Coins,
} from 'lucide-react'

// ── Helpers ──────────────────────────────────────────────

function shortAddr(addr: string): string {
  if (!addr) return ''
  if (addr.startsWith('qts1') && addr.length > 16) return `${addr.slice(0, 10)}...${addr.slice(-6)}`
  if (addr.length > 20) return `${addr.slice(0, 10)}...${addr.slice(-6)}`
  return addr
}

function formatQtsAddr(address: string): string {
  return address ? `QTS:${address.replace(/^QTS:/i, '')}` : ''
}

// ── Shared Components ────────────────────────────────────

type Screen = 'welcome' | 'pin-login' | 'create-pin' | 'import' | 'main' | 'send' | 'receive' | 'faucet' | 'approve'

const Header = ({ title, onBack }: { title: string; onBack?: () => void }) => (
  <div className="flex items-center gap-3 p-4 border-b border-border shrink-0">
    {onBack && (
      <button onClick={onBack} className="p-1 hover:bg-muted rounded-lg"><ArrowLeft className="w-5 h-5" /></button>
    )}
    <h1 className="font-bold text-lg">{title}</h1>
  </div>
)

const Btn = ({ children, onClick, disabled, variant = 'primary', className = '' }: any) => (
  <button
    onClick={onClick}
    disabled={disabled}
    className={cn(
      'w-full h-12 rounded-xl font-semibold flex items-center justify-center gap-2 transition-all',
      variant === 'primary' && 'text-white bg-gradient-to-r from-purple-500 to-cyan-500 hover:opacity-90 disabled:opacity-40',
      variant === 'outline' && 'border border-border hover:bg-muted/50',
      variant === 'green' && 'text-white bg-green-600 disabled:opacity-60',
      variant === 'blue' && 'text-white bg-gradient-to-r from-blue-500 to-cyan-500 hover:opacity-90 disabled:opacity-40',
      variant === 'red' && 'text-white bg-red-600 hover:bg-red-700 disabled:opacity-40',
      className,
    )}
  >
    {children}
  </button>
)

const PinInput = ({ value, onChange }: { value: string; onChange: (v: string) => void }) => (
  <input
    type="password" inputMode="numeric" maxLength={6} placeholder="------"
    value={value} onChange={(e) => onChange(e.target.value.replace(/\D/g, ''))}
    className="w-full h-12 text-center text-2xl tracking-[0.5em] rounded-xl bg-muted border border-border focus:border-purple-500 focus:outline-none"
    autoFocus
  />
)

const ErrorBanner = ({ msg }: { msg: string }) => msg ? (
  <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20">
    <AlertTriangle className="w-4 h-4 text-red-500 shrink-0" />
    <p className="text-[11px] text-red-400">{msg}</p>
  </div>
) : null

const Spinner = () => (
  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
)

// ── App ──────────────────────────────────────────────────

export default function App() {
  // Detect approval mode from URL hash: #approve/REQUEST_ID
  const hash = window.location.hash
  const approvalMatch = hash.match(/^#approve\/(.+)$/)
  const approvalRequestId = approvalMatch?.[1] || null

  const [screen, setScreen] = useState<Screen>(approvalRequestId ? 'approve' : 'welcome')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  // Wallet state
  const [wallets, setWallets] = useState<Array<{ address: string; qtsAddress: string }>>([])
  const [activeAddress, setActiveAddress] = useState<string | null>(null)
  const [isUnlocked, setIsUnlocked] = useState(false)

  // Balance state
  const [balanceData, setBalanceData] = useState<{
    balance_formatted: string
    qtest_balance_formatted: string
    qtest_balance: string
    sqtest_balance_formatted: string
    sqtest_balance: string
    balance: string
    stake_formatted: string
    qts_address: string
  } | null>(null)

  // Form state
  const [pin, setPin] = useState('')
  const [confirmPin, setConfirmPin] = useState('')
  const [importSecretKey, setImportSecretKey] = useState('')
  const [sendAmount, setSendAmount] = useState('')
  const [sendAddress, setSendAddress] = useState('')
  const [sendToken, setSendToken] = useState<'QTS' | 'QTEST'>('QTEST')
  const [txHash, setTxHash] = useState('')

  // Faucet
  const [faucetClaiming, setFaucetClaiming] = useState(false)
  const [faucetClaimed, setFaucetClaimed] = useState(false)
  const [faucetTxHash, setFaucetTxHash] = useState('')

  // Approval state
  const [pendingRequest, setPendingRequest] = useState<any>(null)
  const [approvalPin, setApprovalPin] = useState('')
  const [approving, setApproving] = useState(false)

  // ── Init: Check wallet status ──
  useEffect(() => {
    if (approvalRequestId) return // Skip for approval popup

    chrome.runtime.sendMessage({ type: 'GET_WALLET_STATUS' }, (resp) => {
      if (resp?.result) {
        const { isUnlocked: unlocked, activeAddress: addr, wallets: wl } = resp.result
        setWallets(wl || [])
        setActiveAddress(addr)
        setIsUnlocked(unlocked)
        if (unlocked && addr) {
          setScreen('main')
          fetchBalance(addr)
        } else if (wl?.length > 0) {
          setScreen('pin-login')
        }
      }
    })
  }, [])

  // ── Init: Load pending request for approval popup ──
  useEffect(() => {
    if (!approvalRequestId) return

    chrome.runtime.sendMessage({ type: 'GET_PENDING_REQUEST', requestId: approvalRequestId }, (resp) => {
      if (resp?.result) {
        setPendingRequest(resp.result)
        setIsUnlocked(resp.result.isUnlocked)
        setActiveAddress(resp.result.activeAddress)
        setWallets(resp.result.wallets || [])
      } else {
        setError('Request not found or expired')
      }
    })
  }, [approvalRequestId])

  // ── Fetch balance ──
  const fetchBalance = useCallback(async (addr: string) => {
    try {
      const resp = await chrome.runtime.sendMessage({ method: 'qnt_getBalance' })
      if (resp?.result) {
        setBalanceData(resp.result)
      }
    } catch {
      // Silently fail
    }
  }, [])

  // ── Send message helper ──
  const sendMsg = useCallback(async (msg: Record<string, unknown>): Promise<any> => {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(msg, (resp) => {
        if (resp?.error) reject(new Error(resp.error))
        else resolve(resp?.result)
      })
    })
  }, [])

  // ── Create Wallet ──
  const handleCreateWallet = async () => {
    if (pin.length !== 6 || pin !== confirmPin) return
    setLoading(true)
    setError('')
    try {
      const result = await sendMsg({ method: 'qnt_createWallet', params: { pin } })
      setActiveAddress(result.address)
      setIsUnlocked(true)
      setWallets((prev) => [...prev, result])
      setPin('')
      setConfirmPin('')
      setScreen('main')
      fetchBalance(result.address)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  // ── Import Wallet ──
  const handleImportWallet = async () => {
    if (pin.length !== 6 || !importSecretKey) return
    setLoading(true)
    setError('')
    try {
      const result = await sendMsg({ method: 'qnt_importWallet', params: { secretKeyHex: importSecretKey, pin } })
      setActiveAddress(result.address)
      setWallets((prev) => [...prev, result])
      setImportSecretKey('')
      setPin('')
      // Now unlock
      await sendMsg({ method: 'qnt_unlockWallet', params: { address: result.address, pin } })
      setIsUnlocked(true)
      setScreen('main')
      fetchBalance(result.address)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  // ── Unlock Wallet ──
  const handleUnlock = async () => {
    if (pin.length !== 6) return
    setLoading(true)
    setError('')
    try {
      const addr = activeAddress || wallets[0]?.address
      if (!addr) throw new Error('No wallet found')
      const result = await sendMsg({ method: 'qnt_unlockWallet', params: { address: addr, pin } })
      setActiveAddress(result.address)
      setIsUnlocked(true)
      setPin('')
      setScreen('main')
      fetchBalance(result.address)
    } catch (e: any) {
      setError(e.message)
      setPin('')
    } finally {
      setLoading(false)
    }
  }

  // ── Lock Wallet ──
  const handleLock = async () => {
    try {
      await sendMsg({ method: 'qnt_lockWallet' })
    } catch { /* ignore */ }
    setIsUnlocked(false)
    setBalanceData(null)
    setScreen('pin-login')
  }

  // ── Send ──
  const handleSend = async () => {
    if (!sendAddress || !sendAmount || parseFloat(sendAmount) <= 0) return
    setLoading(true)
    setError('')
    setTxHash('')
    try {
      const method = sendToken === 'QTEST' ? 'qnt_transferToken' : 'qnt_sendTransfer'
      const result = await sendMsg({ method, params: { to: sendAddress, amount: sendAmount } })
      setTxHash(result?.tx_hash || result?.txHash || '')
      setSendAmount('')
      setSendAddress('')
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  // ── Faucet Claim ──
  const handleFaucetClaim = async () => {
    setFaucetClaiming(true)
    setError('')
    setFaucetTxHash('')
    try {
      const result = await sendMsg({ method: 'qnt_claimFaucet', params: {} })
      setFaucetTxHash(result?.tx_hash || '')
      setFaucetClaimed(true)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setFaucetClaiming(false)
    }
  }

  const closePopup = () => {
    // Tell the content script overlay to close
    if (window.parent !== window) {
      window.parent.postMessage({ type: 'QUANTOS_CLOSE_POPUP' }, '*')
    } else {
      window.close()
    }
  }

  // Methods that don't require wallet unlock
  const NO_UNLOCK_METHODS = ['qnt_requestAccounts']
  const hasSessionToken = Boolean(pendingRequest?.params?.sessionToken)
  const needsUnlock = pendingRequest && !NO_UNLOCK_METHODS.includes(pendingRequest.method) && !isUnlocked && !hasSessionToken

  // ── Approval: Approve ──
  const handleApprove = async () => {
    if (!approvalRequestId) return
    setApproving(true)
    setError('')
    try {
      if (needsUnlock) {
        if (approvalPin.length !== 6) {
          setError('Enter your 6-digit PIN to sign')
          setApproving(false)
          return
        }
        const addr = activeAddress || wallets[0]?.address
        if (!addr) { setError('No wallet found'); setApproving(false); return }
        await sendMsg({ type: 'POPUP_UNLOCK_AND_APPROVE', requestId: approvalRequestId, address: addr, pin: approvalPin })
      } else {
        await sendMsg({ type: 'POPUP_APPROVE', requestId: approvalRequestId })
      }
      closePopup()
    } catch (e: any) {
      setError(e.message)
      setApprovalPin('')
    } finally {
      setApproving(false)
    }
  }

  // ── Approval: Reject ──
  const handleReject = async () => {
    if (!approvalRequestId) return
    try {
      await sendMsg({ type: 'POPUP_REJECT', requestId: approvalRequestId })
    } catch { /* ignore */ }
    closePopup()
  }

  // ── Helper: get display info for a pending request ──
  function getTxDisplayInfo(req: any): { icon: any; label: string; details: string[] } {
    if (!req) return { icon: Coins, label: 'Transaction', details: [] }
    const m = req.method
    const p = req.params || {}
    if (m === 'qnt_sendTransfer') return { icon: Send, label: 'Send QTS', details: [`To: ${shortAddr(p.to)}`, `Amount: ${p.amount} QTS`] }
    if (m === 'qnt_transferToken') return { icon: Coins, label: 'Send QTEST', details: [`To: ${shortAddr(p.to)}`, `Amount: ${p.amount} QTEST`] }
    if (m === 'qnt_callContract') return { icon: FileCode, label: 'Contract Call', details: [`Contract: ${shortAddr(p.contractAddress)}`, p.amount ? `Value: ${p.amount}` : ''] }
    if (m === 'qnt_bridgeApprove') return { icon: Shield, label: 'Approve Bridge', details: [`Amount: ${p.amount} QTEST`, p.vaultAddress ? `Vault: ${shortAddr(p.vaultAddress)}` : ''] }
    if (m === 'qnt_bridgeDeposit') return { icon: ArrowDownLeft, label: 'Bridge to Base', details: [`Amount: ${p.amount} QTEST`, p.baseRecipient ? `Base recipient: ${shortAddr(p.baseRecipient)}` : '', p.vaultAddress ? `Vault: ${shortAddr(p.vaultAddress)}` : ''] }
    if (m === 'qnt_bridgeRelease') return { icon: ArrowDownLeft, label: 'Bridge Release', details: [p.to ? `To: ${shortAddr(p.to)}` : '', `Amount: ${p.amount} QTEST`, p.releaseId ? `Release: ${shortAddr(p.releaseId)}` : ''] }
    if (m === 'qnt_deployContract') return { icon: FileCode, label: 'Deploy Contract', details: [`Bytecode: ${(p.bytecodeHex || '').length / 2} bytes`] }
    if (m === 'qnt_signMessage') return { icon: PenTool, label: 'Sign Message', details: [`Message: ${(p.message || '').slice(0, 60)}${(p.message || '').length > 60 ? '...' : ''}`] }
    if (m === 'qnt_claimFaucet') return { icon: Droplet, label: 'Claim Faucet', details: ['Claim 1000 QTEST from faucet'] }
    if (m === 'qnt_requestAccounts') return { icon: Globe, label: 'Connect Wallet', details: ['This site wants to see your wallet address'] }
    return { icon: Coins, label: m, details: [] }
  }

  const qtsAddr = balanceData?.qts_address || (activeAddress ? shortAddr(activeAddress) : '')

  // ══════════════════════════════════════════════════════
  // ── APPROVAL SCREEN ──
  // ══════════════════════════════════════════════════════
  if (screen === 'approve' && approvalRequestId) {
    const txInfo = getTxDisplayInfo(pendingRequest)
    const TxIcon = txInfo.icon

    return (
      <div className="h-[600px] flex flex-col">
        {/* Top bar */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-border shrink-0">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-full bg-gradient-to-br from-purple-500 to-cyan-500 flex items-center justify-center">
              <Shield className="w-3.5 h-3.5 text-white" />
            </div>
            <span className="text-sm font-semibold">Quantos Wallet</span>
          </div>
          <span className="text-[10px] text-muted-foreground px-2 py-0.5 rounded-full bg-muted">Testnet</span>
        </div>

        <div className="flex-1 px-5 py-5 flex flex-col">
          {/* Origin */}
          {pendingRequest?.origin && (
            <div className="flex items-center gap-2 mb-5">
              <div className="w-8 h-8 rounded-full bg-muted flex items-center justify-center shrink-0">
                <Globe className="w-4 h-4 text-muted-foreground" />
              </div>
              <div>
                <p className="text-[11px] text-muted-foreground">Requesting site</p>
                <p className="text-sm font-medium">{pendingRequest.origin}</p>
              </div>
            </div>
          )}

          {/* TX Card */}
          <div className="flex-1 flex flex-col items-center justify-center text-center space-y-4">
            <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-purple-500/20 to-cyan-500/20 border border-purple-500/30 flex items-center justify-center">
              <TxIcon className="w-7 h-7 text-purple-400" />
            </div>
            <div>
              <h2 className="text-xl font-bold mb-1">{txInfo.label}</h2>
              {txInfo.details.filter(Boolean).map((d, i) => (
                <p key={i} className="text-sm text-muted-foreground">{d}</p>
              ))}
            </div>

            {/* Network badge */}
            <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-muted/50 text-[11px] text-muted-foreground">
              <Zap className="w-3 h-3 text-yellow-500" />
              <span>Gasless transaction</span>
            </div>
          </div>

          <ErrorBanner msg={error} />

          {/* PIN input when wallet is locked and method requires signing */}
          {needsUnlock && (
            <div className="w-full space-y-2 mt-4">
              <p className="text-xs text-muted-foreground text-center">Enter PIN to unlock & sign</p>
              <PinInput value={approvalPin} onChange={setApprovalPin} />
            </div>
          )}
        </div>

        {/* Bottom action buttons */}
        <div className="px-5 pb-5 pt-2 space-y-2.5 shrink-0">
          <Btn
            onClick={handleApprove}
            disabled={approving || (needsUnlock && approvalPin.length !== 6)}
            variant="primary"
          >
            {approving ? <><Spinner /> Confirming...</> : needsUnlock ? 'Unlock & Sign' : 'Confirm'}
          </Btn>
          <Btn onClick={handleReject} variant="outline" disabled={approving}>
            Reject
          </Btn>
        </div>
      </div>
    )
  }

  // ══════════════════════════════════════════════════════
  // ── WELCOME SCREEN ──
  // ══════════════════════════════════════════════════════
  if (screen === 'welcome') return (
    <div className="h-[600px] flex flex-col">
      <div className="flex-1 flex flex-col items-center justify-center px-6">
        <div className="w-20 h-20 rounded-full bg-gradient-to-br from-purple-500 to-cyan-500 flex items-center justify-center mb-6">
          <Wallet className="w-10 h-10 text-white" />
        </div>
        <h1 className="text-2xl font-bold mb-2">Quantos Wallet</h1>
        <p className="text-muted-foreground text-sm text-center mb-8">Post-quantum secure. No seed phrase. Zero gas fees.</p>
        <div className="grid grid-cols-3 gap-3 mb-8 w-full">
          {[
            { icon: Shield, color: 'text-green-500', label: 'PQ Secure' },
            { icon: Fingerprint, color: 'text-blue-500', label: 'PIN Auth' },
            { icon: Zap, color: 'text-yellow-500', label: 'Gasless TX' },
          ].map((f) => (
            <div key={f.label} className="text-center p-3 rounded-lg bg-muted/30">
              <f.icon className={cn('w-6 h-6 mx-auto mb-1.5', f.color)} />
              <p className="text-[10px] font-medium">{f.label}</p>
            </div>
          ))}
        </div>
        <div className="w-full space-y-3">
          <Btn onClick={() => { setError(''); setScreen('create-pin') }}><Sparkles className="w-4 h-4" />Create New Wallet</Btn>
          <Btn variant="outline" onClick={() => { setError(''); setScreen('import') }}><Download className="w-4 h-4" />Import Existing Wallet</Btn>
          {wallets.length > 0 && (
            <>
              <div className="relative py-2"><div className="absolute inset-0 flex items-center"><span className="w-full border-t" /></div><div className="relative flex justify-center text-xs uppercase"><span className="bg-background px-2 text-muted-foreground">Or</span></div></div>
              <Btn variant="outline" onClick={() => { setError(''); setPin(''); setScreen('pin-login') }}><Lock className="w-4 h-4" />Unlock with PIN</Btn>
            </>
          )}
        </div>
      </div>
      <p className="text-[10px] text-center text-muted-foreground p-4">Powered by Quantos — Post-Quantum Blockchain</p>
    </div>
  )

  // ══════════════════════════════════════════════════════
  // ── PIN LOGIN ──
  // ══════════════════════════════════════════════════════
  if (screen === 'pin-login') return (
    <div className="h-[600px] flex flex-col">
      <Header title="Unlock Wallet" onBack={() => setScreen('welcome')} />
      <div className="flex-1 flex flex-col items-center justify-center px-6">
        <div className="w-16 h-16 rounded-full bg-gradient-to-br from-purple-500 to-cyan-500 flex items-center justify-center mb-6">
          <Lock className="w-8 h-8 text-white" />
        </div>
        <p className="text-muted-foreground text-sm mb-2">Enter your 6-digit PIN</p>
        {wallets[0]?.qtsAddress && (
          <p className="text-[11px] text-muted-foreground mb-6 font-mono">{shortAddr(wallets[0].qtsAddress)}</p>
        )}
        <PinInput value={pin} onChange={setPin} />
        <ErrorBanner msg={error} />
        <div className="w-full mt-6">
          <Btn onClick={handleUnlock} disabled={pin.length !== 6 || loading}>
            {loading ? <><Spinner /> Unlocking...</> : <><Lock className="w-4 h-4" />Unlock Wallet</>}
          </Btn>
        </div>
      </div>
    </div>
  )

  // ══════════════════════════════════════════════════════
  // ── CREATE WALLET ──
  // ══════════════════════════════════════════════════════
  if (screen === 'create-pin') return (
    <div className="h-[600px] flex flex-col">
      <Header title="Create Wallet" onBack={() => setScreen('welcome')} />
      <div className="flex-1 px-6 py-6 space-y-5">
        <div className="text-center">
          <Lock className="w-12 h-12 mx-auto mb-3 text-purple-500" />
          <h2 className="text-lg font-bold mb-1">Set Your PIN</h2>
          <p className="text-muted-foreground text-xs">Choose a 6-digit PIN to encrypt your wallet</p>
        </div>
        <div className="space-y-3">
          <div><label className="text-sm font-medium mb-1 block">PIN Code</label><PinInput value={pin} onChange={setPin} /></div>
          <div><label className="text-sm font-medium mb-1 block">Confirm PIN</label><PinInput value={confirmPin} onChange={setConfirmPin} /></div>
        </div>
        {pin && confirmPin && pin !== confirmPin && <p className="text-xs text-red-500 text-center">PINs do not match</p>}
        <ErrorBanner msg={error} />
        <Btn onClick={handleCreateWallet}
          disabled={!pin || !confirmPin || pin !== confirmPin || pin.length !== 6 || loading}>
          {loading ? <><Spinner /> Creating...</> : <><CheckCircle className="w-4 h-4" />Create Wallet</>}
        </Btn>
        <div className="flex items-center gap-2 p-3 rounded-lg bg-blue-500/10 border border-blue-500/20">
          <Shield className="w-4 h-4 text-blue-500 shrink-0" />
          <p className="text-[11px] text-muted-foreground">Your keys are encrypted with AES-256-GCM and stored locally. The server never sees your PIN.</p>
        </div>
      </div>
    </div>
  )

  // ══════════════════════════════════════════════════════
  // ── IMPORT WALLET ──
  // ══════════════════════════════════════════════════════
  if (screen === 'import') return (
    <div className="h-[600px] flex flex-col">
      <Header title="Import Wallet" onBack={() => setScreen('welcome')} />
      <div className="flex-1 px-6 py-6 space-y-5 overflow-y-auto">
        <div className="text-center">
          <Download className="w-12 h-12 mx-auto mb-3 text-purple-500" />
          <h2 className="text-lg font-bold mb-1">Import Secret Key</h2>
          <p className="text-muted-foreground text-xs">Paste your Dilithium-3 secret key (8000 hex chars)</p>
        </div>
        <div>
          <label className="text-sm font-medium mb-1 block">Secret Key (hex)</label>
          <textarea
            placeholder="Paste your secret key hex..."
            value={importSecretKey}
            onChange={(e) => setImportSecretKey(e.target.value.trim())}
            className="w-full h-24 px-3 py-2 rounded-xl bg-muted border border-border focus:border-purple-500 focus:outline-none text-xs font-mono resize-none"
          />
          <p className="text-[10px] text-muted-foreground mt-1">{importSecretKey.length}/8000 characters</p>
        </div>
        <div><label className="text-sm font-medium mb-1 block">PIN Code (6 digits)</label><PinInput value={pin} onChange={setPin} /></div>
        <ErrorBanner msg={error} />
        <Btn onClick={handleImportWallet}
          disabled={importSecretKey.length !== 8000 || pin.length !== 6 || loading}>
          {loading ? <><Spinner /> Importing...</> : <><Download className="w-4 h-4" />Import Wallet</>}
        </Btn>
      </div>
    </div>
  )

  // ══════════════════════════════════════════════════════
  // ── SEND ──
  // ══════════════════════════════════════════════════════
  if (screen === 'send') return (
    <div className="h-[600px] flex flex-col">
      <Header title="Send" onBack={() => { setScreen('main'); setTxHash(''); setError('') }} />
      <div className="flex-1 px-4 py-4 space-y-4 overflow-y-auto">
        {txHash ? (
          <div className="space-y-4">
            <div className="p-6 rounded-xl bg-green-500/10 border border-green-500/20 text-center">
              <CheckCircle className="w-12 h-12 mx-auto mb-3 text-green-500" />
              <h3 className="text-lg font-bold">Transaction Sent!</h3>
            </div>
            <div className="p-3 rounded-lg bg-muted/30">
              <p className="text-[11px] text-muted-foreground mb-1">Transaction Hash</p>
              <div className="flex items-center gap-2">
                <p className="text-[10px] font-mono truncate flex-1">{txHash}</p>
                <button onClick={() => navigator.clipboard.writeText(txHash)} className="shrink-0 hover:text-foreground">
                  <Copy className="w-3 h-3" />
                </button>
              </div>
            </div>
            <Btn onClick={() => { setTxHash(''); setScreen('main'); if (activeAddress) fetchBalance(activeAddress) }}>
              Done
            </Btn>
          </div>
        ) : (
          <>
            <div><label className="text-sm font-medium mb-1.5 block">Token</label>
              <select value={sendToken} onChange={(e) => setSendToken(e.target.value as 'QTS' | 'QTEST')}
                className="w-full h-11 px-3 rounded-xl bg-muted border border-border focus:border-purple-500 focus:outline-none text-sm">
                <option value="QTEST">QTEST ({balanceData?.qtest_balance_formatted || '0'})</option>
                <option value="QTS">QTS ({balanceData?.balance_formatted || '0'})</option>
              </select>
            </div>
            <div><label className="text-sm font-medium mb-1.5 block">Recipient</label>
              <input placeholder="QTS:hex... or qts1..." value={sendAddress} onChange={(e) => setSendAddress(e.target.value)}
                className="w-full h-11 px-3 rounded-xl bg-muted border border-border focus:border-purple-500 focus:outline-none text-sm font-mono" />
            </div>
            <div><label className="text-sm font-medium mb-1.5 block">Amount</label>
              <input type="number" placeholder="0.0" value={sendAmount} onChange={(e) => setSendAmount(e.target.value)}
                className="w-full h-11 px-3 rounded-xl bg-muted border border-border focus:border-purple-500 focus:outline-none text-sm" />
            </div>
            <ErrorBanner msg={error} />
            <div className="flex items-center gap-2 p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
              <Zap className="w-4 h-4 text-yellow-500 shrink-0" />
              <p className="text-[11px]"><span className="font-semibold">Gasless</span> — powered by Quantos</p>
            </div>
            <Btn onClick={handleSend}
              disabled={!sendAddress || !sendAmount || parseFloat(sendAmount) <= 0 || loading}>
              {loading ? <><Spinner /> Sending...</> : <><Send className="w-4 h-4" />Send {sendToken}</>}
            </Btn>
          </>
        )}
      </div>
    </div>
  )

  // ══════════════════════════════════════════════════════
  // ── RECEIVE ──
  // ══════════════════════════════════════════════════════
  if (screen === 'receive') return (
    <div className="h-[600px] flex flex-col">
      <Header title="Receive" onBack={() => setScreen('main')} />
      <div className="flex-1 px-4 py-6 flex flex-col items-center">
        <div className="p-4 bg-white rounded-xl mb-4">
          <div className="w-40 h-40 bg-gradient-to-br from-purple-200 to-cyan-200 rounded-lg flex items-center justify-center">
            <Wallet className="w-10 h-10 text-purple-600" />
          </div>
        </div>
        <p className="text-sm text-muted-foreground mb-4">Copy your address to receive tokens</p>
        <div className="w-full space-y-3">
          <div><label className="text-sm font-medium mb-1.5 block">Your Address (hex)</label>
            <div className="flex gap-2">
              <input value={formatQtsAddr(activeAddress || '')} readOnly className="flex-1 h-11 px-3 rounded-xl bg-muted border border-border text-[10px] font-mono" />
              <button onClick={() => navigator.clipboard.writeText(formatQtsAddr(activeAddress || ''))}
                className="h-11 w-11 rounded-xl border border-border hover:bg-muted/50 flex items-center justify-center">
                <Copy className="w-4 h-4" />
              </button>
            </div>
          </div>
          {balanceData?.qts_address && (
            <div><label className="text-sm font-medium mb-1.5 block">Your Address (bech32)</label>
              <div className="flex gap-2">
                <input value={balanceData.qts_address} readOnly className="flex-1 h-11 px-3 rounded-xl bg-muted border border-border text-[10px] font-mono" />
                <button onClick={() => navigator.clipboard.writeText(balanceData.qts_address)}
                  className="h-11 w-11 rounded-xl border border-border hover:bg-muted/50 flex items-center justify-center">
                  <Copy className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </div>
        <div className="w-full mt-4 flex items-center gap-2 p-3 rounded-lg bg-blue-500/10 border border-blue-500/20">
          <Shield className="w-4 h-4 text-blue-500 shrink-0" />
          <p className="text-[11px] text-muted-foreground">Only send Quantos-compatible tokens to this address.</p>
        </div>
      </div>
    </div>
  )

  // ══════════════════════════════════════════════════════
  // ── FAUCET ──
  // ══════════════════════════════════════════════════════
  if (screen === 'faucet') return (
    <div className="h-[600px] flex flex-col">
      <Header title="QTEST Faucet" onBack={() => { setScreen('main'); setFaucetClaimed(false); setError(''); setFaucetTxHash('') }} />
      <div className="flex-1 px-4 py-4 space-y-4 overflow-y-auto">
        <div className="p-6 rounded-xl bg-gradient-to-br from-purple-500/10 to-cyan-500/10 border border-purple-500/20 text-center">
          <div className="text-4xl mb-2">🧪</div>
          <h3 className="text-2xl font-bold">1000 QTEST</h3>
          <p className="text-sm text-muted-foreground">Quantos Test Token</p>
        </div>
        <ErrorBanner msg={error} />
        {faucetClaimed && faucetTxHash ? (
          <div className="space-y-3">
            <Btn variant="green" disabled><CheckCircle className="w-4 h-4" />Claimed 1000 QTEST!</Btn>
            <div className="p-3 rounded-lg bg-muted/30">
              <p className="text-[11px] text-muted-foreground mb-1">Transaction Hash</p>
              <div className="flex items-center gap-2">
                <p className="text-[10px] font-mono truncate flex-1">{faucetTxHash}</p>
                <button onClick={() => navigator.clipboard.writeText(faucetTxHash)} className="shrink-0 hover:text-foreground">
                  <Copy className="w-3 h-3" />
                </button>
              </div>
            </div>
          </div>
        ) : (
          <Btn variant="blue" onClick={handleFaucetClaim} disabled={faucetClaiming}>
            {faucetClaiming ? <><Spinner />Claiming...</> : <><Droplet className="w-4 h-4" />Claim 1000 QTEST</>}
          </Btn>
        )}
        <div className="flex items-center gap-2 p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
          <Zap className="w-4 h-4 text-yellow-500 shrink-0" />
          <p className="text-[11px] text-muted-foreground"><span className="font-semibold text-foreground">On-chain faucet</span> — calls QTEST contract's claim()</p>
        </div>
      </div>
    </div>
  )

  // ══════════════════════════════════════════════════════
  // ── MAIN WALLET ──
  // ══════════════════════════════════════════════════════
  return (
    <div className="h-[600px] flex flex-col overflow-hidden">
      {/* Balance Header */}
      <div className="px-4 pt-5 pb-4 bg-gradient-to-b from-purple-500/10 to-transparent shrink-0">
        <div className="flex items-center gap-2 mb-3">
          <div className="w-8 h-8 rounded-full bg-gradient-to-br from-purple-500 to-cyan-500 flex items-center justify-center">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold">Quantos Wallet</p>
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <span className="truncate font-mono">{qtsAddr}</span>
              <button onClick={() => navigator.clipboard.writeText(formatQtsAddr(activeAddress || ''))} className="hover:text-foreground shrink-0">
                <Copy className="w-3 h-3" />
              </button>
            </div>
          </div>
          <button onClick={handleLock} className="p-1.5 rounded-lg hover:bg-muted" title="Lock wallet">
            <Lock className="w-4 h-4 text-muted-foreground" />
          </button>
        </div>
        <div className="mb-4">
          <p className="text-2xl font-bold gradient-text">{balanceData?.balance_formatted || '0 QTS'}</p>
        </div>
        <div className="grid grid-cols-3 gap-2">
          <button onClick={() => { setError(''); setTxHash(''); setScreen('send') }} className="h-10 rounded-xl text-xs font-semibold text-white bg-gradient-to-r from-purple-500 to-cyan-500 flex items-center justify-center gap-1.5">
            <Send className="w-3.5 h-3.5" />Send
          </button>
          <button onClick={() => setScreen('receive')} className="h-10 rounded-xl text-xs font-semibold border border-border hover:bg-muted/50 flex items-center justify-center gap-1.5">
            <ArrowDownLeft className="w-3.5 h-3.5" />Receive
          </button>
          <button onClick={() => { setError(''); setFaucetClaimed(false); setScreen('faucet') }} className="h-10 rounded-xl text-xs font-semibold border border-border hover:bg-muted/50 flex items-center justify-center gap-1.5">
            <Droplet className="w-3.5 h-3.5" />Faucet
          </button>
        </div>
      </div>

      {/* Scrollable content */}
      <div className="flex-1 overflow-y-auto px-4 pb-4 space-y-4">
        {/* Features */}
        <div className="grid grid-cols-3 gap-2 pt-2">
          {[
            { icon: Shield, color: 'text-green-500', label: 'PQ Secure', sub: 'Dilithium-3' },
            { icon: Zap, color: 'text-yellow-500', label: 'Gasless', sub: 'Sponsored' },
            { icon: Fingerprint, color: 'text-blue-500', label: 'PIN Auth', sub: 'AES-256' },
          ].map((f) => (
            <div key={f.label} className="p-2.5 rounded-lg bg-muted/30 text-center">
              <f.icon className={cn('w-4 h-4 mx-auto mb-1', f.color)} />
              <p className="text-[10px] font-medium">{f.label}</p>
              <p className="text-[9px] text-muted-foreground">{f.sub}</p>
            </div>
          ))}
        </div>

        {/* Assets */}
        <div>
          <h3 className="text-sm font-semibold mb-2">Assets</h3>
          <div className="rounded-xl border border-border overflow-hidden divide-y divide-border">
            <div className="flex items-center justify-between p-3 hover:bg-muted/30 transition-colors">
              <div className="flex items-center gap-2.5">
                <span className="text-xl">🧪</span>
                <div>
                  <p className="text-sm font-semibold">QTEST</p>
                  <p className="text-[11px] text-muted-foreground">Quantos test token</p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-sm font-semibold">{balanceData?.qtest_balance_formatted || '0 QTEST'}</p>
              </div>
            </div>
            <div className="flex items-center justify-between p-3 hover:bg-muted/30 transition-colors">
              <div className="flex items-center gap-2.5">
                <span className="text-xl">🟣</span>
                <div>
                  <p className="text-sm font-semibold">SQTEST</p>
                  <p className="text-[11px] text-muted-foreground">SQTEST Stablecoin</p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-sm font-semibold">{balanceData?.sqtest_balance_formatted || '0 SQTEST'}</p>
              </div>
            </div>
            <div className="flex items-center justify-between p-3 hover:bg-muted/30 transition-colors">
              <div className="flex items-center gap-2.5">
                <span className="text-xl">💎</span>
                <div>
                  <p className="text-sm font-semibold">QTS</p>
                  <p className="text-[11px] text-muted-foreground">Quantos Native</p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-sm font-semibold">{balanceData?.balance_formatted || '0 QTS'}</p>
              </div>
            </div>
            {balanceData?.stake_formatted && balanceData.stake_formatted !== '0.000000 QTS' && (
              <div className="flex items-center justify-between p-3 hover:bg-muted/30 transition-colors">
                <div className="flex items-center gap-2.5">
                  <span className="text-xl">🔒</span>
                  <div>
                    <p className="text-sm font-semibold">Staked</p>
                    <p className="text-[11px] text-muted-foreground">Locked in staking</p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-sm font-semibold">{balanceData.stake_formatted}</p>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* NFTs (QN8) */}
        <div>
          <h3 className="text-sm font-semibold mb-2">NFTs</h3>
          <div className="rounded-xl border border-border overflow-hidden p-4 text-center text-muted-foreground">
            <Sparkles className="w-6 h-6 mx-auto mb-2 opacity-50" />
            <p className="text-xs">No NFTs found</p>
            <p className="text-[10px] mt-1">QN8 NFTs you own will appear here</p>
          </div>
        </div>

        {/* Refresh */}
        <button
          onClick={() => { if (activeAddress) fetchBalance(activeAddress) }}
          className="w-full h-10 rounded-xl text-xs font-medium border border-border hover:bg-muted/50 flex items-center justify-center gap-1.5"
        >
          <Loader2 className="w-3.5 h-3.5" />Refresh Balance
        </button>
      </div>
    </div>
  )
}
