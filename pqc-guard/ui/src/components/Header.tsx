'use client';

import { useState } from 'react';
import { Settings, X, Wallet, LogOut, ChevronDown } from 'lucide-react';
import { useConfig, type ChainKind } from '@/lib/config';
import { useWallet } from '@/lib/wallet';
import { shortenHash } from '@/lib/utils';
import { CHAIN_IDS } from '@/lib/sdk';

const CHAINS: { kind: ChainKind; label: string; color: string }[] = [
  { kind: 'evm', label: 'EVM', color: '#627eea' },
  { kind: 'tron', label: 'Tron', color: '#ff060a' },
  { kind: 'sui', label: 'Sui', color: '#4da2ff' },
  { kind: 'aptos', label: 'Aptos', color: '#06d6a0' },
  { kind: 'solana', label: 'Solana', color: '#9945ff' },
  { kind: 'near', label: 'NEAR', color: '#00ec97' },
  { kind: 'stellar', label: 'Stellar', color: '#7d00ff' },
  { kind: 'bitcoinStacks', label: 'Bitcoin/Stacks', color: '#f7931a' },
  { kind: 'canton', label: 'Canton', color: '#0a8d80' },
  { kind: 'icp', label: 'ICP', color: '#3b00f6' },
];

export function Header() {
  const { config, setConfig } = useConfig();
  const { address, connect, disconnect, connecting, error: walletError } = useWallet();
  const [open, setOpen] = useState(false);
  const [chainOpen, setChainOpen] = useState(false);

  const currentChain = CHAINS.find((c) => c.kind === config.chainKind) ?? CHAINS[0];

  const selectChain = (kind: ChainKind) => {
    setConfig({ chainKind: kind });
    if (kind !== 'evm' && kind !== 'tron') {
      setConfig({ chainId: CHAIN_IDS[kind as keyof typeof CHAIN_IDS] });
    }
    setChainOpen(false);
  };

  return (
    <>
      <header className="h-14 border-b border-border bg-bg-card flex items-center justify-between px-4 md:px-6">
        <div className="flex items-center gap-3">
          {config.accountAddress ? (
            <span className="badge-muted font-mono">
              {shortenHash(config.accountAddress, 8)}
            </span>
          ) : (
            <span className="badge-warn">No account set</span>
          )}
          {config.verifierAddress && (
            <span className="badge-muted font-mono hidden sm:inline-flex">
              Verifier: {shortenHash(config.verifierAddress, 4)}
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          <div className="relative">
            <button
              onClick={() => setChainOpen((v) => !v)}
              className="flex items-center gap-2 rounded-lg border border-border bg-bg-input px-3 py-1.5 text-sm hover:border-accent/50 transition-colors"
            >
              <span
                className="w-2 h-2 rounded-full"
                style={{ backgroundColor: currentChain.color }}
              />
              <span className="font-medium">{currentChain.label}</span>
              <ChevronDown className="w-3 h-3 text-muted" />
            </button>
            {chainOpen && (
              <>
                <div className="fixed inset-0 z-40" onClick={() => setChainOpen(false)} />
                <div className="absolute right-0 top-full mt-1 z-50 w-44 rounded-lg border border-border bg-bg-card shadow-xl py-1">
                  {CHAINS.map((c) => (
                    <button
                      key={c.kind}
                      onClick={() => selectChain(c.kind)}
                      className={`flex items-center gap-2 w-full px-3 py-2 text-sm hover:bg-bg-input transition-colors ${
                        c.kind === config.chainKind ? 'text-accent' : ''
                      }`}
                    >
                      <span
                        className="w-2 h-2 rounded-full"
                        style={{ backgroundColor: c.color }}
                      />
                      <span className="font-medium">{c.label}</span>
                      {c.kind !== 'evm' && c.kind !== 'tron' && (
                        <span className="text-xs text-muted ml-auto">
                          {CHAIN_IDS[c.kind as keyof typeof CHAIN_IDS].toString(16).slice(0, 6)}…
                        </span>
                      )}
                      {(c.kind === 'evm' || c.kind === 'tron') && (
                        <span className="text-xs text-muted ml-auto">
                          {config.chainId.toString()}
                        </span>
                      )}
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>
          {walletError && (
            <span className="text-xs text-err hidden md:inline">{walletError}</span>
          )}
          {address ? (
            <div className="flex items-center gap-2">
              <span className="badge-ok font-mono">
                {shortenHash(address, 6)}
              </span>
              <button onClick={disconnect} className="btn-ghost px-2" title="Disconnect">
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <button onClick={connect} disabled={connecting} className="btn-primary">
              <Wallet className="w-4 h-4" />
              <span>{connecting ? 'Connecting...' : 'Connect Wallet'}</span>
            </button>
          )}
          <button
            onClick={() => setOpen(true)}
            className="btn-ghost"
          >
            <Settings className="w-4 h-4" />
            <span className="hidden sm:inline">Settings</span>
          </button>
        </div>
      </header>

      {open && (
        <div
          className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4"
          onClick={() => setOpen(false)}
        >
          <div
            className="card w-full max-w-lg space-y-4"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold">Configuration</h2>
              <button onClick={() => setOpen(false)} className="text-muted hover:text-gray-200">
                <X className="w-5 h-5" />
              </button>
            </div>
            <p className="text-xs text-muted">
              Set the contract addresses and RPC endpoint. Values are saved to localStorage.
            </p>
            <div>
              <label className="label">RPC URL</label>
              <input
                className="input"
                value={config.rpcUrl}
                onChange={(e) => setConfig({ rpcUrl: e.target.value })}
                placeholder="http://127.0.0.1:8545"
              />
            </div>
            <div>
              <label className="label">Chain ID</label>
              <input
                className="input"
                value={config.chainId.toString()}
                onChange={(e) => {
                  try { setConfig({ chainId: BigInt(e.target.value) }); } catch {}
                }}
                placeholder="31337"
              />
            </div>
            <div>
              <label className="label">Guardian Account Address</label>
              <input
                className="input font-mono"
                value={config.accountAddress}
                onChange={(e) => setConfig({ accountAddress: e.target.value })}
                placeholder="0x..."
              />
            </div>
            <div>
              <label className="label">StakeAttestationVerifier Address</label>
              <input
                className="input font-mono"
                value={config.verifierAddress}
                onChange={(e) => setConfig({ verifierAddress: e.target.value })}
                placeholder="0x..."
              />
            </div>
            <div>
              <label className="label">QuantosAttestorOracle Address</label>
              <input
                className="input font-mono"
                value={config.oracleAddress}
                onChange={(e) => setConfig({ oracleAddress: e.target.value })}
                placeholder="0x..."
              />
            </div>
            <div>
              <label className="label">AttestorRegistry Address</label>
              <input
                className="input font-mono"
                value={config.registryAddress}
                onChange={(e) => setConfig({ registryAddress: e.target.value })}
                placeholder="0x..."
              />
            </div>
            <button onClick={() => setOpen(false)} className="btn-primary w-full">
              Save & Close
            </button>
          </div>
        </div>
      )}
    </>
  );
}
