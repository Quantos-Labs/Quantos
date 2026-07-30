'use client';

import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from 'react';
import { BrowserProvider, type JsonRpcSigner } from 'ethers';

interface WalletState {
  address: string | null;
  signer: JsonRpcSigner | null;
  connecting: boolean;
  error: string | null;
}

interface WalletContextValue extends WalletState {
  connect: () => Promise<void>;
  disconnect: () => void;
}

const WalletContext = createContext<WalletContextValue | null>(null);

export function WalletProvider({ children }: { children: ReactNode }) {
  const [address, setAddress] = useState<string | null>(null);
  const [signer, setSigner] = useState<JsonRpcSigner | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const connect = useCallback(async () => {
    if (typeof window === 'undefined' || !window.ethereum) {
      setError('MetaMask not found. Install it or use a browser with wallet support.');
      return;
    }
    setConnecting(true);
    setError(null);
    try {
      const provider = new BrowserProvider(window.ethereum as never);
      await provider.send('eth_requestAccounts', []);
      const s = await provider.getSigner();
      const addr = await s.getAddress();
      setSigner(s);
      setAddress(addr);
    } catch (e: unknown) {
      const err = e as { code?: number; message?: string };
      if (err.code === 4001) {
        setError('Connection rejected. Please approve the MetaMask request.');
      } else if (err.code === -32002) {
        setError('MetaMask request pending. Check the MetaMask extension popup.');
      } else if (err.message?.includes('Failed to connect')) {
        setError('MetaMask connection failed. Make sure MetaMask is unlocked and try again.');
      } else {
        setError(err.message ?? String(e));
      }
    } finally {
      setConnecting(false);
    }
  }, []);

  const disconnect = useCallback(() => {
    setAddress(null);
    setSigner(null);
    setError(null);
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined' || !window.ethereum) return;
    const handler = (...args: unknown[]) => {
      const accounts = args[0] as string[];
      if (accounts.length === 0) {
        disconnect();
      } else if (accounts[0] !== address) {
        connect();
      }
    };
    window.ethereum.on?.('accountsChanged', handler);
    return () => {
      window.ethereum?.removeListener?.('accountsChanged', handler);
    };
  }, [address, connect, disconnect]);

  return (
    <WalletContext.Provider value={{ address, signer, connecting, error, connect, disconnect }}>
      {children}
    </WalletContext.Provider>
  );
}

export function useWallet() {
  const ctx = useContext(WalletContext);
  if (!ctx) throw new Error('useWallet must be used within WalletProvider');
  return ctx;
}
