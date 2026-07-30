'use client';

import { createContext, useContext, useState, useCallback, type ReactNode } from 'react';

export type ChainKind = 'evm' | 'tron' | 'sui' | 'aptos' | 'solana' | 'near' | 'stellar' | 'bitcoinStacks' | 'canton' | 'icp';

interface Config {
  chainKind: ChainKind;
  rpcUrl: string;
  chainId: bigint;
  accountAddress: string;
  verifierAddress: string;
  oracleAddress: string;
  registryAddress: string;
}

const DEFAULT_CONFIG: Config = {
  chainKind: 'evm',
  rpcUrl: 'http://127.0.0.1:8545',
  chainId: 31337n,
  accountAddress: '',
  verifierAddress: '',
  oracleAddress: '',
  registryAddress: '',
};

interface ConfigContextValue {
  config: Config;
  setConfig: (partial: Partial<Config>) => void;
}

const ConfigContext = createContext<ConfigContextValue | null>(null);

export function ConfigProvider({ children }: { children: ReactNode }) {
  const [config, setConfigState] = useState<Config>(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('guardian-config');
      if (saved) {
        try {
          const parsed = JSON.parse(saved);
          return {
            ...DEFAULT_CONFIG,
            ...parsed,
            chainId: BigInt(parsed.chainId ?? '31337'),
          };
        } catch {}
      }
    }
    return DEFAULT_CONFIG;
  });

  const setConfig = useCallback((partial: Partial<Config>) => {
    setConfigState((prev) => {
      const next = { ...prev, ...partial };
      if (typeof window !== 'undefined') {
        localStorage.setItem(
          'guardian-config',
          JSON.stringify({ ...next, chainId: next.chainId.toString() })
        );
      }
      return next;
    });
  }, []);

  return (
    <ConfigContext.Provider value={{ config, setConfig }}>
      {children}
    </ConfigContext.Provider>
  );
}

export function useConfig() {
  const ctx = useContext(ConfigContext);
  if (!ctx) throw new Error('useConfig must be used within ConfigProvider');
  return ctx;
}
