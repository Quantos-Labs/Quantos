'use client';

import { useCallback } from 'react';
import { JsonRpcProvider, Contract, type JsonRpcSigner } from 'ethers';
import { useConfig } from './config';
import { useWallet } from './wallet';
import {
  PQCGUARD_ACCOUNT_ABI,
  ATTESTOR_REGISTRY_ABI,
  STAKE_ATTESTATION_VERIFIER_ABI,
  QUANTOS_ATTESTOR_ORACLE_ABI,
} from './abis';

export function useContracts() {
  const { config } = useConfig();
  const { signer } = useWallet();

  const getProvider = useCallback((): JsonRpcProvider => {
    return new JsonRpcProvider(config.rpcUrl);
  }, [config.rpcUrl]);

  const getSigner = useCallback((): JsonRpcSigner | null => {
    return signer;
  }, [signer]);

  const getAccount = useCallback((): Contract | null => {
    if (!config.accountAddress) return null;
    return new Contract(config.accountAddress, PQCGUARD_ACCOUNT_ABI, signer ?? getProvider());
  }, [config.accountAddress, signer, getProvider]);

  const getRegistry = useCallback((): Contract | null => {
    if (!config.registryAddress) return null;
    return new Contract(config.registryAddress, ATTESTOR_REGISTRY_ABI, signer ?? getProvider());
  }, [config.registryAddress, signer, getProvider]);

  const getVerifier = useCallback((): Contract | null => {
    if (!config.verifierAddress) return null;
    return new Contract(config.verifierAddress, STAKE_ATTESTATION_VERIFIER_ABI, signer ?? getProvider());
  }, [config.verifierAddress, signer, getProvider]);

  const getOracle = useCallback((): Contract | null => {
    if (!config.oracleAddress) return null;
    return new Contract(config.oracleAddress, QUANTOS_ATTESTOR_ORACLE_ABI, signer ?? getProvider());
  }, [config.oracleAddress, signer, getProvider]);

  return { getProvider, getSigner, getAccount, getRegistry, getVerifier, getOracle, config };
}
