'use client';

import { randomBytes } from '@noble/hashes/utils';
import { hexlify, keccak256 } from 'ethers';
import { genKeypair, pqcSign, computeCommitment } from '@sdk/pqc';
import { Attestor } from '@sdk/attestor';
import { authorizationDigest, requestAttestation, buildMigration } from '@sdk/account';
import { merkleRoot } from '@sdk/merkle';
import {
  encodeAttestationCanonical,
  encodeAttestationCanonicalHex,
  digestForChain,
  normalizeTo,
  canonicalDigest,
  CHAIN_IDS,
  type ChainKind as SdkChainKind,
} from '@sdk/canonical';

function rand32(): string {
  return hexlify(randomBytes(32));
}

export interface DemoResult {
  commitment: string;
  pqcPublicKeyHex: string;
  setRoot: string;
  digest: string;
  pqcSignatureBytes: number;
  attestationBytes: number;
  attestation: string;
  canonicalAttestation: string;
  proofs: ReturnType<typeof requestAttestation>['proofs'];
}

export interface DemoConfig {
  numAttestors: number;
  threshold: number;
  treeHeight: number;
  to: string;
  value: bigint;
  data: string;
  nonce: bigint;
  chainId: bigint;
  chainKind?: SdkChainKind;
}

export function runFullDemo(cfg: DemoConfig): DemoResult {
  const kp = genKeypair();
  const { commitment, pqcPublicKeyHex } = buildMigration(kp.publicKey);

  const attestors: Attestor[] = [];
  for (let i = 0; i < cfg.numAttestors; i++) {
    attestors.push(new Attestor({ id: rand32(), seed: rand32(), height: cfg.treeHeight }));
  }
  const finalizedLeaves = attestors.map((a) => a.setLeaf());
  const setRoot = merkleRoot(finalizedLeaves);

  const chainKind = cfg.chainKind ?? 'evm';
  const digest = (chainKind === 'evm' || chainKind === 'tron')
    ? authorizationDigest({
        account: commitment,
        to: cfg.to,
        value: cfg.value,
        data: cfg.data,
        nonce: cfg.nonce,
        chainId: cfg.chainId,
      })
    : digestForChain(chainKind, {
        account: commitment,
        to: cfg.to,
        value: cfg.value,
        data: cfg.data,
        nonce: cfg.nonce,
        chainId: cfg.chainId,
      });

  const pqcMessage = Buffer.from(digest.replace(/^0x/, ''), 'hex');
  const pqcSignature = pqcSign(kp.secretKey, pqcMessage);

  const { attestation, proofs } = requestAttestation({
    attestors: attestors.slice(0, cfg.threshold),
    finalizedLeaves,
    pqcPublicKey: kp.publicKey,
    pqcSignature,
    pqcMessage,
    digest,
  });

  const canonicalHex = encodeAttestationCanonicalHex(proofs);

  return {
    commitment,
    pqcPublicKeyHex,
    setRoot,
    digest,
    pqcSignatureBytes: pqcSignature.length,
    attestationBytes: (attestation.length - 2) / 2,
    attestation,
    canonicalAttestation: canonicalHex,
    proofs,
  };
}

export { genKeypair, pqcSign, computeCommitment, buildMigration, authorizationDigest, requestAttestation };
export { Attestor, merkleRoot };
export { keccak256 };
export { encodeAttestationCanonical, encodeAttestationCanonicalHex, digestForChain, normalizeTo, canonicalDigest, CHAIN_IDS };
export type { SdkChainKind };
