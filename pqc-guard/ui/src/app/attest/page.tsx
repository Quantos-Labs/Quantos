'use client';

import { useState } from 'react';
import { PageHeader, Button, CopyableField, ErrorBanner, SuccessBanner } from '@/components/ui';
import { genKeypair, pqcSign, authorizationDigest, digestForChain, Attestor, merkleRoot, requestAttestation, encodeAttestationCanonicalHex, type DemoResult } from '@/lib/sdk';
import { useContracts } from '@/lib/contracts';
import { shortenHash } from '@/lib/utils';
import { PenTool, CheckCircle2, XCircle } from 'lucide-react';
import { randomBytes } from '@noble/hashes/utils';
import { hexlify } from 'ethers';

interface AttestorState {
  attestor: Attestor;
  id: string;
  wotsRoot: string;
  leafIndex: number;
  signed: boolean;
  result?: { leafIndex: number; wotsSig: string[]; merklePath: string[] };
}

export default function AttestPage() {
  const { config } = useContracts();
  const [attestors, setAttestors] = useState<AttestorState[]>([]);
  const [digest, setDigest] = useState('');
  const [pqcPubKey, setPqcPubKey] = useState<Uint8Array | null>(null);
  const [pqcSig, setPqcSig] = useState<Uint8Array | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const setupAttestors = () => {
    const list: AttestorState[] = [];
    for (let i = 0; i < 3; i++) {
      const id = hexlify(randomBytes(32));
      const seed = hexlify(randomBytes(32));
      const att = new Attestor({ id, seed, height: 3 });
      list.push({ attestor: att, id, wotsRoot: att.wotsRoot, leafIndex: 0, signed: false });
    }
    setAttestors(list);
    setError(null);
  };

  const computeDigest = () => {
    const kp = genKeypair();
    setPqcPubKey(kp.publicKey);
    const commitment = '0x' + Buffer.from(
      Array.from({ length: 32 }, (_, i) =>
        i < kp.publicKey.length ? kp.publicKey[i] : 0
      )
    ).toString('hex');
    const d = (config.chainKind === 'evm' || config.chainKind === 'tron')
      ? authorizationDigest({
          account: commitment,
          to: '0x000000000000000000000000000000000000bEEF',
          value: 1n,
          data: '0x',
          nonce: 0n,
          chainId: config.chainId,
        })
      : digestForChain(config.chainKind, {
          account: commitment,
          to: '0x000000000000000000000000000000000000bEEF',
          value: 1n,
          data: '0x',
          nonce: 0n,
          chainId: config.chainId,
        });
    setDigest(d);
    const msg = Buffer.from(d.replace(/^0x/, ''), 'hex');
    const sig = pqcSign(kp.secretKey, msg);
    setPqcSig(sig);
  };

  const signWithAttestor = (idx: number) => {
    if (!pqcPubKey || !pqcSig || !digest) { setError('Generate digest first'); return; }
    setError(null);
    try {
      const state = attestors[idx];
      const result = state.attestor.attest({
        pqcPublicKey: pqcPubKey,
        pqcMessage: Buffer.from(digest.replace(/^0x/, ''), 'hex'),
        pqcSignature: pqcSig,
        digest,
      });
      setAttestors((prev) => prev.map((s, i) =>
        i === idx ? { ...s, signed: true, result, leafIndex: result.leafIndex } : s
      ));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const buildAttestation = () => {
    const signed = attestors.filter((s) => s.signed && s.result);
    if (signed.length < 2) { setError('Need at least 2 attestors signed'); return; }
    setError(null);
    setSuccess(null);
    try {
      const leaves = attestors.map((s) => s.attestor.setLeaf());
      const result = requestAttestation({
        attestors: signed.map((s) => s.attestor),
        finalizedLeaves: leaves,
        pqcPublicKey: pqcPubKey!,
        pqcSignature: pqcSig!,
        pqcMessage: Buffer.from(digest.replace(/^0x/, ''), 'hex'),
        digest,
      });
      const canonicalHex = encodeAttestationCanonicalHex(result.proofs);
      const chainLabel = config.chainKind === 'evm' ? 'ABI' : `${config.chainKind} canonical`;
      setSuccess(`Attestation built (${chainLabel}): ${result.proofs.length} proofs, ABI=${(result.attestation.length - 2) / 2} bytes, canonical=${(canonicalHex.length - 2) / 2} bytes`);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div>
      <PageHeader
        title="Attestor Signing"
        description="Simulate the off-chain attestor flow: verify SLH-DSA signature, then sign the digest with a WOTS one-time leaf."
      />

      <ErrorBanner message={error} />
      <SuccessBanner message={success} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card space-y-4">
          <h2 className="font-semibold flex items-center gap-2">
            <PenTool className="w-4 h-4 text-accent" />
            Step 1: Prepare Digest
          </h2>
          <p className="text-sm text-muted">
            Generate a PQC keypair and compute the authorization digest for a sample transaction.
          </p>
          <Button onClick={computeDigest}>Generate Key & Digest</Button>
          {digest && (
            <CopyableField label="Authorization Digest" value={digest} />
          )}
        </div>

        <div className="card space-y-4">
          <h2 className="font-semibold">Step 2: Setup Attestors</h2>
          <p className="text-sm text-muted">
            Spin up 3 mock Quantos validators with WOTS trees (height 3 = 8 one-time leaves each).
          </p>
          <Button onClick={setupAttestors} variant="ghost">Initialize 3 Attestors</Button>
          {attestors.length > 0 && (
            <div className="space-y-2">
              {attestors.map((s, i) => (
                <div key={i} className="flex items-center justify-between rounded-lg bg-bg-input border border-border px-3 py-2">
                  <div className="text-xs">
                    <div className="font-mono">{shortenHash(s.id, 6)}</div>
                    <div className="text-muted">WOTS root: {shortenHash(s.wotsRoot, 6)}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    {s.signed ? (
                      <span className="badge-ok"><CheckCircle2 className="w-3 h-3" /> Signed (leaf {s.leafIndex})</span>
                    ) : (
                      <button onClick={() => signWithAttestor(i)} className="btn-ghost text-xs px-2 py-1">
                        Sign
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {attestors.some((s) => s.signed) && (
        <div className="card mt-6 space-y-4">
          <h2 className="font-semibold">Step 3: Build Attestation</h2>
          <p className="text-sm text-muted">
            Combine the signed WOTS proofs into an ABI-encoded attestation blob ready for on-chain submission.
          </p>
          <Button onClick={buildAttestation}>Build M-of-N Attestation</Button>
        </div>
      )}
    </div>
  );
}
