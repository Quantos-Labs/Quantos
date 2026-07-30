'use client';

import { useState } from 'react';
import { PageHeader, Button, CopyableField, ErrorBanner, SuccessBanner } from '@/components/ui';
import { runFullDemo, authorizationDigest, digestForChain, type DemoResult } from '@/lib/sdk';
import { useContracts } from '@/lib/contracts';
import { useConfig } from '@/lib/config';
import { shortenHash } from '@/lib/utils';
import { Send, Zap, FileCode } from 'lucide-react';

export default function ExecutePage() {
  const { getAccount, getVerifier, config } = useContracts();
  const [to, setTo] = useState('0x000000000000000000000000000000000000bEEF');
  const [value, setValue] = useState('1000000000000000000');
  const [data, setData] = useState('0x');
  const [attestation, setAttestation] = useState('');
  const [demoResult, setDemoResult] = useState<DemoResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);

  const generateAttestation = () => {
    setGenerating(true);
    setError(null);
    try {
      const result = runFullDemo({
        numAttestors: 3,
        threshold: 2,
        treeHeight: 3,
        to,
        value: BigInt(value),
        data,
        nonce: 0n,
        chainId: config.chainId,
        chainKind: config.chainKind,
      });
      setDemoResult(result);
      setAttestation(result.attestation);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setGenerating(false);
    }
  };

  const execute = async () => {
    const acct = getAccount();
    if (!acct) { setError('No account address configured'); return; }
    setLoading(true);
    setError(null);
    setSuccess(null);
    try {
      const tx = await acct.execute(to, BigInt(value), data, attestation);
      await tx.wait();
      setSuccess('Transaction executed successfully!');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  const verifyOffChain = () => {
    const verifier = getVerifier();
    if (!verifier) { setError('No verifier address configured'); return; }
    if (!demoResult) return;
    setError(null);
    setSuccess(null);
    verifier.verifyAuthorization(
      demoResult.commitment,
      to,
      BigInt(value),
      data,
      0n,
      attestation
    ).then((ok: boolean) => {
      if (ok) setSuccess('Off-chain verification: PASS');
      else setError('Off-chain verification: FAIL');
    }).catch((e: unknown) => {
      setError(e instanceof Error ? e.message : String(e));
    });
  };

  return (
    <div>
      <PageHeader
        title="Execute"
        description="Submit a transaction authorized by a post-quantum attestation. Anyone can relay."
      />

      <ErrorBanner message={error} />
      <SuccessBanner message={success} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card space-y-4">
          <h2 className="font-semibold flex items-center gap-2">
            <Send className="w-4 h-4 text-accent" />
            Transaction
          </h2>
          <div>
            <label className="label">To Address</label>
            <input className="input font-mono" value={to} onChange={(e) => setTo(e.target.value)} />
          </div>
          <div>
            <label className="label">Value (wei)</label>
            <input className="input font-mono" value={value} onChange={(e) => setValue(e.target.value)} />
          </div>
          <div>
            <label className="label">Calldata (hex)</label>
            <input className="input font-mono" value={data} onChange={(e) => setData(e.target.value)} />
          </div>
        </div>

        <div className="card space-y-4">
          <h2 className="font-semibold flex items-center gap-2">
            <Zap className="w-4 h-4 text-accent" />
            Generate Attestation (Demo)
          </h2>
          <p className="text-sm text-muted">
            Runs the full off-chain flow: generate SLH-DSA key, spin up mock attestors, sign with SLH-DSA, produce WOTS attestation.
          </p>
          <Button onClick={generateAttestation} loading={generating}>Generate Attestation</Button>
          {demoResult && (
            <div className="space-y-2 text-xs">
              <div className="flex justify-between"><span className="text-muted">PQC Commitment:</span><code className="font-mono">{shortenHash(demoResult.commitment, 8)}</code></div>
              <div className="flex justify-between"><span className="text-muted">Set Root:</span><code className="font-mono">{shortenHash(demoResult.setRoot, 8)}</code></div>
              <div className="flex justify-between"><span className="text-muted">Digest:</span><code className="font-mono">{shortenHash(demoResult.digest, 8)}</code></div>
              <div className="flex justify-between"><span className="text-muted">SLH-DSA sig:</span><span>{demoResult.pqcSignatureBytes} bytes</span></div>
              <div className="flex justify-between"><span className="text-muted">Attestation:</span><span>{demoResult.attestationBytes} bytes</span></div>
              <div className="flex justify-between"><span className="text-muted">Proofs:</span><span>{demoResult.proofs.length}</span></div>
            </div>
          )}
        </div>
      </div>

      {attestation && (
        <div className="card mt-6 space-y-4">
          <h2 className="font-semibold flex items-center gap-2">
            <FileCode className="w-4 h-4 text-accent" />
            Attestation Blob
          </h2>
          <CopyableField label="ABI-encoded AttestorProof[] (EVM/Tron)" value={attestation} />
          {demoResult && config.chainKind !== 'evm' && config.chainKind !== 'tron' && (
            <CopyableField
              label={`Canonical Binary (${config.chainKind})`}
              value={demoResult.canonicalAttestation}
            />
          )}
          <div className="flex gap-3">
            {(config.chainKind === 'evm' || config.chainKind === 'tron') && (
              <Button onClick={verifyOffChain} variant="ghost">Verify (on-chain view)</Button>
            )}
            {(config.chainKind === 'evm' || config.chainKind === 'tron') && (
              <Button onClick={execute} loading={loading}>Execute Transaction</Button>
            )}
            {config.chainKind !== 'evm' && config.chainKind !== 'tron' && (
              <p className="text-sm text-muted">
                On-chain submission for {config.chainKind} requires the native chain wallet adapter
                (not yet integrated). The canonical blob above is ready for the target VM's verifier.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
