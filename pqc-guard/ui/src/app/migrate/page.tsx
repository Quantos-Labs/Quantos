'use client';

import { useState } from 'react';
import { PageHeader, Button, CopyableField, ErrorBanner, SuccessBanner } from '@/components/ui';
import { genKeypair, computeCommitment, buildMigration } from '@/lib/sdk';
import { useContracts } from '@/lib/contracts';
import { shortenHash, timeRemaining } from '@/lib/utils';
import { KeyRound, Clock, XCircle, CheckCircle2 } from 'lucide-react';

export default function MigratePage() {
  const { getAccount, config } = useContracts();
  const [pubKeyHex, setPubKeyHex] = useState('');
  const [commitment, setCommitment] = useState('');
  const [verifier, setVerifier] = useState('');
  const [guardians, setGuardians] = useState('');
  const [threshold, setThreshold] = useState('2');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [pendingCommit, setPendingCommit] = useState('');
  const [commitTime, setCommitTime] = useState(0n);
  const [migrated, setMigrated] = useState(false);

  const generateKey = () => {
    const kp = genKeypair();
    const { commitment: c, pqcPublicKeyHex } = buildMigration(kp.publicKey);
    setPubKeyHex(pqcPublicKeyHex);
    setCommitment(c);
    setError(null);
  };

  const commitMigration = async () => {
    const acct = getAccount();
    if (!acct) { setError('No account address configured'); return; }
    setLoading(true);
    setError(null);
    setSuccess(null);
    try {
      const guardianList = guardians.split(',').map((g) => g.trim()).filter(Boolean);
      if (guardianList.length === 0) throw new Error('At least one guardian required');
      const tx = await acct.migrate(
        commitment,
        verifier,
        guardianList,
        BigInt(threshold)
      );
      await tx.wait();
      setPendingCommit(commitment);
      const ct = await acct.migrationCommitTime();
      setCommitTime(ct);
      setSuccess('Migration committed. Wait 24h before finalizing.');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  const finalize = async () => {
    const acct = getAccount();
    if (!acct) { setError('No account address configured'); return; }
    setLoading(true);
    setError(null);
    setSuccess(null);
    try {
      const tx = await acct.finalizeMigration(pubKeyHex);
      await tx.wait();
      setMigrated(true);
      setSuccess('Migration finalized! Account is now Guardian-secured.');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  const cancel = async () => {
    const acct = getAccount();
    if (!acct) { setError('No account address configured'); return; }
    setLoading(true);
    setError(null);
    setSuccess(null);
    try {
      const tx = await acct.cancelMigration();
      await tx.wait();
      setPendingCommit('');
      setSuccess('Migration cancelled.');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <PageHeader
        title="Migration"
        description="Commit-delay-reveal: migrate from ECDSA to post-quantum (SLH-DSA) authorization."
      />

      <ErrorBanner message={error} />
      <SuccessBanner message={success} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card space-y-4">
          <h2 className="font-semibold flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-accent" />
            Step 1: Generate PQC Key
          </h2>
          <p className="text-sm text-muted">
            Generate an SLH-DSA (SHA2-128f) keypair. The commitment is keccak256(publicKey).
          </p>
          <Button onClick={generateKey} variant="ghost">Generate Key</Button>
          {pubKeyHex && (
            <div className="space-y-3">
              <CopyableField label="PQC Public Key" value={pubKeyHex} />
              <CopyableField label="Commitment (keccak256)" value={commitment} />
            </div>
          )}
        </div>

        <div className="card space-y-4">
          <h2 className="font-semibold flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-accent" />
            Step 2: Commit Migration
          </h2>
          <div>
            <label className="label">Verifier Address</label>
            <input className="input font-mono" value={verifier} onChange={(e) => setVerifier(e.target.value)} placeholder="0x..." />
          </div>
          <div>
            <label className="label">Guardians (comma-separated)</label>
            <input className="input font-mono" value={guardians} onChange={(e) => setGuardians(e.target.value)} placeholder="0xAAA...,0xBBB..." />
          </div>
          <div>
            <label className="label">Guardian Threshold (M-of-N)</label>
            <input className="input" type="number" value={threshold} onChange={(e) => setThreshold(e.target.value)} />
          </div>
          <Button onClick={commitMigration} disabled={!commitment || !verifier || loading} loading={loading}>
            Commit Migration
          </Button>
          {pendingCommit && (
            <div className="rounded-lg bg-warn/10 border border-warn/20 px-4 py-3 text-sm">
              <div className="flex items-center gap-2 text-warn font-medium mb-1">
                <Clock className="w-4 h-4" />
                Waiting for commit delay
              </div>
              <div className="text-muted">
                Commitment: <code className="font-mono">{shortenHash(pendingCommit, 8)}</code>
              </div>
              <div className="text-muted">
                Ready in: {timeRemaining(commitTime + 86400n)}
              </div>
            </div>
          )}
        </div>

        <div className="card space-y-4">
          <h2 className="font-semibold flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-ok" />
            Step 3: Finalize (after 24h)
          </h2>
          <p className="text-sm text-muted">
            Reveal the full PQC public key. The contract verifies keccak256(pubKey) == commitment.
          </p>
          <Button onClick={finalize} disabled={!pubKeyHex || !pendingCommit || migrated || loading} loading={loading} variant="primary">
            Finalize Migration
          </Button>
          {migrated && (
            <div className="rounded-lg bg-ok/10 border border-ok/20 px-4 py-3 text-sm text-ok">
              Migration complete! ECDSA spending is now disabled.
            </div>
          )}
        </div>

        <div className="card space-y-4">
          <h2 className="font-semibold flex items-center gap-2">
            <XCircle className="w-4 h-4 text-err" />
            Cancel Migration
          </h2>
          <p className="text-sm text-muted">
            Abort a pending migration. Only the legacy ECDSA owner can call this.
          </p>
          <Button onClick={cancel} disabled={!pendingCommit || loading} loading={loading} variant="danger">
            Cancel Pending Migration
          </Button>
        </div>
      </div>
    </div>
  );
}
