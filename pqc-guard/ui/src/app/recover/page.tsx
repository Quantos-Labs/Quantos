'use client';

import { useState, useEffect, useCallback } from 'react';
import { PageHeader, Button, ErrorBanner, SuccessBanner, StatCard } from '@/components/ui';
import { useContracts } from '@/lib/contracts';
import { shortenHash, formatTimestamp, idleRemaining } from '@/lib/utils';
import { LifeBuoy, Clock, Shield, Users } from 'lucide-react';

export default function RecoverPage() {
  const { getAccount, config } = useContracts();
  const [newCommitment, setNewCommitment] = useState('');
  const [newVerifier, setNewVerifier] = useState('');
  const [fundsRecipient, setFundsRecipient] = useState('');
  const [recoveryId, setRecoveryId] = useState('');
  const [approvals, setApprovals] = useState(0n);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [lastActivity, setLastActivity] = useState(0n);
  const [recoveryTimeout, setRecoveryTimeout] = useState(0n);
  const [guardianCount, setGuardianCount] = useState(0n);
  const [guardianThreshold, setGuardianThreshold] = useState(0n);

  const refresh = useCallback(async () => {
    const acct = getAccount();
    if (!acct) return;
    try {
      const [la, rt, gc, gt] = await Promise.all([
        acct.lastActivity(), acct.RECOVERY_TIMEOUT(),
        acct.guardianCount(), acct.guardianThreshold(),
      ]);
      setLastActivity(la);
      setRecoveryTimeout(rt);
      setGuardianCount(gc);
      setGuardianThreshold(gt);
      if (recoveryId) {
        const a = await acct.recoveryApprovals(recoveryId);
        setApprovals(a);
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [getAccount, recoveryId]);

  useEffect(() => { refresh(); }, [refresh]);

  const propose = async () => {
    const acct = getAccount();
    if (!acct) { setError('No account address configured'); return; }
    setLoading(true);
    setError(null);
    setSuccess(null);
    try {
      const tx = await acct.proposeRecovery(newCommitment, newVerifier, fundsRecipient);
      await tx.wait();
      const id = await acct.recoveryApprovals.staticCall(newCommitment);
      setRecoveryId(newCommitment);
      setSuccess('Recovery proposed. Guardians must approve.');
      refresh();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  const approve = async () => {
    const acct = getAccount();
    if (!acct) { setError('No account address configured'); return; }
    if (!recoveryId) { setError('No recovery proposed yet'); return; }
    setLoading(true);
    setError(null);
    setSuccess(null);
    try {
      const tx = await acct.approveRecovery(recoveryId);
      await tx.wait();
      setSuccess('Recovery approved.');
      refresh();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  const execute = async () => {
    const acct = getAccount();
    if (!acct) { setError('No account address configured'); return; }
    if (!recoveryId) { setError('No recovery proposed yet'); return; }
    setLoading(true);
    setError(null);
    setSuccess(null);
    try {
      const tx = await acct.executeRecovery(recoveryId);
      await tx.wait();
      setSuccess('Recovery executed! Account has been recovered.');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  const canRecover = Number(lastActivity) + Number(recoveryTimeout) < Math.floor(Date.now() / 1000);

  return (
    <div>
      <PageHeader
        title="Recovery"
        description="Guardian-based escape hatch: if the account is idle for 30 days, guardians can rotate keys or sweep funds."
      />

      <ErrorBanner message={error} />
      <SuccessBanner message={success} />

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
        <StatCard
          label="Last Activity"
          value={formatTimestamp(lastActivity)}
          icon={<Clock className="w-4 h-4 text-muted" />}
        />
        <StatCard
          label="Recovery Window"
          value={idleRemaining(lastActivity, recoveryTimeout)}
          badge={canRecover ? <span className="badge-warn">Available</span> : <span className="badge-muted">Locked</span>}
        />
        <StatCard
          label="Guardians"
          value={`${guardianCount} / threshold ${guardianThreshold}`}
          icon={<Users className="w-4 h-4 text-muted" />}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card space-y-4">
          <h2 className="font-semibold flex items-center gap-2">
            <LifeBuoy className="w-4 h-4 text-accent" />
            Propose Recovery
          </h2>
          <p className="text-sm text-muted">
            Only available after 30 days of inactivity. Guardians propose a new commitment + verifier, or a funds sweep.
          </p>
          <div>
            <label className="label">New Commitment (bytes32)</label>
            <input className="input font-mono" value={newCommitment} onChange={(e) => setNewCommitment(e.target.value)} placeholder="0x..." />
          </div>
          <div>
            <label className="label">New Verifier Address</label>
            <input className="input font-mono" value={newVerifier} onChange={(e) => setNewVerifier(e.target.value)} placeholder="0x..." />
          </div>
          <div>
            <label className="label">Funds Recipient (for sweep)</label>
            <input className="input font-mono" value={fundsRecipient} onChange={(e) => setFundsRecipient(e.target.value)} placeholder="0x..." />
          </div>
          <Button onClick={propose} disabled={!canRecover || loading} loading={loading}>
            Propose Recovery
          </Button>
          {!canRecover && (
            <p className="text-xs text-warn">
              Recovery is locked until the 30-day idle period expires.
            </p>
          )}
        </div>

        <div className="card space-y-4">
          <h2 className="font-semibold flex items-center gap-2">
            <Shield className="w-4 h-4 text-accent" />
            Approve & Execute
          </h2>
          <p className="text-sm text-muted">
            M-of-N guardians must approve before execution.
          </p>
          {recoveryId && (
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-muted">Recovery ID:</span>
                <code className="font-mono">{shortenHash(recoveryId, 8)}</code>
              </div>
              <div className="flex justify-between">
                <span className="text-muted">Approvals:</span>
                <span>{approvals} / {guardianThreshold}</span>
              </div>
            </div>
          )}
          <div className="flex gap-3">
            <Button onClick={approve} disabled={!recoveryId || loading} loading={loading} variant="ghost">
              Approve
            </Button>
            <Button onClick={execute} disabled={!recoveryId || loading} loading={loading}>
              Execute Recovery
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
