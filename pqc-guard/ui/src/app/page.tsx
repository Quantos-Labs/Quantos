'use client';

import { useState, useEffect, useCallback } from 'react';
import { useContracts } from '@/lib/contracts';
import { PageHeader, StatCard, ErrorBanner } from '@/components/ui';
import { shortenHash, formatTimestamp, idleRemaining } from '@/lib/utils';
import { ShieldCheck, ShieldAlert, Clock, Key, Users, Activity, Layers, Hash } from 'lucide-react';

interface AccountState {
  migrated: boolean;
  pqcCommitment: string;
  legacyOwner: string;
  nonce: bigint;
  lastActivity: bigint;
  attestationVerifier: string;
  pendingCommitment: string;
  migrationCommitTime: bigint;
  guardianCount: bigint;
  guardianThreshold: bigint;
  recoveryTimeout: bigint;
  commitDelay: bigint;
}

interface OracleState {
  setRoot: string;
  epoch: bigint;
  threshold: bigint;
}

interface RegistryState {
  activeCount: bigint;
  attestorCount: bigint;
  threshold: bigint;
  slashTreasury: bigint;
  reporterRewardBps: bigint;
  minStake: bigint;
}

export default function DashboardPage() {
  const { getAccount, getOracle, getRegistry, config } = useContracts();
  const [account, setAccount] = useState<AccountState | null>(null);
  const [oracle, setOracle] = useState<OracleState | null>(null);
  const [registry, setRegistry] = useState<RegistryState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const acct = getAccount();
      const orc = getOracle();
      const reg = getRegistry();

      if (acct) {
        const [
          migrated, pqcCommitment, legacyOwner, nonce, lastActivity,
          attestationVerifier, pendingCommitment, migrationCommitTime,
          guardianCount, guardianThreshold, recoveryTimeout, commitDelay,
        ] = await Promise.all([
          acct.migrated(), acct.pqcCommitment(), acct.legacyOwner(),
          acct.nonce(), acct.lastActivity(), acct.attestationVerifier(),
          acct.pendingCommitment(), acct.migrationCommitTime(),
          acct.guardianCount(), acct.guardianThreshold(),
          acct.RECOVERY_TIMEOUT(), acct.COMMIT_DELAY(),
        ]);
        setAccount({
          migrated, pqcCommitment, legacyOwner, nonce, lastActivity,
          attestationVerifier, pendingCommitment, migrationCommitTime,
          guardianCount, guardianThreshold, recoveryTimeout, commitDelay,
        });
      }

      if (orc) {
        const [setRoot, epoch, threshold] = await Promise.all([
          orc.attestorSetRoot(), orc.attestorEpoch(), orc.threshold(),
        ]);
        setOracle({ setRoot, epoch, threshold });
      }

      if (reg) {
        const [activeCount, attestorCount, threshold, slashTreasury, reporterRewardBps, minStake] = await Promise.all([
          reg.activeCount(), reg.attestorCount(), reg.threshold(),
          reg.slashTreasury(), reg.REPORTER_REWARD_BPS(), reg.minStake(),
        ]);
        setRegistry({ activeCount, attestorCount, threshold, slashTreasury, reporterRewardBps, minStake });
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [getAccount, getOracle, getRegistry]);

  useEffect(() => { refresh(); }, [refresh]);

  return (
    <div>
      <PageHeader
        title="Dashboard"
        description="On-chain state of the Guardian account, attestor oracle, and registry."
      />

      <ErrorBanner message={error} />

      {!config.accountAddress && !config.oracleAddress && !config.registryAddress && (
        <div className="card mb-6 text-sm text-muted">
          No contract addresses configured. Click <span className="text-accent font-medium">Settings</span> in the top-right to set them.
        </div>
      )}

      <div className="flex items-center gap-3 mb-6">
        <button onClick={refresh} disabled={loading} className="btn-ghost">
          {loading ? 'Loading...' : 'Refresh'}
        </button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
        <StatCard
          label="Account Status"
          value={account ? (account.migrated ? 'Migrated (PQC)' : 'Pre-migration (ECDSA)') : '—'}
          badge={account?.migrated ? <span className="badge-ok">PQC Active</span> : <span className="badge-warn">ECDSA Only</span>}
          icon={account?.migrated ? <ShieldCheck className="w-4 h-4 text-ok" /> : <ShieldAlert className="w-4 h-4 text-warn" />}
        />
        <StatCard
          label="Nonce"
          value={account ? account.nonce.toString() : '—'}
          icon={<Activity className="w-4 h-4 text-muted" />}
        />
        <StatCard
          label="PQC Commitment"
          value={account ? shortenHash(account.pqcCommitment, 10) : '—'}
          icon={<Key className="w-4 h-4 text-muted" />}
        />
      </div>

      <h2 className="text-sm font-semibold text-muted uppercase tracking-wide mb-3">Attestor Set (Oracle)</h2>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
        <StatCard
          label="Set Root"
          value={oracle ? shortenHash(oracle.setRoot, 10) : '—'}
          icon={<Hash className="w-4 h-4 text-muted" />}
        />
        <StatCard
          label="Epoch"
          value={oracle ? oracle.epoch.toString() : '—'}
          icon={<Layers className="w-4 h-4 text-muted" />}
        />
        <StatCard
          label="Quorum Threshold"
          value={oracle ? oracle.threshold.toString() : '—'}
          icon={<Users className="w-4 h-4 text-muted" />}
        />
      </div>

      <h2 className="text-sm font-semibold text-muted uppercase tracking-wide mb-3">Attestor Registry</h2>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4 mb-6">
        <StatCard label="Active Attestors" value={registry ? registry.activeCount.toString() : '—'} />
        <StatCard label="Total Registered" value={registry ? registry.attestorCount.toString() : '—'} />
        <StatCard label="Registry Threshold" value={registry ? registry.threshold.toString() : '—'} />
        <StatCard label="Slash Treasury" value={registry ? registry.slashTreasury.toString() : '—'} />
      </div>

      {account && (
        <>
          <h2 className="text-sm font-semibold text-muted uppercase tracking-wide mb-3">Migration & Recovery</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <StatCard
              label="Legacy Owner"
              value={shortenHash(account.legacyOwner, 8)}
            />
            <StatCard
              label="Verifier"
              value={shortenHash(account.attestationVerifier, 8)}
            />
            <StatCard
              label="Pending Commitment"
              value={account.pendingCommitment === '0x' + '0'.repeat(64) ? 'None' : shortenHash(account.pendingCommitment, 8)}
            />
            <StatCard
              label="Guardians"
              value={`${account.guardianCount} / threshold ${account.guardianThreshold}`}
              icon={<Users className="w-4 h-4 text-muted" />}
            />
            <StatCard
              label="Last Activity"
              value={formatTimestamp(account.lastActivity)}
              icon={<Clock className="w-4 h-4 text-muted" />}
            />
            <StatCard
              label="Recovery Window"
              value={idleRemaining(account.lastActivity, account.recoveryTimeout)}
              badge={
                Number(account.lastActivity) + Number(account.recoveryTimeout) < Math.floor(Date.now() / 1000)
                  ? <span className="badge-warn">Recovery available</span>
                  : <span className="badge-muted">Idle countdown</span>
              }
            />
          </div>
        </>
      )}
    </div>
  );
}
