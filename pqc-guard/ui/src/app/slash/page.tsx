'use client';

import { useState, useEffect, useCallback } from 'react';
import { PageHeader, Button, ErrorBanner, SuccessBanner, StatCard, CopyableField } from '@/components/ui';
import { useContracts } from '@/lib/contracts';
import { shortenHash } from '@/lib/utils';
import { ShieldAlert, Scissors, Coins, Users } from 'lucide-react';

export default function SlashPage() {
  const { getRegistry, config } = useContracts();
  const [attestor, setAttestor] = useState('');
  const [leafIndex, setLeafIndex] = useState('0');
  const [digestA, setDigestA] = useState('');
  const [sigA, setSigA] = useState('');
  const [pathA, setPathA] = useState('');
  const [digestB, setDigestB] = useState('');
  const [sigB, setSigB] = useState('');
  const [pathB, setPathB] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeCount, setActiveCount] = useState(0n);
  const [slashTreasury, setSlashTreasury] = useState(0n);
  const [reporterRewardBps, setReporterRewardBps] = useState(0n);
  const [attestorInfo, setAttestorInfo] = useState<{ stake: bigint; wotsRoot: string; active: boolean; slashed: boolean } | null>(null);

  const refresh = useCallback(async () => {
    const reg = getRegistry();
    if (!reg) return;
    try {
      const [ac, st, rb] = await Promise.all([
        reg.activeCount(), reg.slashTreasury(), reg.REPORTER_REWARD_BPS(),
      ]);
      setActiveCount(ac);
      setSlashTreasury(st);
      setReporterRewardBps(rb);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [getRegistry]);

  useEffect(() => { refresh(); }, [refresh]);

  const lookupAttestor = async () => {
    const reg = getRegistry();
    if (!reg) { setError('No registry address configured'); return; }
    setError(null);
    try {
      const [stake, wotsRoot, active, slashed] = await reg.getAttestor(attestor);
      setAttestorInfo({ stake, wotsRoot, active, slashed });
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const submitSlash = async () => {
    const reg = getRegistry();
    if (!reg) { setError('No registry address configured'); return; }
    setLoading(true);
    setError(null);
    setSuccess(null);
    try {
      const parseBytes32Array = (s: string): string[] => {
        const items = s.split(',').map((x) => x.trim()).filter(Boolean);
        if (items.length === 0) throw new Error('Empty bytes32 array');
        return items;
      };
      const tx = await reg.slashOnReuse(
        attestor,
        BigInt(leafIndex),
        digestA,
        parseBytes32Array(sigA),
        parseBytes32Array(pathA),
        digestB,
        parseBytes32Array(sigB),
        parseBytes32Array(pathB),
      );
      await tx.wait();
      setSuccess('Attestor slashed! Reporter reward sent.');
      refresh();
      if (attestor) lookupAttestor();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <PageHeader
        title="Slashing"
        description="Prove WOTS one-time key reuse: same leaf index signed two different digests. Reporter gets a reward."
      />

      <ErrorBanner message={error} />
      <SuccessBanner message={success} />

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
        <StatCard label="Active Attestors" value={activeCount.toString()} icon={<Users className="w-4 h-4 text-muted" />} />
        <StatCard label="Slash Treasury" value={slashTreasury.toString()} icon={<Coins className="w-4 h-4 text-muted" />} />
        <StatCard label="Reporter Reward" value={`${reporterRewardBps / 100n}%`} icon={<Scissors className="w-4 h-4 text-muted" />} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card space-y-4">
          <h2 className="font-semibold flex items-center gap-2">
            <Users className="w-4 h-4 text-accent" />
            Lookup Attestor
          </h2>
          <div>
            <label className="label">Attestor Address</label>
            <input className="input font-mono" value={attestor} onChange={(e) => setAttestor(e.target.value)} placeholder="0x..." />
          </div>
          <Button onClick={lookupAttestor} variant="ghost">Lookup</Button>
          {attestorInfo && (
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-muted">Stake:</span>
                <span className="font-mono">{attestorInfo.stake.toString()}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted">WOTS Root:</span>
                <code className="font-mono">{shortenHash(attestorInfo.wotsRoot, 8)}</code>
              </div>
              <div className="flex justify-between">
                <span className="text-muted">Status:</span>
                {attestorInfo.slashed ? (
                  <span className="badge-err">Slashed</span>
                ) : attestorInfo.active ? (
                  <span className="badge-ok">Active</span>
                ) : (
                  <span className="badge-muted">Inactive</span>
                )}
              </div>
            </div>
          )}
        </div>

        <div className="card space-y-4">
          <h2 className="font-semibold flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-err" />
            Submit Slashing Proof
          </h2>
          <p className="text-sm text-muted">
            Provide two WOTS signatures from the same leaf index over different digests. Both must verify to the attestor's WOTS root.
          </p>
          <div>
            <label className="label">Leaf Index</label>
            <input className="input" type="number" value={leafIndex} onChange={(e) => setLeafIndex(e.target.value)} />
          </div>
          <div className="border-t border-border pt-3">
            <label className="label text-warn">Signature A (first use)</label>
            <input className="input font-mono mb-2" value={digestA} onChange={(e) => setDigestA(e.target.value)} placeholder="Digest A (bytes32)" />
            <input className="input font-mono mb-2" value={sigA} onChange={(e) => setSigA(e.target.value)} placeholder="Sig A: 0xaaa,0xbbb,... (67 × bytes32)" />
            <input className="input font-mono" value={pathA} onChange={(e) => setPathA(e.target.value)} placeholder="Path A: 0xaaa,0xbbb,... (height × bytes32)" />
          </div>
          <div className="border-t border-border pt-3">
            <label className="label text-err">Signature B (reuse — fraud)</label>
            <input className="input font-mono mb-2" value={digestB} onChange={(e) => setDigestB(e.target.value)} placeholder="Digest B (bytes32, must differ from A)" />
            <input className="input font-mono mb-2" value={sigB} onChange={(e) => setSigB(e.target.value)} placeholder="Sig B: 0xaaa,0xbbb,... (67 × bytes32)" />
            <input className="input font-mono" value={pathB} onChange={(e) => setPathB(e.target.value)} placeholder="Path B: 0xaaa,0xbbb,... (height × bytes32)" />
          </div>
          <Button onClick={submitSlash} disabled={!attestor || !digestA || !digestB || loading} loading={loading} variant="danger">
            Slash Attestor
          </Button>
        </div>
      </div>
    </div>
  );
}
