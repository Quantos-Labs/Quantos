import { motion } from 'framer-motion'
import { Shield, Globe, Cpu, Landmark, Layers, Zap } from 'lucide-react'

const l0Modules = [
  {
    metric: 'L0-01',
    title: 'PQC Finality Proofs',
    name: 'Layer 0 Hub',
    desc: 'Post-quantum signature aggregation with Dilithium-3. Finality checkpoints are cryptographically anchored and verifiable by any external chain.',
    accent: '#22D3EE',
    icon: Shield,
  },
  {
    metric: 'L0-02',
    title: 'STACC Collateral Model',
    name: 'Sovereign Consensus',
    desc: 'Subnets enforce QTS collateral leasing and double-staking on Quantos L1. Economic security is programmable and on-chain enforceable.',
    accent: '#A78BFA',
    icon: Landmark,
  },
  {
    metric: 'L0-03',
    title: 'Subnet Orchestration',
    name: 'Custom Validator Sets',
    desc: 'Launch sovereign subnets with independent consensus rules while inheriting Quantos finality. Custom validators, custom policies, shared security.',
    accent: '#67E8F9',
    icon: Layers,
  },
  {
    metric: 'L0-04',
    title: 'Cross-Chain Anchoring',
    name: 'Light Client Relay',
    desc: 'Native light clients for Bitcoin, Ethereum, Tezos, Cardano, and more. Bridgeless finality relay with batched proof verification.',
    accent: '#86EFAC',
    icon: Globe,
  },
  {
    metric: 'L0-05',
    title: 'zk-STARK Scaling',
    name: 'Winterfell Proofs',
    desc: 'State transition, cross-shard, and private transfer proofs using Winterfell STARKs. Recursive composition enables 100K+ cumulative TPS.',
    accent: '#FCA5A5',
    icon: Cpu,
  },
  {
    metric: 'L0-06',
    title: 'Institutional Grade',
    name: 'Bare-Metal Performance',
    desc: 'Sub-1.5s finality with batched verification and stake-weighted rate limiting. Optimized for stable throughput and institutional deployment.',
    accent: '#FBBF24',
    icon: Zap,
  },
]

const l0Pills = [
  'Dilithium-3', 'STACC', 'Subnet Leasing', 'Double-Staking',
  'Light Clients', 'Cross-Shard STARKs', 'Recursive Proofs', 'Private Transfer',
  'Winterfell', 'Batched Verification',
]

export default function L0Section() {
  return (
    <section id="l0" className="relative py-28 px-6 border-t border-white/[0.04]">
      <div className="absolute inset-0 mesh-bg opacity-35 pointer-events-none" />

      <div className="relative max-w-[1200px] mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-80px' }}
          transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
          className="max-w-3xl mb-16"
        >
          <p className="h-eyebrow mb-5">Interoperability, anchored.</p>
          <h2
            className="font-display text-[#F0F4FF] mb-6"
            style={{ fontSize: 'clamp(36px, 5vw, 64px)', lineHeight: 1.02 }}
          >
            The Layer 0{' '}
            <span className="text-shimmer italic font-light">finality hub.</span>
          </h2>
          <p className="text-[#8893AC] text-[17px] leading-[1.55] max-w-xl">
            Quantos L0 is a post-quantum DAG interoperability layer that anchors its finalized
            state to external chains instead of competing with them. Through quantum-safe proofs,
            sovereign subnets, and native light clients, Quantos acts as a trust anchor for the
            multi-chain economy — without altering those chains' own consensus.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-20">
          {l0Modules.map((p, i) => {
            const Icon = p.icon
            return (
              <motion.div
                key={p.name}
                initial={{ opacity: 0, y: 20, scale: 0.985 }}
                whileInView={{ opacity: 1, y: 0, scale: 1 }}
                viewport={{ once: true, margin: '-50px' }}
                transition={{ duration: 0.65, delay: i * 0.05, ease: [0.22, 1, 0.36, 1] }}
                className="card card-glow group p-7 hover:-translate-y-1 hover:scale-[1.01] transition-transform duration-500"
              >
                <div className="flex items-center justify-between mb-4">
                  <span
                    className="text-[10px] font-mono px-2 py-1 rounded-md uppercase tracking-[0.14em]"
                    style={{ color: p.accent, background: `${p.accent}14`, border: `1px solid ${p.accent}35` }}
                  >
                    {p.metric}
                  </span>
                  <span className="text-[10px] text-[#5B6478] uppercase tracking-[0.12em] font-mono">L0 Module</span>
                </div>

                <div className="flex items-start gap-3 mb-3">
                  <div
                    className="mt-0.5 p-1.5 rounded-md"
                    style={{ background: `${p.accent}14`, border: `1px solid ${p.accent}30` }}
                  >
                    <Icon size={16} style={{ color: p.accent }} />
                  </div>
                  <div>
                    <h3 className="text-[#F0F4FF] font-semibold text-[18px] tracking-[-0.015em] mb-1">
                      {p.title}
                    </h3>
                    <p className="text-[#9DB0CF] text-[13px] font-mono">{p.name}</p>
                  </div>
                </div>
                <p className="text-[#8893AC] text-[14px] leading-[1.6] mb-0">
                  {p.desc}
                </p>
              </motion.div>
            )
          })}
        </div>

        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.7 }}
        >
          <p className="h-eyebrow mb-5 text-center">— L0 technology stack</p>
          <div className="flex flex-wrap gap-1.5 justify-center max-w-3xl mx-auto">
            {l0Pills.map((t, i) => (
              <motion.span
                key={t}
                initial={{ opacity: 0, scale: 0.95 }}
                whileInView={{ opacity: 1, scale: 1 }}
                viewport={{ once: true }}
                transition={{ duration: 0.3, delay: i * 0.025 }}
                className="text-[12px] font-mono px-3 py-1.5 rounded-md border border-white/[0.05] text-[#6B7588] hover:text-[#F0F4FF] hover:border-white/[0.12] hover:bg-white/[0.02] cursor-default transition-all"
              >
                {t}
              </motion.span>
            ))}
          </div>
        </motion.div>
      </div>
    </section>
  )
}
