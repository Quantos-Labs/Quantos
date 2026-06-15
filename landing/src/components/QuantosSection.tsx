import { motion } from 'framer-motion'
import { ArrowUpRight } from 'lucide-react'

const stack = [
  {
    metric: '01',
    title: 'Layer 0 finality hub',
    name: 'L0 Hub',
    desc: 'PQC-anchored finality for external chains with sovereign subnets and cross-chain light clients.',
    accent: '#22D3EE',
  },
  {
    metric: '02',
    title: 'Asset and service coordination',
    name: 'Quantos DAG',
    desc: 'Parallel transaction graph for coordinated settlement across service modules.',
    accent: '#67E8F9',
  },
  {
    metric: '03',
    title: 'Trusted data layer',
    name: 'Service Data Fabric',
    desc: 'Deterministic state snapshots with integrity-oriented indexing for product surfaces.',
    accent: '#86EFAC',
  },
  {
    metric: '04',
    title: 'Post-quantum security',
    name: 'PQC Signature Path',
    desc: 'Dilithium/SPHINCS+ compatible security path for long-horizon cryptographic resilience.',
    accent: '#A78BFA',
  },
  {
    metric: '05',
    title: 'Verifiable execution',
    name: 'WASM Runtime',
    desc: 'Predictable execution model with reproducible behavior and strict state transitions.',
    accent: '#FCA5A5',
  },
  {
    metric: '06',
    title: 'Liquidity and transfer rails',
    name: 'Bridge + Swap Layers',
    desc: 'Cross-service liquidity primitives designed for composability and policy constraints.',
    accent: '#FBBF24',
  },
  {
    metric: '07',
    title: 'Identity and permissions',
    name: 'Unified Account Model',
    desc: 'Shared identity, permissions, and security controls across all product domains.',
    accent: '#7DD3FC',
  },
]

const techPills = [
  'L0 Finality Hub', 'STACC', 'Subnets', 'Falcon-512', 'Dilithium',
  'DAG consensus', 'WASM', 'NIST PQC', 'SPHINCS+', 'zk-STARKs',
  'Hybrid crypto', 'Sharding', 'libp2p', 'QUIC', 'Reed-Solomon',
  'Proof systems', 'State sync', 'Rust', '.qts domains',
]

export default function QuantosSection() {
  return (
    <section
      id="architecture"
      className="relative py-28 px-6 border-t border-white/[0.04]"
    >
      <div className="absolute inset-0 mesh-bg opacity-35 pointer-events-none" />

      <div className="relative max-w-[1200px] mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-80px' }}
          transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
          className="max-w-3xl mb-16"
        >
          <p className="h-eyebrow mb-5">Innovation, engineered.</p>
          <h2
            className="font-display text-[#F0F4FF] mb-6"
            style={{ fontSize: 'clamp(36px, 5vw, 64px)', lineHeight: 1.02 }}
          >
            A composable post-quantum Layer 1 stack for
            <span className="text-shimmer italic font-light"> product and protocol.</span>
          </h2>
          <p className="text-[#8893AC] text-[17px] leading-[1.55] max-w-xl">
            Quantos is a quantum-safe DAG that maps each infrastructure layer to a concrete
            product role — from DAG consensus and WASM runtime to zero-gas settlement and
            institutional-grade security.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-20">
          {stack.map((p, i) => (
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
                <span className="text-[10px] text-[#5B6478] uppercase tracking-[0.12em] font-mono">Stack module</span>
              </div>

              <h3 className="text-[#F0F4FF] font-semibold text-[18px] tracking-[-0.015em] mb-1">
                {p.title}
              </h3>
              <p className="text-[#9DB0CF] text-[13px] font-mono mb-2.5">{p.name}</p>
              <p className="text-[#8893AC] text-[14px] leading-[1.6] mb-0">
                {p.desc}
              </p>
            </motion.div>
          ))}
        </div>

        <motion.div
          id="security"
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-80px' }}
          transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
          className="gradient-border overflow-hidden mb-20"
        >
          <div className="grid grid-cols-1 md:grid-cols-[1.2fr_1px_1fr] backdrop-blur-2xl">
            <div className="p-9">
              <p className="h-eyebrow mb-4">— Security posture</p>
              <h3 className="text-[28px] md:text-[34px] font-bold tracking-[-0.025em] text-[#F0F4FF] leading-[1.1] mb-4">
                Built to withstand{' '}
                <span className="text-shimmer">quantum advances.</span>
              </h3>
              <p className="text-[#8893AC] text-[15px] leading-[1.6] mb-6">
                The goal is to reduce systemic cryptographic risk, keep the
                execution model deterministic, and make security assumptions
                explicit and testable. External review and reproducible
                benchmarking are first-class milestones.
              </p>

              <a
                href="https://github.com/Wayleyy/Quantos_labs"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-[13px] text-[#A78BFA] hover:text-[#C4B5FD] transition-colors"
              >
                Read the security model
                <ArrowUpRight size={13} />
              </a>
            </div>

            <div className="hidden md:block divider-vertical" />
            <div className="block md:hidden divider mx-9" />

            <div className="p-9">
              <p className="h-eyebrow mb-5">— Key principles</p>
              <div className="space-y-5">
                {[
                  {
                    title: 'Explicit assumptions',
                    desc: 'Threat model is written down and testable.',
                  },
                  {
                    title: 'Reproducible benchmarks',
                    desc: 'Numbers tied to code and environments.',
                  },
                  {
                    title: 'Review as a milestone',
                    desc: 'Security review gates releases.',
                  },
                ].map((x, idx) => (
                  <div key={x.title} className="flex items-start gap-4">
                    <span className="mt-1 text-[10px] font-mono text-[#5B6478] tabular">
                      0{idx + 1}
                    </span>
                    <div>
                      <p className="text-[14px] font-semibold text-[#F0F4FF] mb-1">
                        {x.title}
                      </p>
                      <p className="text-[12.5px] text-[#6B7588] leading-relaxed">
                        {x.desc}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.7 }}
        >
          <p className="h-eyebrow mb-5 text-center">— Core technology stack</p>
          <div className="flex flex-wrap gap-1.5 justify-center max-w-3xl mx-auto">
            {techPills.map((t, i) => (
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
