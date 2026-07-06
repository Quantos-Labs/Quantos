import { motion } from 'framer-motion'
import { Layers, Network, Shield, ArrowRight } from 'lucide-react'

const steps = [
  {
    n: '01',
    title: 'L1 DAG Core',
    subtitle: 'The settlement engine',
    desc: 'Quantos L1 is a Directed Acyclic Graph (DAG) — not a traditional blockchain. Transactions form a parallel graph with deterministic ordering, enabling sub-second finality and zero-gas settlement. No blocks, no miners, no bottlenecks.',
    accent: '#22D3EE',
    icon: Network,
  },
  {
    n: '02',
    title: 'L0 Finality Hub',
    subtitle: 'Cross-chain trust anchor',
    desc: 'Quantos L0 does not compete with other chains — it finalizes them. Through post-quantum proofs (Dilithium-3), sovereign subnets, and native light clients, Quantos acts as a universal trust anchor for Bitcoin, Ethereum, Tezos, Cardano, and more.',
    accent: '#A78BFA',
    icon: Layers,
  },
  {
    n: '03',
    title: 'PQC Security Layer',
    subtitle: 'Quantum-ready by design',
    desc: 'Every checkpoint is secured by NIST-standardized post-quantum cryptography. A hybrid signature path combines classical and quantum-safe algorithms, with an explicit migration roadmap toward full quantum resistance.',
    accent: '#67E8F9',
    icon: Shield,
  },
]

export default function HowItWorks() {
  return (
    <section id="how-it-works" className="relative py-28 px-6 border-t border-white/[0.04]">
      <div className="absolute inset-0 mesh-bg opacity-35 pointer-events-none" />

      <div className="relative max-w-[1200px] mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-80px' }}
          transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
          className="max-w-3xl mb-16"
        >
          <p className="h-eyebrow mb-5">How it works</p>
          <h2
            className="font-display text-[#F0F4FF] mb-6"
            style={{ fontSize: 'clamp(36px, 5vw, 64px)', lineHeight: 1.02 }}
          >
            L1 DAG settlement,{' '}
            <span className="text-shimmer italic font-light">L0 cross-chain finality.</span>
          </h2>
          <p className="text-[#8893AC] text-[17px] leading-[1.55] max-w-xl">
            Quantos is both a Layer 1 DAG for high-throughput settlement and a Layer 0 hub
            that anchors external chains. Two layers, one cohesive post-quantum infrastructure.
          </p>
        </motion.div>

        <div className="space-y-4">
          {steps.map((step, i) => {
            const Icon = step.icon
            return (
              <motion.div
                key={step.n}
                initial={{ opacity: 0, y: 20, scale: 0.985 }}
                whileInView={{ opacity: 1, y: 0, scale: 1 }}
                viewport={{ once: true, margin: '-50px' }}
                transition={{ duration: 0.65, delay: i * 0.08, ease: [0.22, 1, 0.36, 1] }}
                className="card card-glow p-7 hover:-translate-y-0.5 hover:scale-[1.005] transition-transform duration-500"
              >
                <div className="grid grid-cols-1 md:grid-cols-[80px_1fr] gap-6 items-start">
                  <div
                    className="flex items-center justify-center w-16 h-16 rounded-2xl"
                    style={{ background: `${step.accent}14`, border: `1px solid ${step.accent}30` }}
                  >
                    <Icon size={28} style={{ color: step.accent }} />
                  </div>
                  <div>
                    <div className="flex items-center gap-3 mb-3">
                      <span
                        className="text-[10px] font-mono px-2 py-1 rounded-md uppercase tracking-[0.14em]"
                        style={{ color: step.accent, background: `${step.accent}14`, border: `1px solid ${step.accent}35` }}
                      >
                        Step {step.n}
                      </span>
                      <span className="text-[10px] text-[#5B6478] uppercase tracking-[0.12em] font-mono">
                        {step.subtitle}
                      </span>
                    </div>
                    <h3 className="text-[#F0F4FF] font-semibold text-[22px] tracking-[-0.02em] mb-2">
                      {step.title}
                    </h3>
                    <p className="text-[#8893AC] text-[15px] leading-[1.6] max-w-2xl">
                      {step.desc}
                    </p>
                  </div>
                </div>
              </motion.div>
            )
          })}
        </div>

        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.3 }}
          className="mt-12 flex items-center justify-center gap-6"
        >
          <div className="flex items-center gap-2 text-[13px] text-[#5B6478]">
            <span className="w-2 h-2 rounded-full bg-[#22D3EE]" />
            L1 DAG Settlement
          </div>
          <ArrowRight size={14} className="text-[#5B6478]" />
          <div className="flex items-center gap-2 text-[13px] text-[#5B6478]">
            <span className="w-2 h-2 rounded-full bg-[#A78BFA]" />
            L0 Finality Hub
          </div>
          <ArrowRight size={14} className="text-[#5B6478]" />
          <div className="flex items-center gap-2 text-[13px] text-[#5B6478]">
            <span className="w-2 h-2 rounded-full bg-[#67E8F9]" />
            PQC Security
          </div>
        </motion.div>
      </div>
    </section>
  )
}
