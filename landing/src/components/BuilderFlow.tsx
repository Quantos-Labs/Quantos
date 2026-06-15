import { motion } from 'framer-motion'

const steps = [
  {
    n: '01',
    t: 'Compose modules',
    d: 'Pick from 120+ typed primitives. Wallet, identity, settlement, AI - already wired.',
  },
  {
    n: '02',
    t: 'Prove the stack',
    d: 'Reproducible benchmarks, deterministic execution, transparent checkpoints.',
  },
  {
    n: '03',
    t: 'Ship the surface',
    d: 'Vybss product flows expose your stack as a polished user experience.',
  },
  {
    n: '04',
    t: 'Open the network',
    d: 'Roll out to testnet once audits and stability gates are complete.',
  },
]

export default function BuilderFlow() {
  return (
    <section id="builder-flow" className="relative py-24 px-6 border-t border-white/[0.04]">
      <div className="max-w-[1200px] mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-80px' }}
          transition={{ duration: 0.7 }}
          className="max-w-3xl mb-12"
        >
          <p className="h-eyebrow mb-4">- Builder flow</p>
          <h2 className="font-display text-[#F0F4FF] mb-4" style={{ fontSize: 'clamp(34px, 5vw, 56px)', lineHeight: 1.02 }}>
            Four moves to launch on a quantum-safe DAG.
          </h2>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {steps.map((step, i) => (
            <motion.div
              key={step.n}
              initial={{ opacity: 0, y: 14 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.55, delay: i * 0.06 }}
              className="card p-7"
            >
              <p className="text-[11px] text-[#5B6478] font-mono mb-3">{step.n}</p>
              <h3 className="text-[#F0F4FF] text-[22px] font-semibold tracking-[-0.02em] mb-2">{step.t}</h3>
              <p className="text-[#8893AC] text-[14px] leading-relaxed">{step.d}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  )
}
