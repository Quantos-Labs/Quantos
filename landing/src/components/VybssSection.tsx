import { motion } from 'framer-motion'
import { Sparkles, ArrowUpRight } from 'lucide-react'

const industries = [
  {
    title: 'AI',
    accent: '#A78BFA',
    bullets: [
      'Privacy-aware data pathways',
      'Verifiable automation output',
      'Service-native AI workflows',
    ],
  },
  {
    title: 'Payments',
    accent: '#67E8F9',
    bullets: [
      'Programmable transfer policies',
      'Cross-surface settlement logic',
      'Business-grade observability',
    ],
  },
  {
    title: 'DeFi',
    accent: '#FBBF24',
    bullets: [
      'Composable liquidity rails',
      'Deterministic transaction ordering',
      'Risk and security toolchain',
    ],
  },
  {
    title: 'Consumer Super App',
    accent: '#86EFAC',
    bullets: [
      'Wallet, social, and trading surfaces',
      'Shared identity and permission model',
      'One account across all modules',
    ],
  },
]

export default function SolutionsSection() {
  return (
    <section id="services" className="relative py-28 px-6 border-t border-white/[0.04] overflow-hidden">
      <div className="liquid-blob liquid-blob-c" />
      <div className="relative max-w-[1200px] mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-80px' }}
          transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
          className="max-w-3xl mb-16"
        >
          <p className="h-eyebrow mb-5 flex items-center gap-2">
            <Sparkles size={11} />
            Industry transformation powered by Quantos
          </p>
          <h2
            className="font-display text-[#F0F4FF] mb-6"
            style={{ fontSize: 'clamp(36px, 5vw, 64px)', lineHeight: 1.02 }}
          >
            Build quantum-safe products,
            <span className="text-shimmer italic font-light"> on one composable stack.</span>
          </h2>
          <p className="text-[#8893AC] text-[17px] leading-[1.55]">
            Quantos post-quantum DAG infrastructure supports vertical products from AI
            to payments and DeFi. Quantum-safe primitives turn into user-facing services
            with shared identity, wallet, and security behavior.
          </p>
        </motion.div>

        <div id="catalog" className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {industries.map((category, index) => (
            <motion.div
              key={category.title}
              initial={{ opacity: 0, y: 24, scale: 0.985 }}
              whileInView={{ opacity: 1, y: 0, scale: 1 }}
              viewport={{ once: true, margin: '-40px' }}
              transition={{ duration: 0.65, delay: index * 0.045, ease: [0.22, 1, 0.36, 1] }}
              className="card card-glow p-6 hover:-translate-y-1 hover:scale-[1.01] transition-transform duration-500"
            >
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-[#F0F4FF] text-[20px] font-semibold tracking-[-0.02em]">
                  {category.title}
                </h3>
                <span
                  className="text-[10px] font-bold uppercase tracking-[0.12em] px-2 py-0.5 rounded-md"
                  style={{
                    color: category.accent,
                    background: `${category.accent}10`,
                    border: `1px solid ${category.accent}30`,
                  }}
                >
                  solution
                </span>
              </div>

              <ul className="space-y-2.5">
                {category.bullets.map((service) => (
                  <li key={service} className="text-[13px] text-[#9AA5BB] leading-relaxed flex items-start gap-2.5">
                    <span className="mt-1 w-1.5 h-1.5 rounded-full" style={{ background: category.accent }} />
                    <span>{service}</span>
                  </li>
                ))}
              </ul>

              <a href="#cta" className="inline-flex items-center gap-1 text-[12px] mt-5 text-[#D8E2F8] hover:text-white transition-colors">
                Explore stack for {category.title}
                <ArrowUpRight size={12} />
              </a>
            </motion.div>
          ))}
        </div>

        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.55, delay: 0.18 }}
          className="mt-12 flex flex-wrap items-center justify-center gap-3 text-[13px]"
        >
          <span className="chip">Unified identity</span>
          <span className="chip">Shared wallet layer</span>
          <span className="chip">Cross-surface discovery</span>
          <span className="chip">Quantos settlement rail</span>
          <a
            href="https://github.com/Wayleyy/Quantos_labs"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-[#F0F4FF] hover:text-white transition-colors font-medium"
          >
            Review implementation
            <ArrowUpRight size={12} />
          </a>
        </motion.div>
      </div>
    </section>
  )
}
