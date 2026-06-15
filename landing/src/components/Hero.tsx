import { motion } from 'framer-motion'
import { ArrowUpRight } from 'lucide-react'
const railTags = ['AI', 'Payments', 'DeFi', 'Trading', 'Social', 'Wallet', 'Identity', 'Security']

export default function Hero() {
  return (
    <section id="overview" className="relative pt-32 pb-20 px-6 overflow-hidden">
      <div className="aurora" />
      <div className="liquid-blob liquid-blob-a" />
      <div className="liquid-blob liquid-blob-b" />
      <div className="absolute inset-0 bg-dotgrid opacity-35 pointer-events-none" />

      <div className="relative z-10 max-w-[1200px] mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.65 }}
          className="mb-8"
        >
          <span className="chip chip-cyan">
            <span className="live-pulse" style={{ background: '#22D3EE' }} />
            Build full stack
          </span>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-[1fr_0.95fr] gap-12 items-start">
          <div>
            <h1
              className="font-display text-[#F0F4FF]"
              style={{
                fontSize: 'clamp(52px, 8vw, 108px)',
                lineHeight: 0.92,
                letterSpacing: '-0.06em',
                fontWeight: 800,
              }}
            >
              <span className="block">Build full stack</span>
              <span className="block">with Quantos</span>
              <span className="block text-cyan-300">and Vybss.</span>
            </h1>

            <p className="text-[#AAB5CB] max-w-2xl mt-8 text-[18px] leading-[1.6]">
              Quantos delivers the base infrastructure for a new product economy — including a
              Layer 0 PQC finality hub that anchors external chains. Vybss is the service surface
              built on top. The testnet is not launched yet, but modules, product flows and
              architecture are already visible.
            </p>

            <div className="flex flex-wrap items-center gap-3 mt-10">
              <a href="#architecture" className="btn-primary">
                Go to platform
                <ArrowUpRight size={15} />
              </a>
              <a href="#network" className="btn-secondary">
                View launch status
              </a>
            </div>

            <div className="mt-10">
              <p className="h-eyebrow mb-3">The most ambitious teams build on composable rails</p>
              <div className="marquee">
                <div className="marquee-track">
                  {railTags.map((item) => (
                    <span key={item} className="chip">{item}</span>
                  ))}
                </div>
                <div className="marquee-track" aria-hidden="true">
                  {railTags.map((item) => (
                    <span key={`dup-${item}`} className="chip">{item}</span>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div className="lg:pl-4">
            <div className="gradient-border overflow-hidden">
              <div className="p-7 border-b border-white/[0.06]">
                <p className="h-eyebrow mb-3">The economy, rebuilt on integrity</p>
                <h3 className="text-[#F0F4FF] text-[28px] font-semibold tracking-[-0.03em] leading-[1.15]">
                  Ownable assets, verifiable flows, business-ready infrastructure.
                </h3>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2">
                {[
                  {
                    title: 'Ownable by design',
                    text: 'Assets, permissions, and service actions are modeled for clear ownership.',
                  },
                  {
                    title: 'Verifiable by default',
                    text: 'Execution, signatures, and status exposed with transparent checkpoints.',
                  },
                  {
                    title: 'Business ready',
                    text: 'Reliability and integration pathways prioritized before public release.',
                  },
                  {
                    title: 'Composable and scalable',
                    text: 'Modules compose into products without redesigning the core rails.',
                  },
                ].map((item, i) => (
                  <div key={item.title} className={`p-5 md:p-6 border-t border-white/[0.06] ${i % 2 === 0 ? 'md:border-r md:border-white/[0.06]' : ''}`}>
                    <p className="h-eyebrow mb-2">{item.title}</p>
                    <p className="text-[13.5px] text-[#AAB5CB] leading-[1.6]">{item.text}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        <p className="text-center text-[11px] text-[#4A5568] mt-10 font-mono tracking-wide">
          Quantos testnet is not launched yet. Public release remains gated by audits, stability and rollout readiness.
        </p>
      </div>
    </section>
  )
}
