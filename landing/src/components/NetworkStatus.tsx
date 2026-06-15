import { motion } from 'framer-motion'
import { GitBranch } from 'lucide-react'

export default function NetworkStatus() {
  return (
    <section
      id="network"
      className="relative py-28 px-6 border-t border-white/[0.04]"
    >
      <div className="absolute inset-0 mesh-bg opacity-25 pointer-events-none" />

      <div className="relative max-w-[1200px] mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-80px' }}
          transition={{ duration: 0.7 }}
          className="flex items-end justify-between flex-wrap gap-6 mb-12"
        >
          <div className="max-w-2xl">
            <p className="h-eyebrow mb-5 flex items-center gap-2">
              <GitBranch size={11} className="text-[#A78BFA]" />
              Roadmap
            </p>
            <h2
              className="font-display text-[#F0F4FF] mb-6"
              style={{ fontSize: 'clamp(36px, 5vw, 64px)', lineHeight: 1.02 }}
            >
              Transparent post-quantum DAG{' '}
              <span className="text-shimmer italic font-light">launch status.</span>
            </h2>
            <p className="text-[#8893AC] text-[17px] leading-[1.55]">
              The quantum-safe product stack is visible and accessible. Quantos testnet is not live yet.
              We are finalizing hardening, audits, and release sequencing before opening public network access.
            </p>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-50px' }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="gradient-border overflow-hidden"
        >
          <div className="backdrop-blur-2xl p-8 md:p-10">
            <div className="space-y-4">
              {[
                {
                  title: 'Core chain architecture — built',
                  status: 'done',
                  color: '#22C55E',
                },
                {
                  title: 'L0 finality hub with PQC proofs — built',
                  status: 'done',
                  color: '#22C55E',
                },
                {
                  title: 'Vybss service stack — live product surfaces',
                  status: 'active',
                  color: '#FBBF24',
                },
                {
                  title: 'Quantos testnet — not launched yet',
                  status: 'pending',
                  color: '#67E8F9',
                },
                {
                  title: 'Public rollout — after audits and stability gates',
                  status: 'planned',
                  color: '#A78BFA',
                },
              ].map((item) => (
                <div
                  key={item.title}
                  className="flex items-center justify-between py-3 border-b border-white/[0.04] last:border-0"
                >
                  <div className="flex items-center gap-3">
                    <span className="w-1.5 h-1.5 rounded-full" style={{ background: item.color }} />
                    <p className="text-[14px] md:text-[15px] text-[#F0F4FF] font-medium tracking-[-0.01em]">
                      {item.title}
                    </p>
                  </div>
                  <span
                    className="text-[10px] font-mono uppercase tracking-[0.12em] px-2 py-0.5 rounded"
                    style={{
                      color: item.color,
                      background: `${item.color}10`,
                      border: `1px solid ${item.color}20`,
                    }}
                  >
                    {item.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  )
}
