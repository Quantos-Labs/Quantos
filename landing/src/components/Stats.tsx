import { motion } from 'framer-motion'
import { CheckCircle2 } from 'lucide-react'

const builderPoints = [
  'Ship faster with one integrated service surface',
  'Scale on a DAG core with post-quantum-ready crypto path',
  'Keep product UX familiar while infra stays verifiable',
  'Monetize across AI, trading, social, and creator rails',
]

const userPoints = [
  'Own identity, assets, and activity across modules',
  'Move value through one wallet and shared account layer',
  'Get transparent product status before network launch',
  'Access unified tools instead of fragmented apps',
]

const quickFacts = [
  { label: 'SERVICE MODULES', value: '120+' },
  { label: 'CORE SETTLEMENT', value: 'DAG' },
  { label: 'L0 FINALITY', value: '<1.5s' },
  { label: 'SECURITY POSTURE', value: 'PQC' },
  { label: 'STARK BATCH SIZE', value: '1K tx' },
  { label: 'PRODUCT SURFACES LIVE', value: '24' },
]

export default function Stats() {
  return (
    <section className="relative py-14 px-6 border-t border-white/[0.04]">
      <div className="max-w-[1200px] mx-auto">
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
            One post-quantum DAG platform,
            <span className="text-shimmer italic font-light"> many roles.</span>
          </h2>
          <p className="text-[#8893AC] text-[17px] leading-[1.55]">
            Quantos is a post-quantum Layer 1 DAG built for both builders and users.
            The infrastructure layer enables unprecedented product velocity and composability
            with quantum-safe cryptography and zero-gas settlement.
          </p>
        </motion.div>

        <div className="space-y-4">
          <div className="rounded-3xl border border-white/[0.06] bg-white/[0.02] backdrop-blur-xl overflow-hidden">
          <div className="grid md:grid-cols-2">
            <motion.div
              initial={{ opacity: 0, y: 26 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-70px' }}
              transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
              className="p-8 md:p-10 border-b md:border-b-0 md:border-r border-white/[0.06]"
            >
              <p className="h-eyebrow mb-5">Why builders choose Quantos</p>
              <div className="space-y-3.5">
                {builderPoints.map((point, i) => (
                  <div key={point} className="flex items-start gap-3">
                    <CheckCircle2 size={16} className="text-[#67E8F9] mt-0.5 shrink-0" />
                    <p className="text-[14px] text-[#D7E3FA] leading-relaxed">
                      <span className="text-[#6B7588] font-mono text-[11px] mr-2">0{i + 1}</span>
                      {point}
                    </p>
                  </div>
                ))}
              </div>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 26 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-70px' }}
              transition={{ duration: 0.8, delay: 0.08, ease: [0.22, 1, 0.36, 1] }}
              className="p-8 md:p-10"
            >
              <p className="h-eyebrow mb-5">How users benefit</p>
              <div className="space-y-3.5">
                {userPoints.map((point, i) => (
                  <div key={point} className="flex items-start gap-3">
                    <CheckCircle2 size={16} className="text-[#A78BFA] mt-0.5 shrink-0" />
                    <p className="text-[14px] text-[#D7E3FA] leading-relaxed">
                      <span className="text-[#6B7588] font-mono text-[11px] mr-2">0{i + 1}</span>
                      {point}
                    </p>
                  </div>
                ))}
              </div>
            </motion.div>
          </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          {quickFacts.map((fact, i) => (
            <motion.div
              key={fact.label}
              initial={{ opacity: 0, y: 14, scale: 0.98 }}
              whileInView={{ opacity: 1, y: 0, scale: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.55, delay: i * 0.06, ease: [0.22, 1, 0.36, 1] }}
              className="rounded-2xl border border-white/[0.06] bg-white/[0.015] p-5 hover:border-white/[0.14] hover:bg-white/[0.03] transition-all duration-500"
            >
              <p className="h-eyebrow mb-2">{fact.label}</p>
              <p className="text-[32px] font-bold leading-none tracking-[-0.03em] text-[#F0F4FF]">
                {fact.value}
              </p>
            </motion.div>
          ))}
          </div>
        </div>
      </div>
    </section>
  )
}
