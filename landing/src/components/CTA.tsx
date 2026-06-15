import { motion } from 'framer-motion'
import { ArrowUpRight, Github } from 'lucide-react'

const actionCards = [
  {
    title: 'Start building',
    desc: 'Build, launch, and scale products with Quantos architecture and Vybss service rails.',
    href: '#architecture',
    label: 'Read launch playbook',
  },
  {
    title: 'Start coding',
    desc: 'Get the technical base, modules, and implementation references in the source repo.',
    href: 'https://github.com/Wayleyy/Quantos_labs',
    label: 'Go to docs and source',
  },
  {
    title: 'Start integrating',
    desc: 'Integrate wallet, trading, and service modules on top of Quantos primitives.',
    href: '#services',
    label: 'Explore integration layer',
  },
  {
    title: 'Track launch status',
    desc: 'Follow transparent rollout gates, readiness checkpoints, and public launch status.',
    href: '#network',
    label: 'View roadmap status',
  },
]

export default function CTA() {
  return (
    <section
      id="cta"
      className="relative py-28 px-6 overflow-hidden border-t border-white/[0.04]"
    >
      <div className="aurora opacity-50" />

      <div className="relative z-10 max-w-3xl mx-auto text-center">
        <motion.div
          initial={{ opacity: 0, y: 24, scale: 0.99 }}
          whileInView={{ opacity: 1, y: 0, scale: 1 }}
          viewport={{ once: true, margin: '-80px' }}
          transition={{ duration: 0.85, ease: [0.22, 1, 0.36, 1] }}
        >
          <h2
            className="font-display mb-6"
            style={{ fontSize: 'clamp(40px, 6vw, 72px)', lineHeight: 0.98 }}
          >
            <span className="bg-gradient-to-b from-white via-white to-[#A8B4CD] bg-clip-text text-transparent">
              Start building on
            </span>
            <br />
            <span className="bg-gradient-to-b from-white via-white to-[#A8B4CD] bg-clip-text text-transparent">
              Quantos post-quantum DAG{' '}
            </span>
            <span className="text-shimmer italic font-light">with a clear launch path.</span>
          </h2>

          <p className="text-[#8893AC] text-[17px] leading-[1.55] mb-10 max-w-xl mx-auto">
            Product and infrastructure evolve together: design the surface, prove the stack,
            then roll out the network when readiness gates are complete.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-10 text-left">
            {actionCards.map((card, i) => (
              <motion.a
                key={card.title}
                href={card.href}
                target={card.href.startsWith('http') ? '_blank' : undefined}
                rel={card.href.startsWith('http') ? 'noopener noreferrer' : undefined}
                initial={{ opacity: 0, y: 14 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.55, delay: 0.06 * i, ease: [0.22, 1, 0.36, 1] }}
                className="card p-5 block hover:-translate-y-1 hover:scale-[1.01] transition-transform duration-500"
              >
                <p className="h-eyebrow mb-2">{card.title}</p>
                <p className="text-[#F0F4FF] text-[18px] font-semibold tracking-[-0.02em] mb-2">{card.label}</p>
                <p className="text-[13px] text-[#8893AC] leading-relaxed mb-4">{card.desc}</p>
                <span className="inline-flex items-center gap-1 text-[#A8B4CD] text-[13px]">
                  Continue
                  <ArrowUpRight size={13} />
                </span>
              </motion.a>
            ))}
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-3 transition-transform duration-500">
            <a
              href="https://github.com/Wayleyy/Quantos_labs"
              target="_blank"
              rel="noopener noreferrer"
              className="btn-primary"
            >
              <Github size={14} />
              Explore Quantos source
            </a>
            <a href="#architecture" className="btn-secondary">
              Browse architecture
              <ArrowUpRight size={15} />
            </a>
          </div>

          <div className="mt-14 flex items-center justify-center gap-6">
            {[
              { label: 'Platform', href: '#architecture' },
              { label: 'Solutions', href: '#catalog' },
              { label: 'Developers', href: 'https://github.com/Wayleyy/Quantos_labs' },
              { label: 'Network info', href: '#network' },
            ].map((link, i) => (
              <span key={link.label} className="flex items-center gap-6">
                <a
                  href={link.href}
                  target={link.href.startsWith('http') ? '_blank' : undefined}
                  rel={link.href.startsWith('http') ? 'noopener noreferrer' : undefined}
                  className="text-[12px] text-[#5B6478] hover:text-[#B0BAD0] transition-colors"
                >
                  {link.label}
                </a>
                {i < 3 && <span className="text-[#1E2A3A] text-[10px]">·</span>}
              </span>
            ))}
          </div>
        </motion.div>
      </div>
    </section>
  )
}
