import { motion } from 'framer-motion'
import { Pen, Upload, TrendingUp } from 'lucide-react'

const steps = [
  {
    num: '01',
    icon: Pen,
    title: 'Create & edit',
    desc: 'Upload content or record directly in Vybss. Kai AI instantly adds captions, extracts highlights, enhances audio, and auto-crops for every format — Stories, Clips, and Live.',
    color: '#00C2FF',
    tags: ['AI captions', 'Smart crop', 'Audio enhance', 'Highlight reel'],
  },
  {
    num: '02',
    icon: Upload,
    title: 'Publish & reach',
    desc: 'One tap to publish or go live. Content is served globally via CDN across 120+ countries. The feed surfaces your content to interested audiences — not just your existing followers.',
    color: '#7C3AED',
    tags: ['One-tap publish', 'Global CDN', 'Multi-format', 'Discovery feed'],
  },
  {
    num: '03',
    icon: TrendingUp,
    title: 'Earn in real time',
    desc: 'Ads run via Google IMA + Unity LevelPlay. Every impression generates revenue — 60% flows directly to you, settled on Quantos DAG in under 400ms, no minimum payout.',
    color: '#FF6B2B',
    tags: ['60% share', '<400ms payout', 'Multi-format ads', 'No minimum'],
  },
]

export default function TechStack() {
  return (
    <section id="tech" className="py-28 px-6">
      <div className="max-w-5xl mx-auto">

        <motion.div
          initial={{ opacity: 0, y: 24 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="max-w-xl mb-20"
        >
          <p className="text-xs font-mono text-[#4A5568] uppercase tracking-widest mb-4">How it works</p>
          <h2 className="text-[clamp(30px,4.5vw,52px)] font-black tracking-[-0.03em] text-[#F0F4FF] leading-[1.1] mb-4">
            Three steps from<br />zero to creator.
          </h2>
          <p className="text-[#8B95A8] text-base leading-relaxed">
            No setup fees, no minimum audience size, no monthly minimum payout. Start earning from your very first video.
          </p>
        </motion.div>

        <div className="relative">
          {/* Vertical timeline line */}
          <div className="absolute left-[27px] top-14 bottom-14 w-px bg-gradient-to-b from-[#00C2FF]/40 via-[#7C3AED]/40 to-[#FF6B2B]/40 hidden md:block" />

          <div className="flex flex-col gap-12">
            {steps.map((step, i) => (
              <motion.div
                key={step.num}
                initial={{ opacity: 0, x: -20 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.6, delay: i * 0.15 }}
                className="relative flex gap-8 items-start"
              >
                {/* Icon (timeline dot) */}
                <div
                  className="relative shrink-0 w-14 h-14 rounded-2xl flex items-center justify-center z-10"
                  style={{ background: `${step.color}18`, border: `1px solid ${step.color}35` }}
                >
                  <step.icon size={22} style={{ color: step.color }} />
                </div>

                <div className="flex-1 pb-2">
                  <div className="flex items-center gap-3 mb-3">
                    <span className="text-xs font-mono text-[#4A5568] font-bold">{step.num}</span>
                    <h3 className="text-[#F0F4FF] font-bold text-xl">{step.title}</h3>
                  </div>
                  <p className="text-[#8B95A8] text-base leading-relaxed mb-4 max-w-lg">{step.desc}</p>
                  <div className="flex flex-wrap gap-2">
                    {step.tags.map((tag) => (
                      <span
                        key={tag}
                        className="text-xs px-2.5 py-1 rounded-full font-medium"
                        style={{ background: `${step.color}12`, color: step.color, border: `1px solid ${step.color}28` }}
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>

      </div>
    </section>
  )
}

