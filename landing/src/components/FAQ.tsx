import { motion } from 'framer-motion'
import { useEffect } from 'react'

const questions = [
  {
    q: 'What is a post-quantum DAG?',
    a: 'A post-quantum DAG uses cryptographic algorithms resistant to quantum computer attacks. Quantos implements NIST-standardized PQC signatures (Dilithium, SPHINCS+) alongside classical cryptography to ensure long-term security.',
  },
  {
    q: 'Is the Quantos testnet live?',
    a: 'Not yet. Public network access is gated by audits, stability, and rollout readiness. Product surfaces and architecture are already visible.',
  },
  {
    q: 'What makes Quantos quantum-safe?',
    a: 'A hybrid signature path compatible with NIST PQC candidates (Dilithium, SPHINCS+) sits alongside classical signatures, with an explicit migration roadmap toward full quantum resistance.',
  },
  {
    q: 'Can I build on a quantum-safe Layer 1 before testnet?',
    a: 'Yes. Quantos exposes wallet, identity, payment and AI modules today on its post-quantum DAG primitives. Integrate now, settle on mainnet when the network opens.',
  },
  {
    q: 'How is settlement coordinated on Quantos?',
    a: 'A DAG core enables parallel transaction graphs with deterministic ordering, designed for high-throughput service composition and zero-gas settlement.',
  },
  {
    q: 'Where can I read the quantum-safe security model?',
    a: 'The source repository hosts the threat model, benchmarks and review milestones. External review gates every public release of the post-quantum DAG infrastructure.',
  },
]

export default function FAQ() {
  useEffect(() => {
    const schema = {
      '@context': 'https://schema.org',
      '@type': 'FAQPage',
      'mainEntity': questions.map((item) => ({
        '@type': 'Question',
        'name': item.q,
        'acceptedAnswer': {
          '@type': 'Answer',
          'text': item.a,
        },
      })),
    }
    const script = document.createElement('script')
    script.type = 'application/ld+json'
    script.text = JSON.stringify(schema)
    script.id = 'faq-schema'
    document.head.appendChild(script)
    return () => {
      const existing = document.getElementById('faq-schema')
      if (existing) existing.remove()
    }
  }, [])

  return (
    <section id="questions" className="relative py-24 px-6 border-t border-white/[0.04]">
      <div className="max-w-[1200px] mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-80px' }}
          transition={{ duration: 0.7 }}
          className="max-w-3xl mb-12"
        >
          <p className="h-eyebrow mb-4">- Questions</p>
          <h2 className="font-display text-[#F0F4FF] mb-4" style={{ fontSize: 'clamp(34px, 5vw, 56px)', lineHeight: 1.02 }}>
            Post-quantum blockchain questions, answered.
          </h2>
        </motion.div>

        <div className="space-y-3">
          {questions.map((item, i) => (
            <motion.details
              key={item.q}
              initial={{ opacity: 0, y: 10 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.45, delay: i * 0.05 }}
              className="card p-5 group"
            >
              <summary className="list-none cursor-pointer flex items-center justify-between text-[#F0F4FF] text-[15px] font-medium">
                {item.q}
                <span className="text-[#6B7588] group-open:rotate-45 transition-transform">+</span>
              </summary>
              <p className="text-[#8893AC] text-[14px] leading-relaxed mt-4 pr-8">{item.a}</p>
            </motion.details>
          ))}
        </div>
      </div>
    </section>
  )
}
