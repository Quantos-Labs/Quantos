import { motion } from 'framer-motion'
import { Linkedin, Github } from 'lucide-react'

const teamMembers = [
  { name: 'Yacine Wayle', role: 'CEO', initials: 'YW', photo: '/team/yacine-wayle.png', bio: 'Developed the entire Quantos stack single-handedly. DAG expert and product visionary.', linkedin: 'https://www.linkedin.com/in/yacine-wayle-bb0114217/', github: 'https://github.com/Wayleyy' },
  { name: 'Yann Mastin', role: 'COO', initials: 'YM', photo: '/team/yann-mastin.png', bio: 'Former Nomiks. Tokenomics expert with deep experience in incentive design and DeFi protocols.', linkedin: 'https://www.linkedin.com/in/yannmastin/' },
  { name: 'Imane El Yaqoti', role: 'CFO', initials: 'IE', photo: '/team/imane-elyaqoti.png', bio: 'Several years of financial operations experience in tech and Web3 ventures.', linkedin: 'https://www.linkedin.com/in/imane-ey-7aa001227/' },
  { name: 'Jean-Jacques Quisquater', role: 'Advisor', initials: 'JQ', photo: '/team/jean-jacques-quisquater.png', bio: 'Mentioned in the Bitcoin whitepaper by Satoshi Nakamoto. Pioneer in cryptography and security.', linkedin: 'https://www.linkedin.com/in/jean-jacques-quisquater-3671682/' },
  { name: 'Laurent Leloup', role: 'Managing Director', initials: 'LL', photo: '/team/laurent-leloup.png', bio: 'Quantum computing expert, author and thought leader in quantum-safe technologies.', linkedin: 'https://www.linkedin.com/in/laurentleloup001/' },
  { name: 'Lionel Klein', role: 'Advisor', initials: 'LK', photo: '/team/lionel-klein.png', bio: 'Expert in digital sovereignty and critical infrastructure resilience.' },
  { name: 'Maximiliano Beccera', role: 'CTO', initials: 'MB', bio: 'Expert in AI and blockchain. Oversees all technical architecture and engineering for Quantos.', linkedin: 'https://www.linkedin.com/in/maxbecerra/' },
  { name: 'Iliane Chikhaoui', role: 'Researcher', initials: 'IC', photo: '/team/iliane-chikhaoui.png', bio: 'Student at EM Lyon Business School. Research focus on post-quantum systems and tokenomics.', linkedin: 'https://www.linkedin.com/in/iliane-chikhaoui/' },
  { name: 'Mounir Danyte', role: 'Advisor — Go-to-Market & Marketing', initials: 'MD', photo: '/team/mounir-danyte.png', bio: 'Go-to-market expert with several years of experience scaling Web3 and fintech products.', linkedin: 'https://www.linkedin.com/in/mounir-danyte/' },
]

export default function TeamSection() {
  return (
    <section id="team" className="relative px-6 py-24 overflow-hidden">
      <div className="max-w-6xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-80px' }}
          transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
          className="mb-14"
        >
          <p className="h-eyebrow mb-4">TEAM</p>
          <h2 className="text-[36px] md:text-[48px] font-semibold tracking-[-0.03em] leading-[1.1]">
            The people building <span className="text-cyan-300">Quantos</span>
          </h2>
        </motion.div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {teamMembers.map((member, i) => (
            <motion.div
              key={member.name}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-40px' }}
              transition={{ duration: 0.5, delay: i * 0.08, ease: [0.22, 1, 0.36, 1] }}
              className="group relative bg-[#0B1120] border border-white/[0.06] rounded-2xl p-6 overflow-hidden"
            >
              <div className="absolute inset-0 bg-cyan-400/[0.02] opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
              <div className="relative flex items-center gap-4">
                <div className="w-14 h-14 rounded-full bg-[#131B2E] border border-white/[0.08] flex items-center justify-center shrink-0 overflow-hidden">
                  {'photo' in member && member.photo ? (
                    <img src={member.photo} alt={member.name} className="w-full h-full object-cover" />
                  ) : (
                    <span className="text-[13px] font-semibold text-[#AAB5CB]">{member.initials}</span>
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <h3 className="text-[15px] font-semibold text-[#F0F4FF]">{member.name}</h3>
                    <div className="flex items-center gap-1">
                      {'linkedin' in member && member.linkedin && (
                        <a
                          href={member.linkedin}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-[#5B6478] hover:text-cyan-300 transition-colors"
                          aria-label={`${member.name} LinkedIn`}
                        >
                          <Linkedin size={14} />
                        </a>
                      )}
                      {'github' in member && member.github && (
                        <a
                          href={member.github}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-[#5B6478] hover:text-cyan-300 transition-colors"
                          aria-label={`${member.name} GitHub`}
                        >
                          <Github size={14} />
                        </a>
                      )}
                    </div>
                  </div>
                  <p className="text-[13px] text-cyan-300/80 mt-0.5">{member.role}</p>
                  <p className="text-[12px] text-[#5B6478] mt-1.5 leading-[1.5]">{member.bio}</p>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  )
}
