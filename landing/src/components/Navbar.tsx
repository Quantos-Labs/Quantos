import { useState, useEffect } from 'react'
import { Menu, X, ArrowUpRight } from 'lucide-react'

const navLinks = [
  { label: 'Platform', href: '#overview' },
  { label: 'How it works', href: '#how-it-works' },
  { label: 'Stack', href: '#architecture' },
  { label: 'L0 Hub', href: '#l0' },
  { label: 'Security', href: '#security' },
  { label: 'Industries', href: '#catalog' },
  { label: 'Roadmap', href: '#network' },
  { label: 'Team', href: '#team' },
]

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8)
    window.addEventListener('scroll', onScroll)
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  return (
    <nav
      className={`fixed top-4 left-0 right-0 z-50 transition-all duration-700 px-4 ${
        scrolled
          ? 'bg-[#07101A]/70 backdrop-blur-2xl shadow-[0_18px_60px_-28px_rgba(8,39,74,0.85)]'
          : 'bg-transparent'
      }`}
    >
      <div className="max-w-[1200px] mx-auto px-5 h-[68px] flex items-center justify-between rounded-full border border-white/[0.06] bg-white/[0.02] backdrop-blur-2xl">
        <a href="#" className="flex items-center gap-2.5 group">
          <div className="w-8 h-8 rounded-full overflow-hidden flex items-center justify-center bg-white/[0.05] border border-white/[0.08] shadow-[0_0_20px_rgba(99,102,241,0.18)]">
            <img
              src="/quantos-logo.png"
              alt="Quantos"
              className="w-full h-full object-contain p-1"
              loading="eager"
              decoding="async"
            />
          </div>
          <span className="text-[#F5F8FF] font-semibold text-[14px] tracking-[-0.01em]">
            Quantos
          </span>
          <span className="hidden sm:inline-block ml-1 text-[10px] text-[#5B6478] uppercase tracking-[0.15em] font-mono pt-0.5">
            Labs
          </span>
        </a>

        <div className="hidden md:flex items-center gap-1 absolute left-1/2 -translate-x-1/2 px-2 py-1 rounded-full border border-white/[0.05] bg-white/[0.02]">
          {navLinks.map((link) => (
            <a
              key={link.label}
              href={link.href}
              className="text-[13px] text-[#8B95A8] hover:text-[#F0F4FF] transition-all px-3 py-1.5 rounded-full hover:bg-white/[0.06]"
            >
              {link.label}
            </a>
          ))}
        </div>

        <div className="hidden md:flex items-center gap-3">
          <a
            href="#services"
            className="text-[13px] text-[#8B95A8] hover:text-[#F0F4FF] transition-colors"
          >
            Product tour
          </a>
          <a
            href="https://github.com/Wayleyy/Quantos_labs"
            target="_blank"
            rel="noopener noreferrer"
            className="text-[13px] text-[#8B95A8] hover:text-[#F0F4FF] transition-colors flex items-center gap-1"
          >
            Source
            <ArrowUpRight size={12} className="opacity-50" />
          </a>
        </div>

        <button
          onClick={() => setMobileOpen(!mobileOpen)}
          className="md:hidden text-[#B0BAD0] hover:text-white p-2 rounded-full border border-white/[0.06] bg-white/[0.03]"
          aria-label="Toggle menu"
        >
          {mobileOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </div>

      {mobileOpen && (
        <div className="md:hidden bg-[#05080F]/95 backdrop-blur-2xl border-b border-white/[0.06]">
          <div className="px-6 py-4 flex flex-col gap-1">
            {navLinks.map((link) => (
              <a
                key={link.label}
                href={link.href}
                onClick={() => setMobileOpen(false)}
                className="text-[#B0BAD0] hover:text-[#F0F4FF] transition-colors py-2.5 text-sm"
              >
                {link.label}
              </a>
            ))}
            <a
              href="#services"
              onClick={() => setMobileOpen(false)}
              className="mt-3 text-sm px-4 py-2.5 rounded-xl bg-white text-[#05080F] font-bold text-center"
            >
              Explore services
            </a>
          </div>
        </div>
      )}
    </nav>
  )
}
