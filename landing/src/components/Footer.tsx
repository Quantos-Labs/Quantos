const links = [
  { label: 'Platform', href: '#overview' },
  { label: 'Stack', href: '#architecture' },
  { label: 'Security', href: '#security' },
  { label: 'Industries', href: '#catalog' },
  { label: 'Roadmap', href: '#network' },
]

export default function Footer() {
  return (
    <footer className="relative border-t border-white/[0.05] py-12 px-6">
      <div className="max-w-[1200px] mx-auto">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div>
            <div className="flex items-center gap-2.5 mb-2">
              <div className="w-7 h-7 rounded-lg overflow-hidden flex items-center justify-center bg-white/[0.04] border border-white/[0.08]">
                <img src="/quantos-logo.png" alt="Quantos" className="w-full h-full object-contain p-1" loading="lazy" decoding="async" />
              </div>
              <span className="text-[#F5F8FF] font-semibold text-[14px] tracking-[-0.01em]">Quantos</span>
              <span className="text-[10px] text-[#5B6478] uppercase tracking-[0.15em] font-mono pt-0.5">LABS</span>
            </div>
            <p className="text-[12px] text-[#6B7588]">© {new Date().getFullYear()} Quantos Labs. All systems verifiable.</p>
          </div>

          <div className="flex flex-wrap items-center gap-5 text-[12px]">
            {links.map((link) => (
              <a key={link.label} href={link.href} className="text-[#8893AC] hover:text-[#F0F4FF] transition-colors">
                {link.label}
              </a>
            ))}
            <a href="https://github.com/Wayleyy/Quantos_labs" target="_blank" rel="noopener noreferrer" className="text-[#8893AC] hover:text-[#F0F4FF] transition-colors">
              Source
            </a>
          </div>
        </div>
      </div>
    </footer>
  )
}
