import { useEffect, useRef } from 'react'

const LABELS = [
  { text: 'PQC finality', side: 'left-top' },
  { text: '100M+ TPS', side: 'right-mid' },
  { text: 'Zero gas', side: 'left-bottom' },
] as const

export default function SphereGlobe() {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    let raf = 0
    let width = 0
    let height = 0
    let dpr = 1

    const resize = () => {
      const rect = canvas.getBoundingClientRect()
      dpr = Math.min(window.devicePixelRatio || 1, 2)
      width = rect.width * dpr
      height = rect.height * dpr
      canvas.width = width
      canvas.height = height
    }

    resize()
    const ro = new ResizeObserver(resize)
    ro.observe(canvas)

    const particleCount = 520
    const particles: { x: number; y: number; z: number; color: string; size: number }[] = []
    const palette = ['#FFFFFF', '#E0F2FE', '#C7D2E7', '#67E8F9', '#A78BFA']

    for (let i = 0; i < particleCount; i++) {
      const theta = Math.random() * Math.PI * 2
      const phi = Math.acos((Math.random() * 2) - 1)
      const r = 1
      particles.push({
        x: r * Math.sin(phi) * Math.cos(theta),
        y: r * Math.sin(phi) * Math.sin(theta),
        z: r * Math.cos(phi),
        color: palette[Math.floor(Math.random() * palette.length)],
        size: Math.random() * 1.2 + 0.6,
      })
    }

    let angleY = 0
    let angleX = 0.25

    const draw = () => {
      ctx.clearRect(0, 0, width, height)

      const cx = width / 2
      const cy = height / 2
      const radius = Math.min(width, height) * 0.34

      angleY += 0.003
      angleX += 0.0008

      const cosY = Math.cos(angleY)
      const sinY = Math.sin(angleY)
      const cosX = Math.cos(angleX)
      const sinX = Math.sin(angleX)

      const projected = particles.map((p) => {
        let x = p.x * cosY - p.z * sinY
        let z = p.x * sinY + p.z * cosY
        let y = p.y * cosX - z * sinX
        z = p.y * sinX + z * cosX

        const scale = radius / (radius * 0.5 + z + 2.2)
        return {
          x: cx + x * radius * scale,
          y: cy + y * radius * scale,
          z,
          scale,
          color: p.color,
          size: p.size * scale * dpr,
          alpha: 0.4 + 0.6 * ((z + 1) / 2),
        }
      })

      projected.sort((a, b) => a.z - b.z)

      const coreGradient = ctx.createRadialGradient(cx, cy, 0, cx, cy, radius * 1.1)
      coreGradient.addColorStop(0, 'rgba(34, 211, 238, 0.06)')
      coreGradient.addColorStop(0.4, 'rgba(99, 102, 241, 0.04)')
      coreGradient.addColorStop(1, 'rgba(5, 8, 15, 0)')
      ctx.fillStyle = coreGradient
      ctx.beginPath()
      ctx.arc(cx, cy, radius * 1.1, 0, Math.PI * 2)
      ctx.fill()

      const edgeGlow = ctx.createRadialGradient(cx, cy, radius * 0.8, cx, cy, radius * 1.25)
      edgeGlow.addColorStop(0, 'rgba(99, 102, 241, 0)')
      edgeGlow.addColorStop(0.5, 'rgba(34, 211, 238, 0.05)')
      edgeGlow.addColorStop(1, 'rgba(5, 8, 15, 0)')
      ctx.fillStyle = edgeGlow
      ctx.beginPath()
      ctx.arc(cx, cy, radius * 1.25, 0, Math.PI * 2)
      ctx.fill()

      for (const p of projected) {
        const alpha = Math.max(0.15, Math.min(1, p.alpha))
        ctx.globalAlpha = alpha
        ctx.fillStyle = p.color
        ctx.beginPath()
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2)
        ctx.fill()
      }
      ctx.globalAlpha = 1

      ctx.save()
      ctx.translate(cx, cy)
      const logoSize = radius * 0.26
      ctx.fillStyle = 'rgba(255, 255, 255, 0.08)'
      ctx.beginPath()
      ctx.roundRect(-logoSize / 2, -logoSize / 2, logoSize, logoSize, logoSize * 0.22)
      ctx.fill()
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.16)'
      ctx.lineWidth = 1 * dpr
      ctx.stroke()

      ctx.fillStyle = '#F0F4FF'
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      const fontSize = logoSize * 0.55
      ctx.font = `${fontSize}px Sora, system-ui, sans-serif`
      ctx.fillText('Q', 0, fontSize * 0.04)
      ctx.restore()

      raf = requestAnimationFrame(draw)
    }

    draw()

    return () => {
      cancelAnimationFrame(raf)
      ro.disconnect()
    }
  }, [])

  return (
    <div className="relative w-full h-[420px] md:h-[520px] lg:h-[580px]">
      <canvas
        ref={canvasRef}
        className="absolute inset-0 w-full h-full"
        aria-hidden="true"
      />

      <div className="absolute inset-0 pointer-events-none">
        {LABELS.map((label) => {
          const positions: Record<string, string> = {
            'left-top': 'left-[8%] top-[18%]',
            'right-mid': 'right-[6%] top-[46%]',
            'left-bottom': 'left-[10%] bottom-[18%]',
          }
          return (
            <div
              key={label.text}
              className={`absolute ${positions[label.side]} flex items-center gap-2`}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-300/80 shadow-[0_0_8px_rgba(34,211,238,0.6)]" />
              <span className="px-2.5 py-1 text-[11px] font-medium tracking-wide text-[#B0BAD0] bg-[#0B1120]/60 border border-white/[0.08] rounded-md backdrop-blur-sm font-mono">
                {label.text}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
