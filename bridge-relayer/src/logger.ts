const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 } as const
type Level = keyof typeof LEVELS

let currentLevel: Level = 'info'

export function setLogLevel(level: Level): void {
  currentLevel = level
}

function fmt(level: Level, msg: string, ...args: unknown[]): void {
  if (LEVELS[level] < LEVELS[currentLevel]) return
  const ts = new Date().toISOString()
  const prefix = `[${ts}] [relayer] [${level.toUpperCase()}]`
  if (args.length > 0) {
    const extra = args.map(a => {
      if (a instanceof Error) return `${a.message}\n${a.stack}`
      if (typeof a === 'object') return JSON.stringify(a)
      return String(a)
    }).join(' ')
    console.log(`${prefix} ${msg} ${extra}`)
  } else {
    console.log(`${prefix} ${msg}`)
  }
}

export const logger = {
  debug: (msg: string, ...args: unknown[]) => fmt('debug', msg, ...args),
  info: (msg: string, ...args: unknown[]) => fmt('info', msg, ...args),
  warn: (msg: string, ...args: unknown[]) => fmt('warn', msg, ...args),
  error: (msg: string, ...args: unknown[]) => fmt('error', msg, ...args),
}
