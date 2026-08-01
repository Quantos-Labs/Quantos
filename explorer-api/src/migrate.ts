import { readFileSync } from 'fs'
import { resolve, dirname } from 'path'
import { fileURLToPath } from 'url'
import { supabaseAdmin } from './db.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

/**
 * Split SQL into statements, respecting DO $$ ... END $$ blocks and
 * single-quoted strings that may contain semicolons.
 */
function splitSqlStatements(sql: string): string[] {
  const statements: string[] = []
  let current = ''
  let inDollarQuote = false
  let dollarTag = ''
  let inSingleQuote = false

  for (let i = 0; i < sql.length; i++) {
    const char = sql[i]
    const next = sql[i + 1]
    current += char

    // Handle single-quoted strings
    if (char === "'" && !inDollarQuote) {
      if (inSingleQuote && next === "'") {
        // Escaped quote ''
        current += next
        i++
        continue
      }
      inSingleQuote = !inSingleQuote
      continue
    }

    if (inSingleQuote) continue

    // Handle dollar-quoted blocks ($$ ... $$ or $tag$ ... $tag$)
    if (char === '$' && !inDollarQuote) {
      // Find the dollar tag
      let tag = ''
      let j = i + 1
      while (j < sql.length && sql[j] !== '$' && sql[j] !== '\n') {
        tag += sql[j]
        j++
      }
      if (sql[j] === '$') {
        inDollarQuote = true
        dollarTag = tag
        current += sql.slice(i + 1, j + 1)
        i = j
        continue
      }
    }

    if (inDollarQuote) {
      // Look for closing $tag$
      const closing = `$${dollarTag}$`
      if (current.endsWith(closing)) {
        inDollarQuote = false
        dollarTag = ''
      }
      continue
    }

    // Statement separator: semicolon followed by newline
    if (char === ';' && (next === '\n' || next === '\r' || next === undefined)) {
      const trimmed = current.trim()
      if (trimmed.length > 0 && !trimmed.startsWith('--')) {
        statements.push(trimmed)
      }
      current = ''
    }
  }

  // Catch any trailing statement without semicolon
  const trimmed = current.trim()
  if (trimmed.length > 0 && !trimmed.startsWith('--')) {
    statements.push(trimmed)
  }

  return statements
}

async function migrate() {
  const sql = readFileSync(
    resolve(__dirname, '../supabase/migrations/001_schema.sql'),
    'utf-8'
  )

  const statements = splitSqlStatements(sql)

  console.log(`[migrate] running ${statements.length} statements...`)

  let success = 0
  let failed = 0

  for (const stmt of statements) {
    // Add trailing semicolon if missing
    const query = stmt.endsWith(';') ? stmt : stmt + ';'
    const { error } = await supabaseAdmin.rpc('exec_sql', { query })
    if (error) {
      console.warn(`[migrate] FAILED: ${error.message}`)
      console.warn(`           statement: ${stmt.substring(0, 100)}...`)
      failed++
    } else {
      success++
    }
  }

  console.log(`[migrate] done — ${success} succeeded, ${failed} failed`)
  if (failed > 0) {
    console.log('[migrate] some statements failed — you may need to run them manually in Supabase SQL Editor')
  }
}

migrate().catch((err) => {
  console.error('[migrate] fatal:', err)
  process.exit(1)
})
