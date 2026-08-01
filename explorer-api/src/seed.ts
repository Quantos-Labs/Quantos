import { supabaseAdmin } from './db.js'

// ============================================================================
// Quantos Explorer — Wipe all data
// Clears Supabase tables. Data will be populated by the indexer when the
// testnet goes live.
// ============================================================================

async function wipe() {
  console.log('[wipe] clearing all explorer data...')

  await supabaseAdmin.from('tokens').delete().neq('address', '')
  await supabaseAdmin.from('contracts').delete().neq('address', '')
  await supabaseAdmin.from('transactions').delete().neq('hash', '')
  await supabaseAdmin.from('blocks').delete().neq('height', -1)
  await supabaseAdmin.from('vertices').delete().neq('hash', '')
  await supabaseAdmin.from('validators').delete().neq('address', '')
  await supabaseAdmin.from('accounts').delete().neq('address', '')
  await supabaseAdmin.from('network_stats').delete().neq('key', '')

  console.log('[wipe] all tables cleared — explorer is empty')
  console.log('[wipe] data will be populated by the indexer when the testnet launches')
}

wipe().catch((err) => {
  console.error('[wipe] error:', err)
  process.exit(1)
})
