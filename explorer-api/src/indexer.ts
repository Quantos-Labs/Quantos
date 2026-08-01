import { supabaseAdmin } from './db.js'
import { rpc, type ConfirmedTransactionInfo } from './rpc-client.js'
import { config } from './config.js'

let lastIndexedSlot = 0
let lastIndexedTxSlot = 0
let isRunning = false

async function getLastIndexedBlock(): Promise<number> {
  const { data } = await supabaseAdmin
    .from('blocks')
    .select('height')
    .order('height', { ascending: false })
    .limit(1)
    .single()
  return data?.height ?? 0
}

async function getLastIndexedTxSlot(): Promise<number> {
  const { data } = await supabaseAdmin
    .from('network_stats')
    .select('value')
    .eq('key', 'last_indexed_tx_slot')
    .single()
  return data ? Number(data.value) : 0
}

async function indexValidators(): Promise<void> {
  try {
    const res = await rpc.getValidators()
    const sorted = [...res.validators].sort((a, b) => {
      const stakeA = BigInt(a.stake.replace('QTS:', '') || '0')
      const stakeB = BigInt(b.stake.replace('QTS:', '') || '0')
      return stakeB > stakeA ? 1 : stakeB < stakeA ? -1 : 0
    })

    for (let i = 0; i < sorted.length; i++) {
      const v = sorted[i]
      const status = v.jailed ? 'jailed' : v.active ? 'active' : 'inactive'
      await supabaseAdmin.from('validators').upsert({
        address: v.address,
        stake: v.stake,
        commission_rate: v.commission_rate / 100,
        status,
        jailed: v.jailed,
        slash_count: v.slash_count,
        last_active_slot: v.last_active_slot,
        rank: i + 1,
      }, { onConflict: 'address' })
    }

    await updateStat('total_validators', String(res.total_active))
    await updateStat('total_stake', res.total_stake)
    console.log(`[indexer] indexed ${sorted.length} validators`)
  } catch (err) {
    console.error('[indexer] failed to index validators:', err)
  }
}

async function indexMetrics(): Promise<void> {
  try {
    const metrics = await rpc.getMetrics()
    await updateStat('current_slot', String(metrics.current_slot))
    await updateStat('current_epoch', String(metrics.current_epoch))
    await updateStat('finalized_slot', String(metrics.finalized_slot))
    await updateStat('pending_transactions', String(metrics.pending_transactions))
    await updateStat('total_validators', String(metrics.total_validators))
    await updateStat('confirmed_vertices', String(metrics.confirmed_vertices))
  } catch (err) {
    console.error('[indexer] failed to index metrics:', err)
  }
}

async function indexTransactions(): Promise<void> {
  try {
    const txs = lastIndexedTxSlot === 0
      ? await rpc.getRecentTransactions(200)
      : await rpc.getReceiptsSinceSlot(lastIndexedTxSlot + 1, 200)
    if (txs.length === 0) return

    let count = 0
    let maxSlot = lastIndexedTxSlot

    for (const tx of txs) {
      const timestamp = normalizeTimestamp(tx.timestamp)

      await ensureBlockExists(tx.slot, tx.shard_id, timestamp, tx.gas_used)

      const { error } = await supabaseAdmin.from('transactions').upsert({
        hash: tx.hash,
        block_height: tx.slot,
        from_address: tx.from,
        to_address: tx.to,
        value: tx.value,
        tx_type: tx.tx_type,
        status: tx.status,
        nonce: tx.nonce,
        gas_used: tx.gas_used,
        gas_price: 0,
        shard_id: tx.shard_id,
        timestamp,
      }, { onConflict: 'hash' })

      if (error) {
        console.error(`[indexer] failed to upsert tx ${tx.hash}:`, error.message)
      } else {
        count++
      }

      if (tx.slot > maxSlot) maxSlot = tx.slot

      // Also upsert accounts (from + to)
      for (const addr of [tx.from, tx.to]) {
        if (addr && addr !== 'QTS:' + '0'.repeat(64)) {
          await supabaseAdmin.from('accounts').upsert({
            address: addr,
            last_active: timestamp,
          }, { onConflict: 'address' }).then(() => {})
        }
      }
    }

    if (maxSlot > lastIndexedTxSlot) {
      lastIndexedTxSlot = maxSlot
      await updateStat('last_indexed_tx_slot', String(maxSlot))
    }

    // Update total_transactions count
    const { count: totalCount } = await supabaseAdmin
      .from('transactions')
      .select('*', { count: 'exact', head: true })
    if (totalCount !== null) {
      await updateStat('total_transactions', String(totalCount))
    }

    if (count > 0) {
      console.log(`[indexer] indexed ${count} transactions (up to slot ${maxSlot})`)
    }
  } catch (err) {
    console.error('[indexer] failed to index transactions:', err)
  }
}

async function ensureBlockExists(height: number, shardId: number, timestamp: string, gasUsed: number): Promise<void> {
  await supabaseAdmin.from('blocks').upsert({
    height,
    hash: `QTS:${height.toString(16).padStart(64, '0')}`,
    parent_hash: `QTS:${Math.max(0, height - 1).toString(16).padStart(64, '0')}`,
    timestamp,
    tx_count: 0,
    validator: `QTS:${'0'.repeat(64)}`,
    shard_id: shardId,
    gas_limit: gasUsed,
    gas_used: gasUsed,
    state_root: `QTS:${'0'.repeat(64)}`,
    size_bytes: 0,
  }, { onConflict: 'height' })
}

function normalizeTimestamp(timestamp: number): string {
  if (timestamp <= 0) return new Date().toISOString()
  const ms = timestamp > 1_000_000_000_000 ? timestamp : timestamp * 1000
  return new Date(ms).toISOString()
}

async function updateStat(key: string, value: string): Promise<void> {
  await supabaseAdmin.from('network_stats').upsert(
    { key, value, updated_at: new Date().toISOString() },
    { onConflict: 'key' }
  )
}

async function poll(): Promise<void> {
  if (isRunning) return
  isRunning = true

  try {
    const currentSlot = await rpc.getSlot()

    if (currentSlot > lastIndexedSlot) {
      await indexMetrics()
      await indexTransactions()

      // Index validators every 32 slots (~epoch boundary)
      if (currentSlot % 32 === 0 || lastIndexedSlot === 0) {
        await indexValidators()
      }

      lastIndexedSlot = currentSlot
    }
  } catch (err) {
    // Node might not be running yet — silently retry
    if (String(err).includes('ECONNREFUSED')) {
      // Node offline, skip
    } else {
      console.error('[indexer] poll error:', err)
    }
  } finally {
    isRunning = false
  }
}

async function main(): Promise<void> {
  console.log('[indexer] starting Quantos Explorer indexer')
  console.log(`[indexer] Quantos RPC: ${config.quantos.rpcUrl}`)
  console.log(`[indexer] Supabase: ${config.supabase.url}`)
  console.log(`[indexer] poll interval: ${config.indexer.pollIntervalMs}ms`)

  lastIndexedSlot = await getLastIndexedBlock()
  lastIndexedTxSlot = await getLastIndexedTxSlot()
  console.log(`[indexer] resuming from slot ${lastIndexedSlot}, tx slot ${lastIndexedTxSlot}`)

  // Initial poll
  await poll()

  // Continuous polling
  setInterval(poll, config.indexer.pollIntervalMs)
}

main().catch((err) => {
  console.error('[indexer] fatal:', err)
  process.exit(1)
})
