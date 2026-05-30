import { createClient } from '@supabase/supabase-js'
import { config } from './config.js'
import { logger } from './logger.js'

const supabase = createClient(config.supabaseUrl, config.supabaseServiceRoleKey)

export interface BridgeDeposit {
  id: string
  direction: 'quantos_to_base' | 'base_to_quantos'
  status: 'pending' | 'quantos_confirmed' | 'relaying' | 'completed' | 'failed'
  user_id: string | null
  quantos_tx_hash: string
  quantos_sender: string
  quantos_nonce: number | null
  base_recipient: string
  base_tx_hash: string | null
  amount: string
  amount_raw: string
  vault_address: string
  deposit_id_hex: string | null
  error_message: string | null
  retry_count: number
  created_at: string
  updated_at: string
  relayed_at: string | null
}

export const db = {
  async getPendingDeposits(): Promise<BridgeDeposit[]> {
    const { data, error } = await supabase
      .from('bridge_deposits')
      .select('*')
      .in('status', ['pending', 'quantos_confirmed'])
      .eq('direction', 'quantos_to_base')
      .lt('retry_count', config.maxRetries)
      .order('created_at', { ascending: true })
      .limit(20)

    if (error) {
      logger.error('Failed to fetch pending deposits:', error)
      return []
    }
    return data || []
  },

  async getFailedRetryable(): Promise<BridgeDeposit[]> {
    const { data, error } = await supabase
      .from('bridge_deposits')
      .select('*')
      .eq('status', 'relaying')
      .eq('direction', 'quantos_to_base')
      .lt('retry_count', config.maxRetries)
      .lt('updated_at', new Date(Date.now() - 120_000).toISOString()) // stuck for 2+ min
      .order('created_at', { ascending: true })
      .limit(10)

    if (error) {
      logger.error('Failed to fetch stuck deposits:', error)
      return []
    }
    return data || []
  },

  async updateDeposit(id: string, updates: Partial<BridgeDeposit>): Promise<void> {
    const { error } = await supabase
      .from('bridge_deposits')
      .update({ ...updates, updated_at: new Date().toISOString() })
      .eq('id', id)

    if (error) {
      logger.error(`Failed to update deposit ${id}:`, error)
      throw error
    }
  },

  async getDepositByQuantosTxHash(hash: string): Promise<BridgeDeposit | null> {
    const { data, error } = await supabase
      .from('bridge_deposits')
      .select('*')
      .eq('quantos_tx_hash', hash)
      .maybeSingle()

    if (error) {
      logger.error(`Failed to fetch deposit by hash ${hash}:`, error)
      return null
    }
    return data
  },

  async getRecentDeposits(limit = 50): Promise<BridgeDeposit[]> {
    const { data, error } = await supabase
      .from('bridge_deposits')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(limit)

    if (error) {
      logger.error('Failed to fetch recent deposits:', error)
      return []
    }
    return data || []
  },

  async getStats(): Promise<{ total: number; pending: number; completed: number; failed: number }> {
    const counts = { total: 0, pending: 0, completed: 0, failed: 0 }

    const { count: total } = await supabase
      .from('bridge_deposits').select('*', { count: 'exact', head: true })
    counts.total = total || 0

    const { count: pending } = await supabase
      .from('bridge_deposits').select('*', { count: 'exact', head: true })
      .in('status', ['pending', 'quantos_confirmed', 'relaying'])
    counts.pending = pending || 0

    const { count: completed } = await supabase
      .from('bridge_deposits').select('*', { count: 'exact', head: true })
      .eq('status', 'completed')
    counts.completed = completed || 0

    const { count: failed } = await supabase
      .from('bridge_deposits').select('*', { count: 'exact', head: true })
      .eq('status', 'failed')
    counts.failed = failed || 0

    return counts
  },
}
