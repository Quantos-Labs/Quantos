import { createClient } from '@supabase/supabase-js'
import { config } from './config.js'
import type { BridgeDeposit } from './db.js'
import { logger } from './logger.js'

const supabase = createClient(config.supabaseUrl, config.supabaseServiceRoleKey)

const MIN_AMOUNT_RAW = 25n * 10n ** 18n
const BRIDGE_REWARD_POINTS = 25
const FIRST_BRIDGE_BONUS = 200
const FIFTH_BRIDGE_BONUS = 100
const TENTH_BRIDGE_BONUS = 150
const COOLDOWN_MS = 30 * 60 * 1000
const MAX_REWARDED_BRIDGES_PER_DAY = 3
const DAILY_POINTS_CAP = 100
const WEEKLY_POINTS_CAP = 300

type AwardType = 'bridge_complete' | 'bridge_first_bonus' | 'bridge_5_bonus' | 'bridge_10_bonus'

interface RewardRow {
  award_type: AwardType
  points: number
  counts_toward_points_cap: boolean
  awarded_at: string
  bridge_deposit_id: string
}

function parseAmountToRaw(value: string): bigint {
  const normalized = value.trim()
  if (!normalized) return 0n
  const [whole = '0', fraction = ''] = normalized.split('.')
  const frac = fraction.slice(0, 18).padEnd(18, '0')
  return BigInt(whole || '0') * 10n ** 18n + BigInt(frac || '0')
}

function getAmountRaw(deposit: BridgeDeposit): bigint {
  try {
    if (deposit.amount_raw && deposit.amount_raw !== '0') {
      return BigInt(deposit.amount_raw)
    }
  } catch {
  }
  return parseAmountToRaw(deposit.amount)
}

function startOfUtcDay(now: Date): Date {
  const result = new Date(now)
  result.setUTCHours(0, 0, 0, 0)
  return result
}

async function getRewardContext(userId: string, depositId: string): Promise<{
  existingAwardTypes: Set<AwardType>
  priorRewardedBridgeCount: number
  rewardedBridgesToday: number
  pointsToday: number
  pointsWeek: number
  lastRewardAt: Date | null
}> {
  const now = new Date()
  const dayStart = startOfUtcDay(now)
  const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)

  const [existingResult, priorCountResult, recentResult, lastRewardResult] = await Promise.all([
    supabase
      .from('bridge_point_awards')
      .select('award_type')
      .eq('bridge_deposit_id', depositId),
    supabase
      .from('bridge_point_awards')
      .select('id', { count: 'exact', head: true })
      .eq('user_id', userId)
      .eq('award_type', 'bridge_complete')
      .neq('bridge_deposit_id', depositId),
    supabase
      .from('bridge_point_awards')
      .select('award_type, points, counts_toward_points_cap, awarded_at, bridge_deposit_id')
      .eq('user_id', userId)
      .gte('awarded_at', weekAgo.toISOString())
      .order('awarded_at', { ascending: false }),
    supabase
      .from('bridge_point_awards')
      .select('awarded_at')
      .eq('user_id', userId)
      .eq('award_type', 'bridge_complete')
      .neq('bridge_deposit_id', depositId)
      .order('awarded_at', { ascending: false })
      .limit(1)
      .maybeSingle(),
  ])

  if (existingResult.error) throw existingResult.error
  if (priorCountResult.error) throw priorCountResult.error
  if (recentResult.error) throw recentResult.error
  if (lastRewardResult.error) throw lastRewardResult.error

  const existingAwardTypes = new Set((existingResult.data || []).map((row: { award_type: AwardType }) => row.award_type))
  const recentRows = (recentResult.data || []) as RewardRow[]

  let rewardedBridgesToday = 0
  let pointsToday = 0
  let pointsWeek = 0

  for (const row of recentRows) {
    if (row.bridge_deposit_id === depositId) continue

    const awardedAt = new Date(row.awarded_at)

    if (row.award_type === 'bridge_complete' && awardedAt >= dayStart) {
      rewardedBridgesToday += 1
    }

    if (row.counts_toward_points_cap) {
      pointsWeek += row.points
      if (awardedAt >= dayStart) {
        pointsToday += row.points
      }
    }
  }

  return {
    existingAwardTypes,
    priorRewardedBridgeCount: priorCountResult.count || 0,
    rewardedBridgesToday,
    pointsToday,
    pointsWeek,
    lastRewardAt: lastRewardResult.data?.awarded_at ? new Date(lastRewardResult.data.awarded_at) : null,
  }
}

async function insertAward(params: {
  deposit: BridgeDeposit
  awardType: AwardType
  points: number
  countsTowardPointsCap: boolean
  idempotencyKey: string
}): Promise<boolean> {
  const { deposit, awardType, points, countsTowardPointsCap, idempotencyKey } = params

  const { error } = await supabase
    .from('bridge_point_awards')
    .insert({
      user_id: deposit.user_id,
      bridge_deposit_id: deposit.id,
      award_type: awardType,
      points,
      counts_toward_points_cap: countsTowardPointsCap,
      idempotency_key: idempotencyKey,
      metadata: {
        direction: deposit.direction,
        quantos_tx_hash: deposit.quantos_tx_hash,
        base_tx_hash: deposit.base_tx_hash,
        amount: deposit.amount,
        amount_raw: deposit.amount_raw,
      },
    })

  if (!error) {
    logger.info(`[${deposit.id.slice(0, 8)}] Awarded ${points} pts for ${awardType}`)
    return true
  }

  if (error.code === '23505') {
    return false
  }

  throw error
}

export async function awardBridgePoints(deposit: BridgeDeposit): Promise<void> {
  if (deposit.direction !== 'quantos_to_base') return
  if (!deposit.user_id) return

  const amountRaw = getAmountRaw(deposit)
  if (amountRaw < MIN_AMOUNT_RAW) {
    logger.info(`[${deposit.id.slice(0, 8)}] Bridge points skipped: amount below minimum`)
    return
  }

  const context = await getRewardContext(deposit.user_id, deposit.id)
  const hasBridgeReward = context.existingAwardTypes.has('bridge_complete')

  if (!hasBridgeReward) {
    if (context.lastRewardAt && Date.now() - context.lastRewardAt.getTime() < COOLDOWN_MS) {
      logger.info(`[${deposit.id.slice(0, 8)}] Bridge points skipped: cooldown active`)
      return
    }

    if (context.rewardedBridgesToday >= MAX_REWARDED_BRIDGES_PER_DAY) {
      logger.info(`[${deposit.id.slice(0, 8)}] Bridge points skipped: daily bridge limit reached`)
      return
    }

    if (context.pointsToday + BRIDGE_REWARD_POINTS > DAILY_POINTS_CAP) {
      logger.info(`[${deposit.id.slice(0, 8)}] Bridge points skipped: daily points cap reached`)
      return
    }

    if (context.pointsWeek + BRIDGE_REWARD_POINTS > WEEKLY_POINTS_CAP) {
      logger.info(`[${deposit.id.slice(0, 8)}] Bridge points skipped: weekly points cap reached`)
      return
    }
  }

  const bridgeIndex = context.priorRewardedBridgeCount + 1

  await insertAward({
    deposit,
    awardType: 'bridge_complete',
    points: BRIDGE_REWARD_POINTS,
    countsTowardPointsCap: true,
    idempotencyKey: `bridge_complete:${deposit.id}`,
  })

  if (bridgeIndex === 1) {
    await insertAward({
      deposit,
      awardType: 'bridge_first_bonus',
      points: FIRST_BRIDGE_BONUS,
      countsTowardPointsCap: false,
      idempotencyKey: `bridge_first_bonus:${deposit.user_id}`,
    })
  }

  if (bridgeIndex === 5) {
    await insertAward({
      deposit,
      awardType: 'bridge_5_bonus',
      points: FIFTH_BRIDGE_BONUS,
      countsTowardPointsCap: false,
      idempotencyKey: `bridge_5_bonus:${deposit.user_id}`,
    })
  }

  if (bridgeIndex === 10) {
    await insertAward({
      deposit,
      awardType: 'bridge_10_bonus',
      points: TENTH_BRIDGE_BONUS,
      countsTowardPointsCap: false,
      idempotencyKey: `bridge_10_bonus:${deposit.user_id}`,
    })
  }
}
