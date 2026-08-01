// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1

// ============================================================================
// Quantos L1 — RPC response types
// All hex values use the QTS: prefix (case-insensitive on input).
// Addresses are 32 bytes (64 hex chars), amounts are u128.
// See docs/RPC_SPEC.md for the canonical specification.
// ============================================================================

/** A QTS:-prefixed hex string. Strip the prefix to get raw hex. */
export type QtsHex = string

/** A 32-byte address: `QTS:` + 64 hex chars. */
export type Address = QtsHex

/** A 32-byte hash: `QTS:` + 64 hex chars. */
export type Hash = QtsHex

/** A u128 amount encoded as `QTS:` + lowercase hex. */
export type Amount = QtsHex

// ── Account & State ──────────────────────────────────────────────────────────

export interface AccountInfo {
  address: Address
  balance: Amount
  nonce: QtsHex
  code_hash: Hash | null
  storage_root: Hash
  stake: Amount
  is_validator: boolean
  is_contract: boolean
}

// ── Transactions ─────────────────────────────────────────────────────────────

export type TransactionType =
  | 'transfer'
  | 'stake'
  | 'unstake'
  | 'stake_transfer'
  | 'validator_register'
  | 'validator_exit'
  | 'contract_call'
  | 'contract_deploy'
  | 'unknown'

export interface TransactionInfo {
  hash: Hash
  from: Address
  to: Address
  value: Amount
  nonce: QtsHex
  gas: QtsHex
  input: QtsHex
}

export interface LogInfo {
  address: Address
  topics: Hash[]
  data: QtsHex
}

export interface ReceiptInfo {
  transaction_hash: Hash
  block_number: QtsHex
  from: Address
  to: Address
  gas_used: QtsHex
  status: QtsHex
  logs: LogInfo[]
  revert_reason?: string
}

export interface ConfirmedTransactionInfo {
  hash: Hash
  from: Address
  to: Address
  value: Amount
  nonce: number
  gas_used: number
  tx_type: TransactionType
  status: 'success' | 'failed'
  success: boolean
  slot: number
  shard_id: number
  timestamp: number
  logs: LogInfo[]
  revert_reason?: string
}

export interface CallRequest {
  from?: Address
  to: Address
  data?: QtsHex
  gas?: QtsHex
  value?: Amount
}

export interface SendTransactionRequest {
  from_private_key: QtsHex
  to: Address
  amount: Amount
  data?: QtsHex
  nonce?: QtsHex
  tx_type?: TransactionType
  shard_id?: number
  max_compute_units?: QtsHex
}

export interface KeyPairResponse {
  address: Address
  public_key: QtsHex
  private_key: QtsHex
}

// ── Node & Network ───────────────────────────────────────────────────────────

export interface NodeInfoResponse {
  version: string
  protocol_version: number
  chain_id: number
  current_slot: number
  current_epoch: number
  finalized_slot: number
  state_root: Hash
  num_shards: number
  uptime_seconds: number
}

export interface HealthResponse {
  healthy: boolean
  current_slot: number
  finalized_slot: number
  slot_lag: number
  pending_transactions: number
  validators_active: number
}

export interface SyncStatus {
  syncing: boolean
  current_slot: number
  highest_slot: number
  finalized_slot: number
}

export interface PeerInfoResponse {
  peer_id: string
  addr: string
  protocol_version: string
  agent_version: string
  connected_at: number
  last_seen: number
  latency_ms: number
  messages_received: number
  messages_sent: number
  reputation: number
}

export interface MetricsInfo {
  current_slot: number
  current_epoch: number
  finalized_slot: number
  pending_transactions: number
  pending_vertices: number
  confirmed_vertices: number
  total_validators: number
  num_shards: number
}

export interface ShardInfo {
  shard_id: number
  validator_count: number
  pending_txs: number
  tps: number
}

// ── Validators ───────────────────────────────────────────────────────────────

export interface ValidatorInfoResponse {
  address: Address
  stake: Amount
  commission_rate: number
  active: boolean
  jailed: boolean
  slash_count: number
  last_active_slot: number
  performance_score?: number
  uptime_pct?: number
  blocks_proposed?: number
}

export interface ValidatorsResponse {
  validators: ValidatorInfoResponse[]
  total_stake: Amount
  total_active: number
  epoch: number
}

export interface ValidatorEpochHistoryEntry {
  epoch: number
  blocks_proposed: number
  votes_cast: number
  votes_expected: number
  avg_inclusion_latency_ms: number
  total_cu_proposed: number
  checkpoint_signatures: number
  performance_score: number
  uptime: number
  epoch_reward: bigint
}

export interface ValidatorStatsResponse {
  address: Address
  current_epoch: number
  current_blocks_proposed: number
  current_votes_cast: number
  current_votes_expected: number
  current_checkpoint_signatures: number
  current_performance_score: number
  current_uptime: number
  total_blocks_proposed: number
  total_votes_cast: number
  total_checkpoint_signatures: number
  avg_performance_score: number
  avg_uptime: number
  total_rewards_earned: bigint
  history: ValidatorEpochHistoryEntry[]
}

export interface EpochRewardEntry {
  address: Address
  stake_weight: number
  performance_score: number
  uptime: number
  blocks_proposed: number
  votes_cast: number
  epoch_reward: bigint
}

export interface EpochRewardsResponse {
  epoch: number
  total_reward_distributed: bigint
  validator_count: number
  rewards: EpochRewardEntry[]
}

// ── DAG ──────────────────────────────────────────────────────────────────────

export type VertexStatus = string

export interface VertexInfo {
  hash: Hash
  parents: Hash[]
  tx_count: number
  timestamp: number
  shard_id: number
  creator: Address
  height: number
  status: VertexStatus
  state_root: Hash
}

// ── Mempool / Ingress ────────────────────────────────────────────────────────

export interface TxPoolStatusResponse {
  pending: number
  shards: { shard_id: number; pending: number }[]
}

// ── Contracts ────────────────────────────────────────────────────────────────

export interface ContractMetadataInfo {
  address: Address
  bytecode_hash: Hash
  deployer: Address
  deployed_at: number
  deployed_height: number
  bytecode_size: number
  version: string
}

// ── Tokens (QN4 / QN8) ───────────────────────────────────────────────────────

export interface NFTInfo {
  token_id: number
  collection_address: Address
  collection_name: string
  collection_symbol: string
  owner: Address
  token_uri: string
}

export interface TokenBalanceInfo {
  token_address: Address
  name: string
  symbol: string
  decimals: number
  balance: number
  balance_formatted: string
}

// ── L0 Finality Hub ──────────────────────────────────────────────────────────

export interface L0ProofInfo {
  proof_hash: Hash
  chain_id: string | null
  epoch: number
  slot: number
  state_root: Hash
  block_hash: Hash
  validator_set_root: Hash
  total_stake: Amount
  signed_stake: Amount
  stake_threshold: Amount
  signature_count: number
  emitted_at_ms: number
}

export interface L0MetricsInfo {
  proofs_produced: number
  proofs_failed: number
  archived_proofs: number
}

export interface ExternalCheckpointRequest {
  chain_id: string
  block_number: number
  block_hash: Hash
  state_root: Hash
  timestamp_ms: number
  proof_json: string
  metadata?: string | null
}

export interface ExternalCheckpointResponse {
  proof_hash: Hash
  status: 'finalized' | 'pending_signatures'
  signed_stake: Amount
  required_stake: Amount
}

// ── Subnets ──────────────────────────────────────────────────────────────────

export interface SubnetValidatorInfo {
  address: Address
  stake: Amount
  qts_double_stake: Amount
}

export interface RegisterSubnetRequest {
  id: string
  name: string
  fee_token: string
  custom_validators?: SubnetValidatorInfo[]
  reward_multiplier: number
  stacc_collateral_leased: Amount
  min_double_stake_qts: Amount
}

export interface SubnetInfo {
  id: string
  name: string
  fee_token: string
  custom_validators?: SubnetValidatorInfo[]
  reward_multiplier: number
  stacc_collateral_leased: Amount
  min_double_stake_qts: Amount
}

// ── Subscriptions ────────────────────────────────────────────────────────────

export interface NewHeadsNotification {
  slot: number
  epoch: number
  finalized_slot: number
  state_root: Hash
}

export interface NewPendingTransactionsNotification {
  shard: number
  pending: number
}

export type SubscriptionKind = 'newHeads' | 'newPendingTransactions' | 'logs'

// ── Errors ───────────────────────────────────────────────────────────────────

export interface RpcError {
  code: number
  message: string
  data?: unknown
}

export class QuantosRpcError extends Error {
  code: number
  data?: unknown

  constructor(error: RpcError) {
    super(`[${error.code}] ${error.message}`)
    this.name = 'QuantosRpcError'
    this.code = error.code
    this.data = error.data
  }
}

// ── Chain IDs ────────────────────────────────────────────────────────────────

export enum ChainId {
  Mainnet = 1,
  Testnet = 2,
  Devnet = 3,
}
