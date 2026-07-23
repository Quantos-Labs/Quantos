// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

// src/types.rs — API types (requests / responses)
// Transaction types must match quantos node (bincode-compatible)

use serde::{Deserialize, Serialize};

// ── Bincode-compatible transaction types ───────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransactionType {
    Transfer,
    Stake,
    Unstake,
    ValidatorRegister,
    ValidatorExit,
    ContractCall,
    ContractDeploy,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum VmKind {
    Qvm,
    Evm,
}

impl Default for VmKind {
    fn default() -> Self {
        Self::Qvm
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Amount(pub u128);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PriorityBoost {
    pub locked_tokens: u64,
    pub lock_duration_blocks: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub tx_type: TransactionType,
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: Amount,
    pub nonce: u64,
    pub max_compute_units: u64,
    pub boost: Option<PriorityBoost>,
    pub vm_kind: VmKind,
    pub data: Vec<u8>,
    pub shard_id: u16,
    pub timestamp: u64,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub chain_id: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedTransaction {
    pub transaction: Transaction,
    pub hash: [u8; 32],
    pub size: usize,
}

// ── API Request types ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateWalletRequest {
    pub pin: String,
    pub label: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImportWalletRequest {
    pub secret_key_hex: String,
    pub pin: String,
    pub label: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnlockWalletRequest {
    pub pin: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptKeyRequest {
    pub encrypted_key: String,
    pub pin: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteWalletRequest {
    pub pin: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendTransferRequest {
    pub session_token: String,
    pub to: String,
    pub amount: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignMessageRequest {
    pub session_token: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeployContractRequest {
    pub session_token: String,
    pub bytecode_hex: Option<String>,
    pub wasm_url: Option<String>,
    pub constructor_data_hex: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CallContractRequest {
    pub session_token: String,
    pub contract_address: String,
    pub calldata_hex: String,
    pub amount: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchCallItem {
    pub contract_address: String,
    pub calldata_hex: String,
    pub amount: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchCallContractRequest {
    pub session_token: String,
    pub calls: Vec<BatchCallItem>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReadContractRequest {
    pub contract_address: String,
    pub calldata_hex: String,
    pub from_address: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransferTokenRequest {
    pub session_token: String,
    pub to: String,
    pub amount: String, // human-readable e.g. "100"
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BridgeApproveRequest {
    pub session_token: String,
    pub amount: String,
    pub vault_address: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BridgeDepositRequest {
    pub session_token: String,
    pub amount: String,
    pub base_recipient: String,
    pub vault_address: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BridgeReleaseRequest {
    pub session_token: String,
    pub release_id: String,
    pub to: String,
    pub amount: String,
    pub vault_address: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FaucetClaimRequest {
    pub session_token: String,
}

// ── API Response types ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WalletInfoResponse {
    pub address: String,
    pub qts_address: String,
    pub rpc_address: String,
    pub public_key: String,
    pub label: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionTokenResponse {
    pub session_token: String,
    pub expires_at: i64,
    pub address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WalletBalanceResponse {
    pub address: String,
    pub qts_address: String,
    pub balance: String,
    pub stake: String,
    pub nonce: u64,
    pub is_validator: bool,
    pub balance_formatted: String,
    pub stake_formatted: String,
    pub qtest_balance: String,
    pub qtest_balance_formatted: String,
    pub sqtest_balance: String,
    pub sqtest_balance_formatted: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NFTInfo {
    pub token_id: u64,
    pub collection_address: String,
    pub collection_name: String,
    pub collection_symbol: String,
    pub owner: String,
    pub token_uri: String,
}
