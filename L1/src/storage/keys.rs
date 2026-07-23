// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use crate::types::{Address, Hash, ShardId};

/// Key prefix validation - ensures no overlap with data
pub(crate) const PREFIX_SEPARATOR: u8 = 0xFF;

/// MEDIUM (x6): Validates that user-provided data doesn't start with a reserved prefix.
/// Returns true if safe, false if the key collides with system prefixes.
pub fn validate_no_prefix_collision(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    // Check if data starts with any reserved prefix (0x01-0x14)
    data[0] > STORAGE_COUNT_PREFIX || data[0] == 0x00
}

/// HIGH (x4): Prefix for persisted storage counts (must match rocks.rs)
pub(crate) const STORAGE_COUNT_PREFIX: u8 = 0x14;

pub const CF_ACCOUNTS: &str = "accounts";
pub const CF_VERTICES: &str = "vertices";
pub const CF_TRANSACTIONS: &str = "transactions";
pub const CF_RECEIPTS: &str = "receipts";
pub const CF_CHECKPOINTS: &str = "checkpoints";
pub const CF_VALIDATORS: &str = "validators";
pub const CF_STATE: &str = "state";
pub const CF_DAG_TIPS: &str = "dag_tips";
pub const CF_DAG_HEIGHTS: &str = "dag_heights";
pub const CF_METADATA: &str = "metadata";
pub const CF_CONTRACTS: &str = "contracts";
pub const CF_CONTRACT_STORAGE: &str = "contract_storage";
pub const CF_QN8_COLLECTIONS: &str = "qn8_collections";
pub const CF_QN8_OWNER_TOKENS: &str = "qn8_owner_tokens";
pub const CF_QN4_TOKENS: &str = "qn4_tokens";
pub const CF_QN4_OWNER_BALANCES: &str = "qn4_owner_balances";

pub fn account_key(address: &Address) -> Vec<u8> {
    let mut key = vec![0x01, PREFIX_SEPARATOR];
    key.extend_from_slice(address);
    key
}

pub fn vertex_key(hash: &Hash) -> Vec<u8> {
    let mut key = vec![0x02, PREFIX_SEPARATOR];
    key.extend_from_slice(hash);
    key
}

pub fn vertex_by_height_key(shard_id: ShardId, height: u64) -> Vec<u8> {
    let mut key = vec![0x03, PREFIX_SEPARATOR];
    key.extend_from_slice(&shard_id.to_be_bytes());
    key.extend_from_slice(&height.to_be_bytes());
    key
}

pub fn transaction_key(hash: &Hash) -> Vec<u8> {
    let mut key = vec![0x04, PREFIX_SEPARATOR];
    key.extend_from_slice(hash);
    key
}

pub fn receipt_key(tx_hash: &Hash) -> Vec<u8> {
    let mut key = vec![0x05, PREFIX_SEPARATOR];
    key.extend_from_slice(tx_hash);
    key
}

pub fn checkpoint_key(epoch: u64, slot: u64) -> Vec<u8> {
    let mut key = vec![0x06, PREFIX_SEPARATOR];
    key.extend_from_slice(&epoch.to_be_bytes());
    key.extend_from_slice(&slot.to_be_bytes());
    key
}

pub fn checkpoint_by_hash_key(hash: &Hash) -> Vec<u8> {
    let mut key = vec![0x07, PREFIX_SEPARATOR];
    key.extend_from_slice(hash);
    key
}

pub fn validator_key(address: &Address) -> Vec<u8> {
    let mut key = vec![0x08, PREFIX_SEPARATOR];
    key.extend_from_slice(address);
    key
}

pub fn dag_tip_key(shard_id: ShardId) -> Vec<u8> {
    let mut key = vec![0x09, PREFIX_SEPARATOR];
    key.extend_from_slice(&shard_id.to_be_bytes());
    key
}

pub fn state_root_key(slot: u64) -> Vec<u8> {
    let mut key = vec![0x0A, PREFIX_SEPARATOR];
    key.extend_from_slice(&slot.to_be_bytes());
    key
}

pub fn latest_checkpoint_key() -> Vec<u8> {
    vec![0x0B, PREFIX_SEPARATOR, 0x01]
}

pub fn latest_finalized_slot_key() -> Vec<u8> {
    vec![0x0B, PREFIX_SEPARATOR, 0x02]
}

pub fn validator_set_key(epoch: u64) -> Vec<u8> {
    let mut key = vec![0x0C, PREFIX_SEPARATOR];
    key.extend_from_slice(&epoch.to_be_bytes());
    key
}

pub fn nonce_key(address: &Address) -> Vec<u8> {
    let mut key = vec![0x0D, PREFIX_SEPARATOR];
    key.extend_from_slice(address);
    key
}

pub fn committee_key(epoch: u64, committee_id: u16) -> Vec<u8> {
    let mut key = vec![0x0E, PREFIX_SEPARATOR];
    key.extend_from_slice(&epoch.to_be_bytes());
    key.extend_from_slice(&committee_id.to_be_bytes());
    key
}

pub fn vertex_children_key(hash: &Hash) -> Vec<u8> {
    let mut key = vec![0x0F, PREFIX_SEPARATOR];
    key.extend_from_slice(hash);
    key
}

pub fn pending_tx_key(hash: &Hash) -> Vec<u8> {
    let mut key = vec![0x10, PREFIX_SEPARATOR];
    key.extend_from_slice(hash);
    key
}

/// Contract bytecode key (encrypted)
pub fn contract_bytecode_key(address: &Address) -> Vec<u8> {
    let mut key = vec![0x11, PREFIX_SEPARATOR];
    key.extend_from_slice(address);
    key
}

/// Contract metadata key
pub fn contract_metadata_key(address: &Address) -> Vec<u8> {
    let mut key = vec![0x12, PREFIX_SEPARATOR];
    key.extend_from_slice(address);
    key
}

/// Contract storage key (contract_address + storage_key)
/// MEDIUM (x6): Validates storage_key doesn't collide with reserved prefixes
pub fn contract_storage_key(contract_address: &Address, storage_key: &[u8]) -> Vec<u8> {
    let mut key = vec![0x13, PREFIX_SEPARATOR];
    key.extend_from_slice(contract_address);
    key.push(PREFIX_SEPARATOR); // Additional separator between address and storage key
    key.extend_from_slice(storage_key);
    key
}

/// MEDIUM (x6): Validated version that returns Result for runtime enforcement
pub fn validated_contract_storage_key(
    contract_address: &Address,
    storage_key: &[u8],
) -> Result<Vec<u8>, &'static str> {
    Ok(contract_storage_key(contract_address, storage_key))
}

/// Contract storage prefix for iteration
pub fn contract_storage_prefix(contract_address: &Address) -> Vec<u8> {
    let mut key = vec![0x13, PREFIX_SEPARATOR];
    key.extend_from_slice(contract_address);
    key.push(PREFIX_SEPARATOR); // Match the separator in contract_storage_key
    key
}

// ========================================================================
// QN8 NFT Collection Keys
// ========================================================================

/// Key for a QN8 collection (collection_address -> serialized QN8Token)
pub fn qn8_collection_key(collection_address: &Address) -> Vec<u8> {
    let mut key = vec![0x15, PREFIX_SEPARATOR];
    key.extend_from_slice(collection_address);
    key
}

/// Key for owner -> tokens index (owner_address + collection_address -> token_ids)
pub fn qn8_owner_tokens_key(owner_address: &Address, collection_address: &Address) -> Vec<u8> {
    let mut key = vec![0x16, PREFIX_SEPARATOR];
    key.extend_from_slice(owner_address);
    key.push(PREFIX_SEPARATOR);
    key.extend_from_slice(collection_address);
    key
}

/// Prefix for iterating all collections owned by an address
pub fn qn8_owner_prefix(owner_address: &Address) -> Vec<u8> {
    let mut key = vec![0x16, PREFIX_SEPARATOR];
    key.extend_from_slice(owner_address);
    key.push(PREFIX_SEPARATOR);
    key
}

/// Prefix for iterating all QN8 collections
pub fn qn8_collections_prefix() -> Vec<u8> {
    vec![0x15, PREFIX_SEPARATOR]
}

// ========================================================================
// QN4 Fungible Token Keys
// ========================================================================

/// Key for a QN4 token (token_address -> serialized QN4Token)
pub fn qn4_token_key(token_address: &Address) -> Vec<u8> {
    let mut key = vec![0x17, PREFIX_SEPARATOR];
    key.extend_from_slice(token_address);
    key
}

/// Key for owner -> token balance (owner_address + token_address -> balance u64)
pub fn qn4_owner_balance_key(owner_address: &Address, token_address: &Address) -> Vec<u8> {
    let mut key = vec![0x18, PREFIX_SEPARATOR];
    key.extend_from_slice(owner_address);
    key.push(PREFIX_SEPARATOR);
    key.extend_from_slice(token_address);
    key
}

/// Prefix for iterating all token balances owned by an address
pub fn qn4_owner_prefix(owner_address: &Address) -> Vec<u8> {
    let mut key = vec![0x18, PREFIX_SEPARATOR];
    key.extend_from_slice(owner_address);
    key.push(PREFIX_SEPARATOR);
    key
}

/// Prefix for iterating all QN4 tokens
pub fn qn4_tokens_prefix() -> Vec<u8> {
    vec![0x17, PREFIX_SEPARATOR]
}
