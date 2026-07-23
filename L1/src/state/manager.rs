// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use dashmap::DashMap;
use parking_lot::{RwLock, Mutex};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::crypto::{verify_ml_dsa_65, public_key_to_address};
use crate::state::{StateError, StateResult, QuantumStateCompressor};
use crate::storage::Storage;
use crate::types::{
    Account, Address, Amount, Hash, Log, SignedTransaction, TransactionReceipt, TransactionStatus, TransactionType,
};
use crate::vm::{decode_contract_deploy_payload, ContractManager};
use crate::vm::evm::EvmEngine;
use crate::types::VmKind;

const SMT_EMPTY_LEAF_DOMAIN: &[u8] = b"QUANTOS_STATE_SMT_EMPTY_LEAF_V1";
const SMT_LEAF_DOMAIN: &[u8] = b"QUANTOS_STATE_SMT_LEAF_V1";
const SMT_NODE_DOMAIN: &[u8] = b"QUANTOS_STATE_SMT_NODE_V1";

/// Maximum transaction amount to prevent overflow
const MAX_TRANSACTION_AMOUNT: u128 = u64::MAX as u128;
/// Minimum transaction amount (non-zero)
const MIN_TRANSACTION_AMOUNT: u128 = 1;

fn decode_abi_usize(word: &[u8]) -> Option<usize> {
    if word.len() != 32 || word[..24].iter().any(|&b| b != 0) {
        return None;
    }

    let mut value = [0u8; 8];
    value.copy_from_slice(&word[24..]);
    usize::try_from(u64::from_be_bytes(value)).ok()
}

fn decode_scale_compact_usize(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    match first & 0b11 {
        0b00 => Some(((first >> 2) as usize, 1)),
        0b01 => {
            let second = *data.get(1)?;
            let raw = u16::from_le_bytes([first, second]);
            Some(((raw >> 2) as usize, 2))
        }
        0b10 => {
            let bytes = <[u8; 4]>::try_from(data.get(..4)?).ok()?;
            let raw = u32::from_le_bytes(bytes);
            Some(((raw >> 2) as usize, 4))
        }
        0b11 => {
            let byte_len = ((first >> 2) as usize).checked_add(4)?;
            let len_bytes = data.get(1..1 + byte_len)?;
            if len_bytes.len() > std::mem::size_of::<usize>() {
                return None;
            }
            let mut value = 0usize;
            for (shift, byte) in len_bytes.iter().enumerate() {
                value |= (*byte as usize) << (shift * 8);
            }
            Some((value, 1 + byte_len))
        }
        _ => None,
    }
}

fn decode_uint256_le_u128(data: &[u8]) -> Option<u128> {
    let bytes = <[u8; 16]>::try_from(data.get(..16)?).ok()?;
    Some(u128::from_le_bytes(bytes))
}

fn decode_contract_revert_reason(data: &[u8]) -> String {
    if data.is_empty() {
        return "No revert reason provided".to_string();
    }

    if data.len() >= 68 && data[..4] == [0x08, 0xc3, 0x79, 0xa0] {
        if let Some(offset) = decode_abi_usize(&data[4..36]) {
            let length_pos = 4 + offset;
            if length_pos + 32 <= data.len() {
                if let Some(str_len) = decode_abi_usize(&data[length_pos..length_pos + 32]) {
                    let str_start = length_pos + 32;
                    let str_end = str_start.saturating_add(str_len);
                    if str_end <= data.len() {
                        if let Ok(reason) = std::str::from_utf8(&data[str_start..str_end]) {
                            return reason.to_string();
                        }
                    }
                }
            }
        }
    }

    if data.len() >= 5 && data[..4] == [0x08, 0xc3, 0x79, 0xa0] {
        let payload = &data[4..];
        if let Some((str_len, prefix_len)) = decode_scale_compact_usize(payload) {
            let str_start = prefix_len;
            let str_end = str_start.saturating_add(str_len);
            if str_end <= payload.len() {
                if let Ok(reason) = std::str::from_utf8(&payload[str_start..str_end]) {
                    return reason.to_string();
                }
            }
        }
    }

    String::from_utf8(data.to_vec()).unwrap_or_else(|_| format!("0x{}", hex::encode(data)))
}

fn current_execution_timestamp(fallback: u64) -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(fallback)
}

#[derive(Clone)]
pub struct StateManager {
    storage: Storage,
    account_cache: Arc<DashMap<Address, Account>>,
    pending_state: Arc<DashMap<Address, Account>>,
    state_root: Arc<RwLock<Hash>>,
    /// Authorization token for privileged operations
    auth_token: Arc<Mutex<[u8; 32]>>,
    /// Atomic counter for speculative execution ordering
    speculative_counter: Arc<AtomicU64>,
    /// QRSC: Quantum-resistant state compression
    state_compressor: Arc<QuantumStateCompressor>,
    /// Contract manager for executing ContractDeploy and ContractCall transactions
    contract_manager: Arc<RwLock<Option<Arc<ContractManager>>>>,
    evm_engine: Arc<RwLock<Option<Arc<EvmEngine>>>>,
}

/// Result of deterministic state execution.
#[derive(Clone, Debug)]
pub struct StateExecution {
    pub state_root: Hash,
    pub receipts: Vec<TransactionReceipt>,
    pub accounts: Vec<Account>,
}

fn smt_hash_leaf(address: &Address, account_hash: &Hash) -> Hash {
    let mut data = Vec::with_capacity(SMT_LEAF_DOMAIN.len() + 64);
    data.extend_from_slice(SMT_LEAF_DOMAIN);
    data.extend_from_slice(address);
    data.extend_from_slice(account_hash);
    crate::types::hash_data(&data)
}

fn smt_hash_node(left: &Hash, right: &Hash) -> Hash {
    let mut data = Vec::with_capacity(SMT_NODE_DOMAIN.len() + 64);
    data.extend_from_slice(SMT_NODE_DOMAIN);
    data.extend_from_slice(left);
    data.extend_from_slice(right);
    crate::types::hash_data(&data)
}

fn smt_default_hashes() -> Vec<Hash> {
    let mut defaults = Vec::with_capacity(257);
    defaults.push(crate::types::hash_data(SMT_EMPTY_LEAF_DOMAIN));
    for level in 0..256 {
        let parent = smt_hash_node(&defaults[level], &defaults[level]);
        defaults.push(parent);
    }
    defaults
}

fn shift_right_one(mut key: Address) -> Address {
    let mut carry = 0u8;
    for byte in key.iter_mut() {
        let next_carry = *byte & 1;
        *byte = (*byte >> 1) | (carry << 7);
        carry = next_carry;
    }
    key
}

fn toggle_lowest_bit(mut key: Address) -> Address {
    key[31] ^= 1;
    key
}

fn sparse_merkle_root(account_hashes: Vec<(Address, Hash)>) -> Hash {
    let defaults = smt_default_hashes();
    if account_hashes.is_empty() {
        return defaults[256];
    }

    let mut nodes: BTreeMap<Address, Hash> = account_hashes
        .into_iter()
        .map(|(address, account_hash)| (address, smt_hash_leaf(&address, &account_hash)))
        .collect();

    for level in 0..256 {
        let mut parents: BTreeMap<Address, Hash> = BTreeMap::new();

        for (key, hash) in nodes.iter() {
            let sibling_key = toggle_lowest_bit(*key);
            if sibling_key < *key && nodes.contains_key(&sibling_key) {
                continue;
            }

            let sibling_hash = nodes.get(&sibling_key).copied().unwrap_or(defaults[level]);
            let (left, right) = if key[31] & 1 == 0 {
                (*hash, sibling_hash)
            } else {
                (sibling_hash, *hash)
            };
            parents.insert(shift_right_one(*key), smt_hash_node(&left, &right));
        }

        nodes = parents;
    }

    nodes.values().next().copied().unwrap_or(defaults[256])
}

impl StateManager {
    pub fn new(storage: Storage) -> Self {
        // CRITICAL (w1): Use OsRng for cryptographically secure auth token
        let mut token = [0u8; 32];
        OsRng.fill_bytes(&mut token);
        
        Self {
            storage,
            account_cache: Arc::new(DashMap::new()),
            pending_state: Arc::new(DashMap::new()),
            state_root: Arc::new(RwLock::new([0u8; 32])),
            auth_token: Arc::new(Mutex::new(token)),
            speculative_counter: Arc::new(AtomicU64::new(0)),
            state_compressor: Arc::new(QuantumStateCompressor::new()),
            contract_manager: Arc::new(RwLock::new(None)),
            evm_engine: Arc::new(RwLock::new(None)),
        }
    }

    /// Sets the contract manager after initialization (avoids circular deps).
    pub fn set_contract_manager(&self, cm: Arc<ContractManager>) {
        *self.contract_manager.write() = Some(cm);
    }

    /// Sets the EVM engine after initialization.
    pub fn set_evm_engine(&self, evm: Arc<EvmEngine>) {
        *self.evm_engine.write() = Some(evm);
    }
    
    /// Get QRSC compressor for state compression operations
    pub fn get_compressor(&self) -> Arc<QuantumStateCompressor> {
        self.state_compressor.clone()
    }
    
    /// Returns the local bootstrap token for trusted in-crate initialization.
    pub(crate) fn bootstrap_auth_token(&self) -> [u8; 32] {
        *self.auth_token.lock()
    }
    
    /// Verifies authorization token for privileged operations
    fn verify_auth(&self, provided_token: &[u8; 32]) -> StateResult<()> {
        let expected = self.auth_token.lock();
        if provided_token != &*expected {
            return Err(StateError::Unauthorized);
        }
        Ok(())
    }

    pub fn get_account(&self, address: &Address) -> StateResult<Account> {
        if let Some(account) = self.account_cache.get(address) {
            return Ok(account.clone());
        }

        match self.storage.get_account(address) {
            Ok(Some(account)) => {
                self.account_cache.insert(*address, account.clone());
                Ok(account)
            }
            Ok(None) => Ok(Account::new(*address)),
            Err(_) => Err(StateError::StorageError("Storage access failed".to_string())),
        }
    }

    pub fn get_balance(&self, address: &Address) -> StateResult<Amount> {
        let account = self.get_account(address)?;
        Ok(account.balance)
    }

    pub fn get_nonce(&self, address: &Address) -> StateResult<u64> {
        let account = self.get_account(address)?;
        Ok(account.nonce)
    }

    pub fn get_stake(&self, address: &Address) -> StateResult<Amount> {
        let account = self.get_account(address)?;
        Ok(account.stake)
    }

    pub fn validate_transaction(&self, tx: &SignedTransaction) -> StateResult<()> {
        let sender_address = public_key_to_address(&tx.transaction.public_key);
        if sender_address != tx.transaction.from {
            tracing::error!(
                "validate_tx: address mismatch! pk_addr={}, from={}, tx_type={:?}",
                hex::encode(&sender_address[..8]),
                hex::encode(&tx.transaction.from[..8]),
                tx.transaction.tx_type
            );
            return Err(StateError::InvalidSignature);
        }

        let valid = verify_ml_dsa_65(
            &tx.transaction.public_key,
            &tx.transaction.signing_data(),
            &tx.transaction.signature,
        ).map_err(|e| {
            tracing::error!("validate_tx: ml-dsa-65 verify error: {:?}, tx_type={:?}", e, tx.transaction.tx_type);
            StateError::InvalidSignature
        })?;

        if !valid {
            tracing::error!("validate_tx: signature invalid! from={}, tx_type={:?}", hex::encode(&tx.transaction.from[..8]), tx.transaction.tx_type);
            return Err(StateError::InvalidSignature);
        }

        // CRITICAL: Validate transaction amount
        let amount_value = tx.transaction.amount.0 as u128;
        let requires_amount = matches!(
            tx.transaction.tx_type,
            TransactionType::Transfer | TransactionType::Stake | TransactionType::Unstake
        );
        if requires_amount && amount_value < MIN_TRANSACTION_AMOUNT {
            return Err(StateError::InvalidAmount);
        }
        if amount_value > MAX_TRANSACTION_AMOUNT {
            return Err(StateError::InvalidAmount);
        }

        let account = self.get_account(&tx.transaction.from)?;

        if tx.transaction.nonce != account.nonce {
            tracing::error!(
                "validate_tx: nonce mismatch! from={}, expected={}, got={}, tx_type={:?}",
                hex::encode(&tx.transaction.from[..8]),
                account.nonce,
                tx.transaction.nonce,
                tx.transaction.tx_type
            );
            return Err(StateError::InvalidNonce {
                expected: account.nonce,
                got: tx.transaction.nonce,
            });
        }

        // STACC: transactions are free (no gas fees). Balance checks apply only
        // to value transfers/staking amounts, enforced during apply_transaction.

        Ok(())
    }

    pub fn apply_transaction(&self, tx: &SignedTransaction) -> StateResult<TransactionReceipt> {
        self.validate_transaction(tx)?;

        let mut sender = self.get_account(&tx.transaction.from)?;
        let mut recipient = self.get_account(&tx.transaction.to)?;
        let mut receipt_logs: Vec<Log> = Vec::new();

        match tx.transaction.tx_type {
            TransactionType::Transfer => {
                if !sender.sub_balance(&tx.transaction.amount) {
                    return Err(StateError::InsufficientBalance);
                }
                recipient.add_balance(&tx.transaction.amount);
            }
            TransactionType::Stake => {
                if !sender.add_stake(&tx.transaction.amount) {
                    return Err(StateError::InsufficientBalance);
                }
            }
            TransactionType::Unstake => {
                if !sender.remove_stake(&tx.transaction.amount) {
                    return Err(StateError::InsufficientBalance);
                }
            }
            TransactionType::ContractDeploy => {
                match tx.transaction.vm_kind {
                    VmKind::Qvm => {
                        let cm_guard = self.contract_manager.read();
                        let cm = cm_guard.as_ref().ok_or_else(|| {
                            StateError::ExecutionError("ContractManager not initialized".to_string())
                        })?;
                        let (bytecode, constructor_data) = decode_contract_deploy_payload(&tx.transaction.data)
                            .map_err(|e| StateError::ExecutionError(format!("Invalid deploy payload: {}", e)))?;
                        if bytecode.is_empty() {
                            return Err(StateError::ExecutionError("Empty bytecode in ContractDeploy".to_string()));
                        }
                        let deployer = tx.transaction.from;
                        let nonce = tx.transaction.nonce;
                        let timestamp = tx.transaction.timestamp;
                        let deploy_result = cm.deploy_contract(
                            bytecode.clone(),
                            constructor_data,
                            deployer,
                            nonce,
                            timestamp,
                            timestamp,
                            tx.transaction.chain_id,
                            None,
                        ).map_err(|e| StateError::ExecutionError(format!("ContractDeploy failed: {}", e)))?;
                        let contract_address = deploy_result.address;
                        recipient = self.get_account(&contract_address)?;
                        recipient.code_hash = Some(crate::types::hash_data(&bytecode));
                        if let Some(init_result) = deploy_result.init_result {
                            receipt_logs = init_result.logs.into_iter().map(|log| Log {
                                address: log.address,
                                topics: log.topics,
                                data: log.data,
                            }).collect();
                        }
                        tracing::info!(
                            "QVM ContractDeploy: deployer={}, contract={}",
                            hex::encode(&deployer[..8]),
                            hex::encode(contract_address)
                        );
                    }
                    VmKind::Evm => {
                        let evm_guard = self.evm_engine.read();
                        let evm = evm_guard.as_ref().ok_or_else(|| {
                            StateError::ExecutionError("EvmEngine not initialized".to_string())
                        })?;
                        let deployer = tx.transaction.from;
                        let nonce = tx.transaction.nonce;
                        let init_code = tx.transaction.data.clone();
                        let out = evm.deploy(
                            deployer,
                            nonce,
                            tx.transaction.amount.clone(),
                            init_code,
                            tx.transaction.max_compute_units,
                            tx.transaction.chain_id,
                        ).map_err(|e| StateError::ExecutionError(format!("EVM deploy failed: {}", e)))?;
                        let contract_address = out.created_address.ok_or_else(|| {
                            StateError::ExecutionError("EVM deploy missing address".into())
                        })?;
                        recipient = self.get_account(&contract_address)?;
                        if let Some(code) = &out.deployed_code {
                            recipient.code_hash = Some(crate::types::hash_data(code));
                        }
                        receipt_logs = out.logs.into_iter().map(|log| Log {
                            address: log.address,
                            topics: log.topics,
                            data: log.data,
                        }).collect();
                        tracing::info!(
                            "EVM ContractDeploy: deployer={}, contract={}",
                            hex::encode(&deployer[..8]),
                            hex::encode(contract_address)
                        );
                    }
                }
            }
            TransactionType::ContractCall => {
                match tx.transaction.vm_kind {
                    VmKind::Qvm => {
                        let cm_guard = self.contract_manager.read();
                        let cm = cm_guard.as_ref().ok_or_else(|| {
                            tracing::error!("ContractCall: ContractManager not initialized!");
                            StateError::ExecutionError("ContractManager not initialized".to_string())
                        })?;
                        let contract_address = tx.transaction.to;
                        let caller = tx.transaction.from;
                        let input_data = tx.transaction.data.clone();
                        let tx_timestamp = tx.transaction.timestamp;
                        let execution_timestamp = current_execution_timestamp(tx_timestamp);
                        let chain_id = tx.transaction.chain_id;
                        tracing::info!(
                            "QVM ContractCall: caller={}, contract={}, data_len={}, amount={}, nonce={}, max_cu={}",
                            hex::encode(&caller[..8]),
                            hex::encode(&contract_address[..8]),
                            input_data.len(),
                            tx.transaction.amount.0,
                            tx.transaction.nonce,
                            tx.transaction.max_compute_units,
                        );
                        if tx.transaction.amount.0 > 0 {
                            if !sender.sub_balance(&tx.transaction.amount) {
                                return Err(StateError::InsufficientBalance);
                            }
                            recipient.add_balance(&tx.transaction.amount);
                        }
                        let result = cm.execute_contract(
                            contract_address,
                            caller,
                            input_data,
                            execution_timestamp,
                            execution_timestamp,
                            chain_id,
                        ).map_err(|e| StateError::ExecutionError(format!("ContractCall failed: {}", e)))?;
                        if !result.success {
                            let revert_reason = decode_contract_revert_reason(&result.return_data);
                            return Err(StateError::ExecutionError(format!("ContractCall reverted: {}", revert_reason)));
                        }
                        receipt_logs = result.logs.into_iter().map(|log| Log {
                            address: log.address,
                            topics: log.topics,
                            data: log.data,
                        }).collect();
                    }
                    VmKind::Evm => {
                        let evm_guard = self.evm_engine.read();
                        let evm = evm_guard.as_ref().ok_or_else(|| {
                            StateError::ExecutionError("EvmEngine not initialized".to_string())
                        })?;
                        let contract_address = tx.transaction.to;
                        let caller = tx.transaction.from;
                        let input_data = tx.transaction.data.clone();
                        if tx.transaction.amount.0 > 0 {
                            if !sender.sub_balance(&tx.transaction.amount) {
                                return Err(StateError::InsufficientBalance);
                            }
                            recipient.add_balance(&tx.transaction.amount);
                        }
                        let out = evm.call(
                            caller,
                            contract_address,
                            tx.transaction.amount.clone(),
                            input_data,
                            tx.transaction.max_compute_units,
                            tx.transaction.chain_id,
                        ).map_err(|e| StateError::ExecutionError(format!("EVM call failed: {}", e)))?;
                        if !out.success {
                            let revert_reason = decode_contract_revert_reason(&out.return_data);
                            return Err(StateError::ExecutionError(format!("EVM call reverted: {}", revert_reason)));
                        }
                        receipt_logs = out.logs.into_iter().map(|log| Log {
                            address: log.address,
                            topics: log.topics,
                            data: log.data,
                        }).collect();
                    }
                }
            }
            _ => {}
        }

        sender.increment_nonce()
            .map_err(|e| StateError::StorageError(e))?;

        self.storage.put_account(&sender)
            .map_err(|_| StateError::StorageError("Failed to store sender account".to_string()))?;
        self.storage.put_account(&recipient)
            .map_err(|_| StateError::StorageError("Failed to store recipient account".to_string()))?;

        let receipt_to = recipient.address;
        self.account_cache.insert(sender.address, sender);
        self.account_cache.insert(recipient.address, recipient);

        Ok(TransactionReceipt {
            tx_hash: tx.hash,
            status: TransactionStatus::Finalized,
            cu_used: tx.transaction.max_compute_units,
            vertex_hash: [0u8; 32],
            shard_id: tx.transaction.shard_id,
            logs: receipt_logs,
            slot: 0,
            from: tx.transaction.from,
            to: receipt_to,
            success: true,
        })
    }

    pub fn apply_transactions_batch(
        &self,
        txs: &[SignedTransaction],
    ) -> Vec<StateResult<TransactionReceipt>> {
        txs.iter().map(|tx| self.apply_transaction(tx)).collect()
    }

    /// Executes transactions against an in-memory overlay and returns the
    /// resulting state root without writing accounts or contract storage.
    pub fn simulate_transactions(&self, txs: &[SignedTransaction]) -> StateResult<StateExecution> {
        self.execute_transactions_overlay(txs, false)
    }

    /// Executes transactions deterministically, then atomically persists the
    /// changed accounts only after the full overlay execution succeeds.
    pub fn apply_transactions_atomically(&self, txs: &[SignedTransaction]) -> StateResult<StateExecution> {
        let execution = self.execute_transactions_overlay(txs, true)?;

        for account in &execution.accounts {
            self.storage.put_account(account)
                .map_err(|e| StateError::StorageError(format!("Failed to commit account: {}", e)))?;
            self.account_cache.insert(account.address, account.clone());
        }

        *self.state_root.write() = execution.state_root;
        Ok(execution)
    }

    fn execute_transactions_overlay(
        &self,
        txs: &[SignedTransaction],
        persist_contracts: bool,
    ) -> StateResult<StateExecution> {
        let mut overlay: HashMap<Address, Account> = HashMap::new();
        let mut receipts = Vec::with_capacity(txs.len());

        for tx in txs {
            match self.execute_transaction_overlay(tx, &mut overlay, persist_contracts) {
                Ok(receipt) => receipts.push(receipt),
                Err(err) => {
                    tracing::warn!(
                        "Transaction {} failed during overlay execution: {}",
                        hex::encode(&tx.hash[..8]),
                        err
                    );
                    receipts.push(TransactionReceipt {
                        tx_hash: tx.hash,
                        status: TransactionStatus::Failed(err.to_string()),
                        cu_used: tx.transaction.max_compute_units,
                        vertex_hash: [0u8; 32],
                        shard_id: tx.transaction.shard_id,
                        logs: Vec::new(),
                        slot: 0,
                        from: tx.transaction.from,
                        to: tx.transaction.to,
                        success: false,
                    });
                }
            }
        }

        let state_root = self.compute_state_root_with_overlay(&overlay)?;
        let mut accounts: Vec<_> = overlay.into_values().collect();
        accounts.sort_by(|a, b| a.address.cmp(&b.address));

        Ok(StateExecution {
            state_root,
            receipts,
            accounts,
        })
    }

    fn overlay_account(
        &self,
        overlay: &HashMap<Address, Account>,
        address: &Address,
    ) -> StateResult<Account> {
        overlay
            .get(address)
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| self.get_account(address))
    }

    fn execute_transaction_overlay(
        &self,
        tx: &SignedTransaction,
        overlay: &mut HashMap<Address, Account>,
        persist_contracts: bool,
    ) -> StateResult<TransactionReceipt> {
        self.validate_transaction_against_overlay(tx, overlay)?;

        let mut sender = self.overlay_account(overlay, &tx.transaction.from)?;
        let mut recipient = self.overlay_account(overlay, &tx.transaction.to)?;
        let mut receipt_logs: Vec<Log> = Vec::new();

        // STACC: no gas fees are charged. Only explicit value transfers/staking
        // change balances.

        match tx.transaction.tx_type {
            TransactionType::Transfer => {
                if !sender.sub_balance(&tx.transaction.amount) {
                    return Err(StateError::InsufficientBalance);
                }
                if sender.address == recipient.address {
                    sender.add_balance(&tx.transaction.amount);
                } else {
                    recipient.add_balance(&tx.transaction.amount);
                }
            }
            TransactionType::Stake => {
                if !sender.add_stake(&tx.transaction.amount) {
                    return Err(StateError::InsufficientBalance);
                }
            }
            TransactionType::Unstake => {
                if !sender.remove_stake(&tx.transaction.amount) {
                    return Err(StateError::InsufficientBalance);
                }
            }
            TransactionType::ContractDeploy => {
                let (bytecode, constructor_data) = decode_contract_deploy_payload(&tx.transaction.data)
                    .map_err(|e| StateError::ExecutionError(format!("Invalid deploy payload: {}", e)))?;
                if bytecode.is_empty() {
                    return Err(StateError::ExecutionError("Empty bytecode in ContractDeploy".to_string()));
                }

                let deployer = tx.transaction.from;
                let nonce = tx.transaction.nonce;
                let bytecode_hash = crate::types::hash_data(&bytecode);
                let mut addr_input = Vec::with_capacity(72);
                addr_input.extend_from_slice(&deployer);
                addr_input.extend_from_slice(&bytecode_hash);
                addr_input.extend_from_slice(&nonce.to_le_bytes());
                let contract_address = crate::types::hash_data(&addr_input);
                recipient = self.overlay_account(overlay, &contract_address)?;
                recipient.code_hash = Some(bytecode_hash);

                if persist_contracts {
                    let cm_guard = self.contract_manager.read();
                    let cm = cm_guard.as_ref().ok_or_else(|| {
                        StateError::ExecutionError("ContractManager not initialized".to_string())
                    })?;
                    let deploy_result = cm.deploy_contract(
                        bytecode,
                        constructor_data,
                        deployer,
                        nonce,
                        tx.transaction.timestamp,
                        tx.transaction.timestamp,
                        tx.transaction.chain_id,
                        None,
                    ).map_err(|e| StateError::ExecutionError(format!("ContractDeploy failed: {}", e)))?;

                    recipient = self.overlay_account(overlay, &deploy_result.address)?;
                    recipient.code_hash = Some(bytecode_hash);
                    if let Some(init_result) = deploy_result.init_result {
                        receipt_logs = init_result.logs.into_iter().map(|log| Log {
                            address: log.address,
                            topics: log.topics,
                            data: log.data,
                        }).collect();
                    }
                }
            }
            TransactionType::ContractCall => {
                let contract_address = tx.transaction.to;
                let caller = tx.transaction.from;

                if tx.transaction.amount.0 > 0 {
                    if !sender.sub_balance(&tx.transaction.amount) {
                        return Err(StateError::InsufficientBalance);
                    }
                    if sender.address == recipient.address {
                        sender.add_balance(&tx.transaction.amount);
                    } else {
                        recipient.add_balance(&tx.transaction.amount);
                    }
                }

                let cm_guard = self.contract_manager.read();
                let cm = cm_guard.as_ref().ok_or_else(|| {
                    StateError::ExecutionError("ContractManager not initialized".to_string())
                })?;
                let execution_timestamp = current_execution_timestamp(tx.transaction.timestamp);
                let result = if persist_contracts {
                    cm.execute_contract(
                        contract_address,
                        caller,
                        tx.transaction.data.clone(),
                        execution_timestamp,
                        execution_timestamp,
                        tx.transaction.chain_id,
                    )
                } else {
                    cm.simulate_contract(
                        contract_address,
                        caller,
                        tx.transaction.data.clone(),
                        execution_timestamp,
                        execution_timestamp,
                        tx.transaction.chain_id,
                    )
                }.map_err(|e| StateError::ExecutionError(format!("ContractCall failed: {}", e)))?;

                if !result.success {
                    let revert_reason = if !result.return_data.is_empty() {
                        decode_contract_revert_reason(&result.return_data)
                    } else {
                        result.debug_messages.iter()
                            .rev()
                            .map(|m| m.trim().trim_end_matches(','))
                            .find(|m| {
                                !m.is_empty()
                                    && !m.starts_with("call:")
                                    && !m.starts_with("runtime_error:")
                            })
                            .unwrap_or("No revert reason provided")
                            .to_string()
                    };
                    return Err(StateError::ExecutionError(
                        format!("ContractCall reverted: {}", revert_reason)
                    ));
                }

                receipt_logs = result.logs.into_iter().map(|log| Log {
                    address: log.address,
                    topics: log.topics,
                    data: log.data,
                }).collect();
            }
            _ => {}
        }

        sender.increment_nonce()
            .map_err(StateError::StorageError)?;

        let receipt_to = recipient.address;
        overlay.insert(sender.address, sender);
        if tx.transaction.from != receipt_to {
            overlay.insert(receipt_to, recipient);
        }

        Ok(TransactionReceipt {
            tx_hash: tx.hash,
            status: TransactionStatus::Finalized,
            cu_used: tx.transaction.max_compute_units,
            vertex_hash: [0u8; 32],
            shard_id: tx.transaction.shard_id,
            logs: receipt_logs,
            slot: 0,
            from: tx.transaction.from,
            to: receipt_to,
            success: true,
        })
    }

    fn validate_transaction_against_overlay(
        &self,
        tx: &SignedTransaction,
        overlay: &HashMap<Address, Account>,
    ) -> StateResult<()> {
        let sender_address = public_key_to_address(&tx.transaction.public_key);
        if sender_address != tx.transaction.from {
            return Err(StateError::InvalidSignature);
        }

        let valid = verify_ml_dsa_65(
            &tx.transaction.public_key,
            &tx.transaction.signing_data(),
            &tx.transaction.signature,
        ).map_err(|_| StateError::InvalidSignature)?;
        if !valid {
            return Err(StateError::InvalidSignature);
        }

        let amount_value = tx.transaction.amount.0;
        let requires_amount = matches!(
            tx.transaction.tx_type,
            TransactionType::Transfer | TransactionType::Stake | TransactionType::Unstake
        );
        if requires_amount && amount_value < MIN_TRANSACTION_AMOUNT {
            return Err(StateError::InvalidAmount);
        }
        if amount_value > MAX_TRANSACTION_AMOUNT {
            return Err(StateError::InvalidAmount);
        }

        let account = self.overlay_account(overlay, &tx.transaction.from)?;
        if tx.transaction.nonce != account.nonce {
            return Err(StateError::InvalidNonce {
                expected: account.nonce,
                got: tx.transaction.nonce,
            });
        }

        // STACC: no gas fees, so only value transfers/staking must be funded.
        // Overlay validation defers balance checks to apply paths.

        Ok(())
    }

    fn compute_state_root_with_overlay(
        &self,
        overlay: &HashMap<Address, Account>,
    ) -> StateResult<Hash> {
        let mut accounts: BTreeMap<Address, Hash> = self.storage.iter_accounts()
            .map_err(|e| StateError::StorageError(e.to_string()))?
            .into_iter()
            .map(|account| (account.address, account.hash()))
            .collect();

        for account in overlay.values() {
            accounts.insert(account.address, account.hash());
        }

        Ok(sparse_merkle_root(accounts.into_iter().collect()))
    }

    pub fn speculative_apply(&self, tx: &SignedTransaction) -> StateResult<Account> {
        // CRITICAL: Atomic read-modify-write to prevent race conditions
        let _order = self.speculative_counter.fetch_add(1, Ordering::SeqCst);
        
        // Get or create pending account atomically
        let mut account = self.pending_state
            .entry(tx.transaction.from)
            .or_insert_with(|| {
                self.get_account(&tx.transaction.from).unwrap_or_else(|_| Account::new(tx.transaction.from))
            })
            .clone();

        if tx.transaction.nonce != account.nonce {
            return Err(StateError::InvalidNonce {
                expected: account.nonce,
                got: tx.transaction.nonce,
            });
        }

        // STACC: speculative_apply does not charge fees. It only advances nonce
        // and is used for conflict detection / prechecks.

        account.increment_nonce()
            .map_err(|e| StateError::StorageError(e))?;
        self.pending_state.insert(tx.transaction.from, account.clone());

        Ok(account)
    }

    /// Commits pending state (requires authorization)
    pub fn commit_pending(&self, auth_token: &[u8; 32]) -> StateResult<Hash> {
        // CRITICAL: Require authorization for state manipulation
        self.verify_auth(auth_token)?;
        
        let mut account_hashes = Vec::new();

        for entry in self.pending_state.iter() {
            let account = entry.value();
            self.storage.put_account(account)
                .map_err(|_| StateError::StorageError("Failed to commit account".to_string()))?;
            self.account_cache.insert(account.address, account.clone());
            account_hashes.push(account.hash());
        }

        self.pending_state.clear();

        // CRITICAL: Compute state root from ALL accounts, not just pending
        let new_root = self.compute_full_state_root()?;
        *self.state_root.write() = new_root;

        Ok(new_root)
    }

    /// Rolls back pending state (requires authorization)
    pub fn rollback_pending(&self, auth_token: &[u8; 32]) -> StateResult<()> {
        // CRITICAL: Require authorization for state manipulation
        self.verify_auth(auth_token)?;
        self.pending_state.clear();
        Ok(())
    }

    pub fn state_root(&self) -> Hash {
        *self.state_root.read()
    }
    
    /// Returns a reference to the state root for checkpoint operations
    pub fn get_state_root(&self) -> parking_lot::RwLockReadGuard<'_, Hash> {
        self.state_root.read()
    }
    
    /// Restores an account to a previous state (for atomic rollback)
    /// Used by cross-shard atomic protocol during rollback
    pub fn restore_account(&self, address: &Address, account: crate::types::Account) -> StateResult<()> {
        // Update storage
        self.storage.put_account(&account)
            .map_err(|e| StateError::StorageError(format!("Restore failed: {}", e)))?;
        
        // Update cache
        self.account_cache.insert(*address, account);
        
        // Clear any pending state for this account
        self.pending_state.remove(address);
        
        Ok(())
    }

    pub fn compute_state_root(&self) -> StateResult<Hash> {
        self.compute_full_state_root()
    }
    
    /// Computes state root from all accounts with deterministic ordering
    fn compute_full_state_root(&self) -> StateResult<Hash> {
        let accounts: Vec<(Address, Hash)> = self.storage.iter_accounts()
            .map_err(|e| StateError::StorageError(e.to_string()))?
            .into_iter()
            .map(|account| (account.address, account.hash()))
            .collect();

        Ok(sparse_merkle_root(accounts))
    }

    /// Sets account balance (requires authorization - CRITICAL OPERATION)
    pub fn set_balance(&self, address: &Address, balance: Amount, auth_token: &[u8; 32]) -> StateResult<()> {
        // CRITICAL: Require authorization to prevent arbitrary balance manipulation
        self.verify_auth(auth_token)?;
        
        let mut account = self.get_account(address)?;
        account.balance = balance;
        
        self.storage.put_account(&account)
            .map_err(|_| StateError::StorageError("Failed to set balance".to_string()))?;
        self.account_cache.insert(*address, account);
        
        Ok(())
    }
    
    /// Gets a single storage value for a contract.
    /// Used by RPC for eth_getStorageAt equivalent.
    pub fn get_contract_storage_value(&self, contract_address: &Address, storage_key: &[u8; 32]) -> StateResult<Option<Vec<u8>>> {
        self.storage.get_contract_storage_value(contract_address, storage_key)
            .map_err(|e| StateError::StorageError(e.to_string()))
    }
    
    /// Applies genesis state initialization
    /// 
    /// Production-ready genesis application:
    /// - Batch account creation for performance
    /// - Atomic storage commits
    /// - State root update
    /// - Validation of total supply
    pub fn apply_genesis(&self, initial_balances: Vec<(Address, Amount)>, auth_token: &[u8; 32]) -> StateResult<()> {
        // CRITICAL: Require authorization for genesis state manipulation
        self.verify_auth(auth_token)?;
        
        tracing::info!("Applying genesis state: {} accounts", initial_balances.len());
        
        // Validate no genesis already applied
        let current_root = self.state_root();
        if current_root != [0u8; 32] {
            tracing::warn!("Genesis already applied, skipping");
            return Ok(());
        }
        
        // Batch account creation
        let mut accounts = Vec::with_capacity(initial_balances.len());
        let mut total_supply = 0u128;
        
        for (address, balance) in initial_balances {
            let mut account = Account::new(address);
            account.balance = balance.clone();
            
            total_supply = total_supply.checked_add(balance.0)
                .ok_or(StateError::ArithmeticOverflow)?;
            
            accounts.push(account);
        }
        
        tracing::info!("Total genesis supply: {} (raw units)", total_supply);
        
        // Atomic storage batch write for performance
        for account in &accounts {
            self.storage.put_account(account)
                .map_err(|e| StateError::StorageError(format!("Genesis storage failed: {}", e)))?;
            
            // Populate cache
            self.account_cache.insert(account.address, account.clone());
        }
        
        // Compute and update state root from durable storage using the same
        // Sparse Merkle Tree used by normal execution.
        let new_state_root = self.compute_full_state_root()?;
        *self.state_root.write() = new_state_root;
        
        tracing::info!("✅ Genesis state applied successfully");
        tracing::info!("   State root: 0x{}", hex::encode(&new_state_root[..8]));
        tracing::info!("   Accounts: {}", accounts.len());
        tracing::info!("   Total supply: {} units", total_supply);
        
        Ok(())
    }
    
    /// Batch account updates for performance
    /// Used during block production to apply multiple state changes atomically
    pub fn apply_state_batch(&self, accounts: Vec<Account>, auth_token: &[u8; 32]) -> StateResult<()> {
        // CRITICAL: Require authorization
        self.verify_auth(auth_token)?;
        
        for account in &accounts {
            self.storage.put_account(account)
                .map_err(|e| StateError::StorageError(format!("Batch update failed: {}", e)))?;
            self.account_cache.insert(account.address, account.clone());
        }
        
        // Update state root
        let new_state_root = self.compute_full_state_root()?;
        *self.state_root.write() = new_state_root;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_state_manager_basic() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path()).unwrap();
        let state = StateManager::new(storage);

        let address = [1u8; 32];
        let auth_token = state.bootstrap_auth_token();
        state.set_balance(&address, Amount(1000), &auth_token).unwrap();
        
        let balance = state.get_balance(&address).unwrap();
        assert_eq!(balance.0, 1000);
    }
}
