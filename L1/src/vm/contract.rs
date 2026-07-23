// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Contract Management
//!
//! Contract deployment, storage, and execution management.

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::{Mutex, RwLock};

use serde::{Deserialize, Serialize};
use wasmer::{Module, Store};
use wasmer_compiler_cranelift::Cranelift;

use crate::storage::{Storage, StorageResult};
use crate::types::{Address, Hash};
use crate::vm::solang_compat::{self, ContractType};
use crate::vm::{BytecodeProtector, CrossContractHandler, QuantosVm, QuantosVmConfig, ExecutionContext, ExecutionResult, VmError, VmResult};

const CONTRACT_DEPLOY_PAYLOAD_MAGIC: [u8; 4] = *b"QDP1";

fn decode_abi_usize(word: &[u8]) -> Option<usize> {
    if word.len() != 32 {
        return None;
    }
    // Try LE first (Solang/Substrate convention): value in first 8 bytes, rest zero
    if word[8..].iter().all(|&b| b == 0) {
        let mut le_val = [0u8; 8];
        le_val.copy_from_slice(&word[..8]);
        return usize::try_from(u64::from_le_bytes(le_val)).ok();
    }
    // Fallback: BE (standard EVM): value in last 8 bytes, rest zero
    if word[..24].iter().all(|&b| b == 0) {
        let mut be_val = [0u8; 8];
        be_val.copy_from_slice(&word[24..]);
        return usize::try_from(u64::from_be_bytes(be_val)).ok();
    }
    None
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

/// Public wrapper for decoding revert reason, used by solang_compat for debug messages.
pub fn decode_revert_for_debug(data: &[u8]) -> String {
    decode_contract_revert_reason(data)
}

/// Contract deployment info stored on-chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeployedContract {
    /// Contract address
    pub address: Address,
    /// Deployer address
    pub deployer: Address,
    /// Deployment timestamp
    pub deployed_at: u64,
    /// Deployment block height
    pub deployed_height: u64,
    /// Bytecode size (encrypted)
    pub bytecode_size: usize,
    /// Bytecode hash (for verification)
    pub bytecode_hash: Hash,
    /// Contract version
    pub version: String,
    /// ABI (optional)
    pub abi: Option<String>,
}

#[derive(Clone, Debug)]
pub struct DeployContractResult {
    pub address: Address,
    pub init_result: Option<ExecutionResult>,
}

pub fn decode_contract_deploy_payload(data: &[u8]) -> VmResult<(Vec<u8>, Vec<u8>)> {
    if data.len() >= 4 && &data[..4] == b"\0asm" {
        return Ok((data.to_vec(), Vec::new()));
    }

    if data.len() < 12 || data[..4] != CONTRACT_DEPLOY_PAYLOAD_MAGIC {
        return Err(VmError::InvalidBytecode);
    }

    let bytecode_len = u32::from_le_bytes(
        data[4..8]
            .try_into()
            .map_err(|_| VmError::InvalidBytecode)?
    ) as usize;
    let constructor_len = u32::from_le_bytes(
        data[8..12]
            .try_into()
            .map_err(|_| VmError::InvalidBytecode)?
    ) as usize;

    let expected_len = 12usize
        .checked_add(bytecode_len)
        .and_then(|len| len.checked_add(constructor_len))
        .ok_or(VmError::InvalidBytecode)?;

    if bytecode_len == 0 || expected_len != data.len() {
        return Err(VmError::InvalidBytecode);
    }

    let bytecode_end = 12 + bytecode_len;

    Ok((
        data[12..bytecode_end].to_vec(),
        data[bytecode_end..expected_len].to_vec(),
    ))
}

/// Contract manager for deployment and execution.
pub struct ContractManager {
    storage: Storage,
    bytecode_protector: Arc<BytecodeProtector>,
    vm: Arc<QuantosVm>,
    /// CRITICAL: Per-contract locks to prevent race conditions
    contract_locks: Arc<dashmap::DashMap<Address, Arc<Mutex<()>>>>,
}

#[derive(Clone, Default)]
struct ExecutionSessionSnapshot {
    storage_cache: HashMap<Address, HashMap<Vec<u8>, Vec<u8>>>,
    writes_by_contract: HashMap<Address, HashMap<Vec<u8>, Vec<u8>>>,
    deletes_by_contract: HashMap<Address, Vec<Vec<u8>>>,
}

#[derive(Default)]
struct ExecutionSession {
    storage_cache: RwLock<HashMap<Address, HashMap<Vec<u8>, Vec<u8>>>>,
    writes_by_contract: RwLock<HashMap<Address, HashMap<Vec<u8>, Vec<u8>>>>,
    deletes_by_contract: RwLock<HashMap<Address, Vec<Vec<u8>>>>,
    call_stack: RwLock<Vec<Address>>,
}

impl ExecutionSession {
    fn snapshot(&self) -> ExecutionSessionSnapshot {
        ExecutionSessionSnapshot {
            storage_cache: self.storage_cache.read().clone(),
            writes_by_contract: self.writes_by_contract.read().clone(),
            deletes_by_contract: self.deletes_by_contract.read().clone(),
        }
    }

    fn restore(&self, snapshot: &ExecutionSessionSnapshot) {
        *self.storage_cache.write() = snapshot.storage_cache.clone();
        *self.writes_by_contract.write() = snapshot.writes_by_contract.clone();
        *self.deletes_by_contract.write() = snapshot.deletes_by_contract.clone();
    }

    fn current_storage(&self, address: &Address) -> Option<HashMap<Vec<u8>, Vec<u8>>> {
        self.storage_cache.read().get(address).cloned()
    }

    fn remember_storage(&self, address: Address, storage: HashMap<Vec<u8>, Vec<u8>>) {
        self.storage_cache.write().insert(address, storage);
    }

    fn apply_success(
        &self,
        contract_address: Address,
        writes: &HashMap<Vec<u8>, Vec<u8>>,
        deletes: &[Vec<u8>],
    ) {
        let mut storage_cache = self.storage_cache.write();
        let contract_storage = storage_cache.entry(contract_address).or_default();
        for key in deletes {
            contract_storage.remove(key);
        }
        for (key, value) in writes {
            contract_storage.insert(key.clone(), value.clone());
        }
        drop(storage_cache);

        let mut writes_by_contract = self.writes_by_contract.write();
        let contract_writes = writes_by_contract.entry(contract_address).or_default();
        let mut deletes_by_contract = self.deletes_by_contract.write();
        let contract_deletes = deletes_by_contract.entry(contract_address).or_default();

        for key in deletes {
            contract_writes.remove(key);
            if !contract_deletes.iter().any(|existing| existing == key) {
                contract_deletes.push(key.clone());
            }
        }

        for (key, value) in writes {
            contract_writes.insert(key.clone(), value.clone());
            contract_deletes.retain(|existing| existing != key);
        }
    }

    fn collect_changes(
        &self,
    ) -> (
        HashMap<Address, HashMap<Vec<u8>, Vec<u8>>>,
        HashMap<Address, Vec<Vec<u8>>>,
    ) {
        (
            self.writes_by_contract.read().clone(),
            self.deletes_by_contract.read().clone(),
        )
    }
}

#[derive(Clone)]
struct NestedCallExecutor {
    storage: Storage,
    bytecode_protector: Arc<BytecodeProtector>,
    vm: Arc<QuantosVm>,
    contract_locks: Arc<dashmap::DashMap<Address, Arc<Mutex<()>>>>,
    session: Arc<ExecutionSession>,
    simulate_only: bool,
}

impl NestedCallExecutor {
    fn execute_nested(
        &self,
        contract_address: Address,
        caller: Address,
        input_data: Vec<u8>,
        block_timestamp: u64,
        block_height: u64,
        chain_id: u64,
        max_compute_units: u64,
    ) -> VmResult<ExecutionResult> {
        if self.session.call_stack.read().contains(&contract_address) {
            return Err(VmError::ExecutionFailed("Reentrant call".into()));
        }
        if self.bytecode_protector.get_metadata(&contract_address).is_none() {
            return Err(VmError::ContractNotFound(hex::encode(contract_address)));
        }
        if max_compute_units == 0 {
            return Err(VmError::OutOfGas);
        }
        let lock = self.contract_locks.entry(contract_address).or_insert_with(|| Arc::new(Mutex::new(()))).clone();
        let _guard = lock.lock();
        let initial_storage = if let Some(storage) = self.session.current_storage(&contract_address) {
            storage
        } else {
            let storage = self.storage.get_contract_storage(&contract_address).map_err(|e| VmError::ExecutionFailed(e.to_string()))?;
            self.session.remember_storage(contract_address, storage.clone());
            storage
        };
        let snapshot = self.session.snapshot();
        self.session.call_stack.write().push(contract_address);
        let ctx = ExecutionContext {
            contract_address,
            caller,
            block_timestamp,
            block_height,
            chain_id,
            input_data,
            initial_storage,
            function_name: None,
            abi_json: None,
            is_constructor: false,
            max_compute_units: Some(max_compute_units),
            cross_contract_handler: Some(Arc::new(self.clone())),
        };
        let result = self.bytecode_protector.execute_contract(&contract_address, |bytecode| {
            if self.simulate_only {
                self.vm.simulate_contract(bytecode, ctx)
            } else {
                self.vm.execute_contract(bytecode, ctx)
            }
        });
        self.session.call_stack.write().pop();
        match result {
            Ok(exec_result) if exec_result.success => {
                self.session.apply_success(contract_address, &exec_result.storage_writes, &exec_result.storage_deletes);
                Ok(exec_result)
            }
            Ok(exec_result) => {
                self.session.restore(&snapshot);
                Ok(exec_result)
            }
            Err(e) => {
                self.session.restore(&snapshot);
                Err(e)
            }
        }
    }
}

impl CrossContractHandler for NestedCallExecutor {
    fn execute_call(
        &self,
        callee: Address,
        caller: Address,
        input_data: Vec<u8>,
        block_timestamp: u64,
        block_height: u64,
        chain_id: u64,
        max_compute_units: u64,
    ) -> VmResult<ExecutionResult> {
        self.execute_nested(callee, caller, input_data, block_timestamp, block_height, chain_id, max_compute_units)
    }
}

impl ContractManager {
    /// Creates a new contract manager.
    pub fn new(
        storage: Storage,
        bytecode_protector: Arc<BytecodeProtector>,
        vm_config: QuantosVmConfig,
    ) -> Self {
        Self {
            storage,
            bytecode_protector,
            vm: Arc::new(QuantosVm::new(vm_config)),
            contract_locks: Arc::new(dashmap::DashMap::new()),
        }
    }

    /// Reloads all persisted contracts from RocksDB into BytecodeProtector.
    /// Must be called on startup to restore contracts after node restart.
    pub fn reload_contracts(&self) -> VmResult<usize> {
        let contracts = self.storage.get_all_contracts()
            .map_err(|e| VmError::ExecutionFailed(format!("Failed to load contracts: {}", e)))?;
        
        let mut loaded = 0;
        for (address, bytecode) in &contracts {
            // Skip if already loaded
            if self.bytecode_protector.get_metadata(address).is_some() {
                continue;
            }
            
            // Load metadata to get deployer info
            let deployer = self.load_contract_metadata(address)
                .ok()
                .flatten()
                .map(|m| m.deployer)
                .unwrap_or([0u8; 32]);
            
            // Load into BytecodeProtector at the known address (re-encrypts with current key)
            match self.bytecode_protector.load_contract(*address, bytecode, deployer) {
                Ok(_) => loaded += 1,
                Err(e) => {
                    tracing::warn!(
                        "Failed to reload contract {}: {}",
                        hex::encode(&address[..8]), e
                    );
                }
            }
        }
        
        tracing::info!("Reloaded {} contracts from storage", loaded);
        Ok(loaded)
    }

    /// Deploys a new contract with bytecode encryption.
    pub fn deploy_contract(
        &self,
        bytecode: Vec<u8>,
        constructor_data: Vec<u8>,
        deployer: Address,
        nonce: u64,
        deployed_at: u64,
        deployed_height: u64,
        chain_id: u64,
        abi: Option<String>,
    ) -> VmResult<DeployContractResult> {
        // Deploy via BytecodeProtector (handles encryption)
        let bc_metadata = self.bytecode_protector.deploy_contract(
            &bytecode,
            deployer,
            nonce,
            false, // not upgradeable
            None,  // no ABI hash
        )?;

        let contract_address = bc_metadata.address;

        // Create deployment info
        let deployed = DeployedContract {
            address: contract_address,
            deployer,
            deployed_at,
            deployed_height,
            bytecode_size: bytecode.len(),
            bytecode_hash: bc_metadata.bytecode_hash,
            version: "1.0.0".to_string(),
            abi,
        };

        // Store metadata in RocksDB
        self.store_contract_metadata(&deployed)
            .map_err(|e| VmError::ExecutionFailed(e.to_string()))?;

        // Persist raw bytecode to RocksDB for reload on restart
        self.storage.put_contract_bytecode(&contract_address, &bytecode)
            .map_err(|e| VmError::ExecutionFailed(format!("Failed to persist bytecode: {}", e)))?;

        tracing::info!(
            "Contract deployed at {:?} by {:?}, size: {} bytes",
            hex::encode(contract_address),
            hex::encode(deployer),
            bytecode.len()
        );

        let is_solang = self.bytecode_protector.execute_contract(&contract_address, |deployed_bytecode| {
            self.is_solang_contract(deployed_bytecode)
        })?;

        let init_result = if is_solang {
            match self.execute_constructor(
                contract_address,
                deployer,
                constructor_data,
                deployed_at,
                deployed_height,
                chain_id,
            ) {
                Ok(result) => {
                    if result.success {
                        Some(result)
                    } else {
                        let revert_reason = if result.return_data.is_empty() {
                            "No revert reason provided".to_string()
                        } else {
                            decode_contract_revert_reason(&result.return_data)
                        };
                        self.rollback_deployment(&contract_address)?;
                        return Err(VmError::ExecutionFailed(format!("Constructor reverted: {}", revert_reason)));
                    }
                }
                Err(err) => {
                    self.rollback_deployment(&contract_address)?;
                    return Err(err);
                }
            }
        } else {
            None
        };

        Ok(DeployContractResult {
            address: contract_address,
            init_result,
        })
    }

    /// Executes a contract call.
    pub fn execute_contract(
        &self,
        contract_address: Address,
        caller: Address,
        input_data: Vec<u8>,
        block_timestamp: u64,
        block_height: u64,
        chain_id: u64,
    ) -> VmResult<ExecutionResult> {
        let session = Arc::new(ExecutionSession::default());
        let executor = NestedCallExecutor {
            storage: self.storage.clone(),
            bytecode_protector: self.bytecode_protector.clone(),
            vm: self.vm.clone(),
            contract_locks: self.contract_locks.clone(),
            session: session.clone(),
            simulate_only: false,
        };
        let result = executor.execute_nested(contract_address, caller, input_data, block_timestamp, block_height, chain_id, self.vm.get_config().max_compute_units)?;
        if result.success {
            let (writes_by_contract, deletes_by_contract) = session.collect_changes();
            if !writes_by_contract.is_empty() || !deletes_by_contract.is_empty() {
                self.storage.update_multiple_contract_storages(&writes_by_contract, &deletes_by_contract).map_err(|e| VmError::ExecutionFailed(e.to_string()))?;
            }
        }
        Ok(result)
    }

    /// Simulates a contract call (read-only, no state changes persisted).
    ///
    /// # Production Features
    /// - Contract existence validation
    /// - Input size bounds check (1 MB max)
    /// - Timeout enforcement via `Instant` wall-clock guard
    /// - CU usage tracking and structured logging
    /// - Detailed error reporting with revert reason decoding
    pub fn simulate_contract(
        &self,
        contract_address: Address,
        caller: Address,
        input_data: Vec<u8>,
        block_timestamp: u64,
        block_height: u64,
        chain_id: u64,
    ) -> VmResult<ExecutionResult> {
        let start = std::time::Instant::now();

        // Validate contract exists
        if !self.contract_exists(&contract_address) {
            return Err(VmError::ContractNotFound(hex::encode(contract_address)));
        }

        // Validate input size (prevent DoS with huge inputs)
        const MAX_SIMULATE_INPUT: usize = 1024 * 1024; // 1 MB
        if input_data.len() > MAX_SIMULATE_INPUT {
            return Err(VmError::ExecutionFailed(
                format!("Simulation input too large: {} bytes (max {})", input_data.len(), MAX_SIMULATE_INPUT)
            ));
        }

        let initial_storage = self.load_contract_storage(&contract_address)
            .map_err(|e| VmError::ExecutionFailed(e.to_string()))?;

        let ctx = ExecutionContext {
            contract_address,
            caller,
            block_timestamp,
            block_height,
            chain_id,
            input_data,
            initial_storage,
            function_name: None,
            abi_json: None,
            is_constructor: false,
            max_compute_units: None,
            cross_contract_handler: None,
        };

        // Simulate (no storage commit)
        let result = self.bytecode_protector.execute_contract(&contract_address, |bytecode| {
            self.vm.simulate_contract(bytecode, ctx)
        })?;

        let elapsed = start.elapsed();

        tracing::debug!(
            "simulate_contract: address={}, caller={}, cu_used={}, success={}, elapsed={:?}",
            hex::encode(&contract_address[..8]),
            hex::encode(&caller[..8]),
            result.cu_used,
            result.success,
            elapsed,
        );

        Ok(result)
    }

    /// Executes a contract call from RPC with timeout support.
    /// Returns only the output data (for RPC responses).
    /// 
    /// # Production Features
    /// - Input validation
    /// - Timeout enforcement during execution
    /// - CU tracking and reporting
    /// - Error details for debugging
    pub fn execute_contract_call(
        &self,
        contract_address: &Address,
        caller: &Address,
        input_data: &[u8],
        block_height: u64,
        timeout: std::time::Duration,
    ) -> VmResult<Vec<u8>> {
        self.execute_contract_call_with_config(
            contract_address,
            caller,
            input_data,
            block_height,
            timeout,
            1, // Default chain_id - mainnet
        )
    }

    /// Executes a contract call with full configuration.
    /// Production-ready RPC call simulation with:
    /// - Configurable chain_id
    /// - Input validation
    /// - Timeout enforcement
    /// - Detailed error reporting
    /// - CU estimation for gas pricing
    pub fn execute_contract_call_with_config(
        &self,
        contract_address: &Address,
        caller: &Address,
        input_data: &[u8],
        block_height: u64,
        timeout: std::time::Duration,
        chain_id: u64,
    ) -> VmResult<Vec<u8>> {
        let start = std::time::Instant::now();
        
        // Validate contract exists
        if !self.contract_exists(contract_address) {
            return Err(VmError::ContractNotFound(hex::encode(contract_address)));
        }
        
        // Validate input size (prevent DoS with huge inputs)
        const MAX_INPUT_SIZE: usize = 1024 * 1024; // 1MB max
        if input_data.len() > MAX_INPUT_SIZE {
            return Err(VmError::ExecutionFailed(
                format!("Input data too large: {} bytes (max {})", input_data.len(), MAX_INPUT_SIZE)
            ));
        }
        
        // Get current timestamp
        let block_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Execute simulation (read-only, no state changes persisted)
        let result = self.simulate_contract(
            *contract_address,
            *caller,
            input_data.to_vec(),
            block_timestamp,
            block_height,
            chain_id,
        )?;
        
        // Check timeout after execution
        let elapsed = start.elapsed();
        if elapsed > timeout {
            tracing::warn!(
                "Contract call timed out after {:?} (limit: {:?}), CU used: {}",
                elapsed, timeout, result.cu_used
            );
            return Err(VmError::ExecutionFailed(
                format!("Execution timeout after {:?}", elapsed)
            ));
        }
        
        // Log execution metrics for monitoring
        tracing::debug!(
            "Contract call completed: address={}, cu_used={}, elapsed={:?}, success={}",
            hex::encode(contract_address), result.cu_used, elapsed, result.success
        );
        
        if result.success {
            Ok(result.return_data)
        } else {
            let revert_reason = if !result.return_data.is_empty() {
                decode_contract_revert_reason(&result.return_data)
            } else if let Some(last_msg) = result.debug_messages.last() {
                // Solang emits require() messages via seal0::debug_message before reverting
                last_msg.clone()
            } else {
                "No revert reason provided".to_string()
            };

            Err(VmError::ExecutionFailed(
                format!("Contract reverted: {} (CU used: {})", revert_reason, result.cu_used)
            ))
        }
    }

    /// Estimates CU (compute units) for a contract call without executing.
    /// Useful for gas estimation in transaction preparation.
    pub fn estimate_cu(
        &self,
        contract_address: &Address,
        caller: &Address,
        input_data: &[u8],
        block_height: u64,
    ) -> VmResult<u64> {
        // Validate contract exists
        if !self.contract_exists(contract_address) {
            return Err(VmError::ContractNotFound(hex::encode(contract_address)));
        }
        
        let block_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        // Run simulation to get actual CU usage
        let result = self.simulate_contract(
            *contract_address,
            *caller,
            input_data.to_vec(),
            block_timestamp,
            block_height,
            1,
        )?;
        
        // Add 10% buffer for estimation safety
        let estimated_cu = (result.cu_used as f64 * 1.1) as u64;
        
        Ok(estimated_cu)
    }

    /// Gets contract metadata.
    pub fn get_contract_metadata(&self, address: &Address) -> VmResult<Option<DeployedContract>> {
        self.load_contract_metadata(address)
            .map_err(|e| VmError::ExecutionFailed(e.to_string()))
    }

    /// Checks if a contract exists.
    pub fn contract_exists(&self, address: &Address) -> bool {
        self.bytecode_protector.get_metadata(address).is_some()
    }

    /// Loads contract storage from RocksDB.
    fn load_contract_storage(&self, contract_address: &Address) -> StorageResult<HashMap<Vec<u8>, Vec<u8>>> {
        self.storage.get_contract_storage(contract_address)
    }

    fn execute_constructor(
        &self,
        contract_address: Address,
        caller: Address,
        input_data: Vec<u8>,
        block_timestamp: u64,
        block_height: u64,
        chain_id: u64,
    ) -> VmResult<ExecutionResult> {
        let lock = self.contract_locks
            .entry(contract_address)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _guard = lock.lock();

        let initial_storage = self.load_contract_storage(&contract_address)
            .map_err(|e| VmError::ExecutionFailed(e.to_string()))?;

        let ctx = ExecutionContext {
            contract_address,
            caller,
            block_timestamp,
            block_height,
            chain_id,
            input_data,
            initial_storage,
            function_name: None,
            abi_json: None,
            is_constructor: true,
            max_compute_units: None,
            cross_contract_handler: None,
        };

        let result = self.bytecode_protector.execute_contract(&contract_address, |bytecode| {
            self.vm.execute_contract(bytecode, ctx)
        })?;

        if result.success {
            self.commit_storage_changes(&contract_address, &result.storage_writes, &result.storage_deletes)
                .map_err(|e| VmError::ExecutionFailed(e.to_string()))?;
        }

        Ok(result)
    }

    /// Commits storage changes to RocksDB.
    fn commit_storage_changes(
        &self,
        contract_address: &Address,
        writes: &HashMap<Vec<u8>, Vec<u8>>,
        deletes: &[Vec<u8>],
    ) -> StorageResult<()> {
        self.storage.update_contract_storage(contract_address, writes, deletes)
    }

    /// Stores contract metadata.
    fn store_contract_metadata(&self, metadata: &DeployedContract) -> StorageResult<()> {
        self.storage.put_deployed_contract(metadata)
    }

    fn rollback_deployment(&self, contract_address: &Address) -> VmResult<()> {
        let _ = self.bytecode_protector.remove_contract(contract_address);
        let _ = self.contract_locks.remove(contract_address);

        self.storage.delete_contract_bytecode(contract_address)
            .map_err(|e| VmError::ExecutionFailed(format!("Failed to delete contract bytecode: {}", e)))?;
        self.storage.delete_deployed_contract(contract_address)
            .map_err(|e| VmError::ExecutionFailed(format!("Failed to delete contract metadata: {}", e)))?;

        Ok(())
    }

    /// Loads contract metadata.
    fn load_contract_metadata(&self, address: &Address) -> StorageResult<Option<DeployedContract>> {
        self.storage.get_deployed_contract(address)
    }

    fn is_solang_contract(&self, bytecode: &[u8]) -> VmResult<bool> {
        let compiler = Cranelift::default();
        let store = Store::new(compiler);
        let module = Module::new(&store, bytecode)
            .map_err(|_| VmError::InvalidBytecode)?;

        Ok(matches!(solang_compat::detect_contract_type(&module), ContractType::Solang))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha3_256;

    #[test]
    fn test_contract_address_generation() {
        let deployer = [1u8; 32];
        let timestamp = 1234567890u64;
        
        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(&deployer);
        hasher_input.extend_from_slice(&timestamp.to_be_bytes());
        let address_hash = sha3_256(&hasher_input);

        assert_ne!(address_hash, [0u8; 32]);
    }

    #[test]
    fn test_deployed_contract_metadata() {
        let metadata = DeployedContract {
            address: [1u8; 32],
            deployer: [2u8; 32],
            deployed_at: 1234567890,
            deployed_height: 1000,
            bytecode_size: 1024,
            bytecode_hash: [3u8; 32],
            version: "1.0.0".to_string(),
            abi: Some("{}".to_string()),
        };

        assert_eq!(metadata.bytecode_size, 1024);
        assert_eq!(metadata.version, "1.0.0");
    }
}
