//! # QuantosVM - WASM Runtime
//!
//! Production-ready WASM execution engine with Wasmer.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      QuantosVM Runtime                       │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Wasmer Engine → Cranelift Compiler → Sandbox Isolation     │
//! │  Memory Limits → CU Metering → Host Functions               │
//! │  Bytecode Protection → Secure Execution → Auto-cleanup      │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Features
//!
//! - **Wasmer Engine**: Fast WASM execution with Cranelift
//! - **Sandbox Isolation**: Memory limits, stack limits, CU tracking
//! - **Host Functions**: qnt_storage_*, qnt_block_*, qnt_crypto_*
//! - **Gas Metering**: CU (Compute Units) tracking - zero fees but resource limits
//! - **Security**: Integrated with BytecodeProtector

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use sha3::{Digest, Sha3_256};
use wasmer::{
    imports, Function, FunctionEnv, FunctionEnvMut, Instance, Memory, MemoryType, Module, Store, Value, AsStoreRef,
};
use wasmer_compiler_cranelift::Cranelift;

use crate::crypto::{verify_dilithium, verify_dilithium_batch};
use crate::types::{Address, Hash};
use crate::vm::{VmError, VmResult};
use crate::vm::solang_compat::{self, ContractType};

/// QuantosVM configuration.
#[derive(Clone, Debug)]
pub struct QuantosVmConfig {
    /// Maximum memory pages (64KB each)
    pub max_memory_pages: u32,
    /// Maximum stack size in bytes
    pub max_stack_size: usize,
    /// Maximum CU (Compute Units) per execution
    pub max_compute_units: u64,
    /// Enable debug mode
    pub debug_mode: bool,
}

impl Default for QuantosVmConfig {
    fn default() -> Self {
        Self {
            max_memory_pages: 1024, // 64 MB
            max_stack_size: 1024 * 1024, // 1 MB
            max_compute_units: 100_000_000, // 100M CU
            debug_mode: false,
        }
    }
}

pub trait CrossContractHandler: Send + Sync {
    fn execute_call(
        &self,
        callee: Address,
        caller: Address,
        input_data: Vec<u8>,
        block_timestamp: u64,
        block_height: u64,
        chain_id: u64,
        max_compute_units: u64,
    ) -> VmResult<ExecutionResult>;
}

/// Host environment for WASM execution.
#[derive(Clone)]
pub struct HostEnv {
    /// Contract address being executed
    pub contract_address: Address,
    /// Caller address
    pub caller: Address,
    /// Current block timestamp
    pub block_timestamp: u64,
    /// Current block height
    pub block_height: u64,
    /// Chain ID
    pub chain_id: u64,
    /// Storage access (contract-scoped)
    pub storage: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>,
    /// Logs emitted
    pub logs: Arc<RwLock<Vec<ContractLog>>>,
    /// Remaining compute units
    pub remaining_cu: Arc<RwLock<u64>>,
    /// Initial compute units
    pub initial_cu: u64,
    /// Memory reference (set after instantiation)
    pub memory: Arc<RwLock<Option<Memory>>>,
    /// Return data buffer
    pub return_data: Arc<RwLock<Vec<u8>>>,
    /// Storage writes (for commit)
    pub storage_writes: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>,
    /// Storage deletes
    pub storage_deletes: Arc<RwLock<Vec<Vec<u8>>>>,
    /// Input data (calldata) — used by Solang contracts via seal_input
    pub input_data: Arc<RwLock<Vec<u8>>>,
    /// Set to true when contract explicitly reverts (seal_return flags=1)
    pub reverted: Arc<RwLock<bool>>,
    /// Set to true when seal_return was called (normal Solang termination)
    pub seal_return_called: Arc<RwLock<bool>>,
    pub cross_contract_handler: Option<Arc<dyn CrossContractHandler>>,
    /// Messages emitted via seal0::debug_message (used as revert reason fallback)
    pub debug_messages: Arc<RwLock<Vec<String>>>,
}

/// Contract log entry.
#[derive(Clone, Debug)]
pub struct ContractLog {
    pub address: Address,
    pub topics: Vec<Hash>,
    pub data: Vec<u8>,
}

impl HostEnv {
    pub fn new(
        contract_address: Address,
        caller: Address,
        block_timestamp: u64,
        block_height: u64,
        chain_id: u64,
        max_cu: u64,
        initial_storage: HashMap<Vec<u8>, Vec<u8>>,
        input_data: Vec<u8>,
        cross_contract_handler: Option<Arc<dyn CrossContractHandler>>,
    ) -> Self {
        Self {
            contract_address,
            caller,
            block_timestamp,
            block_height,
            chain_id,
            storage: Arc::new(RwLock::new(initial_storage)),
            logs: Arc::new(RwLock::new(Vec::new())),
            remaining_cu: Arc::new(RwLock::new(max_cu)),
            initial_cu: max_cu,
            memory: Arc::new(RwLock::new(None)),
            return_data: Arc::new(RwLock::new(Vec::new())),
            storage_writes: Arc::new(RwLock::new(HashMap::new())),
            storage_deletes: Arc::new(RwLock::new(Vec::new())),
            input_data: Arc::new(RwLock::new(input_data)),
            reverted: Arc::new(RwLock::new(false)),
            seal_return_called: Arc::new(RwLock::new(false)),
            cross_contract_handler,
            debug_messages: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn set_memory(&self, memory: Memory) {
        *self.memory.write() = Some(memory);
    }

    pub fn consume_cu(&self, amount: u64) -> VmResult<()> {
        let mut remaining = self.remaining_cu.write();
        if *remaining < amount {
            return Err(VmError::OutOfGas);
        }
        *remaining -= amount;
        Ok(())
    }

    pub fn get_remaining_cu(&self) -> u64 {
        *self.remaining_cu.read()
    }

    pub fn get_used_cu(&self) -> u64 {
        self.initial_cu - self.get_remaining_cu()
    }

    /// Reads bytes from WASM memory.
    pub fn read_memory(&self, store: &impl AsStoreRef, ptr: u32, len: u32) -> VmResult<Vec<u8>> {
        let memory_guard = self.memory.read();
        let memory = memory_guard.as_ref()
            .ok_or(VmError::ExecutionFailed("Memory not initialized".into()))?;
        
        let view = memory.view(store);
        let mut buffer = vec![0u8; len as usize];
        view.read(ptr as u64, &mut buffer)
            .map_err(|e| VmError::ExecutionFailed(format!("Memory read failed: {}", e)))?;
        
        Ok(buffer)
    }

    /// Writes bytes to WASM memory.
    pub fn write_memory(&self, store: &impl AsStoreRef, ptr: u32, data: &[u8]) -> VmResult<()> {
        let memory_guard = self.memory.read();
        let memory = memory_guard.as_ref()
            .ok_or(VmError::ExecutionFailed("Memory not initialized".into()))?;
        
        let view = memory.view(store);
        view.write(ptr as u64, data)
            .map_err(|e| VmError::ExecutionFailed(format!("Memory write failed: {}", e)))?;
        
        Ok(())
    }
}

/// QuantosVM runtime.
pub struct QuantosVm {
    config: QuantosVmConfig,
}

impl QuantosVm {
    /// Creates a new QuantosVM runtime.
    pub fn new(config: QuantosVmConfig) -> Self {
        Self { config }
    }

}

// ============================================================================
// Host Functions - Production Ready
// ============================================================================

/// CU costs for operations
const CU_STORAGE_WRITE: u64 = 5000;
const CU_STORAGE_READ: u64 = 1000;
const CU_STORAGE_DELETE: u64 = 2500;
const CU_LOG_BASE: u64 = 500;
const CU_LOG_PER_BYTE: u64 = 5;
const CU_HASH_BASE: u64 = 100;
const CU_HASH_PER_BYTE: u64 = 1;
const CU_VERIFY_SIGNATURE: u64 = 50000;
const CU_MEMORY_COPY_PER_BYTE: u64 = 1;

/// MEDIUM: Maximum storage value size to prevent write amplification
const MAX_STORAGE_VALUE_SIZE: u32 = 64 * 1024; // 64 KB
const MAX_STORAGE_KEY_SIZE: u32 = 256; // 256 bytes

/// Saves data to contract storage.
fn qnt_storage_save(
    env: FunctionEnvMut<HostEnv>,
    key_ptr: u32,
    key_len: u32,
    value_ptr: u32,
    value_len: u32,
) -> u32 {
    let host_env = env.data();
    
    // MEDIUM: Validate sizes to prevent write amplification
    if key_len > MAX_STORAGE_KEY_SIZE {
        return 3; // Key too large
    }
    if value_len > MAX_STORAGE_VALUE_SIZE {
        return 4; // Value too large
    }
    
    // MEDIUM: Use checked arithmetic to prevent overflow
    let memory_cost = (value_len as u64)
        .checked_mul(CU_MEMORY_COPY_PER_BYTE)
        .unwrap_or(u64::MAX);
    
    let cu_cost = CU_STORAGE_WRITE
        .checked_add(memory_cost)
        .unwrap_or(u64::MAX);
    
    if host_env.consume_cu(cu_cost).is_err() {
        return 1; // Out of CU
    }

    // Read key from WASM memory
    let key = match host_env.read_memory(&env, key_ptr, key_len) {
        Ok(k) => k,
        Err(_) => return 2, // Memory error
    };

    // Read value from WASM memory
    let value = match host_env.read_memory(&env, value_ptr, value_len) {
        Ok(v) => v,
        Err(_) => return 2, // Memory error
    };

    // Store in pending writes (will be committed on success)
    host_env.storage_writes.write().insert(key.clone(), value.clone());
    
    // Also update live storage for subsequent reads
    host_env.storage.write().insert(key, value);
    
    0 // Success
}

/// Gets data from contract storage.
fn qnt_storage_get(
    env: FunctionEnvMut<HostEnv>,
    key_ptr: u32,
    key_len: u32,
    value_ptr: u32,
    max_value_len: u32,
) -> u32 {
    let host_env = env.data();
    
    // Base cost for storage read
    if host_env.consume_cu(CU_STORAGE_READ).is_err() {
        return 0; // Out of CU - return 0 length
    }

    // Read key from WASM memory
    let key = match host_env.read_memory(&env, key_ptr, key_len) {
        Ok(k) => k,
        Err(_) => return 0, // Memory error
    };

    // Lookup in storage
    let storage = host_env.storage.read();
    let value = match storage.get(&key) {
        Some(v) => v.clone(),
        None => return 0, // Key not found
    };
    drop(storage);

    // Calculate how much to write
    let write_len = (value.len() as u32).min(max_value_len);
    
    // Charge for memory copy (v5: checked arithmetic)
    let copy_cost = (write_len as u64)
        .checked_mul(CU_MEMORY_COPY_PER_BYTE)
        .unwrap_or(u64::MAX);
    if host_env.consume_cu(copy_cost).is_err() {
        return 0;
    }

    // Write value to WASM memory
    if host_env.write_memory(&env, value_ptr, &value[..write_len as usize]).is_err() {
        return 0;
    }

    write_len // Return actual length written
}

/// Checks if a key exists in storage.
fn qnt_storage_exists(
    env: FunctionEnvMut<HostEnv>,
    key_ptr: u32,
    key_len: u32,
) -> u32 {
    let host_env = env.data();
    
    if host_env.consume_cu(CU_STORAGE_READ / 2).is_err() {
        return 0;
    }

    let key = match host_env.read_memory(&env, key_ptr, key_len) {
        Ok(k) => k,
        Err(_) => return 0,
    };

    if host_env.storage.read().contains_key(&key) { 1 } else { 0 }
}

/// Removes data from contract storage.
fn qnt_storage_remove(
    env: FunctionEnvMut<HostEnv>,
    key_ptr: u32,
    key_len: u32,
) -> u32 {
    let host_env = env.data();
    
    if host_env.consume_cu(CU_STORAGE_DELETE).is_err() {
        return 1;
    }

    let key = match host_env.read_memory(&env, key_ptr, key_len) {
        Ok(k) => k,
        Err(_) => return 2,
    };

    // Record deletion
    host_env.storage_deletes.write().push(key.clone());
    host_env.storage.write().remove(&key);
    
    0 // Success
}

/// Returns current block timestamp.
fn qnt_block_timestamp(env: FunctionEnvMut<HostEnv>) -> u64 {
    env.data().block_timestamp
}

/// Returns current block height.
fn qnt_block_height(env: FunctionEnvMut<HostEnv>) -> u64 {
    env.data().block_height
}

/// Returns chain ID.
fn qnt_chain_id(env: FunctionEnvMut<HostEnv>) -> u64 {
    env.data().chain_id
}

/// Returns remaining compute units.
fn qnt_remaining_cu(env: FunctionEnvMut<HostEnv>) -> u64 {
    env.data().get_remaining_cu()
}

/// Returns caller address (writes to WASM memory).
fn qnt_caller(
    env: FunctionEnvMut<HostEnv>,
    ptr: u32,
) -> u32 {
    let host_env = env.data();
    
    if host_env.consume_cu(50).is_err() {
        return 0;
    }

    // Write 20-byte address to WASM memory
    if host_env.write_memory(&env, ptr, &host_env.caller).is_err() {
        return 0;
    }
    
    20 // Address length
}

/// Returns contract address (writes to WASM memory).
fn qnt_contract_address(
    env: FunctionEnvMut<HostEnv>,
    ptr: u32,
) -> u32 {
    let host_env = env.data();
    
    if host_env.consume_cu(50).is_err() {
        return 0;
    }

    if host_env.write_memory(&env, ptr, &host_env.contract_address).is_err() {
        return 0;
    }
    
    20 // Address length
}

/// Emits a log with topics and data.
fn qnt_log(
    env: FunctionEnvMut<HostEnv>,
    topics_ptr: u32,
    topics_count: u32,
    data_ptr: u32,
    data_len: u32,
) -> u32 {
    let host_env = env.data();
    
    // Calculate CU cost (v5: checked arithmetic)
    let cu_cost = CU_LOG_BASE
        .checked_add((data_len as u64).checked_mul(CU_LOG_PER_BYTE).unwrap_or(u64::MAX))
        .and_then(|c| c.checked_add((topics_count as u64).checked_mul(100).unwrap_or(u64::MAX)))
        .unwrap_or(u64::MAX);
    if host_env.consume_cu(cu_cost).is_err() {
        return 1;
    }

    // Read topics (each is 32 bytes)
    let mut topics = Vec::new();
    for i in 0..topics_count.min(4) { // Max 4 topics
        let topic_offset = topics_ptr + (i * 32);
        match host_env.read_memory(&env, topic_offset, 32) {
            Ok(topic_bytes) => {
                let mut topic = [0u8; 32];
                topic.copy_from_slice(&topic_bytes);
                topics.push(topic);
            }
            Err(_) => return 2,
        }
    }

    // Read data
    let data = match host_env.read_memory(&env, data_ptr, data_len) {
        Ok(d) => d,
        Err(_) => return 2,
    };

    // Record log
    host_env.logs.write().push(ContractLog {
        address: host_env.contract_address,
        topics,
        data,
    });
    
    0 // Success
}

/// Sets return data for the contract call.
fn qnt_return(
    env: FunctionEnvMut<HostEnv>,
    data_ptr: u32,
    data_len: u32,
) {
    let host_env = env.data();
    
    // v5: checked arithmetic
    let cu_cost = (data_len as u64)
        .checked_mul(CU_MEMORY_COPY_PER_BYTE)
        .unwrap_or(u64::MAX);
    if host_env.consume_cu(cu_cost).is_err() {
        return;
    }

    if let Ok(data) = host_env.read_memory(&env, data_ptr, data_len) {
        *host_env.return_data.write() = data;
    }
}

/// Reverts execution with error data.
fn qnt_revert(
    env: FunctionEnvMut<HostEnv>,
    data_ptr: u32,
    data_len: u32,
) {
    let host_env = env.data();
    
    if let Ok(data) = host_env.read_memory(&env, data_ptr, data_len) {
        *host_env.return_data.write() = data;
    }
    
    // Set remaining CU to 0 to trigger abort
    *host_env.remaining_cu.write() = 0;
}

/// Computes SHA3-256 hash.
fn qnt_hash_sha3(
    env: FunctionEnvMut<HostEnv>,
    data_ptr: u32,
    data_len: u32,
    output_ptr: u32,
) -> u32 {
    let host_env = env.data();
    
    // v5: checked arithmetic
    let cu_cost = CU_HASH_BASE
        .checked_add((data_len as u64).checked_mul(CU_HASH_PER_BYTE).unwrap_or(u64::MAX))
        .unwrap_or(u64::MAX);
    if host_env.consume_cu(cu_cost).is_err() {
        return 1;
    }

    // Read data from WASM memory
    let data = match host_env.read_memory(&env, data_ptr, data_len) {
        Ok(d) => d,
        Err(_) => return 2,
    };

    // Compute SHA3-256
    let mut hasher = Sha3_256::new();
    hasher.update(&data);
    let hash: [u8; 32] = hasher.finalize().into();

    // Write hash to output
    if host_env.write_memory(&env, output_ptr, &hash).is_err() {
        return 2;
    }
    
    0 // Success
}

/// Computes Blake3 hash.
fn qnt_hash_blake3(
    env: FunctionEnvMut<HostEnv>,
    data_ptr: u32,
    data_len: u32,
    output_ptr: u32,
) -> u32 {
    let host_env = env.data();
    
    // v5: checked arithmetic
    let cu_cost = CU_HASH_BASE
        .checked_add((data_len as u64).checked_mul(CU_HASH_PER_BYTE).unwrap_or(u64::MAX))
        .unwrap_or(u64::MAX);
    if host_env.consume_cu(cu_cost).is_err() {
        return 1;
    }

    let data = match host_env.read_memory(&env, data_ptr, data_len) {
        Ok(d) => d,
        Err(_) => return 2,
    };

    let hash = blake3::hash(&data);

    if host_env.write_memory(&env, output_ptr, hash.as_bytes()).is_err() {
        return 2;
    }
    
    0
}

/// Verifies a Dilithium signature (post-quantum).
fn qnt_verify_dilithium(
    env: FunctionEnvMut<HostEnv>,
    pubkey_ptr: u32,
    pubkey_len: u32,
    message_ptr: u32,
    message_len: u32,
    sig_ptr: u32,
    sig_len: u32,
) -> u32 {
    let host_env = env.data();
    
    // High CU cost for cryptographic verification
    if host_env.consume_cu(CU_VERIFY_SIGNATURE).is_err() {
        return 2; // Out of CU
    }

    // Read public key
    let pubkey = match host_env.read_memory(&env, pubkey_ptr, pubkey_len) {
        Ok(k) => k,
        Err(_) => return 2,
    };

    // Read message
    let message = match host_env.read_memory(&env, message_ptr, message_len) {
        Ok(m) => m,
        Err(_) => return 2,
    };

    // Read signature
    let signature = match host_env.read_memory(&env, sig_ptr, sig_len) {
        Ok(s) => s,
        Err(_) => return 2,
    };

    // Verify using pooled batch verification worker
    if verify_dilithium_batch(pubkey, message, signature) {
        1
    } else {
        0
    }
}

/// Copies memory within WASM.
fn qnt_memcpy(
    env: FunctionEnvMut<HostEnv>,
    dest_ptr: u32,
    src_ptr: u32,
    len: u32,
) -> u32 {
    let host_env = env.data();
    
    // v5: checked arithmetic
    let cu_cost = (len as u64)
        .checked_mul(CU_MEMORY_COPY_PER_BYTE)
        .unwrap_or(u64::MAX);
    if host_env.consume_cu(cu_cost).is_err() {
        return 1;
    }

    let data = match host_env.read_memory(&env, src_ptr, len) {
        Ok(d) => d,
        Err(_) => return 2,
    };

    if host_env.write_memory(&env, dest_ptr, &data).is_err() {
        return 2;
    }
    
    0
}

/// Execution result.
#[derive(Clone, Debug)]
pub struct ExecutionResult {
    pub success: bool,
    pub return_data: Vec<u8>,
    pub cu_used: u64,
    pub logs: Vec<ContractLog>,
    pub storage_writes: HashMap<Vec<u8>, Vec<u8>>,
    pub storage_deletes: Vec<Vec<u8>>,
    pub storage_updates_by_contract: HashMap<Address, HashMap<Vec<u8>, Vec<u8>>>,
    pub storage_deletes_by_contract: HashMap<Address, Vec<Vec<u8>>>,
    /// Messages emitted by the contract via seal0::debug_message
    pub debug_messages: Vec<String>,
}

/// Execution context for contract calls.
#[derive(Clone)]
pub struct ExecutionContext {
    pub contract_address: Address,
    pub caller: Address,
    pub block_timestamp: u64,
    pub block_height: u64,
    pub chain_id: u64,
    pub input_data: Vec<u8>,
    pub initial_storage: HashMap<Vec<u8>, Vec<u8>>,
    /// Function name to call (if using ABI routing)
    pub function_name: Option<String>,
    /// ABI JSON (for routing)
    pub abi_json: Option<String>,
    /// If true, call the constructor (Solang: "deploy") instead of "call"
    pub is_constructor: bool,
    pub max_compute_units: Option<u64>,
    pub cross_contract_handler: Option<Arc<dyn CrossContractHandler>>,
}

/// Maximum memory pages for Solang contracts (patched at load time).
/// Solang v0.3.x hardcodes max=16 pages (1MB) which is too small for complex contracts.
const SOLANG_MAX_MEMORY_PAGES: u32 = 127; // 8 MB — max single-byte LEB128 value

/// Patches a Solang-compiled WASM binary to increase the memory import's max pages.
///
/// Solang v0.3.x for Polkadot declares `(import "env" "memory" (memory 16 16))`,
/// limiting contracts to 1MB. Complex math (e.g. concentrated liquidity AMM) needs
/// more heap. This scans the import section and bumps max to SOLANG_MAX_MEMORY_PAGES.
///
/// Returns patched bytecode, or empty Vec if no patch needed.
fn patch_solang_memory_limit(bytecode: &[u8]) -> Vec<u8> {
    // Pattern: 0x03 "env" 0x06 "memory" 0x02(mem import) 0x01(has_max) min max
    let pattern: &[u8] = &[
        0x03, 0x65, 0x6e, 0x76,                         // "\x03env"
        0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79,       // "\x06memory"
        0x02,                                             // import kind = memory
        0x01,                                             // limits: has_max flag
    ];
    // Find the pattern in the bytecode
    for i in 0..bytecode.len().saturating_sub(pattern.len() + 2) {
        if bytecode[i..i + pattern.len()] == *pattern {
            let min_idx = i + pattern.len();
            let max_idx = min_idx + 1; // Both are single-byte LEB128 for values <= 127
            if max_idx < bytecode.len() && bytecode[min_idx] <= 127 && bytecode[max_idx] <= 127 {
                let old_max = bytecode[max_idx];
                if old_max < SOLANG_MAX_MEMORY_PAGES as u8 {
                    let mut patched = bytecode.to_vec();
                    patched[max_idx] = SOLANG_MAX_MEMORY_PAGES as u8;
                    eprintln!("[WASM_PATCH] Increased memory max from {} to {} pages", old_max, SOLANG_MAX_MEMORY_PAGES);
                    return patched;
                }
            }
        }
    }
    Vec::new() // No patch needed
}

impl QuantosVm {
    pub fn get_config(&self) -> &QuantosVmConfig {
        &self.config
    }

    /// Executes contract with full result - Production ready.
    pub fn execute_contract(
        &self,
        bytecode: &[u8],
        ctx: ExecutionContext,
    ) -> VmResult<ExecutionResult> {
        // Create Wasmer store
        let compiler = Cranelift::default();
        let mut store = Store::new(compiler);

        // Patch Solang WASM memory limits: Solang v0.3.x declares max=16 pages (1MB)
        // which is insufficient for complex contracts. Increase to 127 pages (8MB).
        let patched_bytecode = patch_solang_memory_limit(bytecode);
        let wasm_bytes: &[u8] = if !patched_bytecode.is_empty() { &patched_bytecode } else { bytecode };

        // Compile WASM module
        let module = Module::new(&store, wasm_bytes)
            .map_err(|_e| VmError::InvalidBytecode)?;

        // Detect contract type (native Quantos vs Solang-compiled Solidity)
        let contract_type = solang_compat::detect_contract_type(&module);

        // Create host environment
        let host_env = HostEnv::new(
            ctx.contract_address,
            ctx.caller,
            ctx.block_timestamp,
            ctx.block_height,
            ctx.chain_id,
            ctx.max_compute_units.unwrap_or(self.config.max_compute_units),
            ctx.initial_storage,
            ctx.input_data.clone(),
            ctx.cross_contract_handler.clone(),
        );

        let env = FunctionEnv::new(&mut store, host_env.clone());

        // Build import object based on contract type
        let import_object = match contract_type {
            ContractType::Native => {
                imports! {
                    "env" => {
                        "qnt_storage_save" => Function::new_typed_with_env(&mut store, &env, qnt_storage_save),
                        "qnt_storage_get" => Function::new_typed_with_env(&mut store, &env, qnt_storage_get),
                        "qnt_storage_exists" => Function::new_typed_with_env(&mut store, &env, qnt_storage_exists),
                        "qnt_storage_remove" => Function::new_typed_with_env(&mut store, &env, qnt_storage_remove),
                        "qnt_block_timestamp" => Function::new_typed_with_env(&mut store, &env, qnt_block_timestamp),
                        "qnt_block_height" => Function::new_typed_with_env(&mut store, &env, qnt_block_height),
                        "qnt_chain_id" => Function::new_typed_with_env(&mut store, &env, qnt_chain_id),
                        "qnt_remaining_cu" => Function::new_typed_with_env(&mut store, &env, qnt_remaining_cu),
                        "qnt_caller" => Function::new_typed_with_env(&mut store, &env, qnt_caller),
                        "qnt_contract_address" => Function::new_typed_with_env(&mut store, &env, qnt_contract_address),
                        "qnt_log" => Function::new_typed_with_env(&mut store, &env, qnt_log),
                        "qnt_return" => Function::new_typed_with_env(&mut store, &env, qnt_return),
                        "qnt_revert" => Function::new_typed_with_env(&mut store, &env, qnt_revert),
                        "qnt_hash_sha3" => Function::new_typed_with_env(&mut store, &env, qnt_hash_sha3),
                        "qnt_hash_blake3" => Function::new_typed_with_env(&mut store, &env, qnt_hash_blake3),
                        "qnt_verify_dilithium" => Function::new_typed_with_env(&mut store, &env, qnt_verify_dilithium),
                        "qnt_memcpy" => Function::new_typed_with_env(&mut store, &env, qnt_memcpy),
                    }
                }
            }
            ContractType::Solang => {
                // Solang v0.3.x uses names WITHOUT "seal_" prefix (except seal_return).
                // We register BOTH variants for maximum compatibility.
                // Memory is imported from "env" module, not exported by the WASM.
                let solang_memory = Memory::new(&mut store, MemoryType::new(16, Some(SOLANG_MAX_MEMORY_PAGES), false))
                    .map_err(|e| VmError::ExecutionFailed(format!("Memory creation failed: {}", e)))?;
                // Set memory on HostEnv NOW (before instantiation) so seal_* functions can use it.
                host_env.set_memory(solang_memory.clone());

                imports! {
                    // env namespace — memory import required by Solang
                    "env" => {
                        "memory" => solang_memory,
                    },
                    // seal0 namespace — core Substrate contract API
                    // Solang v0.3.x: no "seal_" prefix (except seal_return)
                    "seal0" => {
                        // Input/Output
                        "input" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_input),
                        "seal_input" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_input),
                        "seal_return" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_return),
                        // Caller / Address
                        "caller" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_caller),
                        "seal_caller" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_caller),
                        "address" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_address),
                        "seal_address" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_address),
                        // Block info
                        "block_number" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_block_number),
                        "seal_block_number" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_block_number),
                        "now" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_now),
                        "seal_now" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_now),
                        // Value / Balance
                        "value_transferred" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_value_transferred),
                        "seal_value_transferred" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_value_transferred),
                        "balance" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_balance),
                        "seal_balance" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_balance),
                        "minimum_balance" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_minimum_balance),
                        "seal_minimum_balance" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_minimum_balance),
                        "weight_to_fee" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_weight_to_fee),
                        "seal_weight_to_fee" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_weight_to_fee),
                        // Events
                        "deposit_event" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_deposit_event),
                        "seal_deposit_event" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_deposit_event),
                        // Hashing
                        "hash_keccak_256" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_hash_keccak_256),
                        "seal_hash_keccak_256" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_hash_keccak_256),
                        "hash_sha2_256" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_hash_sha2_256),
                        "seal_hash_sha2_256" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_hash_sha2_256),
                        "hash_blake2_256" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_hash_blake2_256),
                        "seal_hash_blake2_256" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_hash_blake2_256),
                        // Debug
                        "debug_message" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_debug_message),
                        "seal_debug_message" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_debug_message),
                    },
                    // seal1 namespace — storage v1 (variable-length keys)
                    "seal1" => {
                        "call" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_call),
                        "seal_call" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_call),
                        "set_storage" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_set_storage),
                        "seal_set_storage" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_set_storage),
                        "get_storage" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_get_storage),
                        "seal_get_storage" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_get_storage),
                        "clear_storage" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_clear_storage),
                        "seal_clear_storage" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_clear_storage),
                    },
                    // seal2 namespace — storage v2 (latest, used by Solang v0.3.x)
                    "seal2" => {
                        "set_storage" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_set_storage),
                        "seal_set_storage" => Function::new_typed_with_env(&mut store, &env, solang_compat::seal_set_storage),
                    }
                }
            }
        };

        // Instantiate module
        let instance = Instance::new(&mut store, &module, &import_object)
            .map_err(|e| VmError::ExecutionFailed(e.to_string()))?;

        // Get and set memory reference.
        // For Solang contracts, memory is imported via "env"::memory (already in imports).
        // For native contracts, memory is exported by the WASM module.
        // After instantiation, both are accessible via exports.
        if let Ok(memory) = instance.exports.get_memory("memory") {
            host_env.set_memory(memory.clone());
        } else {
            // Fallback: try to get memory from any export
            for export in instance.exports.iter() {
                if let wasmer::Extern::Memory(mem) = export.1 {
                    host_env.set_memory(mem.clone());
                    break;
                }
            }
        }

        // Execute based on contract type
        let exec_result = match contract_type {
            ContractType::Native => {
                // Native: allocate input in WASM memory and pass as args
                let input_ptr = if !ctx.input_data.is_empty() {
                    if let Ok(alloc) = instance.exports.get_function("alloc") {
                        let result = alloc.call(&mut store, &[Value::I32(ctx.input_data.len() as i32)])
                            .map_err(|e| VmError::ExecutionFailed(e.to_string()))?;
                        if let Some(Value::I32(ptr)) = result.first() {
                            let _ = host_env.write_memory(&store, *ptr as u32, &ctx.input_data);
                            *ptr as u32
                        } else {
                            0
                        }
                    } else {
                        0
                    }
                } else {
                    0
                };

                // Get the entry point
                let entry_func = if let Some(ref func_name) = ctx.function_name {
                    instance.exports.get_function(func_name)
                        .or_else(|_| instance.exports.get_function("call"))
                        .map_err(|_| VmError::FunctionNotFound(func_name.clone()))?
                } else {
                    instance.exports.get_function("call")
                        .or_else(|_| instance.exports.get_function("main"))
                        .or_else(|_| instance.exports.get_function("_start"))
                        .map_err(|_| VmError::ExecutionFailed("No entry point found".into()))?
                };

                entry_func.call(
                    &mut store,
                    &[Value::I32(input_ptr as i32), Value::I32(ctx.input_data.len() as i32)]
                )
            }
            ContractType::Solang => {
                // Solang: contract reads calldata via seal_input() — no args to entry point.
                // Use "deploy" for constructors, "call" for regular calls.
                let entry_name = if ctx.is_constructor { "deploy" } else { "call" };

                let entry_func = instance.exports.get_function(entry_name)
                    .map_err(|_| VmError::FunctionNotFound(
                        format!("Solang entry point '{}' not found", entry_name)
                    ))?;

                entry_func.call(&mut store, &[])
            }
        };

        // Collect results from host environment
        let cu_used = host_env.get_used_cu();
        let logs = host_env.logs.read().clone();
        let return_data = host_env.return_data.read().clone();
        let storage_writes = host_env.storage_writes.read().clone();
        let storage_deletes = host_env.storage_deletes.read().clone();
        let debug_messages = host_env.debug_messages.read().clone();

        match exec_result {
            Ok(_) => {
                Ok(ExecutionResult {
                    success: true,
                    return_data,
                    cu_used,
                    logs,
                    storage_writes,
                    storage_deletes,
                    storage_updates_by_contract: HashMap::new(),
                    storage_deletes_by_contract: HashMap::new(),
                    debug_messages,
                })
            }
            Err(_e) => {
                let reverted = *host_env.reverted.read();
                let seal_returned = *host_env.seal_return_called.read();

                tracing::warn!(
                    "[WASM_TRAP] contract={} reverted={} seal_returned={} cu_used={} return_data_len={} debug_msgs={:?} error={:?}",
                    hex::encode(&ctx.contract_address[..8]),
                    reverted,
                    seal_returned,
                    cu_used,
                    return_data.len(),
                    &debug_messages,
                    _e,
                );

                if reverted {
                    // Contract explicitly reverted via seal_return(flags=1)
                    Ok(ExecutionResult {
                        success: false,
                        return_data, // May contain revert reason
                        cu_used,
                        logs: Vec::new(),
                        storage_writes: HashMap::new(),
                        storage_deletes: Vec::new(),
                        storage_updates_by_contract: HashMap::new(),
                        storage_deletes_by_contract: HashMap::new(),
                        debug_messages,
                    })
                } else if seal_returned {
                    // Solang pattern: seal_return(flags=0) was called, then WASM hits
                    // `unreachable` instruction causing a trap. This is NORMAL success.
                    // Applies even with empty return data (constructors).
                    Ok(ExecutionResult {
                        success: true,
                        return_data,
                        cu_used,
                        logs,
                        storage_writes,
                        storage_deletes,
                        storage_updates_by_contract: HashMap::new(),
                        storage_deletes_by_contract: HashMap::new(),
                        debug_messages,
                    })
                } else if host_env.get_remaining_cu() == 0 {
                    Err(VmError::OutOfGas)
                } else {
                    // True execution failure (e.g., trap, panic)
                    Ok(ExecutionResult {
                        success: false,
                        return_data,
                        cu_used,
                        logs,
                        storage_writes: HashMap::new(),
                        storage_deletes: Vec::new(),
                        storage_updates_by_contract: HashMap::new(),
                        storage_deletes_by_contract: HashMap::new(),
                        debug_messages,
                    })
                }
            }
        }
    }

    /// Simulates a contract call (read-only, no state changes persisted).
    pub fn simulate_contract(
        &self,
        bytecode: &[u8],
        ctx: ExecutionContext,
    ) -> VmResult<ExecutionResult> {
        // Same as execute but don't persist storage changes
        let result = self.execute_contract(bytecode, ctx)?;
        Ok(ExecutionResult {
            success: result.success,
            return_data: result.return_data,
            cu_used: result.cu_used,
            logs: result.logs,
            storage_writes: HashMap::new(), // Discard writes in simulation
            storage_deletes: Vec::new(),
            storage_updates_by_contract: HashMap::new(),
            storage_deletes_by_contract: HashMap::new(),
            debug_messages: result.debug_messages,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quantos_vm_creation() {
        let config = QuantosVmConfig::default();
        let vm = QuantosVm::new(config);
        
        assert_eq!(vm.config.max_compute_units, 100_000_000);
    }

    #[test]
    fn test_host_env_cu_consumption() {
        let env = HostEnv::new(
            [1u8; 32],
            [2u8; 32],
            1000,
            100,
            1, // chain_id
            10000,
            HashMap::new(),
            Vec::new(),
            None,
        );

        assert!(env.consume_cu(5000).is_ok());
        assert_eq!(env.get_remaining_cu(), 5000);
        assert_eq!(env.get_used_cu(), 5000);
        
        assert!(env.consume_cu(5000).is_ok());
        assert_eq!(env.get_remaining_cu(), 0);
        
        // Should fail - out of CU
        assert!(env.consume_cu(1).is_err());
    }

    #[test]
    fn test_config_defaults() {
        let config = QuantosVmConfig::default();
        assert_eq!(config.max_memory_pages, 1024);
        assert_eq!(config.max_compute_units, 100_000_000);
        assert_eq!(config.max_stack_size, 1024 * 1024);
    }

    #[test]
    fn test_execution_context() {
        let ctx = ExecutionContext {
            contract_address: [1u8; 32],
            caller: [2u8; 32],
            block_timestamp: 1234567890,
            block_height: 100,
            chain_id: 1,
            input_data: vec![1, 2, 3],
            initial_storage: HashMap::new(),
            function_name: None,
            abi_json: None,
            is_constructor: false,
            max_compute_units: None,
            cross_contract_handler: None,
        };

        assert_eq!(ctx.input_data.len(), 3);
        assert_eq!(ctx.chain_id, 1);
        assert_eq!(ctx.function_name, None);
    }

    #[test]
    fn test_cu_costs() {
        assert!(CU_STORAGE_WRITE > CU_STORAGE_READ);
        assert!(CU_VERIFY_SIGNATURE > CU_HASH_BASE);
    }
}
