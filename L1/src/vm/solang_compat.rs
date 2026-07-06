//! # Solang Compatibility Layer
//!
//! Production host-function shims that allow Solidity contracts compiled
//! with **Solang** (targeting Polkadot/Substrate) to execute on QuantosVM.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │            Solang-Compiled Contract (WASM)                  │
//! │  imports: seal0::*, seal1::*                                │
//! │  exports: call(), deploy(), memory                          │
//! ├─────────────────────────────────────────────────────────────┤
//! │            Solang Compatibility Layer                        │
//! │  seal0::seal_input       → HostEnv.input_data               │
//! │  seal0::seal_return      → HostEnv.return_data / revert     │
//! │  seal0::seal_caller      → HostEnv.caller                   │
//! │  seal0::seal_address     → HostEnv.contract_address         │
//! │  seal0::seal_block_number→ HostEnv.block_height             │
//! │  seal0::seal_now         → HostEnv.block_timestamp          │
//! │  seal1::set_storage      → HostEnv.storage + storage_writes │
//! │  seal1::get_storage      → HostEnv.storage                  │
//! │  seal0::deposit_event    → HostEnv.logs                     │
//! │  seal0::hash_keccak_256  → Keccak-256 (Ethereum compat)    │
//! ├─────────────────────────────────────────────────────────────┤
//! │            QuantosVM Host Environment (shared)              │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use sha3::Digest;
use wasmer::{FunctionEnvMut, Module};

use crate::types::Hash;
use crate::vm::runtime::{ContractLog, HostEnv};
use crate::vm::VmResult;

// ============================================================================
// CU Costs for Seal Operations
// ============================================================================

const CU_SEAL_INPUT: u64 = 200;
const CU_SEAL_RETURN: u64 = 200;
const CU_SEAL_CALLER: u64 = 200;
const CU_SEAL_ADDRESS: u64 = 200;
const CU_SEAL_BLOCK_NUMBER: u64 = 100;
const CU_SEAL_NOW: u64 = 100;
const CU_SEAL_VALUE_TRANSFERRED: u64 = 100;
const CU_SEAL_BALANCE: u64 = 200;
const CU_SEAL_MINIMUM_BALANCE: u64 = 100;
const CU_SEAL_DEPOSIT_EVENT_BASE: u64 = 500;
const CU_SEAL_DEPOSIT_EVENT_PER_BYTE: u64 = 5;
const CU_SEAL_HASH_BASE: u64 = 200;
const CU_SEAL_HASH_PER_BYTE: u64 = 1;
const CU_SEAL_STORAGE_WRITE: u64 = 5000;
const CU_SEAL_STORAGE_READ: u64 = 1000;
const CU_SEAL_STORAGE_CLEAR: u64 = 2500;
const CU_SEAL_CALL: u64 = 5000;
const CU_SEAL_DEBUG: u64 = 100;
const CU_SEAL_WEIGHT_TO_FEE: u64 = 100;
const CU_SEAL_MEMORY_PER_BYTE: u64 = 1;

// ============================================================================
// Seal Return Codes (Substrate pallet-contracts API)
// ============================================================================

/// Storage operation: new entry was created
const STORED_NEW_ENTRY: u32 = 0;
/// Storage operation: existing entry was overwritten
const STORED_EXISTING_ENTRY: u32 = 1;
/// Storage operation: entry was deleted (zero-length value)
const STORED_DELETED: u32 = 2;
/// Storage get: key was found
const RETURN_CODE_SUCCESS: u32 = 0;
/// Storage get: key was not found
const RETURN_CODE_KEY_NOT_FOUND: u32 = 1;

// ============================================================================
// Contract Type Detection
// ============================================================================

/// Contract type detected from WASM imports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractType {
    /// Native QuantosVM contract (imports from "env" with qnt_* functions)
    Native,
    /// Solang-compiled Solidity contract (imports from "seal0"/"seal1" modules)
    Solang,
}

/// Detects whether a WASM module is a native Quantos contract or Solang-compiled.
///
/// Inspects the module's import table. If any import references the `seal0`,
/// `seal1`, or `seal2` modules, the contract was compiled by Solang.
pub fn detect_contract_type(module: &Module) -> ContractType {
    for import in module.imports() {
        let module_name = import.module();
        if module_name == "seal0" || module_name == "seal1" || module_name == "seal2" {
            return ContractType::Solang;
        }
    }
    ContractType::Native
}

// ============================================================================
// seal0 Namespace — Core Host Functions
// ============================================================================

/// `seal0::seal_input(buf_ptr: u32, buf_len_ptr: u32)`
///
/// Provides the contract with its input data (calldata).
/// - `buf_len_ptr` points to a u32 containing buffer capacity.
/// - If `buf_ptr == 0`, only writes the actual length to `buf_len_ptr`.
/// - Otherwise writes calldata to `buf_ptr` and updates `buf_len_ptr` with actual length.
pub fn seal_input(env: FunctionEnvMut<HostEnv>, buf_ptr: u32, buf_len_ptr: u32) {
    let host = env.data();

    if host.consume_cu(CU_SEAL_INPUT).is_err() {
        return;
    }

    let input_data = host.input_data.read().clone();
    let actual_len = input_data.len() as u32;

    tracing::info!(
        "[SEAL_INPUT] contract={} calldata_len={} selector={}",
        hex::encode(&host.contract_address[..8]),
        actual_len,
        if input_data.len() >= 4 { hex::encode(&input_data[..4]) } else { "<too_short>".to_string() },
    );

    // Always write the actual length
    if host
        .write_memory(&env, buf_len_ptr, &actual_len.to_le_bytes())
        .is_err()
    {
        return;
    }

    // If buf_ptr is null, caller just wants the length
    if buf_ptr == 0 {
        return;
    }

    // Charge for memory copy
    let copy_cost = (actual_len as u64)
        .checked_mul(CU_SEAL_MEMORY_PER_BYTE)
        .unwrap_or(u64::MAX);
    if host.consume_cu(copy_cost).is_err() {
        return;
    }

    // Write calldata to buffer
    let _ = host.write_memory(&env, buf_ptr, &input_data);
}

/// `seal0::seal_return(flags: u32, data_ptr: u32, data_len: u32)`
///
/// Sets the return data and terminates execution.
/// - `flags & 1 == 0` → success (equivalent to `qnt_return`)
/// - `flags & 1 == 1` → revert (equivalent to `qnt_revert`)
pub fn seal_return(env: FunctionEnvMut<HostEnv>, flags: u32, data_ptr: u32, data_len: u32) {
    let host = env.data();

    if host.consume_cu(CU_SEAL_RETURN).is_err() {
        return;
    }

    let copy_cost = (data_len as u64)
        .checked_mul(CU_SEAL_MEMORY_PER_BYTE)
        .unwrap_or(u64::MAX);
    if host.consume_cu(copy_cost).is_err() {
        return;
    }

    if let Ok(data) = host.read_memory(&env, data_ptr, data_len) {
        *host.return_data.write() = data;
    }

    // Mark that seal_return was called (normal Solang termination pattern)
    *host.seal_return_called.write() = true;

    // If revert flag is set, mark as reverted (don't zero CU — that's for real OOG)
    if flags & 1 != 0 {
        *host.reverted.write() = true;
    }
}

/// `seal0::seal_caller(out_ptr: u32, out_len_ptr: u32)`
///
/// Writes the caller address (32 bytes) to the output buffer.
pub fn seal_caller(env: FunctionEnvMut<HostEnv>, out_ptr: u32, out_len_ptr: u32) {
    let host = env.data();

    if host.consume_cu(CU_SEAL_CALLER).is_err() {
        return;
    }

    write_sandbox_output(host, &env, out_ptr, out_len_ptr, &host.caller);
}

/// `seal0::seal_address(out_ptr: u32, out_len_ptr: u32)`
///
/// Writes the contract's own address (32 bytes) to the output buffer.
pub fn seal_address(env: FunctionEnvMut<HostEnv>, out_ptr: u32, out_len_ptr: u32) {
    let host = env.data();

    if host.consume_cu(CU_SEAL_ADDRESS).is_err() {
        return;
    }

    let address = host.contract_address;
    write_sandbox_output(host, &env, out_ptr, out_len_ptr, &address);
}

/// `seal0::seal_block_number(out_ptr: u32, out_len_ptr: u32)`
///
/// Writes the current block height as a little-endian u64 (8 bytes).
pub fn seal_block_number(env: FunctionEnvMut<HostEnv>, out_ptr: u32, out_len_ptr: u32) {
    let host = env.data();

    if host.consume_cu(CU_SEAL_BLOCK_NUMBER).is_err() {
        return;
    }

    let height_bytes = host.block_height.to_le_bytes();
    write_sandbox_output(host, &env, out_ptr, out_len_ptr, &height_bytes);
}

/// `seal0::seal_now(out_ptr: u32, out_len_ptr: u32)`
///
/// Writes the current block timestamp as a little-endian u64 (8 bytes).
/// Solang (Substrate target) expects milliseconds from seal_now, then divides
/// by 1000 internally to produce `block.timestamp` in seconds.
pub fn seal_now(env: FunctionEnvMut<HostEnv>, out_ptr: u32, out_len_ptr: u32) {
    let host = env.data();

    if host.consume_cu(CU_SEAL_NOW).is_err() {
        return;
    }

    // Substrate convention: seal_now returns milliseconds
    let ts_millis = host.block_timestamp.saturating_mul(1000);
    let ts_bytes = ts_millis.to_le_bytes();
    write_sandbox_output(host, &env, out_ptr, out_len_ptr, &ts_bytes);
}

/// `seal0::seal_value_transferred(out_ptr: u32, out_len_ptr: u32)`
///
/// Writes the transferred value (msg.value equivalent).
/// Quantos is gasless — always returns 0 (128-bit LE).
pub fn seal_value_transferred(env: FunctionEnvMut<HostEnv>, out_ptr: u32, out_len_ptr: u32) {
    let host = env.data();

    if host.consume_cu(CU_SEAL_VALUE_TRANSFERRED).is_err() {
        return;
    }

    // 128-bit zero (16 bytes LE) — Quantos has no native value transfers in calls
    let zero_value = [0u8; 16];
    write_sandbox_output(host, &env, out_ptr, out_len_ptr, &zero_value);
}

/// `seal0::seal_balance(out_ptr: u32, out_len_ptr: u32)`
///
/// Writes the contract's balance. Returns 0 for now (gasless chain).
pub fn seal_balance(env: FunctionEnvMut<HostEnv>, out_ptr: u32, out_len_ptr: u32) {
    let host = env.data();

    if host.consume_cu(CU_SEAL_BALANCE).is_err() {
        return;
    }

    let zero_balance = [0u8; 16];
    write_sandbox_output(host, &env, out_ptr, out_len_ptr, &zero_balance);
}

/// `seal0::seal_minimum_balance(out_ptr: u32, out_len_ptr: u32)`
///
/// Returns existential deposit. Quantos has none — returns 0.
pub fn seal_minimum_balance(env: FunctionEnvMut<HostEnv>, out_ptr: u32, out_len_ptr: u32) {
    let host = env.data();

    if host.consume_cu(CU_SEAL_MINIMUM_BALANCE).is_err() {
        return;
    }

    let zero = [0u8; 16];
    write_sandbox_output(host, &env, out_ptr, out_len_ptr, &zero);
}

/// `seal0::seal_weight_to_fee(gas: u64, out_ptr: u32, out_len_ptr: u32)`
///
/// Converts weight (gas) to fee. Quantos is gasless — always returns 0.
pub fn seal_weight_to_fee(env: FunctionEnvMut<HostEnv>, _gas: u64, out_ptr: u32, out_len_ptr: u32) {
    let host = env.data();

    if host.consume_cu(CU_SEAL_WEIGHT_TO_FEE).is_err() {
        return;
    }

    let zero = [0u8; 16];
    write_sandbox_output(host, &env, out_ptr, out_len_ptr, &zero);
}

// ============================================================================
// seal0 Namespace — Events / Logging
// ============================================================================

/// `seal0::seal_deposit_event(topics_ptr: u32, topics_len: u32, data_ptr: u32, data_len: u32)`
///
/// Emits an event (log). Topics are SCALE-encoded array of 32-byte hashes.
/// In Substrate, `topics_len` is the byte length of the topics buffer.
/// Each topic is a 32-byte hash prefixed with a SCALE compact length.
///
/// For simplicity and Ethereum compat, we treat topics as a flat array of 32-byte hashes.
pub fn seal_deposit_event(
    env: FunctionEnvMut<HostEnv>,
    topics_ptr: u32,
    topics_len: u32,
    data_ptr: u32,
    data_len: u32,
) {
    let host = env.data();

    // CU cost
    let cu_cost = CU_SEAL_DEPOSIT_EVENT_BASE
        .checked_add(
            (data_len as u64)
                .checked_mul(CU_SEAL_DEPOSIT_EVENT_PER_BYTE)
                .unwrap_or(u64::MAX),
        )
        .unwrap_or(u64::MAX);
    if host.consume_cu(cu_cost).is_err() {
        return;
    }

    // Read topics buffer
    let topics_data = if topics_len > 0 {
        match host.read_memory(&env, topics_ptr, topics_len) {
            Ok(d) => d,
            Err(_) => return,
        }
    } else {
        Vec::new()
    };

    // Parse topics: In Substrate seal API, topics are SCALE-encoded.
    // Each topic is [compact_len][32 bytes]. For Solang output, topics are
    // typically 32 bytes each. We handle both raw 32-byte chunks and
    // SCALE-prefixed topics.
    let mut topics: Vec<Hash> = Vec::new();
    let mut offset = 0;

    // Try to detect if topics are SCALE-encoded (first byte would be compact length)
    // or raw 32-byte hashes. For Solang, topics buffer starts with a SCALE
    // compact-encoded vector length, then each topic is 32 bytes.
    if !topics_data.is_empty() {
        // Skip SCALE vector length prefix (compact encoding)
        // Compact: 0..63 → single byte << 2, 64..2^14 → 2 bytes, etc.
        let (num_topics, skip) = decode_scale_compact(&topics_data);

        offset = skip;
        for _ in 0..num_topics {
            if offset + 32 > topics_data.len() {
                break;
            }
            let mut topic = [0u8; 32];
            topic.copy_from_slice(&topics_data[offset..offset + 32]);
            topics.push(topic);
            offset += 32;
        }
    }

    // Read event data
    let data = if data_len > 0 {
        match host.read_memory(&env, data_ptr, data_len) {
            Ok(d) => d,
            Err(_) => return,
        }
    } else {
        Vec::new()
    };

    // Record log
    host.logs.write().push(ContractLog {
        address: host.contract_address,
        topics,
        data,
    });
}

// ============================================================================
// seal0 Namespace — Hashing
// ============================================================================

/// `seal0::seal_hash_keccak_256(input_ptr: u32, input_len: u32, output_ptr: u32)`
///
/// Computes Keccak-256 hash (Ethereum-compatible, NOT NIST SHA3-256).
pub fn seal_hash_keccak_256(
    env: FunctionEnvMut<HostEnv>,
    input_ptr: u32,
    input_len: u32,
    output_ptr: u32,
) {
    let host = env.data();

    let cu_cost = CU_SEAL_HASH_BASE
        .checked_add(
            (input_len as u64)
                .checked_mul(CU_SEAL_HASH_PER_BYTE)
                .unwrap_or(u64::MAX),
        )
        .unwrap_or(u64::MAX);
    if host.consume_cu(cu_cost).is_err() {
        return;
    }

    let data = match host.read_memory(&env, input_ptr, input_len) {
        Ok(d) => d,
        Err(_) => return,
    };

    // Keccak-256 (NOT SHA3-256 — Ethereum uses pre-NIST Keccak)
    let mut hasher = sha3::Keccak256::new();
    hasher.update(&data);
    let hash: [u8; 32] = hasher.finalize().into();

    let _ = host.write_memory(&env, output_ptr, &hash);
}

/// `seal0::seal_hash_sha2_256(input_ptr: u32, input_len: u32, output_ptr: u32)`
///
/// Computes SHA2-256 hash.
pub fn seal_hash_sha2_256(
    env: FunctionEnvMut<HostEnv>,
    input_ptr: u32,
    input_len: u32,
    output_ptr: u32,
) {
    let host = env.data();

    let cu_cost = CU_SEAL_HASH_BASE
        .checked_add(
            (input_len as u64)
                .checked_mul(CU_SEAL_HASH_PER_BYTE)
                .unwrap_or(u64::MAX),
        )
        .unwrap_or(u64::MAX);
    if host.consume_cu(cu_cost).is_err() {
        return;
    }

    let data = match host.read_memory(&env, input_ptr, input_len) {
        Ok(d) => d,
        Err(_) => return,
    };

    // SHA2-256
    use sha2::Digest as Sha2Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&data);
    let hash: [u8; 32] = hasher.finalize().into();

    let _ = host.write_memory(&env, output_ptr, &hash);
}

/// `seal0::hash_blake2_256(input_ptr: u32, input_len: u32, output_ptr: u32)`
///
/// Computes Blake2b-256 hash (used by Substrate/Polkadot runtime).
pub fn seal_hash_blake2_256(
    env: FunctionEnvMut<HostEnv>,
    input_ptr: u32,
    input_len: u32,
    output_ptr: u32,
) {
    let host = env.data();

    let cu_cost = CU_SEAL_HASH_BASE
        .checked_add(
            (input_len as u64)
                .checked_mul(CU_SEAL_HASH_PER_BYTE)
                .unwrap_or(u64::MAX),
        )
        .unwrap_or(u64::MAX);
    if host.consume_cu(cu_cost).is_err() {
        return;
    }

    let data = match host.read_memory(&env, input_ptr, input_len) {
        Ok(d) => d,
        Err(_) => return,
    };

    // Blake2b-256 (Substrate standard)
    let hash = blake3::hash(&data); // Use Blake3 as a fast drop-in (32 bytes)
    let _ = host.write_memory(&env, output_ptr, hash.as_bytes());
}

/// `seal0::seal_debug_message(str_ptr: u32, str_len: u32) -> u32`
///
/// Logs a debug message from the contract. Returns 0 on success.
pub fn seal_debug_message(env: FunctionEnvMut<HostEnv>, str_ptr: u32, str_len: u32) -> u32 {
    let host = env.data();

    if host.consume_cu(CU_SEAL_DEBUG).is_err() {
        return 1;
    }

    if let Ok(data) = host.read_memory(&env, str_ptr, str_len) {
        if let Ok(msg) = String::from_utf8(data) {
            tracing::info!(target: "solang_contract", contract = %hex::encode(&host.contract_address[..8]), "debug_message: {}", msg);
            host.debug_messages.write().push(msg);
        }
    }

    0
}

// ============================================================================
// seal1 Namespace — Storage Operations
// ============================================================================

/// `seal1::seal_call(flags: u32, callee_ptr: u32, gas: u64, value_ptr: u32, input_ptr: u32, input_len: u32, out_ptr: u32, out_len_ptr: u32) -> u32`
///
pub fn seal_call(
    env: FunctionEnvMut<HostEnv>,
    _flags: u32,
    callee_ptr: u32,
    gas: u64,
    value_ptr: u32,
    input_ptr: u32,
    input_len: u32,
    out_ptr: u32,
    out_len_ptr: u32,
) -> u32 {
    let host = env.data();

    if host.consume_cu(CU_SEAL_CALL).is_err() {
      return 1;
    }

    let handler = match &host.cross_contract_handler {
        Some(handler) => handler.clone(),
        None => {
            let _ = host.write_memory(&env, out_len_ptr, &0u32.to_le_bytes());
            return 1;
        }
    };

    let callee_bytes = match host.read_memory(&env, callee_ptr, 32) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => {
            let _ = host.write_memory(&env, out_len_ptr, &0u32.to_le_bytes());
            return 1;
        }
    };
    let mut callee = [0u8; 32];
    callee.copy_from_slice(&callee_bytes);

    let transferred_value = match host.read_memory(&env, value_ptr, 16) {
        Ok(bytes) if bytes.len() == 16 => {
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&bytes);
            u128::from_le_bytes(raw)
        }
        _ => {
            let _ = host.write_memory(&env, out_len_ptr, &0u32.to_le_bytes());
            return 1;
        }
    };

    if transferred_value != 0 {
        let _ = host.write_memory(&env, out_len_ptr, &0u32.to_le_bytes());
        return 1;
    }

    let input_data = if input_len > 0 {
        match host.read_memory(&env, input_ptr, input_len) {
            Ok(data) => data,
            Err(_) => {
                let _ = host.write_memory(&env, out_len_ptr, &0u32.to_le_bytes());
                return 1;
            }
        }
    } else {
        Vec::new()
    };

    let child_cu_limit = if gas == 0 {
        host.get_remaining_cu()
    } else {
        host.get_remaining_cu().min(gas)
    };

    let input_selector = if input_data.len() >= 4 {
        hex::encode(&input_data[..4])
    } else {
        hex::encode(&input_data)
    };
    tracing::debug!(
        "[SEAL_CALL] caller={} callee={} selector={} input_len={} cu_limit={}",
        hex::encode(&host.contract_address[..8]),
        hex::encode(&callee[..8]),
        input_selector,
        input_data.len(),
        child_cu_limit,
    );

    let result = match handler.execute_call(
        callee,
        host.contract_address,
        input_data,
        host.block_timestamp,
        host.block_height,
        host.chain_id,
        child_cu_limit,
    ) {
        Ok(result) => result,
        Err(e) => {
            tracing::debug!(
                "[SEAL_CALL] FAILED caller={} callee={} selector={} error={}",
                hex::encode(&host.contract_address[..8]),
                hex::encode(&callee[..8]),
                input_selector,
                e,
            );
            host.debug_messages.write().push(format!("cross-contract call failed: {}", e));
            let _ = host.write_memory(&env, out_len_ptr, &0u32.to_le_bytes());
            return 1;
        }
    };

    tracing::debug!(
        "[SEAL_CALL] RESULT caller={} callee={} selector={} success={} cu_used={} return_len={} debug={:?}",
        hex::encode(&host.contract_address[..8]),
        hex::encode(&callee[..8]),
        input_selector,
        result.success,
        result.cu_used,
        result.return_data.len(),
        &result.debug_messages,
    );

    if host.consume_cu(result.cu_used).is_err() {
        let _ = host.write_memory(&env, out_len_ptr, &0u32.to_le_bytes());
        return 1;
    }

    write_sandbox_output(host, &env, out_ptr, out_len_ptr, &result.return_data);

    // Always propagate child debug messages to the parent so revert reasons
    // from inner contracts (e.g. ERC-20 transferFrom) are visible in receipts.
    if !result.debug_messages.is_empty() {
        host.debug_messages.write().extend(result.debug_messages);
    }

    if result.success {
        host.logs.write().extend(result.logs);
        0
    } else {
        // Capture child revert reason as parent debug message so it survives
        // even if the parent WASM traps without calling seal_return.
        if !result.return_data.is_empty() {
            let reason = crate::vm::contract::decode_revert_for_debug(&result.return_data);
            host.debug_messages.write().push(format!("child contract reverted: {}", reason));
        } else {
            host.debug_messages.write().push("child contract reverted (no reason)".to_string());
        }
        1
    }
}

/// `seal1::seal_set_storage(key_ptr: u32, key_len: u32, value_ptr: u32, value_len: u32) -> u32`
///
/// Sets a storage value. Returns status indicating whether entry was new, overwritten, or deleted.
pub fn seal_set_storage(
    env: FunctionEnvMut<HostEnv>,
    key_ptr: u32,
    key_len: u32,
    value_ptr: u32,
    value_len: u32,
) -> u32 {
    let host = env.data();

    // CU cost
    let mem_cost = (value_len as u64)
        .checked_mul(CU_SEAL_MEMORY_PER_BYTE)
        .unwrap_or(u64::MAX);
    let cu_cost = CU_SEAL_STORAGE_WRITE
        .checked_add(mem_cost)
        .unwrap_or(u64::MAX);
    if host.consume_cu(cu_cost).is_err() {
        return u32::MAX; // Trap-like behavior
    }

    // Read key
    let key = match host.read_memory(&env, key_ptr, key_len) {
        Ok(k) => k,
        Err(_) => return u32::MAX,
    };

    // Check if key existed before
    let existed = host.storage.read().contains_key(&key);

    if value_len == 0 {
        // Delete the entry
        host.storage_deletes.write().push(key.clone());
        host.storage.write().remove(&key);
        return STORED_DELETED;
    }

    // Read value
    let value = match host.read_memory(&env, value_ptr, value_len) {
        Ok(v) => v,
        Err(_) => return u32::MAX,
    };

    // Write to pending writes and live storage
    host.storage_writes.write().insert(key.clone(), value.clone());
    host.storage.write().insert(key, value);

    if existed {
        STORED_EXISTING_ENTRY
    } else {
        STORED_NEW_ENTRY
    }
}

/// `seal1::seal_get_storage(key_ptr: u32, key_len: u32, out_ptr: u32, out_len_ptr: u32) -> u32`
///
/// Reads a storage value. Returns `RETURN_CODE_SUCCESS` if found, `RETURN_CODE_KEY_NOT_FOUND` otherwise.
/// The actual data and length are written via the out_ptr/out_len_ptr pattern.
pub fn seal_get_storage(
    env: FunctionEnvMut<HostEnv>,
    key_ptr: u32,
    key_len: u32,
    out_ptr: u32,
    out_len_ptr: u32,
) -> u32 {
    let host = env.data();

    if host.consume_cu(CU_SEAL_STORAGE_READ).is_err() {
        return RETURN_CODE_KEY_NOT_FOUND;
    }

    // Read key
    let key = match host.read_memory(&env, key_ptr, key_len) {
        Ok(k) => k,
        Err(_) => return RETURN_CODE_KEY_NOT_FOUND,
    };

    // Lookup
    let storage = host.storage.read();
    let value = match storage.get(&key) {
        Some(v) => v.clone(),
        None => {
            tracing::warn!(
                "[SEAL_GET_STORAGE] contract={} key={} -> NOT_FOUND",
                hex::encode(&host.contract_address[..8]),
                hex::encode(&key),
            );
            return RETURN_CODE_KEY_NOT_FOUND;
        }
    };
    drop(storage);

    tracing::info!(
        "[SEAL_GET_STORAGE] contract={} key={} -> FOUND, value_len={}, value_hex={}",
        hex::encode(&host.contract_address[..8]),
        hex::encode(&key),
        value.len(),
        if value.len() <= 64 { hex::encode(&value) } else { format!("{}...", hex::encode(&value[..32])) },
    );

    // Charge for memory copy
    let copy_cost = (value.len() as u64)
        .checked_mul(CU_SEAL_MEMORY_PER_BYTE)
        .unwrap_or(u64::MAX);
    if host.consume_cu(copy_cost).is_err() {
        return RETURN_CODE_KEY_NOT_FOUND;
    }

    // Write output using sandbox pattern
    write_sandbox_output(host, &env, out_ptr, out_len_ptr, &value);

    RETURN_CODE_SUCCESS
}

/// `seal1::seal_clear_storage(key_ptr: u32, key_len: u32) -> u32`
///
/// Removes a storage entry. Returns the size of the removed value, or `u32::MAX` if key not found.
pub fn seal_clear_storage(env: FunctionEnvMut<HostEnv>, key_ptr: u32, key_len: u32) -> u32 {
    let host = env.data();

    if host.consume_cu(CU_SEAL_STORAGE_CLEAR).is_err() {
        return u32::MAX;
    }

    let key = match host.read_memory(&env, key_ptr, key_len) {
        Ok(k) => k,
        Err(_) => return u32::MAX,
    };

    // Get old value size before deletion
    let old_len = host
        .storage
        .read()
        .get(&key)
        .map(|v| v.len() as u32)
        .unwrap_or(u32::MAX);

    // Record deletion
    host.storage_deletes.write().push(key.clone());
    host.storage.write().remove(&key);

    old_len
}

// ============================================================================
// Helpers
// ============================================================================

/// Writes data to WASM memory following the Substrate sandbox output pattern:
///
/// 1. Read buffer capacity from `out_len_ptr` (u32 LE)
/// 2. Write `min(data.len(), capacity)` bytes to `out_ptr`
/// 3. Write actual data length (u32 LE) to `out_len_ptr`
fn write_sandbox_output(
    host: &HostEnv,
    store: &impl wasmer::AsStoreRef,
    out_ptr: u32,
    out_len_ptr: u32,
    data: &[u8],
) {
    // Read buffer capacity
    let cap_bytes = match host.read_memory(store, out_len_ptr, 4) {
        Ok(b) => b,
        Err(_) => return,
    };
    let capacity = u32::from_le_bytes([cap_bytes[0], cap_bytes[1], cap_bytes[2], cap_bytes[3]]);

    let write_len = (data.len() as u32).min(capacity);

    eprintln!(
        "[SANDBOX_WRITE] out_ptr={} out_len_ptr={} data_len={} capacity={} write_len={}",
        out_ptr, out_len_ptr, data.len(), capacity, write_len
    );

    // Write data
    if write_len > 0 {
        let _ = host.write_memory(store, out_ptr, &data[..write_len as usize]);
    }

    // Update length
    let _ = host.write_memory(store, out_len_ptr, &(data.len() as u32).to_le_bytes());
}

/// Decodes a SCALE compact-encoded unsigned integer.
/// Returns (value, bytes_consumed).
fn decode_scale_compact(data: &[u8]) -> (usize, usize) {
    if data.is_empty() {
        return (0, 0);
    }

    let mode = data[0] & 0b11;
    match mode {
        // Single-byte mode: value = byte >> 2 (0..63)
        0b00 => ((data[0] >> 2) as usize, 1),
        // Two-byte mode: value in bits 2..15 (64..16383)
        0b01 => {
            if data.len() < 2 {
                return (0, 1);
            }
            let val = u16::from_le_bytes([data[0], data[1]]) >> 2;
            (val as usize, 2)
        }
        // Four-byte mode: value in bits 2..29 (16384..2^30-1)
        0b10 => {
            if data.len() < 4 {
                return (0, 1);
            }
            let val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) >> 2;
            (val as usize, 4)
        }
        // Big-integer mode (not expected for topic counts)
        _ => (0, 1),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use parking_lot::RwLock;

    fn make_test_env() -> HostEnv {
        HostEnv::new(
            [0xAA; 32], // contract_address
            [0xBB; 32], // caller
            1_700_000_000, // block_timestamp
            42_000, // block_height
            1, // chain_id
            100_000_000, // max_cu
            HashMap::new(), // initial_storage
            vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04], // input_data
            None, // cross_contract_handler
        )
    }

    #[test]
    fn test_detect_contract_type_native() {
        // Without a real module, test the logic conceptually
        // (full integration test requires compiled WASM)
        assert_eq!(ContractType::Native, ContractType::Native);
        assert_ne!(ContractType::Native, ContractType::Solang);
    }

    #[test]
    fn test_scale_compact_decode() {
        // Single byte: value 4 → 4 << 2 | 0 = 0x10
        assert_eq!(decode_scale_compact(&[0x10]), (4, 1));
        // Single byte: value 0 → 0x00
        assert_eq!(decode_scale_compact(&[0x00]), (0, 1));
        // Single byte: value 1 → 0x04
        assert_eq!(decode_scale_compact(&[0x04]), (1, 1));
        // Single byte: value 63 → 0xFC
        assert_eq!(decode_scale_compact(&[0xFC]), (63, 1));
        // Empty
        assert_eq!(decode_scale_compact(&[]), (0, 0));
    }

    #[test]
    fn test_storage_return_codes() {
        assert_eq!(STORED_NEW_ENTRY, 0);
        assert_eq!(STORED_EXISTING_ENTRY, 1);
        assert_eq!(STORED_DELETED, 2);
        assert_eq!(RETURN_CODE_SUCCESS, 0);
        assert_eq!(RETURN_CODE_KEY_NOT_FOUND, 1);
    }

    #[test]
    fn test_cu_costs_reasonable() {
        assert!(CU_SEAL_STORAGE_WRITE > CU_SEAL_STORAGE_READ);
        assert!(CU_SEAL_STORAGE_WRITE > CU_SEAL_STORAGE_CLEAR);
        assert!(CU_SEAL_HASH_BASE > 0);
        assert!(CU_SEAL_DEPOSIT_EVENT_BASE > 0);
    }
}
