//! Comprehensive tests for the VM module (vm/runtime, bytecode_protection, abi, mvcc, etc.)

use quantos::vm::*;
use quantos::types::*;
use std::collections::HashMap;

/// Helper: compile WAT text to WASM binary bytes.
fn wat_to_wasm(wat_text: &str) -> Vec<u8> {
    wat::parse_str(wat_text).expect("WAT should parse to valid WASM")
}

// ══════════════════════════════════════════════════════════
//  VM Config
// ══════════════════════════════════════════════════════════

#[test]
fn test_vm_config_defaults() {
    let config = QuantosVmConfig::default();
    assert_eq!(config.max_memory_pages, 1024);
    assert_eq!(config.max_compute_units, 100_000_000);
    assert_eq!(config.max_stack_size, 1024 * 1024);
}

#[test]
fn test_vm_creation() {
    let config = QuantosVmConfig::default();
    let _vm = QuantosVm::new(config);
}

// ══════════════════════════════════════════════════════════
//  ABI
// ══════════════════════════════════════════════════════════

#[test]
fn test_abi_parse_function() {
    let json = r#"[
        {
            "type": "function",
            "name": "transfer",
            "inputs": [
                {"name": "to", "type": "address"},
                {"name": "amount", "type": "uint256"}
            ],
            "outputs": [{"name": "", "type": "bool"}],
            "stateMutability": "nonpayable"
        }
    ]"#;
    let abi = ContractAbi::from_json(json).unwrap();
    assert_eq!(abi.functions.len(), 1);
    assert!(abi.get_function_by_name("transfer").is_some());
}

#[test]
fn test_abi_parse_event() {
    let json = r#"[
        {
            "type": "event",
            "name": "Transfer",
            "inputs": [
                {"name": "from", "type": "address", "indexed": true},
                {"name": "to", "type": "address", "indexed": true},
                {"name": "value", "type": "uint256", "indexed": false}
            ]
        }
    ]"#;
    let abi = ContractAbi::from_json(json).unwrap();
    assert_eq!(abi.events.len(), 1);
    assert_eq!(abi.events[0].name, "Transfer");
}

#[test]
fn test_abi_parse_constructor() {
    let json = r#"[
        {
            "type": "constructor",
            "inputs": [
                {"name": "name", "type": "string"},
                {"name": "symbol", "type": "string"}
            ]
        }
    ]"#;
    let abi = ContractAbi::from_json(json).unwrap();
    assert!(abi.constructor.is_some());
    assert_eq!(abi.constructor.unwrap().len(), 2);
}

#[test]
fn test_abi_parse_fallback_receive() {
    let json = r#"[
        {"type": "fallback"},
        {"type": "receive"}
    ]"#;
    let abi = ContractAbi::from_json(json).unwrap();
    assert!(abi.has_fallback);
    assert!(abi.has_receive);
}

#[test]
fn test_abi_selector_computation() {
    let json = r#"[
        {
            "type": "function",
            "name": "transfer",
            "inputs": [
                {"name": "to", "type": "address"},
                {"name": "amount", "type": "uint256"}
            ],
            "outputs": [{"name": "", "type": "bool"}],
            "stateMutability": "nonpayable"
        }
    ]"#;
    let abi = ContractAbi::from_json(json).unwrap();
    let selector = abi.get_selector("transfer");
    assert!(selector.is_some());
    // Quantos uses its own hash for selectors (not keccak256)
    let sel = selector.unwrap();
    assert_eq!(sel.len(), 4);
}

#[test]
fn test_abi_is_read_only() {
    let json = r#"[
        {
            "type": "function",
            "name": "balanceOf",
            "inputs": [{"name": "account", "type": "address"}],
            "outputs": [{"name": "", "type": "uint256"}],
            "stateMutability": "view"
        },
        {
            "type": "function",
            "name": "transfer",
            "inputs": [
                {"name": "to", "type": "address"},
                {"name": "amount", "type": "uint256"}
            ],
            "outputs": [{"name": "", "type": "bool"}],
            "stateMutability": "nonpayable"
        }
    ]"#;
    let abi = ContractAbi::from_json(json).unwrap();

    let balance_sel = abi.get_selector("balanceOf").unwrap();
    let transfer_sel = abi.get_selector("transfer").unwrap();

    assert!(abi.is_read_only(&balance_sel));
    assert!(!abi.is_read_only(&transfer_sel));
}

#[test]
fn test_abi_unknown_function() {
    let json = r#"[
        {
            "type": "function",
            "name": "transfer",
            "inputs": [],
            "outputs": [],
            "stateMutability": "nonpayable"
        }
    ]"#;
    let abi = ContractAbi::from_json(json).unwrap();
    assert!(abi.get_function_by_name("nonexistent").is_none());
    assert!(abi.get_selector("nonexistent").is_none());
}

#[test]
fn test_abi_invalid_json() {
    let result = ContractAbi::from_json("not valid json");
    assert!(result.is_err());
}

#[test]
fn test_abi_empty_array() {
    let abi = ContractAbi::from_json("[]").unwrap();
    assert!(abi.functions.is_empty());
    assert!(abi.events.is_empty());
    assert!(abi.constructor.is_none());
}

#[test]
fn test_abi_multiple_functions() {
    let json = r#"[
        {
            "type": "function",
            "name": "transfer",
            "inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}],
            "outputs": [{"name": "", "type": "bool"}],
            "stateMutability": "nonpayable"
        },
        {
            "type": "function",
            "name": "approve",
            "inputs": [{"name": "spender", "type": "address"}, {"name": "amount", "type": "uint256"}],
            "outputs": [{"name": "", "type": "bool"}],
            "stateMutability": "nonpayable"
        },
        {
            "type": "function",
            "name": "totalSupply",
            "inputs": [],
            "outputs": [{"name": "", "type": "uint256"}],
            "stateMutability": "view"
        }
    ]"#;
    let abi = ContractAbi::from_json(json).unwrap();
    assert_eq!(abi.functions.len(), 3);
}

// ══════════════════════════════════════════════════════════
//  Bytecode Protection
// ══════════════════════════════════════════════════════════

#[test]
fn test_bytecode_protector_creation() {
    let config = BytecodeProtectionConfig::default();
    let _protector = BytecodeProtector::new(config);
}

#[test]
fn test_bytecode_protector_default_config() {
    let config = BytecodeProtectionConfig::default();
    assert_eq!(config.max_bytecode_size, 1024 * 1024); // 1MB
    assert!(!config.debug_mode);
    assert_eq!(config.sandbox_memory_limit, 64 * 1024 * 1024); // 64MB
}

#[test]
fn test_deploy_valid_wasm() {
    let config = BytecodeProtectionConfig::default();
    let protector = BytecodeProtector::new(config);

    // Minimal valid WASM module
    let wasm = vec![
        0x00, 0x61, 0x73, 0x6D, // magic
        0x01, 0x00, 0x00, 0x00, // version 1
        0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type section
    ];

    let deployer = [1u8; 32];
    let result = protector.deploy_contract(&wasm, deployer, 0, false, None);
    assert!(result.is_ok());

    let metadata = result.unwrap();
    assert_eq!(metadata.deployer, deployer);
    assert_eq!(metadata.original_size, wasm.len());
    assert!(!metadata.upgradeable);
}

#[test]
fn test_deploy_invalid_magic() {
    let config = BytecodeProtectionConfig::default();
    let protector = BytecodeProtector::new(config);

    let invalid_wasm = vec![0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    let result = protector.deploy_contract(&invalid_wasm, [1u8; 32], 0, false, None);
    assert!(result.is_err());
}

#[test]
fn test_deploy_too_short() {
    let config = BytecodeProtectionConfig::default();
    let protector = BytecodeProtector::new(config);

    let short = vec![0x00, 0x61];
    let result = protector.deploy_contract(&short, [1u8; 32], 0, false, None);
    assert!(result.is_err());
}

#[test]
fn test_deploy_and_get_metadata() {
    let config = BytecodeProtectionConfig::default();
    let protector = BytecodeProtector::new(config);

    let wasm = vec![
        0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
    ];

    let metadata = protector.deploy_contract(&wasm, [1u8; 32], 0, false, None).unwrap();
    let fetched = protector.get_metadata(&metadata.address);
    assert!(fetched.is_some());
    let fetched = fetched.unwrap();
    assert_eq!(fetched.address, metadata.address);
    assert_eq!(fetched.bytecode_hash, metadata.bytecode_hash);
}

#[test]
fn test_deploy_different_nonces_different_addresses() {
    let config = BytecodeProtectionConfig::default();
    let protector = BytecodeProtector::new(config);

    let wasm = vec![
        0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
    ];

    let m1 = protector.deploy_contract(&wasm, [1u8; 32], 0, false, None).unwrap();
    let m2 = protector.deploy_contract(&wasm, [1u8; 32], 1, false, None).unwrap();
    assert_ne!(m1.address, m2.address);
}

#[test]
fn test_execute_contract_not_found() {
    let config = BytecodeProtectionConfig::default();
    let protector = BytecodeProtector::new(config);

    let fake_addr = [99u8; 32];
    let result: VmResult<Vec<u8>> = protector.execute_contract(&fake_addr, |_bytecode| {
        Ok(vec![])
    });
    assert!(result.is_err());
}

// ══════════════════════════════════════════════════════════
//  Execution Context
// ══════════════════════════════════════════════════════════

#[test]
fn test_execution_context_creation() {
    let ctx = ExecutionContext {
        contract_address: [1u8; 32],
        caller: [2u8; 32],
        block_timestamp: 1234567890,
        block_height: 1000,
        chain_id: 1,
        input_data: vec![0x01, 0x02, 0x03],
        initial_storage: HashMap::new(),
        function_name: Some("transfer".to_string()),
        abi_json: None,
        is_constructor: false,
    };
    assert_eq!(ctx.input_data.len(), 3);
    assert_eq!(ctx.chain_id, 1);
    assert_eq!(ctx.function_name, Some("transfer".to_string()));
}

#[test]
fn test_execution_result_fields() {
    let result = ExecutionResult {
        success: true,
        return_data: vec![1, 2, 3],
        cu_used: 5000,
        logs: vec![],
        storage_writes: HashMap::new(),
        storage_deletes: vec![],
    };
    assert!(result.success);
    assert_eq!(result.cu_used, 5000);
    assert_eq!(result.return_data, vec![1, 2, 3]);
}

// ══════════════════════════════════════════════════════════
//  MVCC
// ══════════════════════════════════════════════════════════

#[test]
fn test_mvcc_version_creation() {
    let version: Version<u64> = Version::new(1, 100, 42);
    assert_eq!(version.timestamp, 1);
    assert_eq!(version.created_by, 100);
    assert_eq!(version.value, 42);
    assert!(!version.committed);
    assert!(version.prev_version.is_none());
}

#[test]
fn test_mvcc_versioned_value() {
    let mut vv: VersionedValue<u64> = VersionedValue::new();

    let mut v1 = Version::new(1, 100, 10);
    v1.committed = true;
    vv.add_version(v1);

    let mut v2 = Version::new(2, 101, 20);
    v2.committed = true;
    vv.add_version(v2);

    // Read at timestamp 1 should see value 10
    assert_eq!(vv.get_visible(1), Some(&10));
    // Read at timestamp 2 should see value 20
    assert_eq!(vv.get_visible(2), Some(&20));
    // Read at timestamp 3 should see value 20 (latest committed <= 3)
    assert_eq!(vv.get_visible(3), Some(&20));
}

#[test]
fn test_mvcc_uncommitted_not_visible() {
    let mut vv: VersionedValue<u64> = VersionedValue::new();

    let mut v1 = Version::new(1, 100, 10);
    v1.committed = true;
    vv.add_version(v1);

    // Uncommitted version at ts=2
    let v2 = Version::new(2, 101, 20);
    vv.add_version(v2);

    // Read at timestamp 2 should still see value 10 (v2 not committed)
    assert_eq!(vv.get_visible(2), Some(&10));
}

#[test]
fn test_mvcc_empty_versioned_value() {
    let vv: VersionedValue<u64> = VersionedValue::new();
    assert_eq!(vv.get_visible(100), None);
}

#[test]
fn test_mvcc_get_by_txn() {
    let mut vv: VersionedValue<u64> = VersionedValue::new();
    let v = Version::new(1, 42, 99);
    vv.add_version(v);
    assert_eq!(vv.get_by_txn(42), Some(&99));
    assert_eq!(vv.get_by_txn(999), None);
}

// ══════════════════════════════════════════════════════════
//  Speculative Execution Config
// ══════════════════════════════════════════════════════════

#[test]
fn test_speculative_config_defaults() {
    let config = SpeculativeConfig::default();
    assert_eq!(config.max_concurrent, 16);
    assert_eq!(config.max_checkpoint_depth, 10);
    assert!(config.parallel_paths);
    assert_eq!(config.max_cached_results, 1000);
}

// ══════════════════════════════════════════════════════════
//  Transaction Dependency Graph
// ══════════════════════════════════════════════════════════

#[test]
fn test_dependency_types() {
    let raw = DependencyType::ReadAfterWrite;
    let war = DependencyType::WriteAfterRead;
    let waw = DependencyType::WriteAfterWrite;
    assert_ne!(raw, war);
    assert_ne!(raw, waw);
    assert_ne!(war, waw);
}

// ══════════════════════════════════════════════════════════
//  Solang Compatibility Layer — E2E Integration Test
// ══════════════════════════════════════════════════════════

/// Hand-crafted WAT module that imports seal0/seal1 host functions.
/// Exercises the full Solang compat pipeline:
///   seal_input → seal_caller → seal_block_number → seal_hash_keccak_256
///   → seal_set_storage → seal_get_storage → seal_deposit_event → seal_return
const SOLANG_COMPAT_WAT: &str = r#"
(module
  ;; seal0 imports (must precede memory/func declarations)
  (import "seal0" "seal_input" (func $seal_input (param i32 i32)))
  (import "seal0" "seal_return" (func $seal_return (param i32 i32 i32)))
  (import "seal0" "seal_caller" (func $seal_caller (param i32 i32)))
  (import "seal0" "seal_block_number" (func $seal_block_number (param i32 i32)))
  (import "seal0" "seal_deposit_event" (func $seal_deposit_event (param i32 i32 i32 i32)))
  (import "seal0" "seal_hash_keccak_256" (func $seal_hash_keccak_256 (param i32 i32 i32)))

  ;; seal1 imports
  (import "seal1" "seal_set_storage" (func $seal_set_storage (param i32 i32 i32 i32) (result i32)))
  (import "seal1" "seal_get_storage" (func $seal_get_storage (param i32 i32 i32 i32) (result i32)))

  ;; Memory exported for the host
  (memory (export "memory") 1)

  ;; Entry point — Solang contracts export call() with no params
  (func (export "call")
    ;; Memory layout:
    ;; 0-3:     input_buf_len (u32 LE, capacity=64)
    ;; 4-67:    input_buffer (64 bytes)
    ;; 68-71:   caller_buf_len (u32 LE, capacity=32)
    ;; 72-103:  caller_buffer (32 bytes)
    ;; 104-107: block_num_len (u32 LE, capacity=8)
    ;; 108-115: block_num_buffer (8 bytes)
    ;; 200-231: keccak_output (32 bytes)
    ;; 300-303: storage_out_len (u32 LE, capacity=32)
    ;; 304-335: storage_out_buffer (32 bytes)

    ;; Step 1: Read input data via seal_input
    (i32.store (i32.const 0) (i32.const 64))
    (call $seal_input (i32.const 4) (i32.const 0))

    ;; Step 2: Get caller address
    (i32.store (i32.const 68) (i32.const 32))
    (call $seal_caller (i32.const 72) (i32.const 68))

    ;; Step 3: Get block number
    (i32.store (i32.const 104) (i32.const 8))
    (call $seal_block_number (i32.const 108) (i32.const 104))

    ;; Step 4: Hash first 8 bytes of input with Keccak-256
    (call $seal_hash_keccak_256 (i32.const 4) (i32.const 8) (i32.const 200))

    ;; Step 5: Store — key = first 8 bytes of input, value = caller (32 bytes)
    (drop (call $seal_set_storage
      (i32.const 4)   ;; key_ptr
      (i32.const 8)   ;; key_len
      (i32.const 72)  ;; value_ptr (caller)
      (i32.const 32)  ;; value_len
    ))

    ;; Step 6: Read storage back
    (i32.store (i32.const 300) (i32.const 32))
    (drop (call $seal_get_storage
      (i32.const 4)    ;; key_ptr
      (i32.const 8)    ;; key_len
      (i32.const 304)  ;; out_ptr
      (i32.const 300)  ;; out_len_ptr
    ))

    ;; Step 7: Emit event — no topics, data = caller address
    (call $seal_deposit_event
      (i32.const 0)   ;; topics_ptr (none)
      (i32.const 0)   ;; topics_len (0)
      (i32.const 72)  ;; data_ptr (caller)
      (i32.const 32)  ;; data_len
    )

    ;; Step 8: Return keccak hash as output
    (call $seal_return
      (i32.const 0)    ;; flags = 0 (success)
      (i32.const 200)  ;; data_ptr (keccak output)
      (i32.const 32)   ;; data_len
    )
  )
)
"#;

#[test]
fn test_solang_compat_e2e_full_pipeline() {
    let config = QuantosVmConfig::default();
    let vm = QuantosVm::new(config);

    let caller = [0xBB_u8; 32];
    let contract_address = [0xCC_u8; 32];
    let input_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];

    let ctx = ExecutionContext {
        contract_address,
        caller,
        block_timestamp: 1_700_000_000,
        block_height: 42_000,
        chain_id: 1,
        input_data: input_data.clone(),
        initial_storage: HashMap::new(),
        function_name: None,
        abi_json: None,
        is_constructor: false,
    };

    let wasm = wat_to_wasm(SOLANG_COMPAT_WAT);
    let result = vm.execute_contract(&wasm, ctx)
        .expect("Solang compat E2E execution should succeed");

    // ── Verify execution success ──
    assert!(result.success, "Contract should succeed (flags=0)");

    // ── Verify return data is 32 bytes (Keccak-256 hash) ──
    assert_eq!(result.return_data.len(), 32, "Return data should be 32-byte keccak hash");
    assert_ne!(result.return_data, vec![0u8; 32], "Hash should be non-zero");

    // ── Verify storage write ──
    // Key = first 8 bytes of input, Value = caller address (32 bytes)
    let expected_key = input_data.clone();
    let storage_value = result.storage_writes.get(&expected_key);
    assert!(storage_value.is_some(), "Storage should contain the key from input data");
    assert_eq!(
        storage_value.unwrap(),
        &caller.to_vec(),
        "Storage value should be the caller address"
    );

    // ── Verify event emission ──
    assert_eq!(result.logs.len(), 1, "Should have emitted 1 event");
    let log = &result.logs[0];
    assert!(log.topics.is_empty(), "Event should have no topics");
    assert_eq!(log.data, caller.to_vec(), "Event data should be the caller address");

    // ── Verify CU was consumed ──
    assert!(result.cu_used > 0, "Some CU should have been consumed");
}

#[test]
fn test_solang_compat_contract_type_detection() {
    // The WAT module imports from "seal0" and "seal1" → should be detected as Solang
    let config = QuantosVmConfig::default();
    let vm = QuantosVm::new(config);

    let ctx = ExecutionContext {
        contract_address: [0xAA; 32],
        caller: [0xBB; 32],
        block_timestamp: 1_000_000,
        block_height: 100,
        chain_id: 1,
        input_data: vec![0x01, 0x02, 0x03, 0x04],
        initial_storage: HashMap::new(),
        function_name: None,
        abi_json: None,
        is_constructor: false,
    };

    let wasm = wat_to_wasm(SOLANG_COMPAT_WAT);
    let result = vm.execute_contract(&wasm, ctx);
    assert!(result.is_ok(), "Solang contract detection and execution should work");
}

#[test]
fn test_solang_compat_empty_input() {
    let config = QuantosVmConfig::default();
    let vm = QuantosVm::new(config);

    let ctx = ExecutionContext {
        contract_address: [0xAA; 32],
        caller: [0xBB; 32],
        block_timestamp: 1_000_000,
        block_height: 100,
        chain_id: 1,
        input_data: vec![], // Empty input
        initial_storage: HashMap::new(),
        function_name: None,
        abi_json: None,
        is_constructor: false,
    };

    let wasm = wat_to_wasm(SOLANG_COMPAT_WAT);
    let result = vm.execute_contract(&wasm, ctx);
    assert!(result.is_ok(), "Should handle empty input gracefully");
}

#[test]
fn test_solang_compat_storage_persistence() {
    let config = QuantosVmConfig::default();
    let vm = QuantosVm::new(config);

    let input_data = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let caller = [0xFF_u8; 32];

    // First execution: write to storage
    let ctx1 = ExecutionContext {
        contract_address: [0xCC; 32],
        caller,
        block_timestamp: 1_000,
        block_height: 1,
        chain_id: 1,
        input_data: input_data.clone(),
        initial_storage: HashMap::new(),
        function_name: None,
        abi_json: None,
        is_constructor: false,
    };

    let wasm = wat_to_wasm(SOLANG_COMPAT_WAT);
    let result1 = vm.execute_contract(&wasm, ctx1)
        .expect("First execution should succeed");
    assert!(result1.success);

    // Second execution: pass previous storage writes as initial storage
    let ctx2 = ExecutionContext {
        contract_address: [0xCC; 32],
        caller: [0xDD; 32], // Different caller
        block_timestamp: 2_000,
        block_height: 2,
        chain_id: 1,
        input_data: input_data.clone(),
        initial_storage: result1.storage_writes.clone(),
        function_name: None,
        abi_json: None,
        is_constructor: false,
    };

    let result2 = vm.execute_contract(&wasm, ctx2)
        .expect("Second execution with existing storage should succeed");
    assert!(result2.success);

    // The storage key is the same (same input), but value should now be the NEW caller
    let storage_value = result2.storage_writes.get(&input_data);
    assert!(storage_value.is_some());
    assert_eq!(storage_value.unwrap(), &[0xDD_u8; 32].to_vec());
}
