// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use quantos::vm::{ContractManager, QuantosVmConfig, BytecodeProtector, BytecodeProtectionConfig};
use quantos::storage::Storage;
use std::sync::Arc;

#[test]
fn test_cross_contract_call_basic() {
    let temp_dir = tempfile::tempdir().unwrap();
    let storage = Storage::new(temp_dir.path()).unwrap();
    let protector = Arc::new(BytecodeProtector::new(BytecodeProtectionConfig::default()));
    let vm_config = QuantosVmConfig::default();
    let manager = ContractManager::new(storage, protector.clone(), vm_config);

    let caller = [0xAA; 32];
    let contract_a = [0xBB; 32];
    let contract_b = [0xCC; 32];

    // Simple WASM that calls another contract via seal_call
    let wasm_caller = wat::parse_str(r#"
        (module
            (import "seal1" "seal_call" (func $seal_call (param i32 i32 i64 i32 i32 i32 i32 i32) (result i32)))
            (import "env" "memory" (memory 1))
            (func (export "call")
                (local $ret i32)
                ;; Write callee address at offset 0
                (i32.store (i32.const 0) (i32.const 0xCCCCCCCC))
                (i32.store (i32.const 4) (i32.const 0xCCCCCCCC))
                (i32.store (i32.const 8) (i32.const 0xCCCCCCCC))
                (i32.store (i32.const 12) (i32.const 0xCCCCCCCC))
                (i32.store (i32.const 16) (i32.const 0xCCCCCCCC))
                (i32.store (i32.const 20) (i32.const 0xCCCCCCCC))
                (i32.store (i32.const 24) (i32.const 0xCCCCCCCC))
                (i32.store (i32.const 28) (i32.const 0xCCCCCCCC))
                ;; Write zero value at offset 32 (16 bytes)
                (i64.store (i64.const 32) (i64.const 0))
                (i64.store (i64.const 40) (i64.const 0))
                ;; Write output buffer capacity at offset 48
                (i32.store (i32.const 48) (i32.const 32))
                ;; Call seal_call(flags=0, callee=0, gas=1000000, value=32, input=0, input_len=0, out=64, out_len=48)
                (local.set $ret
                    (call $seal_call
                        (i32.const 0)       ;; flags
                        (i32.const 0)       ;; callee_ptr
                        (i64.const 1000000) ;; gas
                        (i32.const 32)      ;; value_ptr
                        (i32.const 0)       ;; input_ptr
                        (i32.const 0)       ;; input_len
                        (i32.const 64)      ;; out_ptr
                        (i32.const 48)      ;; out_len_ptr
                    )
                )
            )
        )
    "#).unwrap();

    let wasm_callee = wat::parse_str(r#"
        (module
            (import "seal0" "seal_return" (func $seal_return (param i32 i32 i32)))
            (import "env" "memory" (memory 1))
            (func (export "call")
                ;; Return success with empty data
                (call $seal_return (i32.const 0) (i32.const 0) (i32.const 0))
            )
        )
    "#).unwrap();

    // Deploy both contracts
    manager.deploy_contract(caller, contract_a, wasm_caller, 1000, 1, 1, None).unwrap();
    manager.deploy_contract(caller, contract_b, wasm_callee, 1000, 1, 1, None).unwrap();

    // Execute contract A which calls contract B
    let result = manager.execute_contract(contract_a, caller, vec![], 1000, 1, 1).unwrap();
    
    assert!(result.success, "Cross-contract call should succeed");
}
