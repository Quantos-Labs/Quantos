// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Fuzz target for WASM bytecode compilation via Wasmer.
//!
//! `QuantosVm::execute_contract` (`src/vm/runtime.rs`) calls
//! `Module::new(&store, wasm_bytes)` on bytecode that ultimately comes
//! from an untrusted `ContractDeploy` transaction (`tx.transaction.data`).
//! A malicious deployer can submit arbitrary bytes as "WASM".
//! Wasmer's Cranelift compiler must never panic, abort, or trigger
//! undefined behaviour on adversarial bytecode — it must return
//! `Err(VmError::InvalidBytecode)` cleanly.

#![no_main]
use libfuzzer_sys::fuzz_target;
use quantos::vm::{QuantosVm, QuantosVmConfig, ExecutionContext};

fuzz_target!(|data: &[u8]| {
    let vm = QuantosVm::new(QuantosVmConfig::default());
    let ctx = ExecutionContext {
        contract_address: [0u8; 32],
        caller: [0u8; 32],
        block_timestamp: 0,
        block_height: 0,
        chain_id: 1,
        input_data: Vec::new(),
        initial_storage: std::collections::HashMap::new(),
        function_name: None,
        abi_json: None,
        is_constructor: false,
        max_compute_units: Some(1_000_000),
        cross_contract_handler: None,
    };
    let _ = vm.execute_contract(data, ctx);
});
