// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Fuzz target for `QuantosVm::execute_contract` with arbitrary calldata.
//!
//! Contract calls arrive via `ContractCall` transactions where
//! `tx.transaction.data` becomes `ExecutionContext::input_data`.
//! A malicious caller can pass arbitrary bytes as calldata to any
//! deployed contract. The WASM runtime's `seal_input` host function
//! and the contract's own parsing logic must never panic on
//! adversarial calldata.
//!
//! We use a minimal valid WASM module (an empty function) as the
//! contract bytecode and fuzz only the `input_data` field, isolating
//! the host-side calldata handling from contract-internal logic.

#![no_main]
use libfuzzer_sys::fuzz_target;
use quantos::vm::{QuantosVm, QuantosVmConfig, ExecutionContext};

/// Minimal valid WASM module: a single empty exported function `_start`.
/// Generated from: `(module (func (export "_start")))`
const MINIMAL_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, // magic: \0asm
    0x01, 0x00, 0x00, 0x00, // version: 1
    // Type section (1 type: () -> ())
    0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
    // Function section (1 function index)
    0x03, 0x02, 0x01, 0x00,
    // Export section (export "_start" as function 0)
    0x07, 0x0a, 0x01, 0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    // Code section (1 function body: nop + end)
    0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
];

fuzz_target!(|data: &[u8]| {
    let vm = QuantosVm::new(QuantosVmConfig::default());
    let ctx = ExecutionContext {
        contract_address: [1u8; 32],
        caller: [0u8; 32],
        block_timestamp: 0,
        block_height: 0,
        chain_id: 1,
        input_data: data.to_vec(),
        initial_storage: std::collections::HashMap::new(),
        function_name: None,
        abi_json: None,
        is_constructor: false,
        max_compute_units: Some(1_000_000),
        cross_contract_handler: None,
    };
    let _ = vm.execute_contract(MINIMAL_WASM, ctx);
});
