// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Fuzz target for `decode_contract_deploy_payload`.
//!
//! `ContractDeploy` transactions carry a `data` field that is parsed by
//! `decode_contract_deploy_payload` (`src/vm/contract.rs`) before the
//! bytecode is passed to the WASM compiler. The parser handles two
//! formats: raw WASM (magic `\0asm`) and a length-prefixed container
//! with constructor calldata. An attacker can craft arbitrary `data`
//! bytes to probe for panics, integer overflows, or out-of-bounds
//! reads in the length-prefix parsing path.

#![no_main]
use libfuzzer_sys::fuzz_target;
use quantos::vm::decode_contract_deploy_payload;

fuzz_target!(|data: &[u8]| {
    let _ = decode_contract_deploy_payload(data);
});
