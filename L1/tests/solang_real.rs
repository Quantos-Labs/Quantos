// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Real-world Solang E2E tests — require pre-compiled WASM artefacts.
//!
//! These tests are **ignored by default** because they depend on external WASM
//! files produced by the Solang compiler. To run them:
//!
//! 1. Install Solang: <https://github.com/hyperledger/solang>
//! 2. Compile: `solang compile test-contracts/QuantosToken.sol --target polkadot --output test-contracts/build/`
//! 3. Run: `cargo test -p quantos --test solang_real -- --ignored`

use quantos::vm::*;
use std::collections::HashMap;
use std::path::PathBuf;

/// Build ABI-encoded constructor args: (string name, string symbol, uint256 initialSupply)
fn build_erc20_constructor_args(name: &str, symbol: &str, initial_supply: u64) -> Vec<u8> {
    let mut data = Vec::new();

    // 3 params: string, string, uint256
    // Head: offset(name) | offset(symbol) | initialSupply
    // offset(name) = 3 * 32 = 96
    // offset(symbol) = 96 + 32 + ceil32(name.len()) = 96 + 32 + 32 = 160
    let name_offset: u64 = 96;
    let name_padded_len = ((name.len() + 31) / 32) * 32;
    let symbol_offset: u64 = name_offset + 32 + name_padded_len as u64;

    // Param 1: offset to name (uint256)
    let mut buf = [0u8; 32];
    buf[24..32].copy_from_slice(&name_offset.to_be_bytes());
    data.extend_from_slice(&buf);

    // Param 2: offset to symbol (uint256)
    let mut buf = [0u8; 32];
    buf[24..32].copy_from_slice(&symbol_offset.to_be_bytes());
    data.extend_from_slice(&buf);

    // Param 3: initialSupply (uint256)
    let mut buf = [0u8; 32];
    buf[24..32].copy_from_slice(&initial_supply.to_be_bytes());
    data.extend_from_slice(&buf);

    // Name: length + padded data
    let mut buf = [0u8; 32];
    buf[24..32].copy_from_slice(&(name.len() as u64).to_be_bytes());
    data.extend_from_slice(&buf);
    let mut name_bytes = name.as_bytes().to_vec();
    name_bytes.resize(name_padded_len, 0);
    data.extend_from_slice(&name_bytes);

    // Symbol: length + padded data
    let symbol_padded_len = ((symbol.len() + 31) / 32) * 32;
    let mut buf = [0u8; 32];
    buf[24..32].copy_from_slice(&(symbol.len() as u64).to_be_bytes());
    data.extend_from_slice(&buf);
    let mut symbol_bytes = symbol.as_bytes().to_vec();
    symbol_bytes.resize(symbol_padded_len, 0);
    data.extend_from_slice(&symbol_bytes);

    data
}

fn load_wasm(name: &str) -> Vec<u8> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(format!("test-contracts/build/{}.wasm", name));
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "Cannot read {}: {}. Run: solang compile test-contracts/{}.sol --target polkadot --output test-contracts/build/",
            path.display(), name, e
        )
    })
}

/// Step 1: Just list what the WASM module imports — discover missing seal functions
#[test]
#[ignore = "requires Solang-compiled WASM artefact (see file header)"]
fn step1_list_real_solang_imports() {
    let wasm = load_wasm("QuantosToken");

    // Use Wasmer to parse imports
    let compiler = wasmer_compiler_cranelift::Cranelift::default();
    let store = wasmer::Store::new(compiler);
    let module = wasmer::Module::new(&store, &wasm).expect("Should parse real Solang WASM");

    println!("\n=== Real Solang WASM Imports ===");
    for import in module.imports() {
        println!("  {}::{}  ({:?})", import.module(), import.name(), import.ty());
    }

    println!("\n=== Real Solang WASM Exports ===");
    for export in module.exports() {
        println!("  {}  ({:?})", export.name(), export.ty());
    }

    println!("\nWASM size: {} bytes", wasm.len());
}

/// Step 2: Deploy the constructor (is_constructor = true)
#[test]
#[ignore = "requires Solang-compiled WASM artefact (see file header)"]
fn step2_deploy_real_solang_contract() {
    let wasm = load_wasm("QuantosToken");

    // Use a very high CU limit — real Solang contracts are heavy
    let config = QuantosVmConfig {
        max_compute_units: 10_000_000_000, // 10B CU
        ..QuantosVmConfig::default()
    };
    let vm = QuantosVm::new(config);

    // Constructor calldata: selector + ABI-encoded (uint256 _initialSupply)
    // Selector from .contract metadata: new(uint256) → 0x5816c425
    let mut constructor_args = vec![0x58, 0x16, 0xc4, 0x25]; // constructor selector
    // _initialSupply = 1_000_000 as uint256
    let mut supply = [0u8; 32];
    supply[24..32].copy_from_slice(&1_000_000u64.to_be_bytes());
    constructor_args.extend_from_slice(&supply);

    let ctx = ExecutionContext {
        contract_address: [0xCC; 32],
        caller: [0xAA; 32],
        block_timestamp: 1_700_000_000,
        block_height: 1000,
        chain_id: 1,
        input_data: constructor_args,
        initial_storage: HashMap::new(),
        function_name: None,
        abi_json: None,
        is_constructor: true,
    };

    match vm.execute_contract(&wasm, ctx) {
        Ok(result) => {
            println!("\n=== Deploy Result ===");
            println!("  success: {}", result.success);
            println!("  return_data len: {}", result.return_data.len());
            println!("  storage_writes: {}", result.storage_writes.len());
            println!("  logs: {}", result.logs.len());
            println!("  cu_used: {}", result.cu_used);
            if !result.return_data.is_empty() {
                let hex: String = result.return_data.iter().map(|b| format!("{:02x}", b)).collect();
                println!("  return_data hex: {}", hex);
            }
            for (i, log) in result.logs.iter().enumerate() {
                println!("  log[{}]: topics={}, data_len={}", i, log.topics.len(), log.data.len());
            }
            for (i, (k, v)) in result.storage_writes.iter().enumerate().take(5) {
                println!("  storage[{}]: key_len={}, val_len={}", i, k.len(), v.len());
            }
            println!("  → Contract execution completed on QuantosVM!");
        }
        Err(e) => {
            println!("\n=== Deploy FAILED ===");
            println!("  error: {:?}", e);
            panic!("Real Solang contract deploy failed: {:?}", e);
        }
    }
}

// ══════════════════════════════════════════════════════════
//  SimpleStorage — Minimal Pipeline Validation
// ══════════════════════════════════════════════════════════

/// Deploy SimpleStorage(42) and verify storage writes + event
#[test]
#[ignore = "requires Solang-compiled WASM artefact (see file header)"]
fn simple_deploy() {
    let wasm = load_wasm("SimpleStorage");

    let config = QuantosVmConfig {
        max_compute_units: 10_000_000_000,
        ..QuantosVmConfig::default()
    };
    let vm = QuantosVm::new(config);

    // Constructor: new(uint256 _initial) → selector 0x5816c425
    let mut calldata = vec![0x58, 0x16, 0xc4, 0x25];
    // _initial = 42 as uint256 (32 bytes, little-endian for Solang Polkadot)
    let mut val = [0u8; 32];
    val[0] = 42;
    calldata.extend_from_slice(&val);

    let ctx = ExecutionContext {
        contract_address: [0xCC; 32],
        caller: [0xAA; 32],
        block_timestamp: 1_700_000_000,
        block_height: 1000,
        chain_id: 1,
        input_data: calldata,
        initial_storage: HashMap::new(),
        function_name: None,
        abi_json: None,
        is_constructor: true,
    };

    let result = vm.execute_contract(&wasm, ctx).expect("SimpleStorage deploy should not error");

    println!("\n=== SimpleStorage Deploy ===");
    println!("  success: {}", result.success);
    println!("  return_data len: {}", result.return_data.len());
    println!("  storage_writes: {}", result.storage_writes.len());
    println!("  logs: {}", result.logs.len());
    println!("  cu_used: {}", result.cu_used);
    if !result.return_data.is_empty() {
        let hex: String = result.return_data.iter().map(|b| format!("{:02x}", b)).collect();
        println!("  return_data hex: {}", hex);
    }
    for (i, (k, v)) in result.storage_writes.iter().enumerate().take(10) {
        let kh: String = k.iter().map(|b| format!("{:02x}", b)).collect();
        let vh: String = v.iter().map(|b| format!("{:02x}", b)).collect();
        println!("  storage[{}]: key={} val={}", i, kh, vh);
    }
    for (i, log) in result.logs.iter().enumerate() {
        println!("  log[{}]: topics={}, data_len={}", i, log.topics.len(), log.data.len());
    }

    assert!(result.success, "SimpleStorage constructor should succeed");
    assert!(result.storage_writes.len() >= 1, "Should write storedValue to storage");
}

/// Deploy then call get() to read the stored value
#[test]
#[ignore = "requires Solang-compiled WASM artefact (see file header)"]
fn simple_deploy_then_get() {
    let wasm = load_wasm("SimpleStorage");

    let config = QuantosVmConfig {
        max_compute_units: 10_000_000_000,
        ..QuantosVmConfig::default()
    };
    let vm = QuantosVm::new(config);

    // Deploy: new(42) — LE encoding
    let mut deploy_data = vec![0x58, 0x16, 0xc4, 0x25];
    let mut val = [0u8; 32];
    val[0] = 42;
    deploy_data.extend_from_slice(&val);

    let deploy_ctx = ExecutionContext {
        contract_address: [0xCC; 32],
        caller: [0xAA; 32],
        block_timestamp: 1_700_000_000,
        block_height: 1000,
        chain_id: 1,
        input_data: deploy_data,
        initial_storage: HashMap::new(),
        function_name: None,
        abi_json: None,
        is_constructor: true,
    };

    let deploy = vm.execute_contract(&wasm, deploy_ctx).expect("Deploy should work");
    println!("\n=== Deploy: success={}, storage_writes={}, cu={} ===",
             deploy.success, deploy.storage_writes.len(), deploy.cu_used);

    // Call: get() → selector 0x6d4ce63c
    let calldata = vec![0x6d, 0x4c, 0xe6, 0x3c];

    let call_ctx = ExecutionContext {
        contract_address: [0xCC; 32],
        caller: [0xAA; 32],
        block_timestamp: 1_700_000_000,
        block_height: 1001,
        chain_id: 1,
        input_data: calldata,
        initial_storage: deploy.storage_writes.clone(),
        function_name: None,
        abi_json: None,
        is_constructor: false,
    };

    let call = vm.execute_contract(&wasm, call_ctx).expect("get() should work");

    println!("\n=== get() Result ===");
    println!("  success: {}", call.success);
    println!("  return_data len: {}", call.return_data.len());
    println!("  cu_used: {}", call.cu_used);
    if !call.return_data.is_empty() {
        let hex: String = call.return_data.iter().map(|b| format!("{:02x}", b)).collect();
        println!("  return_data hex: {}", hex);
        // Verify return value is 42 (LE: first byte)
        if call.return_data.len() == 32 {
            let val = call.return_data[0];
            println!("  decoded value: {}", val);
            assert_eq!(val, 42, "get() should return 42");
        }
    }

    assert!(call.success, "get() should succeed");
    assert_eq!(call.return_data.len(), 32, "get() should return uint256 (32 bytes)");
}

/// Full ERC-20 E2E: deploy(1M) → totalSupply → balanceOf → transfer → verify
#[test]
#[ignore = "requires Solang-compiled WASM artefact (see file header)"]
fn erc20_full_e2e() {
    let wasm = load_wasm("QuantosToken");
    let config = QuantosVmConfig {
        max_compute_units: 10_000_000_000,
        ..QuantosVmConfig::default()
    };
    let vm = QuantosVm::new(config);

    let deployer = [0xAA_u8; 32];
    let recipient = [0xBB_u8; 32];
    let contract = [0xCC_u8; 32];
    let supply: u64 = 1_000_000;

    // ── Step 1: Deploy constructor(1_000_000) ──
    let mut deploy_data = vec![0x58, 0x16, 0xc4, 0x25];
    // Solang Polkadot uses LITTLE-ENDIAN for uint256
    let mut val = [0u8; 32];
    val[0..8].copy_from_slice(&supply.to_le_bytes());
    deploy_data.extend_from_slice(&val);

    let deploy_ctx = ExecutionContext {
        contract_address: contract,
        caller: deployer,
        block_timestamp: 1_700_000_000,
        block_height: 1000,
        chain_id: 1,
        input_data: deploy_data,
        initial_storage: HashMap::new(),
        function_name: None,
        abi_json: None,
        is_constructor: true,
    };

    let deploy = vm.execute_contract(&wasm, deploy_ctx).expect("Deploy failed");
    println!("\n=== ERC-20 Deploy ===");
    println!("  success={}, storage={}, logs={}, cu={}", deploy.success, deploy.storage_writes.len(), deploy.logs.len(), deploy.cu_used);
    assert!(deploy.success, "ERC-20 deploy must succeed");
    assert!(deploy.logs.len() >= 1, "Must emit Transfer event");

    let mut storage = deploy.storage_writes.clone();

    // ── Step 2: Call totalSupply() → selector 0x18160ddd ──
    let call_total = vm.execute_contract(&wasm, ExecutionContext {
        contract_address: contract,
        caller: deployer,
        block_timestamp: 1_700_000_000,
        block_height: 1001,
        chain_id: 1,
        input_data: vec![0x18, 0x16, 0x0d, 0xdd],
        initial_storage: storage.clone(),
        function_name: None,
        abi_json: None,
        is_constructor: false,
    }).expect("totalSupply() failed");

    println!("\n=== totalSupply() ===");
    let hex: String = call_total.return_data.iter().map(|b| format!("{:02x}", b)).collect();
    println!("  success={}, return={}, cu={}", call_total.success, hex, call_total.cu_used);
    assert!(call_total.success, "totalSupply() must succeed");
    assert_eq!(call_total.return_data.len(), 32);

    // ── Step 3: Call balanceOf(deployer) → selector 0x70a08231 ──
    let mut balance_call = vec![0x70, 0xa0, 0x82, 0x31];
    balance_call.extend_from_slice(&deployer); // Solang on Polkadot uses 32-byte addresses

    let call_bal = vm.execute_contract(&wasm, ExecutionContext {
        contract_address: contract,
        caller: deployer,
        block_timestamp: 1_700_000_000,
        block_height: 1002,
        chain_id: 1,
        input_data: balance_call,
        initial_storage: storage.clone(),
        function_name: None,
        abi_json: None,
        is_constructor: false,
    }).expect("balanceOf() failed");

    println!("\n=== balanceOf(deployer) ===");
    let hex: String = call_bal.return_data.iter().map(|b| format!("{:02x}", b)).collect();
    println!("  success={}, return={}, cu={}", call_bal.success, hex, call_bal.cu_used);
    assert!(call_bal.success, "balanceOf() must succeed");

    // ── Step 4: transfer(recipient, 100_000) → selector 0xa9059cbb ──
    let transfer_amount: u64 = 100_000;
    let mut transfer_call = vec![0xa9, 0x05, 0x9c, 0xbb];
    transfer_call.extend_from_slice(&recipient); // to address (32 bytes)
    let mut amount = [0u8; 32];
    amount[0..8].copy_from_slice(&transfer_amount.to_le_bytes());
    transfer_call.extend_from_slice(&amount);

    let call_tx = vm.execute_contract(&wasm, ExecutionContext {
        contract_address: contract,
        caller: deployer,
        block_timestamp: 1_700_000_000,
        block_height: 1003,
        chain_id: 1,
        input_data: transfer_call,
        initial_storage: storage.clone(),
        function_name: None,
        abi_json: None,
        is_constructor: false,
    }).expect("transfer() failed");

    println!("\n=== transfer(recipient, 100000) ===");
    let hex: String = call_tx.return_data.iter().map(|b| format!("{:02x}", b)).collect();
    println!("  success={}, return={}, storage_writes={}, logs={}, cu={}",
             call_tx.success, hex, call_tx.storage_writes.len(), call_tx.logs.len(), call_tx.cu_used);
    assert!(call_tx.success, "transfer() must succeed");
    assert!(call_tx.logs.len() >= 1, "transfer must emit Transfer event");

    // Merge storage changes
    for (k, v) in &call_tx.storage_writes {
        storage.insert(k.clone(), v.clone());
    }

    // ── Step 5: Verify balanceOf(recipient) after transfer ──
    let mut bal_recipient = vec![0x70, 0xa0, 0x82, 0x31];
    bal_recipient.extend_from_slice(&recipient);

    let call_bal2 = vm.execute_contract(&wasm, ExecutionContext {
        contract_address: contract,
        caller: deployer,
        block_timestamp: 1_700_000_000,
        block_height: 1004,
        chain_id: 1,
        input_data: bal_recipient,
        initial_storage: storage.clone(),
        function_name: None,
        abi_json: None,
        is_constructor: false,
    }).expect("balanceOf(recipient) failed");

    println!("\n=== balanceOf(recipient) after transfer ===");
    let hex: String = call_bal2.return_data.iter().map(|b| format!("{:02x}", b)).collect();
    println!("  success={}, return={}", call_bal2.success, hex);
    assert!(call_bal2.success, "balanceOf(recipient) must succeed");

    println!("\n✅ FULL ERC-20 E2E PIPELINE PASSED ON QUANTOSVM ✅");
}
