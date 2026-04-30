//! SQTEST cross-contract integration tests.
//!
//! These tests are **ignored by default** because they require pre-compiled WASM
//! artefacts (`QTEST.wasm`, `SQTEST.wasm`, `SQTESTEngine.wasm`) that are produced
//! by the Solang compiler and are not checked into the repository.
//!
//! To run them:
//! 1. Compile the Solidity contracts in `solidity-contracts/` with Solang.
//! 2. `cargo test -p quantos --test sqtest_cross_contract -- --ignored`

use quantos::storage::Storage;
use quantos::vm::{BytecodeProtectionConfig, BytecodeProtector, ContractManager, QuantosVmConfig};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

fn read_bytes(relative: &str) -> Vec<u8> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative);
    fs::read(&path).unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e))
}

fn encode_address(addr: [u8; 32]) -> Vec<u8> {
    addr.to_vec()
}

fn encode_u256_le(value: u128) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    out[..16].copy_from_slice(&value.to_le_bytes());
    out
}

fn decode_u256_le_u128(data: &[u8]) -> u128 {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&data[..16]);
    u128::from_le_bytes(bytes)
}

#[test]
#[ignore = "requires Solang-compiled WASM artefacts (see file header)"]
fn sqtest_open_vault_measures_nested_cu() {
    let temp_dir = tempfile::tempdir().unwrap();
    let storage = Storage::new(temp_dir.path()).unwrap();
    let protector = Arc::new(BytecodeProtector::new(BytecodeProtectionConfig::default()));
    let vm_config = QuantosVmConfig {
        max_compute_units: 10_000_000_000,
        ..QuantosVmConfig::default()
    };
    let manager = ContractManager::new(storage, protector, vm_config);

    let deployer = [0x11; 32];
    let user = [0x22; 32];
    let block_timestamp = 1_700_000_000;
    let block_height = 1_000;
    let chain_id = 1;

    let qtest_wasm = read_bytes("test-contracts/build/QTEST.wasm");
    let sqtest_wasm = read_bytes("solidity-contracts/SQTEST.wasm");
    let engine_wasm = read_bytes("solidity-contracts/SQTESTEngine.wasm");

    let qtest = manager.deploy_contract(
        qtest_wasm,
        vec![0x86, 0x17, 0x31, 0xd5],
        deployer,
        1,
        block_timestamp,
        block_height,
        chain_id,
        None,
    ).unwrap().address;

    let sqtest = manager.deploy_contract(
        sqtest_wasm,
        vec![0xcd, 0xbf, 0x60, 0x8d],
        deployer,
        2,
        block_timestamp,
        block_height,
        chain_id,
        None,
    ).unwrap().address;

    let mut engine_ctor = vec![0x69, 0xc9, 0xb9, 0xbf];
    engine_ctor.extend_from_slice(&encode_address(sqtest));
    engine_ctor.extend_from_slice(&encode_address(qtest));
    let engine = manager.deploy_contract(
        engine_wasm,
        engine_ctor,
        deployer,
        3,
        block_timestamp,
        block_height,
        chain_id,
        None,
    ).unwrap().address;

    let claim = manager.execute_contract(
        qtest,
        user,
        vec![0x4e, 0x71, 0xd9, 0x2d],
        block_timestamp + 1,
        block_height + 1,
        chain_id,
    ).unwrap();
    println!("claim success={} cu_used={}", claim.success, claim.cu_used);
    assert!(claim.success);

    let mut set_engine = vec![0x0e, 0x83, 0x0e, 0x49];
    set_engine.extend_from_slice(&encode_address(engine));
    let set_engine_result = manager.execute_contract(
        sqtest,
        deployer,
        set_engine,
        block_timestamp + 2,
        block_height + 2,
        chain_id,
    ).unwrap();
    println!("setEngine success={} cu_used={}", set_engine_result.success, set_engine_result.cu_used);
    assert!(set_engine_result.success);

    let collateral = 300u128 * 10u128.pow(18);
    let debt = 100u128 * 10u128.pow(18);

    let mut approve = vec![0x09, 0x5e, 0xa7, 0xb3];
    approve.extend_from_slice(&encode_address(engine));
    approve.extend_from_slice(&encode_u256_le(collateral));
    let approve_result = manager.execute_contract(
        qtest,
        user,
        approve,
        block_timestamp + 3,
        block_height + 3,
        chain_id,
    ).unwrap();
    println!("approve success={} cu_used={}", approve_result.success, approve_result.cu_used);
    assert!(approve_result.success);

    let mut open_vault = vec![0x59, 0xcb, 0x83, 0xd0];
    open_vault.extend_from_slice(&encode_u256_le(collateral));
    open_vault.extend_from_slice(&encode_u256_le(debt));
    let open_vault_result = manager.execute_contract(
        engine,
        user,
        open_vault,
        block_timestamp + 4,
        block_height + 4,
        chain_id,
    ).unwrap();
    println!("openVault success={} cu_used={} return_data_len={}", open_vault_result.success, open_vault_result.cu_used, open_vault_result.return_data.len());
    if !open_vault_result.success {
        println!("openVault revert_data=0x{}", hex::encode(&open_vault_result.return_data));
    }
    assert!(open_vault_result.success, "openVault should succeed with high CU");
}

#[test]
#[ignore = "requires Solang-compiled WASM artefacts (see file header)"]
fn sqtest_get_accrued_debt_tolerates_non_monotonic_timestamp() {
    let temp_dir = tempfile::tempdir().unwrap();
    let storage = Storage::new(temp_dir.path()).unwrap();
    let protector = Arc::new(BytecodeProtector::new(BytecodeProtectionConfig::default()));
    let vm_config = QuantosVmConfig {
        max_compute_units: 10_000_000_000,
        ..QuantosVmConfig::default()
    };
    let manager = ContractManager::new(storage, protector, vm_config);

    let deployer = [0x11; 32];
    let user = [0x22; 32];
    let block_timestamp = 1_700_000_000;
    let block_height = 1_000;
    let chain_id = 1;

    let qtest_wasm = read_bytes("test-contracts/build/QTEST.wasm");
    let sqtest_wasm = read_bytes("solidity-contracts/SQTEST.wasm");
    let engine_wasm = read_bytes("solidity-contracts/SQTESTEngine.wasm");

    let qtest = manager.deploy_contract(
        qtest_wasm,
        vec![0x86, 0x17, 0x31, 0xd5],
        deployer,
        1,
        block_timestamp,
        block_height,
        chain_id,
        None,
    ).unwrap().address;

    let sqtest = manager.deploy_contract(
        sqtest_wasm,
        vec![0xcd, 0xbf, 0x60, 0x8d],
        deployer,
        2,
        block_timestamp,
        block_height,
        chain_id,
        None,
    ).unwrap().address;

    let mut engine_ctor = vec![0x69, 0xc9, 0xb9, 0xbf];
    engine_ctor.extend_from_slice(&encode_address(sqtest));
    engine_ctor.extend_from_slice(&encode_address(qtest));
    let engine = manager.deploy_contract(
        engine_wasm,
        engine_ctor,
        deployer,
        3,
        block_timestamp,
        block_height,
        chain_id,
        None,
    ).unwrap().address;

    let claim = manager.execute_contract(
        qtest,
        user,
        vec![0x4e, 0x71, 0xd9, 0x2d],
        block_timestamp + 1,
        block_height + 1,
        chain_id,
    ).unwrap();
    assert!(claim.success);

    let mut set_engine = vec![0x0e, 0x83, 0x0e, 0x49];
    set_engine.extend_from_slice(&encode_address(engine));
    let set_engine_result = manager.execute_contract(
        sqtest,
        deployer,
        set_engine,
        block_timestamp + 2,
        block_height + 2,
        chain_id,
    ).unwrap();
    assert!(set_engine_result.success);

    let collateral = 300u128 * 10u128.pow(18);
    let debt = 100u128 * 10u128.pow(18);

    let mut approve = vec![0x09, 0x5e, 0xa7, 0xb3];
    approve.extend_from_slice(&encode_address(engine));
    approve.extend_from_slice(&encode_u256_le(collateral));
    let approve_result = manager.execute_contract(
        qtest,
        user,
        approve,
        block_timestamp + 3,
        block_height + 3,
        chain_id,
    ).unwrap();
    assert!(approve_result.success);

    let mut open_vault = vec![0x59, 0xcb, 0x83, 0xd0];
    open_vault.extend_from_slice(&encode_u256_le(collateral));
    open_vault.extend_from_slice(&encode_u256_le(debt));
    let open_vault_result = manager.execute_contract(
        engine,
        user,
        open_vault,
        block_timestamp + 4,
        block_height + 4,
        chain_id,
    ).unwrap();
    assert!(open_vault_result.success);

    let mut get_accrued_debt = vec![0xe5, 0x65, 0x4d, 0x64];
    get_accrued_debt.extend_from_slice(&encode_address(user));
    let accrued_result = manager.execute_contract(
        engine,
        user,
        get_accrued_debt,
        block_timestamp + 3,
        block_height + 5,
        chain_id,
    ).unwrap();

    assert!(accrued_result.success, "getAccruedDebt should not panic when block timestamp goes backwards");
    assert_eq!(accrued_result.return_data.len(), 32);
    assert_eq!(decode_u256_le_u128(&accrued_result.return_data), debt);
}
