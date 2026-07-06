//! # quantos-sol — Solidity Toolchain for Quantos
//!
//! Production CLI for compiling, deploying, and interacting with Solidity
//! smart contracts on the Quantos blockchain via Solang (WASM target).
//!
//! ## Usage
//!
//! ```bash
//! # Compile Solidity to WASM
//! quantos-sol compile contracts/Token.sol --output build/
//!
//! # Deploy compiled contract
//! quantos-sol deploy build/Token.wasm --rpc http://localhost:8545 --deployer QTS:abc...
//!
//! # Call a deployed contract
//! quantos-sol call QTS:def... --function "transfer(address,uint256)" \
//!     --args "QTS:recipient...,1000" --rpc http://localhost:8545 --caller QTS:abc...
//!
//! # Check Solang installation
//! quantos-sol doctor
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

// ============================================================================
// CLI Structure
// ============================================================================

#[derive(Parser)]
#[command(name = "quantos-sol")]
#[command(author = "Quantos Labs")]
#[command(version)]
#[command(about = "Solidity toolchain for Quantos — compile, deploy, interact")]
struct Cli {
    /// RPC endpoint URL
    #[arg(long, default_value = "http://127.0.0.1:8545", global = true)]
    rpc: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compile Solidity files to WASM using Solang
    Compile {
        /// Solidity source file (.sol)
        file: PathBuf,

        /// Output directory for compiled artifacts
        #[arg(short, long, default_value = "build")]
        output: PathBuf,

        /// Import paths for Solidity imports
        #[arg(short = 'I', long)]
        import_path: Vec<PathBuf>,

        /// Optimization level (none, less, default, aggressive)
        #[arg(long, default_value = "default")]
        opt_level: String,
    },

    /// Deploy a compiled WASM contract to Quantos
    Deploy {
        /// Compiled WASM file or Solidity file (auto-compiles if .sol)
        file: PathBuf,

        /// Deployer address (QTS:... or hex)
        #[arg(long)]
        deployer: String,

        /// ABI JSON file (auto-detected from build dir if not specified)
        #[arg(long)]
        abi: Option<PathBuf>,

        /// Constructor arguments (comma-separated)
        #[arg(long)]
        constructor_args: Option<String>,
    },

    /// Call a deployed contract function
    Call {
        /// Contract address (QTS:... or hex)
        address: String,

        /// Function signature, e.g. "transfer(address,uint256)"
        #[arg(long)]
        function: String,

        /// Function arguments (comma-separated)
        #[arg(long)]
        args: Option<String>,

        /// Caller address (QTS:... or hex)
        #[arg(long)]
        caller: String,
    },

    /// Check Solang installation and toolchain status
    Doctor,

    /// Initialize a new Solidity project for Quantos
    Init {
        /// Project directory name
        name: String,
    },
}

// ============================================================================
// RPC Types
// ============================================================================

#[derive(Serialize)]
struct DeployContractRpcRequest {
    bytecode: String,
    deployer: String,
    abi: Option<String>,
}

#[derive(Serialize)]
struct JsonRpcRequest<T: Serialize> {
    jsonrpc: String,
    method: String,
    params: Vec<T>,
    id: u64,
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    result: Option<serde_json::Value>,
    error: Option<JsonRpcError>,
    #[allow(dead_code)]
    id: u64,
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

// ============================================================================
// Solang Wrapper
// ============================================================================

/// Finds the Solang compiler binary on the system.
fn find_solang() -> Option<PathBuf> {
    // Check common locations
    let candidates = [
        "solang",
        "/usr/local/bin/solang",
        "/opt/homebrew/bin/solang",
    ];

    for candidate in &candidates {
        let path = PathBuf::from(candidate);
        if Command::new(candidate)
            .arg("--version")
            .output()
            .is_ok()
        {
            return Some(path);
        }
    }

    // Check if installed via cargo
    if let Ok(home) = std::env::var("HOME") {
        let cargo_bin = PathBuf::from(home).join(".cargo/bin/solang");
        if cargo_bin.exists() {
            return Some(cargo_bin);
        }
    }

    None
}

/// Gets Solang version string.
fn solang_version(solang_path: &Path) -> Option<String> {
    Command::new(solang_path)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
}

/// Compiles a Solidity file using Solang targeting Polkadot/Substrate WASM.
fn compile_solidity(
    solang_path: &Path,
    source: &Path,
    output_dir: &Path,
    import_paths: &[PathBuf],
    opt_level: &str,
) -> Result<CompileOutput, String> {
    // Ensure output directory exists
    std::fs::create_dir_all(output_dir)
        .map_err(|e| format!("Failed to create output directory: {}", e))?;

    // Build Solang command
    let mut cmd = Command::new(solang_path);
    cmd.arg("compile")
        .arg(source)
        .arg("--target")
        .arg("polkadot") // Polkadot/Substrate target → generates WASM with seal_* imports
        .arg("--output")
        .arg(output_dir);

    // Optimization level
    match opt_level {
        "none" => { cmd.arg("-O").arg("none"); }
        "less" => { cmd.arg("-O").arg("less"); }
        "default" => { /* default optimization */ }
        "aggressive" => { cmd.arg("-O").arg("aggressive"); }
        _ => { /* default */ }
    }

    // Import paths
    for path in import_paths {
        cmd.arg("-I").arg(path);
    }

    // Generate verbose output
    cmd.arg("--verbose");

    eprintln!("  Running: {:?}", cmd);

    let output = cmd.output()
        .map_err(|e| format!("Failed to execute Solang: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        return Err(format!(
            "Solang compilation failed (exit code: {}):\n{}\n{}",
            output.status.code().unwrap_or(-1),
            stdout,
            stderr,
        ));
    }

    // Find generated artifacts
    let stem = source.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("contract");

    let wasm_file = output_dir.join(format!("{}.wasm", stem));
    let abi_file = output_dir.join(format!("{}.contract", stem));

    // Solang for Polkadot generates .contract (ink! metadata) files
    // If not found, try plain .abi
    let abi_path = if abi_file.exists() {
        Some(abi_file)
    } else {
        let alt = output_dir.join(format!("{}.abi", stem));
        if alt.exists() { Some(alt) } else { None }
    };

    if !wasm_file.exists() {
        // Solang might name the output differently, search for .wasm files
        let wasm_files: Vec<_> = std::fs::read_dir(output_dir)
            .map_err(|e| format!("Failed to read output dir: {}", e))?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "wasm"))
            .collect();

        if wasm_files.is_empty() {
            return Err(format!(
                "Compilation succeeded but no .wasm file found in {:?}\nStdout: {}\nStderr: {}",
                output_dir, stdout, stderr
            ));
        }

        let actual_wasm = wasm_files[0].path();
        return Ok(CompileOutput {
            wasm_path: actual_wasm,
            abi_path,
            wasm_size: 0, // Will be read later
        });
    }

    let wasm_size = std::fs::metadata(&wasm_file)
        .map(|m| m.len())
        .unwrap_or(0);

    Ok(CompileOutput {
        wasm_path: wasm_file,
        abi_path,
        wasm_size,
    })
}

struct CompileOutput {
    wasm_path: PathBuf,
    abi_path: Option<PathBuf>,
    wasm_size: u64,
}

// ============================================================================
// RPC Client
// ============================================================================

/// Sends a JSON-RPC request to the Quantos node.
fn rpc_call(rpc_url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
    let client = reqwest::blocking::Client::new();

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": [params],
        "id": 1
    });

    let response = client
        .post(rpc_url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .map_err(|e| format!("RPC request failed: {}", e))?;

    let status = response.status();
    let text = response.text()
        .map_err(|e| format!("Failed to read RPC response: {}", e))?;

    if !status.is_success() {
        return Err(format!("RPC HTTP error {}: {}", status, text));
    }

    let rpc_response: JsonRpcResponse = serde_json::from_str(&text)
        .map_err(|e| format!("Failed to parse RPC response: {}\nBody: {}", e, text))?;

    if let Some(error) = rpc_response.error {
        return Err(format!("RPC error {}: {}", error.code, error.message));
    }

    rpc_response.result.ok_or_else(|| "RPC response missing result".to_string())
}

// ============================================================================
// Commands
// ============================================================================

fn cmd_doctor() {
    println!("╔══════════════════════════════════════════════╗");
    println!("║       quantos-sol — Toolchain Doctor         ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();

    // Check Solang
    print!("  Solang compiler ... ");
    match find_solang() {
        Some(path) => {
            let version = solang_version(&path).unwrap_or_else(|| "unknown".to_string());
            println!("✓ found at {:?}", path);
            println!("    Version: {}", version);
        }
        None => {
            println!("✗ NOT FOUND");
            println!();
            println!("  Install Solang:");
            println!("    cargo install solang");
            println!("    or: brew install solang  (macOS)");
            println!("    or: https://solang.readthedocs.io/en/latest/installing.html");
        }
    }
    println!();

    // Check quantos-cli
    print!("  quantos-cli    ... ");
    if Command::new("quantos-cli").arg("--version").output().is_ok() {
        println!("✓ found");
    } else {
        println!("✗ not in PATH (optional)");
    }
    println!();

    println!("  Target: Polkadot/Substrate WASM (seal_* API)");
    println!("  VM:     QuantosVM (Wasmer + Cranelift)");
    println!("  ABI:    Ethereum-compatible (Keccak-256 selectors)");
}

fn cmd_compile(
    file: &Path,
    output: &Path,
    import_paths: &[PathBuf],
    opt_level: &str,
) {
    println!("╔══════════════════════════════════════════════╗");
    println!("║       quantos-sol compile                    ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();

    // Validate source file
    if !file.exists() {
        eprintln!("  ✗ Source file not found: {:?}", file);
        std::process::exit(1);
    }

    if file.extension().map_or(true, |ext| ext != "sol") {
        eprintln!("  ✗ Expected .sol file, got: {:?}", file);
        std::process::exit(1);
    }

    // Find Solang
    let solang_path = match find_solang() {
        Some(p) => p,
        None => {
            eprintln!("  ✗ Solang compiler not found. Run 'quantos-sol doctor' for install instructions.");
            std::process::exit(1);
        }
    };

    println!("  Source:   {:?}", file);
    println!("  Output:   {:?}", output);
    println!("  Compiler: {:?}", solang_path);
    println!("  Target:   Polkadot/Substrate (WASM + seal_* API)");
    println!();

    // Compile
    match compile_solidity(&solang_path, file, output, import_paths, opt_level) {
        Ok(result) => {
            let size = if result.wasm_size > 0 {
                result.wasm_size
            } else {
                std::fs::metadata(&result.wasm_path).map(|m| m.len()).unwrap_or(0)
            };

            println!("  ✓ Compilation successful!");
            println!();
            println!("  Artifacts:");
            println!("    WASM: {:?} ({} bytes)", result.wasm_path, size);
            if let Some(ref abi) = result.abi_path {
                println!("    ABI:  {:?}", abi);
            }
            println!();
            println!("  Next: quantos-sol deploy {:?} --deployer QTS:your_address...", result.wasm_path);
        }
        Err(e) => {
            eprintln!("  ✗ Compilation failed:");
            eprintln!("    {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_deploy(
    file: &Path,
    deployer: &str,
    abi_path: Option<&Path>,
    rpc_url: &str,
) {
    println!("╔══════════════════════════════════════════════╗");
    println!("║       quantos-sol deploy                     ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();

    // If .sol file, compile first
    let wasm_path = if file.extension().map_or(false, |ext| ext == "sol") {
        println!("  Detected .sol file — compiling first...");
        println!();

        let solang_path = match find_solang() {
            Some(p) => p,
            None => {
                eprintln!("  ✗ Solang not found. Install it: cargo install solang");
                std::process::exit(1);
            }
        };

        let output_dir = file.parent().unwrap_or(Path::new(".")).join("build");
        match compile_solidity(&solang_path, file, &output_dir, &[], "default") {
            Ok(result) => {
                println!("  ✓ Compiled successfully");
                result.wasm_path
            }
            Err(e) => {
                eprintln!("  ✗ Compilation failed: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        file.to_path_buf()
    };

    // Read WASM bytecode
    let bytecode = match std::fs::read(&wasm_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("  ✗ Failed to read WASM file {:?}: {}", wasm_path, e);
            std::process::exit(1);
        }
    };

    // Validate WASM magic number
    if bytecode.len() < 8 || &bytecode[0..4] != b"\0asm" {
        eprintln!("  ✗ Invalid WASM file (bad magic number)");
        std::process::exit(1);
    }

    // Read ABI if provided
    let abi_json = if let Some(abi) = abi_path {
        match std::fs::read_to_string(abi) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("  ⚠ Failed to read ABI file: {}. Deploying without ABI.", e);
                None
            }
        }
    } else {
        // Try to find ABI next to WASM file
        let stem = wasm_path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let auto_abi = wasm_path.parent().unwrap_or(Path::new(".")).join(format!("{}.contract", stem));
        if auto_abi.exists() {
            std::fs::read_to_string(&auto_abi).ok()
        } else {
            None
        }
    };

    println!("  WASM:     {:?} ({} bytes)", wasm_path, bytecode.len());
    println!("  Deployer: {}", deployer);
    println!("  RPC:      {}", rpc_url);
    if abi_json.is_some() {
        println!("  ABI:      included");
    }
    println!();
    println!("  Deploying...");

    // Deploy via RPC
    let deploy_params = serde_json::json!({
        "bytecode": format!("0x{}", hex::encode(&bytecode)),
        "deployer": deployer,
        "abi": abi_json,
    });

    match rpc_call(rpc_url, "qnt_deployContract", deploy_params) {
        Ok(result) => {
            let address = result.as_str().unwrap_or("unknown");
            println!();
            println!("  ✓ Contract deployed successfully!");
            println!();
            println!("  Contract address: {}", address);
            println!();
            println!("  Next steps:");
            println!("    quantos-sol call {} --function \"yourFunction()\" --caller {} --rpc {}",
                     address, deployer, rpc_url);
        }
        Err(e) => {
            eprintln!();
            eprintln!("  ✗ Deployment failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_call(
    address: &str,
    function: &str,
    args: Option<&str>,
    caller: &str,
    rpc_url: &str,
) {
    println!("╔══════════════════════════════════════════════╗");
    println!("║       quantos-sol call                       ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();

    // Parse function signature → compute selector
    // e.g. "transfer(address,uint256)" → keccak256 → first 4 bytes
    let selector = compute_keccak_selector(function);

    // Encode arguments (basic ABI encoding)
    let encoded_args = if let Some(args_str) = args {
        encode_basic_args(args_str, function)
    } else {
        Vec::new()
    };

    // Build calldata: selector + encoded args
    let mut calldata = selector.to_vec();
    calldata.extend(&encoded_args);

    println!("  Contract: {}", address);
    println!("  Function: {}", function);
    println!("  Selector: 0x{}", hex::encode(&selector));
    println!("  Caller:   {}", caller);
    println!("  Calldata: 0x{} ({} bytes)", hex::encode(&calldata), calldata.len());
    println!();

    // Call via RPC — use eth_call style or qnt_simulateContract
    let call_params = serde_json::json!({
        "contract_address": address,
        "caller": caller,
        "input_data": format!("0x{}", hex::encode(&calldata)),
    });

    match rpc_call(rpc_url, "qnt_callContract", call_params) {
        Ok(result) => {
            println!("  ✓ Call successful!");
            println!("  Result: {}", result);
        }
        Err(e) => {
            eprintln!("  ✗ Call failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_init(name: &str) {
    println!("╔══════════════════════════════════════════════╗");
    println!("║       quantos-sol init                       ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();

    let project_dir = PathBuf::from(name);
    if project_dir.exists() {
        eprintln!("  ✗ Directory '{}' already exists", name);
        std::process::exit(1);
    }

    // Create project structure
    let contracts_dir = project_dir.join("contracts");
    let build_dir = project_dir.join("build");
    let test_dir = project_dir.join("test");

    std::fs::create_dir_all(&contracts_dir).unwrap();
    std::fs::create_dir_all(&build_dir).unwrap();
    std::fs::create_dir_all(&test_dir).unwrap();

    // Create sample ERC-20 contract
    let sample_contract = r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title QuantosToken — Sample ERC-20 for Quantos
/// @notice Compiled with Solang, deployed on QuantosVM (WASM)
contract QuantosToken {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory _name, string memory _symbol, uint256 _initialSupply) {
        name = _name;
        symbol = _symbol;
        decimals = 18;
        totalSupply = _initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        emit Transfer(address(0), msg.sender, totalSupply);
    }

    function transfer(address to, uint256 value) public returns (bool) {
        require(balanceOf[msg.sender] >= value, "Insufficient balance");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) public returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) public returns (bool) {
        require(balanceOf[from] >= value, "Insufficient balance");
        require(allowance[from][msg.sender] >= value, "Insufficient allowance");
        balanceOf[from] -= value;
        balanceOf[to] += value;
        allowance[from][msg.sender] -= value;
        emit Transfer(from, to, value);
        return true;
    }
}
"#;

    std::fs::write(contracts_dir.join("QuantosToken.sol"), sample_contract).unwrap();

    // Create README
    let readme = format!(r#"# {} — Quantos Solidity Project

## Prerequisites

Install Solang compiler:
```bash
cargo install solang
# or: brew install solang
```

## Commands

```bash
# Compile
quantos-sol compile contracts/QuantosToken.sol --output build/

# Deploy (start a Quantos node first)
quantos-sol deploy build/QuantosToken.wasm \
    --deployer QTS:your_address \
    --rpc http://localhost:8545

# Call
quantos-sol call QTS:contract_address \
    --function "transfer(address,uint256)" \
    --args "QTS:recipient,1000" \
    --caller QTS:your_address \
    --rpc http://localhost:8545
```

## Architecture

```
Solidity (.sol)
    │
    ▼  Solang compiler (target: polkadot)
WASM bytecode (.wasm)
    │
    ▼  quantos-sol deploy
QuantosVM (Wasmer + Cranelift)
    │
    ▼  seal_* host functions → qnt_* mapping
Quantos Blockchain (post-quantum, gasless)
```

## Notes

- Quantos uses **WASM** (not EVM) for contract execution
- Solang compiles Solidity to WASM targeting the Substrate/Polkadot API
- QuantosVM provides a **Solang compatibility layer** (`seal_*` → `qnt_*`)
- **Zero gas fees** — execution uses Compute Units (CU) for resource limits only
- Post-quantum cryptography available via precompiled contracts
"#, name);

    std::fs::write(project_dir.join("README.md"), readme).unwrap();

    // Create .gitignore
    std::fs::write(
        project_dir.join(".gitignore"),
        "build/\nnode_modules/\n*.wasm\n",
    ).unwrap();

    println!("  ✓ Project '{}' created!", name);
    println!();
    println!("  Structure:");
    println!("    {}/", name);
    println!("    ├── contracts/");
    println!("    │   └── QuantosToken.sol  (sample ERC-20)");
    println!("    ├── build/                (compiled artifacts)");
    println!("    ├── test/                 (tests)");
    println!("    ├── README.md");
    println!("    └── .gitignore");
    println!();
    println!("  Next: quantos-sol compile {}/contracts/QuantosToken.sol", name);
}

// ============================================================================
// ABI Encoding Helpers
// ============================================================================

/// Computes the Keccak-256 selector (first 4 bytes) from a function signature.
fn compute_keccak_selector(signature: &str) -> [u8; 4] {
    use sha3::Digest;
    let mut hasher = sha3::Keccak256::new();
    hasher.update(signature.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&hash[..4]);
    selector
}

/// Basic ABI encoding for common types.
/// Handles: address, uint256, bool, string (static only for now).
fn encode_basic_args(args_str: &str, function_sig: &str) -> Vec<u8> {
    let mut encoded = Vec::new();

    // Parse parameter types from signature
    let types = parse_param_types(function_sig);

    let args: Vec<&str> = if args_str.is_empty() {
        vec![]
    } else {
        args_str.split(',').map(|s| s.trim()).collect()
    };

    if args.len() != types.len() {
        eprintln!("  ⚠ Argument count mismatch: {} args for {} params", args.len(), types.len());
        return encoded;
    }

    for (arg, param_type) in args.iter().zip(types.iter()) {
        match param_type.as_str() {
            "address" => {
                // Address: 32-byte left-padded
                let addr_hex = arg.strip_prefix("QTS:").or_else(|| arg.strip_prefix("0x")).unwrap_or(arg);
                let addr_bytes = hex::decode(addr_hex).unwrap_or_else(|_| vec![0u8; 32]);
                let mut padded = [0u8; 32];
                let start = 32_usize.saturating_sub(addr_bytes.len());
                padded[start..].copy_from_slice(&addr_bytes[..addr_bytes.len().min(32)]);
                encoded.extend_from_slice(&padded);
            }
            t if t.starts_with("uint") => {
                // Unsigned integer: 32-byte big-endian
                let value: u128 = arg.parse().unwrap_or(0);
                let mut padded = [0u8; 32];
                padded[16..].copy_from_slice(&value.to_be_bytes());
                encoded.extend_from_slice(&padded);
            }
            "bool" => {
                let mut padded = [0u8; 32];
                padded[31] = if *arg == "true" || *arg == "1" { 1 } else { 0 };
                encoded.extend_from_slice(&padded);
            }
            _ => {
                // Unknown type — encode as raw bytes
                let bytes = hex::decode(arg.strip_prefix("0x").unwrap_or(arg)).unwrap_or_default();
                let mut padded = [0u8; 32];
                let len = bytes.len().min(32);
                padded[32 - len..].copy_from_slice(&bytes[..len]);
                encoded.extend_from_slice(&padded);
            }
        }
    }

    encoded
}

/// Extracts parameter types from a function signature like "transfer(address,uint256)".
fn parse_param_types(signature: &str) -> Vec<String> {
    let start = signature.find('(').unwrap_or(signature.len());
    let end = signature.rfind(')').unwrap_or(signature.len());

    if start >= end || start + 1 == end {
        return vec![];
    }

    let params = &signature[start + 1..end];
    params.split(',').map(|s| s.trim().to_string()).collect()
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Compile {
            file,
            output,
            import_path,
            opt_level,
        } => {
            cmd_compile(file, output, import_path, opt_level);
        }

        Commands::Deploy {
            file,
            deployer,
            abi,
            constructor_args: _,
        } => {
            cmd_deploy(
                file,
                deployer,
                abi.as_deref(),
                &cli.rpc,
            );
        }

        Commands::Call {
            address,
            function,
            args,
            caller,
        } => {
            cmd_call(
                address,
                function,
                args.as_deref(),
                caller,
                &cli.rpc,
            );
        }

        Commands::Doctor => {
            cmd_doctor();
        }

        Commands::Init { name } => {
            cmd_init(name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak_selector_transfer() {
        // transfer(address,uint256) → 0xa9059cbb
        let selector = compute_keccak_selector("transfer(address,uint256)");
        assert_eq!(selector, [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn test_keccak_selector_balanceof() {
        // balanceOf(address) → 0x70a08231
        let selector = compute_keccak_selector("balanceOf(address)");
        assert_eq!(selector, [0x70, 0xa0, 0x82, 0x31]);
    }

    #[test]
    fn test_parse_param_types() {
        assert_eq!(
            parse_param_types("transfer(address,uint256)"),
            vec!["address", "uint256"]
        );
        assert_eq!(
            parse_param_types("balanceOf(address)"),
            vec!["address"]
        );
        assert_eq!(
            parse_param_types("totalSupply()"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn test_encode_uint256() {
        let encoded = encode_basic_args("100", "foo(uint256)");
        assert_eq!(encoded.len(), 32);
        assert_eq!(encoded[31], 100);
    }

    #[test]
    fn test_encode_bool() {
        let encoded = encode_basic_args("true", "foo(bool)");
        assert_eq!(encoded.len(), 32);
        assert_eq!(encoded[31], 1);
    }
}
