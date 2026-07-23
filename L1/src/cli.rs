// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Quantos CLI
//!
//! Production command-line interface for interacting with a Quantos node.
//!
//! ## Usage
//!
//! ```bash
//! # Check node health
//! quantos-cli --rpc http://localhost:8545 node health
//!
//! # Get account balance
//! quantos-cli account balance QTS:ab12...ff
//!
//! # Generate a new keypair
//! quantos-cli keygen
//!
//! # Send a transfer (server-side signing)
//! quantos-cli tx transfer --privkey QTS:... --to QTS:... --amount QTS:de0b6b3a7640000
//!
//! # Send a signed transaction
//! quantos-cli tx send --raw QTS:deadbeef...
//! ```

use std::process;
use clap::{Parser, Subcommand};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::core::params::ArrayParams;
use serde_json::Value;

// ============================================================================
// CLI Structure
// ============================================================================

#[derive(Parser)]
#[command(name = "quantos-cli")]
#[command(author = "Quantos Labs")]
#[command(version)]
#[command(about = "Quantos CLI — interact with a Quantos node", long_about = None)]
struct Cli {
    /// RPC endpoint URL
    #[arg(long, default_value = "http://127.0.0.1:8545", global = true)]
    rpc: String,

    /// Output format (json or text)
    #[arg(long, default_value = "text", global = true)]
    output: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Subcommand)]
enum Commands {
    /// Account operations
    Account {
        #[command(subcommand)]
        cmd: AccountCmd,
    },
    /// Transaction operations
    Tx {
        #[command(subcommand)]
        cmd: TxCmd,
    },
    /// Node information
    Node {
        #[command(subcommand)]
        cmd: NodeCmd,
    },
    /// Validator queries
    Validator {
        #[command(subcommand)]
        cmd: ValidatorCmd,
    },
    /// DAG operations
    Dag {
        #[command(subcommand)]
        cmd: DagCmd,
    },
    /// Mempool queries
    Mempool {
        #[command(subcommand)]
        cmd: MempoolCmd,
    },
    /// Smart contract operations
    Contract {
        #[command(subcommand)]
        cmd: ContractCmd,
    },
    /// Generate a new ML-DSA-65 keypair
    Keygen,
}

// ---- Account ----

#[derive(Subcommand)]
enum AccountCmd {
    /// Get full account state
    Get {
        /// Account address (QTS:...)
        address: String,
    },
    /// Get account balance
    Balance {
        /// Account address (QTS:...)
        address: String,
    },
    /// Get account nonce (transaction count)
    Nonce {
        /// Account address (QTS:...)
        address: String,
    },
}

// ---- Transaction ----

#[derive(Subcommand)]
enum TxCmd {
    /// Send a signed transaction
    Send {
        /// Raw signed transaction hex (QTS:...)
        #[arg(long)]
        raw: String,
    },
    /// Send a batch of signed transactions
    SendBatch {
        /// Raw signed transactions hex, comma-separated
        #[arg(long)]
        raw: String,
    },
    /// Transfer tokens (server-side signing via qnt_sendTransaction)
    Transfer {
        /// Hex-encoded ML-DSA-65 private key (QTS:...)
        #[arg(long)]
        privkey: String,
        /// Destination address (QTS:...)
        #[arg(long)]
        to: String,
        /// Amount in hex (QTS:de0b6b3a7640000 = 1 QTS)
        #[arg(long)]
        amount: String,
        /// Optional nonce in hex (auto-fetched if omitted)
        #[arg(long)]
        nonce: Option<String>,
        /// Shard ID (default 0)
        #[arg(long, default_value = "0")]
        shard_id: u16,
    },
    /// Stake tokens (server-side signing)
    Stake {
        /// Hex-encoded ML-DSA-65 private key (QTS:...)
        #[arg(long)]
        privkey: String,
        /// Amount to stake in hex
        #[arg(long)]
        amount: String,
    },
    /// Unstake tokens (server-side signing)
    Unstake {
        /// Hex-encoded ML-DSA-65 private key (QTS:...)
        #[arg(long)]
        privkey: String,
        /// Amount to unstake in hex
        #[arg(long)]
        amount: String,
    },
    /// Get transaction by hash
    Get {
        /// Transaction hash (QTS:...)
        hash: String,
    },
    /// Get transaction receipt
    Receipt {
        /// Transaction hash (QTS:...)
        hash: String,
    },
}

// ---- Node ----

#[derive(Subcommand)]
enum NodeCmd {
    /// Show node information
    Info,
    /// Health check
    Health,
    /// Sync status
    Sync,
    /// Get current slot (block height)
    Slot,
    /// Get finalized slot
    FinalizedSlot,
    /// Get chain ID
    ChainId,
    /// Get current state root
    StateRoot,
    /// Get consensus metrics
    Metrics,
    /// Get peer count
    Peers,
}

// ---- Validator ----

#[derive(Subcommand)]
enum ValidatorCmd {
    /// List all validators
    List,
    /// Get validator by address
    Get {
        /// Validator address (QTS:...)
        address: String,
    },
}

// ---- DAG ----

#[derive(Subcommand)]
enum DagCmd {
    /// Get DAG vertex by hash
    Vertex {
        /// Vertex hash (QTS:...)
        hash: String,
    },
    /// Get DAG tips for a shard
    Tips {
        /// Shard ID
        shard_id: u16,
    },
    /// Get shard info
    Shard {
        /// Shard ID
        shard_id: u16,
    },
}

// ---- Mempool ----

#[derive(Subcommand)]
enum MempoolCmd {
    /// Show mempool status
    Status,
    /// List pending transactions
    Pending {
        /// Max number of transactions to show
        #[arg(long, default_value = "20")]
        limit: usize,
    },
}

// ---- Contract ----

#[derive(Subcommand)]
enum ContractCmd {
    /// Deploy a contract
    Deploy {
        /// Path to compiled WASM bytecode file
        #[arg(long)]
        bytecode: String,
        /// Deployer address (QTS:...)
        #[arg(long)]
        deployer: String,
        /// Optional ABI JSON string
        #[arg(long)]
        abi: Option<String>,
    },
    /// Call a contract (read-only)
    Call {
        /// Contract address (QTS:...)
        #[arg(long)]
        to: String,
        /// Input data hex (QTS:...)
        #[arg(long)]
        data: Option<String>,
        /// Caller address (QTS:...)
        #[arg(long)]
        from: Option<String>,
    },
    /// Check if a contract exists
    Verify {
        /// Contract address (QTS:...)
        address: String,
    },
    /// Get contract metadata
    Metadata {
        /// Contract address (QTS:...)
        address: String,
    },
    /// Read contract storage slot
    Storage {
        /// Contract address (QTS:...)
        #[arg(long)]
        address: String,
        /// Storage slot (QTS:...)
        #[arg(long)]
        slot: String,
    },
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let client = match HttpClientBuilder::default().build(&cli.rpc) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to connect to {}: {}", cli.rpc, e);
            process::exit(1);
        }
    };

    let result = run(&cli, &client).await;

    match result {
        Ok(output) => {
            match cli.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default()),
                OutputFormat::Text => print_text(&output),
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

// ============================================================================
// Command Dispatch
// ============================================================================

async fn run(cli: &Cli, client: &HttpClient) -> Result<Value, String> {
    match &cli.command {
        Commands::Account { cmd } => run_account(client, cmd).await,
        Commands::Tx { cmd } => run_tx(client, cmd).await,
        Commands::Node { cmd } => run_node(client, cmd).await,
        Commands::Validator { cmd } => run_validator(client, cmd).await,
        Commands::Dag { cmd } => run_dag(client, cmd).await,
        Commands::Mempool { cmd } => run_mempool(client, cmd).await,
        Commands::Contract { cmd } => run_contract(client, cmd).await,
        Commands::Keygen => run_keygen(client).await,
    }
}

// ============================================================================
// RPC Helpers
// ============================================================================

async fn rpc_call(client: &HttpClient, method: &str, params: ArrayParams) -> Result<Value, String> {
    client
        .request::<Value, _>(method, params)
        .await
        .map_err(|e| format!("RPC call '{}' failed: {}", method, e))
}

fn no_params() -> ArrayParams {
    ArrayParams::new()
}

fn one_param<T: serde::Serialize>(val: T) -> ArrayParams {
    let mut p = ArrayParams::new();
    let _ = p.insert(val);
    p
}

fn two_params<T1: serde::Serialize, T2: serde::Serialize>(a: T1, b: T2) -> ArrayParams {
    let mut p = ArrayParams::new();
    let _ = p.insert(a);
    let _ = p.insert(b);
    p
}

// ============================================================================
// Account Commands
// ============================================================================

async fn run_account(client: &HttpClient, cmd: &AccountCmd) -> Result<Value, String> {
    match cmd {
        AccountCmd::Get { address } => {
            rpc_call(client, "qnt_getAccount", one_param(address)).await
        }
        AccountCmd::Balance { address } => {
            rpc_call(client, "qnt_getBalance", two_params(address, Option::<String>::None)).await
        }
        AccountCmd::Nonce { address } => {
            rpc_call(client, "qnt_getTransactionCount", two_params(address, Option::<String>::None)).await
        }
    }
}

// ============================================================================
// Transaction Commands
// ============================================================================

async fn run_tx(client: &HttpClient, cmd: &TxCmd) -> Result<Value, String> {
    match cmd {
        TxCmd::Send { raw } => {
            rpc_call(client, "qnt_sendRawTransaction", one_param(raw)).await
        }
        TxCmd::SendBatch { raw } => {
            let txs: Vec<&str> = raw.split(',').map(|s| s.trim()).collect();
            rpc_call(client, "qnt_sendRawTransactionBatch", one_param(txs)).await
        }
        TxCmd::Transfer { privkey, to, amount, nonce, shard_id } => {
            let request = serde_json::json!({
                "from_private_key": privkey,
                "to": to,
                "amount": amount,
                "nonce": nonce,
                "tx_type": "transfer",
                "shard_id": shard_id,
            });
            rpc_call(client, "qnt_sendTransaction", one_param(request)).await
        }
        TxCmd::Stake { privkey, amount } => {
            let request = serde_json::json!({
                "from_private_key": privkey,
                "to": "QTS:0000000000000000000000000000000000000000000000000000000000000000",
                "amount": amount,
                "tx_type": "stake",
            });
            rpc_call(client, "qnt_sendTransaction", one_param(request)).await
        }
        TxCmd::Unstake { privkey, amount } => {
            let request = serde_json::json!({
                "from_private_key": privkey,
                "to": "QTS:0000000000000000000000000000000000000000000000000000000000000000",
                "amount": amount,
                "tx_type": "unstake",
            });
            rpc_call(client, "qnt_sendTransaction", one_param(request)).await
        }
        TxCmd::Get { hash } => {
            rpc_call(client, "qnt_getTransactionByHash", one_param(hash)).await
        }
        TxCmd::Receipt { hash } => {
            rpc_call(client, "qnt_getTransactionReceipt", one_param(hash)).await
        }
    }
}

// ============================================================================
// Node Commands
// ============================================================================

async fn run_node(client: &HttpClient, cmd: &NodeCmd) -> Result<Value, String> {
    match cmd {
        NodeCmd::Info => rpc_call(client, "qnt_nodeInfo", no_params()).await,
        NodeCmd::Health => rpc_call(client, "qnt_health", no_params()).await,
        NodeCmd::Sync => rpc_call(client, "qnt_syncing", no_params()).await,
        NodeCmd::Slot => rpc_call(client, "qnt_blockNumber", no_params()).await,
        NodeCmd::FinalizedSlot => rpc_call(client, "qnt_getFinalizedSlot", no_params()).await,
        NodeCmd::ChainId => rpc_call(client, "qnt_chainId", no_params()).await,
        NodeCmd::StateRoot => rpc_call(client, "qnt_getStateRoot", no_params()).await,
        NodeCmd::Metrics => rpc_call(client, "qnt_getMetrics", no_params()).await,
        NodeCmd::Peers => rpc_call(client, "qnt_peerCount", no_params()).await,
    }
}

// ============================================================================
// Validator Commands
// ============================================================================

async fn run_validator(client: &HttpClient, cmd: &ValidatorCmd) -> Result<Value, String> {
    match cmd {
        ValidatorCmd::List => rpc_call(client, "qnt_getValidators", no_params()).await,
        ValidatorCmd::Get { address } => {
            rpc_call(client, "qnt_getValidatorByAddress", one_param(address)).await
        }
    }
}

// ============================================================================
// DAG Commands
// ============================================================================

async fn run_dag(client: &HttpClient, cmd: &DagCmd) -> Result<Value, String> {
    match cmd {
        DagCmd::Vertex { hash } => {
            rpc_call(client, "qnt_getVertexByHash", one_param(hash)).await
        }
        DagCmd::Tips { shard_id } => {
            rpc_call(client, "qnt_getDagTips", one_param(shard_id)).await
        }
        DagCmd::Shard { shard_id } => {
            rpc_call(client, "qnt_getShardInfo", one_param(shard_id)).await
        }
    }
}

// ============================================================================
// Mempool Commands
// ============================================================================

async fn run_mempool(client: &HttpClient, cmd: &MempoolCmd) -> Result<Value, String> {
    match cmd {
        MempoolCmd::Status => rpc_call(client, "qnt_txPoolStatus", no_params()).await,
        MempoolCmd::Pending { limit } => {
            rpc_call(client, "qnt_pendingTransactions", one_param(limit)).await
        }
    }
}

// ============================================================================
// Contract Commands
// ============================================================================

async fn run_contract(client: &HttpClient, cmd: &ContractCmd) -> Result<Value, String> {
    match cmd {
        ContractCmd::Deploy { bytecode, deployer, abi } => {
            // Read bytecode from file
            let bytecode_bytes = std::fs::read(bytecode)
                .map_err(|e| format!("Failed to read bytecode file '{}': {}", bytecode, e))?;
            let bytecode_hex = format!("QTS:{}", hex::encode(&bytecode_bytes));

            let request = serde_json::json!({
                "bytecode": bytecode_hex,
                "deployer": deployer,
                "abi": abi,
            });
            rpc_call(client, "qnt_deployContract", one_param(request)).await
        }
        ContractCmd::Call { to, data, from } => {
            let request = serde_json::json!({
                "to": to,
                "data": data,
                "from": from,
            });
            rpc_call(client, "qnt_call", two_params(request, Option::<String>::None)).await
        }
        ContractCmd::Verify { address } => {
            rpc_call(client, "qnt_verifyContract", one_param(address)).await
        }
        ContractCmd::Metadata { address } => {
            rpc_call(client, "qnt_getContractMetadata", one_param(address)).await
        }
        ContractCmd::Storage { address, slot } => {
            rpc_call(client, "qnt_getStorageAt", {
                let mut p = ArrayParams::new();
                let _ = p.insert(address);
                let _ = p.insert(slot);
                let _ = p.insert(Option::<String>::None);
                p
            }).await
        }
    }
}

// ============================================================================
// Keygen Command
// ============================================================================

async fn run_keygen(client: &HttpClient) -> Result<Value, String> {
    rpc_call(client, "qnt_generateKeyPair", no_params()).await
}

// ============================================================================
// Text Output Formatter
// ============================================================================

fn print_text(value: &Value) {
    match value {
        Value::Object(map) => {
            let max_key = map.keys().map(|k| k.len()).max().unwrap_or(0);
            for (key, val) in map {
                let display = match val {
                    Value::String(s) => s.clone(),
                    Value::Bool(b) => b.to_string(),
                    Value::Number(n) => n.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Array(arr) => {
                        if arr.is_empty() {
                            "[]".to_string()
                        } else if arr.len() <= 3 {
                            format!("{}", serde_json::to_string(arr).unwrap_or_default())
                        } else {
                            format!("[{} items]", arr.len())
                        }
                    }
                    Value::Object(_) => {
                        serde_json::to_string_pretty(val).unwrap_or_default()
                    }
                };
                println!("  {:<width$}  {}", key, display, width = max_key);
            }
        }
        Value::Array(arr) => {
            if arr.is_empty() {
                println!("  (empty)");
            } else {
                for (i, item) in arr.iter().enumerate() {
                    println!("  [{}]", i);
                    print_text(item);
                    if i < arr.len() - 1 {
                        println!();
                    }
                }
            }
        }
        Value::String(s) => println!("  {}", s),
        Value::Bool(b) => println!("  {}", b),
        Value::Number(n) => println!("  {}", n),
        Value::Null => println!("  null"),
    }
}
