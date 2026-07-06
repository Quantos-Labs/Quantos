//! # Quantos Node Entry Point
//!
//! Main binary for running a Quantos L1 blockchain node.
//!
//! ## Features
//!
//! - **Post-Quantum Security**: Dilithium-3, SPHINCS+, ML-DSA-65
//! - **Massive Parallelization**: 1000+ shards, ~100M TPS
//! - **Dynamic Sharding**: Auto-scaling based on load
//! - **Sidechains**: Application-specific chains
//!
//! ## Usage
//!
//! ```bash
//! # Run with default config
//! quantos
//!
//! # Run with custom ports
//! QUANTOS_P2P_PORT=30304 QUANTOS_RPC_PORT=8546 quantos
//! ```

mod crypto;
mod types;
mod state;
mod storage;
mod dag;
mod mempool;
mod consensus;
mod network;
mod rpc;
mod parallel;
mod sharding;
mod sidechain;
mod zk;
mod compression;
mod batching;
mod sync;
mod light_client;
mod security;
mod vm;
mod standards;
mod stacc;
mod genesis;
pub mod l0;
mod validator_keys;

use std::time::Duration;
use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use crate::consensus::QuantosConsensus;
use crate::genesis::{GenesisConfig, GenesisBuilder, GenesisValidator, NetworkId};
use crate::network::P2PNetwork;
use crate::validator_keys::ValidatorKeySet;
use crate::NodeConfig;
use crate::rpc::RpcServer;
use crate::storage::Storage;
use crate::state::StateManager;
use crate::parallel::ParallelScheduler;
use crate::sharding::ShardManager;
use crate::sidechain::SidechainRegistry;

/// CLI arguments for Quantos node
#[derive(Parser)]
#[command(name = "quantos")]
#[command(author = "Quantos Labs")]
#[command(version)]
#[command(about = "Quantos Post-Quantum L1 Blockchain Node", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    
    /// Network to connect to (testnet, devnet, mainnet)
    #[arg(short, long, default_value = "testnet")]
    network: String,
    
    /// Path to genesis configuration file
    #[arg(short, long)]
    genesis: Option<String>,
    
    /// Data directory for blockchain data
    #[arg(short, long, default_value = "./data")]
    datadir: String,
    
    /// P2P port
    #[arg(long, default_value = "30303")]
    p2p_port: u16,
    
    /// RPC port
    #[arg(long, default_value = "8545")]
    rpc_port: u16,
    
    /// Prometheus metrics port
    #[arg(long, default_value = "9615")]
    metrics_port: u16,
    
    /// Validator mode (requires validator key)
    #[arg(long)]
    validator: bool,
    
    /// Path to validator key file
    #[arg(long)]
    validator_key: Option<String>,
    
    /// Bootstrap nodes (comma-separated)
    #[arg(long)]
    bootnodes: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new node with genesis
    Init {
        /// Network type (testnet, devnet, mainnet)
        #[arg(short, long, default_value = "testnet")]
        network: String,
        
        /// Output path for genesis file
        #[arg(short, long)]
        output: Option<String>,
    },
    
    /// Start the node
    Run,
    
    /// Export genesis configuration
    ExportGenesis {
        /// Output file path
        #[arg(short, long)]
        output: String,
        
        /// Network type
        #[arg(short, long, default_value = "testnet")]
        network: String,
    },
    
    /// Generate a full validator key set (Dilithium + VRF + ML-DSA-65)
    GenerateValidatorKeys {
        /// Output path for key file
        #[arg(short, long)]
        output: String,
        /// Human-readable validator name
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Create a genesis file from a list of validator key files
    CreateGenesis {
        /// Network type
        #[arg(short, long, default_value = "testnet")]
        network: String,
        /// Output path for genesis file
        #[arg(short, long)]
        output: String,
        /// Validator key files (comma-separated)
        #[arg(short, long, value_delimiter = ',')]
        validators: Vec<String>,
        /// Initial stake per validator in QTS (default 1,000,000)
        #[arg(long, default_value = "1000000")]
        stake: u128,
        /// Commission rate in basis points (100 = 1%)
        #[arg(long, default_value = "500")]
        commission_bps: u16,
    },

    /// Show node info
    Info,
}

/// Main entry point for the Quantos node.
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging with structured output
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;
    
    match cli.command {
        Some(Commands::Init { network, output }) => {
            return init_node(&network, output.as_deref());
        }
        Some(Commands::ExportGenesis { output, network }) => {
            return export_genesis(&output, &network);
        }
        Some(Commands::GenerateValidatorKeys { output, name }) => {
            return generate_validator_keys(&output, name.as_deref());
        }
        Some(Commands::CreateGenesis {
            network,
            output,
            validators,
            stake,
            commission_bps,
        }) => {
            return create_genesis_from_keys(&network, &output, &validators, *stake, *commission_bps);
        }
        Some(Commands::Info) => {
            return show_info();
        }
        Some(Commands::Run) | None => {
            // Continue to run the node
        }
    }

    // Display banner
    print_banner();
    
    // Load genesis configuration
    let genesis = load_genesis(&cli)?;
    info!("✓ Genesis loaded: {} (chain_id: {})", 
          genesis.network.name(), genesis.chain.chain_id);
    info!("  ├─ Validators: {}", genesis.validators.len());
    info!("  ├─ Allocations: {}", genesis.allocations.len());
    info!("  └─ Total supply: {} QTS", genesis.total_supply().unwrap_or(0) / 10u128.pow(18));

    // Load node configuration
    let config = NodeConfig::from_cli(&cli, &genesis);
    
    // Initialize storage layer (RocksDB)
    let storage = Storage::new(&config.db_path)?;
    info!("✓ Storage initialized at {}", config.db_path);

    // Initialize state manager
    let state_manager = StateManager::new(storage.clone());
    let auth_token = state_manager.bootstrap_auth_token();
    info!("✓ State manager initialized");
    
    // Apply genesis state
    let genesis_builder = genesis::GenesisBuilder::new(genesis.clone());
    let initial_balances = genesis_builder.get_initial_balances();
    state_manager.apply_genesis(initial_balances, &auth_token)
        .map_err(|e| anyhow::anyhow!("Failed to apply genesis: {}", e))?;
    info!("✓ Genesis state applied");

    // Initialize parallel execution scheduler
    let parallel_config = parallel::ParallelConfig::default();
    let _parallel_scheduler = ParallelScheduler::new(
        parallel_config,
        state_manager.clone(),
        config.num_shards as u16,
    ).map_err(|e| anyhow::anyhow!("Failed to create parallel scheduler: {}", e))?;
    info!("✓ Parallel scheduler initialized ({} threads)", num_cpus::get());

    // Initialize dynamic shard manager
    let shard_config = sharding::ShardingConfig {
        min_shards: config.min_shards as u16,
        max_shards: config.max_shards as u16,
        ..Default::default()
    };
    let _shard_manager = ShardManager::new(shard_config);
    info!("✓ Dynamic sharding enabled (min: {}, max: {})", 
          config.min_shards, config.max_shards);

    // Initialize sidechain registry
    let _sidechain_registry = SidechainRegistry::new(config.max_sidechains);
    info!("✓ Sidechain registry initialized (max: {})", config.max_sidechains);

    // Initialize consensus engine
    let mut consensus = QuantosConsensus::new(
        config.clone(),
        state_manager.clone(),
        storage.clone(),
    ).await?;

    // Load or generate validator identity so the node can produce vertices
    if let Some(key_path) = &cli.validator_key {
        let keyset = ValidatorKeySet::from_file(key_path)
            .map_err(|e| anyhow::anyhow!("Failed to load validator keys: {}", e))?;
        let signing_key = keyset.signing_keypair()
            .map_err(|e| anyhow::anyhow!("Failed to load signing keypair: {}", e))?;
        let vrf_key = keyset.vrf_keypair()
            .map_err(|e| anyhow::anyhow!("Failed to load VRF keypair: {}", e))?;
        let finality_key = keyset.finality_keypair()
            .map_err(|e| anyhow::anyhow!("Failed to load finality keypair: {}", e))?;
        let addr = signing_key.address();
        info!("✓ Loaded validator identity: {}", hex::encode(&addr[..8]));
        consensus.set_validator_keys(&genesis, signing_key, vrf_key, finality_key);
    } else if let Ok(keyset) = ValidatorKeySet::from_file(ValidatorKeySet::default_path(&config.db_path)) {
        let signing_key = keyset.signing_keypair()
            .map_err(|e| anyhow::anyhow!("Failed to load signing keypair: {}", e))?;
        let vrf_key = keyset.vrf_keypair()
            .map_err(|e| anyhow::anyhow!("Failed to load VRF keypair: {}", e))?;
        let finality_key = keyset.finality_keypair()
            .map_err(|e| anyhow::anyhow!("Failed to load finality keypair: {}", e))?;
        let addr = signing_key.address();
        info!("✓ Loaded validator identity: {}", hex::encode(&addr[..8]));
        consensus.set_validator_keys(&genesis, signing_key, vrf_key, finality_key);
    } else if cli.validator {
        warn!("⚠ Validator mode requested but no key file found. Run `quantos generate-validator-keys` first.");
    } else if genesis.network == NetworkId::Devnet || genesis.network == NetworkId::Testnet {
        warn!("⚠ No validator key file found; generating ephemeral validator identity for local testing.");
        let signing_key = crypto::DilithiumKeypair::generate()
            .expect("Failed to generate validator signing key");
        let vrf_key = crypto::VRFKeypair::generate()
            .expect("Failed to generate validator VRF key");
        let finality_key = crypto::MlDsa65Keypair::generate()
            .expect("Failed to generate validator finality key");
        let addr = signing_key.address();
        info!("✓ Validator identity: {}", hex::encode(&addr[..8]));
        consensus.set_validator_keys(&genesis, signing_key, vrf_key, finality_key);
    }
    info!("✓ Quantos Consensus initialized");
    info!("  ├─ Committees: {}", config.num_committees);
    info!("  ├─ Validators/committee: {}", config.validators_per_committee);
    info!("  ├─ Shards: {}", config.num_shards);
    info!("  ├─ Dynamic sharding: {}", if config.dynamic_sharding { "enabled" } else { "disabled" });
    info!("  └─ Sidechains: {}", if config.sidechains_enabled { "enabled" } else { "disabled" });

    // PRODUCTION: Initialize Self-Healing Shard Manager
    let healing_manager = sharding::SelfHealingShardManager::new(
        config.num_shards as u16,
        state_manager.clone(),
    );
    info!("✓ Self-Healing Shard Manager initialized");
    
    // PRODUCTION: Start Self-Healing background task
    let healing_manager_clone = healing_manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            match healing_manager_clone.heal().await {
                Ok(report) => {
                    tracing::debug!("Self-Healing cycle completed: {:?}", report);
                }
                Err(e) => {
                    tracing::warn!("Self-Healing cycle failed: {}", e);
                }
            }
        }
    });
    info!("✓ Self-Healing background task started");

    // Initialize P2P network
    let network = P2PNetwork::new(config.clone(), consensus.clone()).await?;
    info!("✓ P2P Network initialized on port {}", config.p2p_port);

    // Initialize VM components for RPC
    let bytecode_config = vm::BytecodeProtectionConfig::default();
    let bytecode_protector = std::sync::Arc::new(vm::BytecodeProtector::new(bytecode_config));
    let vm_config = vm::QuantosVmConfig::default();
    let contract_manager = std::sync::Arc::new(vm::ContractManager::new(
        storage.clone(),
        bytecode_protector.clone(),
        vm_config,
    ));

    // Reload persisted contracts from RocksDB into BytecodeProtector
    match contract_manager.reload_contracts() {
        Ok(n) => info!("✓ Reloaded {} contracts from storage", n),
        Err(e) => warn!("Failed to reload contracts: {}", e),
    }

    // Wire ContractManager into StateManager for signed ContractDeploy/ContractCall tx execution
    state_manager.set_contract_manager(contract_manager.clone());
    info!("✓ ContractManager wired into StateManager (signed deploy/call enabled)");

    // Wire EVM engine into StateManager (EVM-compatible execution, no fees; CU-limited)
    let evm_engine = std::sync::Arc::new(vm::evm::EvmEngine::new(storage.clone()));
    state_manager.set_evm_engine(evm_engine);
    info!("✓ EvmEngine wired into StateManager");

    // Initialize RPC server
    let rpc_server = RpcServer::new(
        config.clone(),
        state_manager.clone(),
        consensus.clone(),
        bytecode_protector,
        contract_manager,
    );
    info!("✓ RPC Server starting on port {}", config.rpc_port);

    // Initialize Prometheus metrics
    let metrics = rpc::QuantosMetrics::new();
    let metrics_port = config.metrics_port;
    rpc::metrics::spawn_metrics_updater(
        metrics.clone(),
        consensus.clone(),
        std::time::Instant::now(),
        config.num_shards,
    );
    info!("✓ Prometheus metrics on port {}", metrics_port);

    info!("═══════════════════════════════════════════════════════════════");
    info!("🚀 Quantos node is running!");
    info!("═══════════════════════════════════════════════════════════════");

    // Run all services concurrently
    tokio::select! {
        res = consensus.run() => {
            if let Err(e) = res {
                tracing::error!("Consensus error: {}", e);
            }
        }
        res = network.run() => {
            if let Err(e) = res {
                tracing::error!("Network error: {}", e);
            }
        }
        res = rpc_server.run() => {
            if let Err(e) = res {
                tracing::error!("RPC error: {}", e);
            }
        }
        res = rpc::metrics::serve_metrics(metrics, metrics_port) => {
            if let Err(e) = res {
                tracing::error!("Metrics server error: {}", e);
            }
        }
    }

    Ok(())
}

/// Prints the Quantos startup banner.
fn print_banner() {
    info!("");
    info!("  ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███████╗");
    info!(" ██╔═══██╗██║   ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗██╔════╝");
    info!(" ██║   ██║██║   ██║███████║██╔██╗ ██║   ██║   ██║   ██║███████╗");
    info!(" ██║▄▄ ██║██║   ██║██╔══██║██║╚██╗██║   ██║   ██║   ██║╚════██║");
    info!(" ╚██████╔╝╚██████╔╝██║  ██║██║ ╚████║   ██║   ╚██████╔╝███████║");
    info!("  ╚══▀▀═╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚══════╝");
    info!("");
    info!("  Post-Quantum L1 Blockchain | v{}", env!("CARGO_PKG_VERSION"));
    info!("  https://github.com/quantos-labs/quantos");
    info!("");
    info!("═══════════════════════════════════════════════════════════════");
}

impl NodeConfig {
    fn env_bool(name: &str) -> Option<bool> {
        let raw = std::env::var(name).ok()?;
        match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        }
    }

    /// Creates a new NodeConfig from CLI arguments and genesis config.
    pub fn from_cli(cli: &Cli, genesis: &GenesisConfig) -> Self {
        let network_name = genesis.network.name();
        let stacc_require_activation = Self::env_bool("QUANTOS_STACC_REQUIRE_ACTIVATION")
            .unwrap_or(matches!(genesis.network, NetworkId::Mainnet));
        Self {
            db_path: format!("{}/{}", cli.datadir, network_name),
            p2p_port: cli.p2p_port,
            rpc_port: cli.rpc_port,
            metrics_port: cli.metrics_port,
            num_committees: 1000,
            validators_per_committee: genesis.chain.max_validators_per_committee as usize,
            num_shards: genesis.chain.initial_shards as usize,
            committee_rotation_ms: genesis.chain.block_time_ms / 2,
            checkpoint_interval: genesis.chain.epoch_length,
            max_dag_parents: 8,
            min_dag_parents: 2,
            dynamic_sharding: genesis.chain.dynamic_sharding,
            min_shards: genesis.chain.min_shards as usize,
            max_shards: genesis.chain.max_shards as usize,
            sidechains_enabled: true,
            max_sidechains: 1000,
            l0_config: crate::l0::L0Config {
                enabled: true,
                ..crate::l0::L0Config::default()
            },
            stacc_require_activation,
            privacy_config: Self::privacy_from_env(),
            network_name: network_name.to_string(),
        }
    }

    /// Builds the optional privacy config from environment variables.
    /// Confidential mode is disabled unless `QUANTOS_PRIVACY_ENABLED` is set.
    fn privacy_from_env() -> crate::privacy::PrivacyConfig {
        if Self::env_bool("QUANTOS_PRIVACY_ENABLED").unwrap_or(false) {
            crate::privacy::PrivacyConfig::all_enabled()
        } else {
            crate::privacy::PrivacyConfig::default()
        }
    }
    
    /// Creates a new NodeConfig from environment variables.
    pub fn from_env() -> Self {
        Self {
            db_path: std::env::var("QUANTOS_DB_PATH")
                .unwrap_or_else(|_| "./data/quantos".to_string()),
            p2p_port: std::env::var("QUANTOS_P2P_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30303),
            rpc_port: std::env::var("QUANTOS_RPC_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8545),
            metrics_port: std::env::var("QUANTOS_METRICS_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(9615),
            num_committees: std::env::var("QUANTOS_COMMITTEES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1000),
            validators_per_committee: 21,
            num_shards: std::env::var("QUANTOS_INITIAL_SHARDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(4),
            committee_rotation_ms: 100,
            checkpoint_interval: 32,
            max_dag_parents: 8,
            min_dag_parents: 2,
            dynamic_sharding: true,
            min_shards: 1,
            max_shards: 10_000,
            sidechains_enabled: true,
            max_sidechains: 1000,
            l0_config: crate::l0::L0Config {
                enabled: true,
                ..crate::l0::L0Config::default()
            },
            stacc_require_activation: Self::env_bool("QUANTOS_STACC_REQUIRE_ACTIVATION").unwrap_or(true),
            privacy_config: Self::privacy_from_env(),
            network_name: std::env::var("QUANTOS_NETWORK")
                .unwrap_or_else(|_| "testnet".to_string()),
        }
    }
}

// ============================================================================
// CLI Helper Functions
// ============================================================================

/// Loads genesis configuration based on CLI arguments
fn load_genesis(cli: &Cli) -> Result<GenesisConfig> {
    // If custom genesis file provided, load it
    if let Some(genesis_path) = &cli.genesis {
        info!("Loading genesis from: {}", genesis_path);
        return GenesisConfig::from_file(genesis_path)
            .map_err(|e| anyhow::anyhow!("Failed to load genesis: {}", e));
    }
    
    // Otherwise, use built-in genesis for the network
    let genesis = match cli.network.to_lowercase().as_str() {
        "mainnet" => {
            warn!("Mainnet genesis not yet available, using testnet");
            GenesisConfig::testnet()
                .map_err(|e| anyhow::anyhow!("Failed to create testnet genesis: {}", e))?
        }
        "testnet" => GenesisConfig::testnet()
            .map_err(|e| anyhow::anyhow!("Failed to create testnet genesis: {}", e))?,
        "devnet" | "dev" | "local" => GenesisConfig::devnet()
            .map_err(|e| anyhow::anyhow!("Failed to create devnet genesis: {}", e))?,
        _ => {
            warn!("Unknown network '{}', defaulting to testnet", cli.network);
            GenesisConfig::testnet()
                .map_err(|e| anyhow::anyhow!("Failed to create testnet genesis: {}", e))?
        }
    };
    
    // Validate genesis
    genesis.validate()
        .map_err(|e| anyhow::anyhow!("Invalid genesis: {}", e))?;
    
    Ok(genesis)
}

/// Initializes a new node with genesis configuration
fn init_node(network: &str, output: Option<&str>) -> Result<()> {
    println!("═══════════════════════════════════════════════════════════════");
    println!("  Quantos Node Initialization");
    println!("═══════════════════════════════════════════════════════════════");
    
    let genesis = match network.to_lowercase().as_str() {
        "mainnet" => {
            println!("⚠️  Mainnet not yet available");
            return Ok(());
        }
        "testnet" => {
            println!("📦 Creating testnet genesis...");
            GenesisConfig::testnet()
                .map_err(|e| anyhow::anyhow!("Failed to create testnet genesis: {}", e))?
        }
        "devnet" | "dev" | "local" => {
            println!("📦 Creating devnet genesis...");
            GenesisConfig::devnet()
                .map_err(|e| anyhow::anyhow!("Failed to create devnet genesis: {}", e))?
        }
        _ => {
            println!("❌ Unknown network: {}", network);
            println!("   Available: testnet, devnet");
            return Ok(());
        }
    };
    
    // Validate
    genesis.validate()
        .map_err(|e| anyhow::anyhow!("Genesis validation failed: {}", e))?;
    
    // Save genesis file
    let output_path = output.unwrap_or_else(|| {
        match network.to_lowercase().as_str() {
            "devnet" | "dev" | "local" => "./config/devnet-genesis.json",
            _ => "./config/testnet-genesis.json",
        }
    });
    
    genesis.to_file(output_path)
        .map_err(|e| anyhow::anyhow!("Failed to save genesis: {}", e))?;
    
    println!("");
    println!("✅ Genesis created successfully!");
    println!("");
    println!("   Network:      {}", genesis.network.name());
    println!("   Chain ID:     {}", genesis.chain.chain_id);
    println!("   Validators:   {}", genesis.validators.len());
    println!("   Allocations:  {}", genesis.allocations.len());
    println!("   Total Supply: {} QTS", genesis.total_supply().unwrap_or(0) / 10u128.pow(18));
    println!("   Genesis Hash: 0x{}", hex::encode(&genesis.genesis_hash()[..8]));
    println!("   Output:       {}", output_path);
    println!("");
    println!("To start the node:");
    println!("   quantos --network {} --genesis {}", network, output_path);
    println!("");
    
    Ok(())
}

/// Exports genesis configuration to file
fn export_genesis(output: &str, network: &str) -> Result<()> {
    let genesis = match network.to_lowercase().as_str() {
        "testnet" => GenesisConfig::testnet()
            .map_err(|e| anyhow::anyhow!("Failed to create testnet genesis: {}", e))?,
        "devnet" | "dev" => GenesisConfig::devnet()
            .map_err(|e| anyhow::anyhow!("Failed to create devnet genesis: {}", e))?,
        _ => {
            println!("❌ Unknown network: {}", network);
            return Ok(());
        }
    };
    
    genesis.to_file(output)
        .map_err(|e| anyhow::anyhow!("Failed to export genesis: {}", e))?;
    
    println!("✅ Genesis exported to: {}", output);
    Ok(())
}

/// Generates a full validator key set (Dilithium + VRF + ML-DSA-65).
fn generate_validator_keys(output: &str, name: Option<&str>) -> Result<()> {
    println!("🔑 Generating post-quantum validator key set...");

    let keyset = ValidatorKeySet::generate(name.map(|s| s.to_string()))
        .map_err(|e| anyhow::anyhow!("Failed to generate validator keys: {}", e))?;
    keyset.to_file(output)
        .map_err(|e| anyhow::anyhow!("Failed to save validator keys: {}", e))?;

    println!("");
    println!("✅ Validator key set generated!");
    println!("");
    println!("   Address:    {}", keyset.address);
    println!("   Signing:    {}...", &keyset.signing.public_key[..std::cmp::min(32, keyset.signing.public_key.len())]);
    println!("   VRF:        {}...", &keyset.vrf.public_key[..std::cmp::min(32, keyset.vrf.public_key.len())]);
    println!("   Finality:   {}...", &keyset.finality.public_key[..std::cmp::min(32, keyset.finality.public_key.len())]);
    println!("   Key File:   {}", output);
    println!("");
    println!("⚠️  Keep your key file secure! Never share your secret key.");
    println!("");

    Ok(())
}

/// Creates a genesis file from a list of validator key files.
fn create_genesis_from_keys(
    network: &str,
    output: &str,
    validator_paths: &[String],
    stake_qts: u128,
    commission_bps: u16,
) -> Result<()> {
    if validator_paths.is_empty() {
        anyhow::bail!("At least one validator key file is required");
    }

    let network_id = match network.to_lowercase().as_str() {
        "mainnet" => NetworkId::Mainnet,
        "testnet" => NetworkId::Testnet,
        "devnet" => NetworkId::Devnet,
        _ => NetworkId::Testnet,
    };

    let stake = stake_qts * 10u128.pow(18);
    let mut validators = Vec::new();
    for path in validator_paths {
        let keyset = ValidatorKeySet::from_file(path)
            .map_err(|e| anyhow::anyhow!("Failed to load validator key file {}: {}", path, e))?;
        validators.push(GenesisValidator {
            address: keyset.address_hex,
            public_key: keyset.signing.public_key,
            stake,
            name: keyset.name,
            commission_bps,
        });
    }

    let chain = match network_id {
        NetworkId::Mainnet => crate::genesis::ChainConfig::default(),
        NetworkId::Testnet => crate::genesis::ChainConfig {
            chain_id: 2,
            block_time_ms: 200,
            initial_shards: 4,
            dynamic_sharding: true,
            min_shards: 1,
            max_shards: 10_000,
            min_validator_stake: 10_000 * 10u128.pow(18),
            ..Default::default()
        },
        NetworkId::Devnet => crate::genesis::ChainConfig {
            chain_id: 3,
            block_time_ms: 200,
            initial_shards: 2,
            dynamic_sharding: true,
            min_shards: 1,
            max_shards: 1_000,
            min_validator_stake: 1000 * 10u128.pow(18),
            epoch_length: 16,
            unbonding_period_seconds: 300,
            ..Default::default()
        },
        NetworkId::Custom(id) => crate::genesis::ChainConfig {
            chain_id: id,
            ..Default::default()
        },
    };

    let genesis = GenesisConfig {
        network: network_id,
        genesis_time: chrono::Utc::now().timestamp() as u64,
        chain,
        validators,
        allocations: vec![],
        system_contracts: vec![],
        extra_data: Some(format!("Quantos {} Genesis", network_id.name())),
    };

    genesis.validate()
        .map_err(|e| anyhow::anyhow!("Genesis validation failed: {}", e))?;
    genesis.to_file(output)
        .map_err(|e| anyhow::anyhow!("Failed to write genesis file: {}", e))?;

    println!("");
    println!("✅ Genesis created!");
    println!("");
    println!("   Network:      {}", genesis.network.name());
    println!("   Chain ID:     {}", genesis.chain.chain_id);
    println!("   Validators:   {}", genesis.validators.len());
    println!("   Genesis Hash: 0x{}", hex::encode(&genesis.genesis_hash()[..8]));
    println!("   Output:       {}", output);
    println!("");

    Ok(())
}

/// Shows node information
fn show_info() -> Result<()> {
    println!("");
    println!("  ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███████╗");
    println!(" ██╔═══██╗██║   ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗██╔════╝");
    println!(" ██║   ██║██║   ██║███████║██╔██╗ ██║   ██║   ██║   ██║███████╗");
    println!(" ██║▄▄ ██║██║   ██║██╔══██║██║╚██╗██║   ██║   ██║   ██║╚════██║");
    println!(" ╚██████╔╝╚██████╔╝██║  ██║██║ ╚████║   ██║   ╚██████╔╝███████║");
    println!("  ╚══▀▀═╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚══════╝");
    println!("");
    println!("  Post-Quantum L1 Blockchain");
    println!("  Version: {}", env!("CARGO_PKG_VERSION"));
    println!("");
    println!("═══════════════════════════════════════════════════════════════");
    println!("  Features:");
    println!("  ├─ Post-Quantum Cryptography (Dilithium-3, SPHINCS+, ML-DSA-65)");
    println!("  ├─ DAG-based Consensus");
    println!("  ├─ Dynamic Sharding (up to 10,000 shards)");
    println!("  ├─ ~100M TPS theoretical throughput");
    println!("  ├─ zk-STARK Proofs for cross-shard verification");
    println!("  └─ WASM Smart Contracts");
    println!("");
    println!("  Networks:");
    println!("  ├─ Mainnet  (chain_id: 1) - Coming soon");
    println!("  ├─ Testnet  (chain_id: 2) - Available");
    println!("  └─ Devnet   (chain_id: 3) - Local development");
    println!("");
    println!("  Commands:");
    println!("  ├─ quantos init --network testnet    Initialize node");
    println!("  ├─ quantos run --network testnet     Start node");
    println!("  ├─ quantos generate-key -o key.json  Generate validator key");
    println!("  └─ quantos info                      Show this info");
    println!("");
    
    Ok(())
}
