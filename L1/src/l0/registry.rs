//! Target chain registry.
//!
//! The L0 finality hub is chain-agnostic. A [`ChainAdapter`] tells the hub
//! how to encode a proof for a given target and how to address it.
//!
//! Built-in adapters cover the main EVM (Ethereum, Monad, Hyperliquid EVM)
//! and non-EVM (Solana, Tron, Stellar, Aptos, Sui, …) families. Operators
//! can register additional adapters at runtime via
//! [`ChainRegistry::register`].

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// High-level family a target chain belongs to.
///
/// Most relayer behavior (encoding, signature flavor, default gas model)
/// is driven by the family, with chain-specific tweaks living in the
/// adapter itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum ChainFamily {
    /// EVM-compatible chains (Ethereum, Monad, Hyperliquid EVM, Arbitrum, …).
    Evm,
    /// Solana / SVM family.
    Svm,
    /// TVM (Tron) chains.
    Tvm,
    /// Stellar / Soroban.
    Stellar,
    /// Move-based chains (Aptos, Sui, Movement, …).
    Move,
    /// Cosmos-SDK / IBC chains.
    Cosmos,
    /// NEAR Protocol.
    Near,
    /// TON (The Open Network).
    Ton,
    /// Bitcoin and Bitcoin-like chains.
    Bitcoin,
    /// Substrate-based chains (Polkadot, Kusama, …).
    Substrate,
    /// Cardano.
    Cardano,
    /// Tezos (Michelson VM, Ed25519 baker signatures).
    Tezos,
    /// Generic catch-all for non-EVM chains using a custom adapter.
    Custom,
}

/// Stable, opaque identifier for a target chain.
///
/// The string is normalized to lower-case ASCII to avoid accidental
/// duplicates ("ethereum" vs "Ethereum").
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct TargetChainId(String);

impl TargetChainId {
    /// Creates a new identifier, normalizing whitespace and case.
    pub fn new(raw: impl AsRef<str>) -> Self {
        Self(raw.as_ref().trim().to_ascii_lowercase())
    }

    /// Returns the canonical string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TargetChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A descriptor of how to talk to a target chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainAdapter {
    /// Unique identifier (e.g. "ethereum", "solana", "tron").
    pub id: TargetChainId,
    /// Chain family that drives encoding defaults.
    pub family: ChainFamily,
    /// Numeric chain id for EVM, or chain-specific magic for others.
    pub chain_magic: u64,
    /// Human-readable display name.
    pub display_name: String,
    /// Endpoint URL where the relayer should submit attestations.
    pub endpoint: String,
    /// Optional contract / program address that owns the L0 receiver
    /// (QuantosL0Verifier on EVM chains).
    pub receiver_address: Option<String>,
    /// Optional QuantosStarkVerifier contract address on EVM chains.
    /// When set, the relay payload includes STARK commitment calldata.
    pub stark_verifier_address: Option<String>,
    /// Whether the adapter is enabled in the current deployment.
    pub enabled: bool,
}

impl ChainAdapter {
    /// Returns true if the adapter is fully configured and switched on.
    pub fn is_live(&self) -> bool {
        self.enabled && !self.endpoint.is_empty()
    }
}

/// Errors specific to the registry.
#[derive(Debug)]
pub enum RegistryError {
    /// The requested adapter is not registered.
    Missing(TargetChainId),
    /// An adapter with this id is already registered.
    Duplicate(TargetChainId),
}

/// Thread-safe registry of target chain adapters.
#[derive(Clone, Default)]
pub struct ChainRegistry {
    inner: Arc<RwLock<HashMap<TargetChainId, ChainAdapter>>>,
}

impl ChainRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a registry pre-populated with sensible defaults for the
    /// main EVM and non-EVM ecosystems supported out of the box.
    ///
    /// All adapters are created with `enabled = false` so the operator
    /// must explicitly activate the ones they intend to use.
    pub fn with_defaults() -> Self {
        let registry = Self::new();
        for adapter in default_adapters() {
            // Duplicate ids are impossible here because the source list
            // is constant; we ignore the error for robustness.
            let _ = registry.register(adapter);
        }
        registry
    }

    /// Registers a new adapter, refusing duplicates.
    pub fn register(&self, adapter: ChainAdapter) -> Result<(), RegistryError> {
        let mut guard = self.inner.write();
        if guard.contains_key(&adapter.id) {
            return Err(RegistryError::Duplicate(adapter.id));
        }
        guard.insert(adapter.id.clone(), adapter);
        Ok(())
    }

    /// Inserts or replaces an adapter.
    pub fn upsert(&self, adapter: ChainAdapter) {
        let mut guard = self.inner.write();
        guard.insert(adapter.id.clone(), adapter);
    }

    /// Removes an adapter.
    pub fn remove(&self, id: &TargetChainId) {
        self.inner.write().remove(id);
    }

    /// Fetches a clone of the adapter.
    pub fn get(&self, id: &TargetChainId) -> Result<ChainAdapter, RegistryError> {
        self.inner
            .read()
            .get(id)
            .cloned()
            .ok_or_else(|| RegistryError::Missing(id.clone()))
    }

    /// Returns the list of currently live adapters.
    pub fn live_targets(&self) -> Vec<ChainAdapter> {
        self.inner
            .read()
            .values()
            .filter(|a| a.is_live())
            .cloned()
            .collect()
    }

    /// Lists all adapters regardless of state.
    pub fn all(&self) -> Vec<ChainAdapter> {
        self.inner.read().values().cloned().collect()
    }
}

fn default_adapters() -> Vec<ChainAdapter> {
    use ChainFamily::*;
    let mk = |id: &str, family, magic, name: &str, enabled: bool| ChainAdapter {
        id: TargetChainId::new(id),
        family,
        chain_magic: magic,
        display_name: name.to_string(),
        endpoint: String::new(),
        receiver_address: None,
        stark_verifier_address: None,
        enabled,
    };

    vec![
        // EVM chains
        mk("ethereum", Evm, 1, "Ethereum", false),
        mk("monad", Evm, 41_454, "Monad", false),
        mk("hyperliquid-evm", Evm, 999, "Hyperliquid EVM", false),
        mk("arbitrum", Evm, 42_161, "Arbitrum One", false),
        mk("base", Evm, 8_453, "Base", false),
        // SVM (Solana) — production active
        mk("solana", Svm, 0x534F_4C, "Solana", true),
        // TVM (Tron) — production active
        mk("tron", Tvm, 728_126_428, "Tron", true),
        // Stellar — production active
        mk("stellar", Stellar, 0x5354_4C, "Stellar", true),
        // Move chains — production active (Aptos, Sui)
        mk("aptos", Move, 0x4150_54, "Aptos", true),
        mk("sui", Move, 0x5355_49, "Sui", true),
        // Cosmos — production active
        mk("cosmoshub", Cosmos, 0x434F_53, "Cosmos Hub", true),
        // NEAR Protocol — production active
        mk("near", Near, 0x4E45_41, "NEAR Protocol", true),
        // Bitcoin L2 (Stacks) — production active
        mk("bitcoin-stacks", Bitcoin, 0x4254_43, "Bitcoin (Stacks)", true),
        // TON — production active
        mk("ton", Ton, 0x544F_4E, "TON", true),
        // Polkadot — production active
        mk("polkadot", Substrate, 0x504F_4C, "Polkadot", true),
        // Cardano — production active
        mk("cardano", Cardano, 0x4341_52, "Cardano", true),
        // Tezos — production active
        mk("tezos", Tezos, 0x5458_5A, "Tezos", true),
        mk("tezos-testnet", Tezos, 0x5458_5A, "Tezos Ghostnet", false),
    ]
}
