//! External chain checkpoint types and verification logic.
//!
//! This module enables Quantos L0 to act as a post-quantum finality layer
//! for external chains (Ethereum, Solana, NEAR, Aptos, Sui, TON, Bitcoin,
//! Stellar, Polkadot, Tron, etc.) by accepting their checkpoints and
//! producing PQC-signed finality proofs.

use serde::{Deserialize, Serialize};

use crate::l0::registry::ChainFamily;
use crate::types::Hash;

/// Identifier for external chains that can submit checkpoints to Quantos L0.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum ChainId {
    // EVM chains
    Ethereum,
    EthereumSepolia,
    Base,
    BaseSepolia,
    Arbitrum,
    ArbitrumSepolia,
    Optimism,
    OptimismSepolia,
    Polygon,
    PolygonAmoy,
    Avalanche,
    AvalancheFuji,
    BinanceSmartChain,
    BscTestnet,
    Moonbeam,
    Berachain,
    Hyperliquid,
    Monad,
    Somnia,
    
    // Non-EVM chains
    Solana,
    SolanaDevnet,
    Near,
    NearTestnet,
    Aptos,
    AptosTestnet,
    Sui,
    SuiTestnet,
    Ton,
    TonTestnet,
    Bitcoin,
    BitcoinTestnet,
    Stellar,
    StellarTestnet,
    Polkadot,
    PolkadotTestnet,
    Tron,
    TronShasta,
    Cosmos,
    CosmosTestnet,
    Cardano,
    CardanoTestnet,
    Tezos,
    TezosTestnet,
    
    /// Custom chain (for future extensibility)
    Custom(String),
}

impl ChainId {
    /// Returns a canonical string identifier for this chain.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Ethereum => "ethereum",
            Self::EthereumSepolia => "ethereum-sepolia",
            Self::Base => "base",
            Self::BaseSepolia => "base-sepolia",
            Self::Arbitrum => "arbitrum",
            Self::ArbitrumSepolia => "arbitrum-sepolia",
            Self::Optimism => "optimism",
            Self::OptimismSepolia => "optimism-sepolia",
            Self::Polygon => "polygon",
            Self::PolygonAmoy => "polygon-amoy",
            Self::Avalanche => "avalanche",
            Self::AvalancheFuji => "avalanche-fuji",
            Self::BinanceSmartChain => "bsc",
            Self::BscTestnet => "bsc-testnet",
            Self::Moonbeam => "moonbeam",
            Self::Berachain => "berachain",
            Self::Hyperliquid => "hyperliquid",
            Self::Monad => "monad",
            Self::Somnia => "somnia",
            Self::Solana => "solana",
            Self::SolanaDevnet => "solana-devnet",
            Self::Near => "near",
            Self::NearTestnet => "near-testnet",
            Self::Aptos => "aptos",
            Self::AptosTestnet => "aptos-testnet",
            Self::Sui => "sui",
            Self::SuiTestnet => "sui-testnet",
            Self::Ton => "ton",
            Self::TonTestnet => "ton-testnet",
            Self::Bitcoin => "bitcoin",
            Self::BitcoinTestnet => "bitcoin-testnet",
            Self::Stellar => "stellar",
            Self::StellarTestnet => "stellar-testnet",
            Self::Polkadot => "polkadot",
            Self::PolkadotTestnet => "polkadot-testnet",
            Self::Tron => "tron",
            Self::TronShasta => "tron-shasta",
            Self::Cosmos => "cosmos",
            Self::CosmosTestnet => "cosmos-testnet",
            Self::Cardano => "cardano",
            Self::CardanoTestnet => "cardano-testnet",
            Self::Tezos => "tezos",
            Self::TezosTestnet => "tezos-testnet",
            Self::Custom(s) => s,
        }
    }

    /// Returns the chain family (EVM, Solana, Move, etc.) for encoding purposes.
    pub fn family(&self) -> ChainFamily {
        match self {
            Self::Ethereum | Self::EthereumSepolia
            | Self::Base | Self::BaseSepolia
            | Self::Arbitrum | Self::ArbitrumSepolia
            | Self::Optimism | Self::OptimismSepolia
            | Self::Polygon | Self::PolygonAmoy
            | Self::Avalanche | Self::AvalancheFuji
            | Self::BinanceSmartChain | Self::BscTestnet
            | Self::Moonbeam | Self::Berachain | Self::Hyperliquid
            | Self::Monad | Self::Somnia => ChainFamily::Evm,
            
            Self::Solana | Self::SolanaDevnet => ChainFamily::Svm,
            
            Self::Aptos | Self::AptosTestnet
            | Self::Sui | Self::SuiTestnet => ChainFamily::Move,
            
            Self::Near | Self::NearTestnet => ChainFamily::Near,
            
            Self::Ton | Self::TonTestnet => ChainFamily::Ton,
            
            Self::Bitcoin | Self::BitcoinTestnet => ChainFamily::Bitcoin,
            
            Self::Stellar | Self::StellarTestnet => ChainFamily::Stellar,
            
            Self::Polkadot | Self::PolkadotTestnet => ChainFamily::Substrate,
            
            Self::Tron | Self::TronShasta => ChainFamily::Tvm,
            
            Self::Cosmos | Self::CosmosTestnet => ChainFamily::Cosmos,
            
            Self::Cardano | Self::CardanoTestnet => ChainFamily::Cardano,
            
            Self::Tezos | Self::TezosTestnet => ChainFamily::Custom, // Tezos uses Michelson VM
            
            Self::Custom(_) => ChainFamily::Custom,
        }
    }
}

/// External chain checkpoint submitted to Quantos L0 for PQC finalization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalCheckpoint {
    /// Chain that produced this checkpoint.
    pub chain_id: ChainId,
    
    /// Block number or height.
    pub block_number: u64,
    
    /// Block hash (32 bytes).
    pub block_hash: Hash,
    
    /// State root or equivalent commitment (32 bytes).
    pub state_root: Hash,
    
    /// Timestamp (milliseconds since epoch).
    pub timestamp_ms: u64,
    
    /// Native finality proof from the source chain.
    /// Format depends on the chain:
    /// - EVM: RLP-encoded block header + finality signatures
    /// - Solana: Vote account signatures
    /// - NEAR: Block approval signatures
    /// - Aptos/Sui: Validator signatures
    /// - Bitcoin: Proof of work (block headers)
    /// - etc.
    pub native_finality_proof: Vec<u8>,
    
    /// Optional metadata (JSON-encoded).
    pub metadata: Option<String>,
}

impl ExternalCheckpoint {
    /// Returns a canonical digest for this checkpoint that Quantos validators
    /// will verify before signing.
    pub fn digest(&self) -> Hash {
        use sha3::{Digest, Sha3_256};
        
        let mut hasher = Sha3_256::new();
        hasher.update(self.chain_id.as_str().as_bytes());
        hasher.update(self.block_number.to_be_bytes());
        hasher.update(self.block_hash);
        hasher.update(self.state_root);
        hasher.update(self.timestamp_ms.to_be_bytes());
        
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }
}

/// Verification strategy for external checkpoints.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum VerificationStrategy {
    /// Trust the submitter (for testing only).
    TrustSubmitter,
    
    /// Verify using an embedded light client.
    LightClient,
    
    /// Verify via oracle consensus (majority vote of Quantos validators).
    OracleConsensus { threshold_bps: u16 },
    
    /// Verify using a specific verification contract on Quantos.
    VerificationContract { contract_address: [u8; 32] },
}

/// Result of verifying an external checkpoint.
#[derive(Clone, Debug)]
pub struct VerificationResult {
    /// Whether the checkpoint is valid.
    pub valid: bool,
    
    /// Reason for rejection (if invalid).
    pub reason: Option<String>,
    
    /// Confidence score (0-10000 basis points).
    pub confidence_bps: u16,
}

impl VerificationResult {
    pub fn valid() -> Self {
        Self {
            valid: true,
            reason: None,
            confidence_bps: 10000,
        }
    }
    
    pub fn invalid(reason: impl Into<String>) -> Self {
        Self {
            valid: false,
            reason: Some(reason.into()),
            confidence_bps: 0,
        }
    }
    
    pub fn partial(confidence_bps: u16) -> Self {
        Self {
            valid: confidence_bps >= 6667, // 2/3 threshold
            reason: None,
            confidence_bps,
        }
    }
}
