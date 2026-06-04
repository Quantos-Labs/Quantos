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
            
            Self::Tezos | Self::TezosTestnet => ChainFamily::Tezos,
            
            Self::Custom(_) => ChainFamily::Custom,
        }
    }
}

/// Cryptographic proof submitted by the relayer for a specific chain family.
/// The relayer MUST fetch and include this proof; the L0 light client verifies
/// it cryptographically without any RPC call to the source chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ChainProof {
    /// EVM proof: RLP-encoded block header. The header contains block_hash,
    /// state_root, and consensus signatures (post-Merge: sync committee).
    Evm {
        /// Full RLP-encoded block header.
        block_header_rlp: Vec<u8>,
        /// Optional: sync committee aggregate signature (post-Merge Ethereum).
        sync_committee_signature: Option<Vec<u8>>,
        /// Optional: execution payload block hash for dual verification.
        execution_payload_hash: Option<Hash>,
    },
    /// Bitcoin proof: block header (80 bytes) + confirmation depth + optional SPV tx proof.
    Bitcoin {
        /// Bitcoin block header (80 bytes), stored as Vec<u8> for serde compat.
        block_header: Vec<u8>,
        /// Number of confirming blocks on top (depth).
        confirmations: u32,
        /// Optional: Merkle sibling hashes from leaf to root (SPV inclusion proof).
        tx_merkle_proof: Option<Vec<[u8; 32]>>,
        /// Block height at which this header was mined.
        block_height: u64,
        /// Optional: transaction hash to prove inclusion for (txid, little-endian).
        tx_hash: Option<[u8; 32]>,
        /// Optional: 0-based position of the tx in the block (used for left/right proof direction).
        tx_index: Option<u32>,
    },
    /// Solana proof: ledger entry with vote account signatures.
    Solana {
        /// Ledger entry binary data.
        ledger_entry: Vec<u8>,
        /// Vote account signatures confirming this slot.
        vote_signatures: Vec<Vec<u8>>,
        /// Bank hash for this slot.
        bank_hash: Hash,
    },
    /// Move-family proof (Aptos/Sui): LedgerInfo with multi-sig from validators.
    Move {
        /// LedgerInfo protobuf/struct bytes.
        ledger_info: Vec<u8>,
        /// Aggregated BLS validator signatures (or individual ED25519 sigs).
        validator_signatures: Vec<Vec<u8>>,
        /// Validator public keys used for signing.
        validator_pubkeys: Vec<Vec<u8>>,
    },
    /// NEAR proof: block header + approval signatures from block producers.
    Near {
        /// NEAR block header bytes.
        block_header: Vec<u8>,
        /// Approval signatures from next block producers.
        approval_signatures: Vec<Vec<u8>>,
        /// Block producer public keys.
        producer_pubkeys: Vec<Vec<u8>>,
    },
    /// Cosmos proof: Tendermint block header + commit precommits.
    Cosmos {
        /// Tendermint block header bytes.
        block_header: Vec<u8>,
        /// Precommit signatures from validators.
        commit_signatures: Vec<Vec<u8>>,
        /// Validator set public keys (ed25519).
        validator_pubkeys: Vec<Vec<u8>>,
        /// Signed voting power fraction (basis points).
        signed_power_bps: u16,
    },
    /// Cardano proof: block header + VRF proof + stake pool signatures.
    Cardano {
        /// Cardano block header CBOR bytes.
        block_header: Vec<u8>,
        /// VRF proof for slot leadership.
        vrf_proof: Vec<u8>,
        /// Stake pool operator signatures.
        pool_signatures: Vec<Vec<u8>>,
    },
    /// TON proof: block header + validator Ed25519 signatures.
    Ton {
        /// TON block header or shard state bytes.
        block_header: Vec<u8>,
        /// Validator Ed25519 signatures.
        validator_signatures: Vec<Vec<u8>>,
        /// Validator public keys (Ed25519, 32 bytes each).
        validator_pubkeys: Vec<Vec<u8>>,
    },
    /// Tron proof: block header + producer ECDSA signatures.
    Tron {
        /// Tron block header bytes.
        block_header: Vec<u8>,
        /// Block producer ECDSA (secp256k1) signatures.
        producer_signatures: Vec<Vec<u8>>,
        /// Block producer public keys.
        producer_pubkeys: Vec<Vec<u8>>,
    },
    /// Polkadot proof: GRANDPA vote + validator Ed25519 signatures.
    Polkadot {
        /// GRANDPA vote or justification bytes.
        grandpa_vote: Vec<u8>,
        /// Validator Ed25519 signatures.
        validator_signatures: Vec<Vec<u8>>,
        /// Validator public keys (Ed25519, 32 bytes each).
        validator_pubkeys: Vec<Vec<u8>>,
    },
    /// Stellar proof: SCP statement + node Ed25519 signatures.
    Stellar {
        /// SCP statement or ballot bytes.
        scp_statement: Vec<u8>,
        /// Node Ed25519 signatures.
        node_signatures: Vec<Vec<u8>>,
        /// Node public keys (Ed25519, 32 bytes each).
        node_pubkeys: Vec<Vec<u8>>,
    },
    /// Tezos proof: endorsement + baker Ed25519 signatures.
    Tezos {
        /// Tezos endorsement or block header bytes.
        endorsement: Vec<u8>,
        /// Baker Ed25519 signatures.
        baker_signatures: Vec<Vec<u8>>,
        /// Baker public keys (Ed25519, 32 bytes each).
        baker_pubkeys: Vec<Vec<u8>>,
    },
    /// Generic proof for custom/future chain families.
    Generic {
        /// Raw proof bytes.
        proof_bytes: Vec<u8>,
        /// Signer public keys.
        signer_pubkeys: Vec<Vec<u8>>,
        /// Signatures over proof_bytes.
        signatures: Vec<Vec<u8>>,
    },
}

impl ChainProof {
    /// Returns the chain family this proof is intended for.
    pub fn family(&self) -> ChainFamily {
        match self {
            Self::Evm { .. } => ChainFamily::Evm,
            Self::Bitcoin { .. } => ChainFamily::Bitcoin,
            Self::Solana { .. } => ChainFamily::Svm,
            Self::Move { .. } => ChainFamily::Move,
            Self::Near { .. } => ChainFamily::Near,
            Self::Cosmos { .. } => ChainFamily::Cosmos,
            Self::Cardano { .. } => ChainFamily::Cardano,
            Self::Ton { .. } => ChainFamily::Ton,
            Self::Tron { .. } => ChainFamily::Tvm,
            Self::Polkadot { .. } => ChainFamily::Substrate,
            Self::Stellar { .. } => ChainFamily::Stellar,
            Self::Tezos { .. } => ChainFamily::Tezos,
            Self::Generic { .. } => ChainFamily::Custom,
        }
    }

    /// Serializes the proof to canonical bytes for hashing.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Use a deterministic encoding (bincode or similar would be better;
        // for now, use JSON for simplicity since sha3_256 is used below).
        serde_json::to_vec(self).unwrap_or_default()
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
    /// Parent block hash — enforces canonical chain continuity.
    pub parent_block_hash: Hash,
    /// Chain work (PoW) or justification weight (PoS) — fork-choice tiebreaker.
    pub chain_work: u128,
    /// Timestamp (milliseconds since epoch).
    pub timestamp_ms: u64,
    /// Cryptographic proof from the source chain, verified without RPC.
    pub proof: ChainProof,
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
        hasher.update(self.parent_block_hash);
        hasher.update(self.chain_work.to_be_bytes());
        hasher.update(self.timestamp_ms.to_be_bytes());
        hasher.update(&self.proof.to_bytes());

        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }
}

/// Verification strategy for external checkpoints.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum VerificationStrategy {
    /// Verify using an embedded light client (cryptographic proof required).
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
