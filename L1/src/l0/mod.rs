//! # Quantos L0 — Post-Quantum Finality Hub
//!
//! Quantos doubles as a **Layer 0 PQC finality hub** that produces compact,
//! cryptographically self-contained finality proofs that any external chain
//! (EVM or non-EVM: Ethereum, Solana, Tron, Monad, Hyperliquid, Stellar, …)
//! can verify and consume as a source of post-quantum security.
//!
//! ## Design tenets
//!
//! 1. **Non-intrusive**: the L1 DAG path keeps working unchanged. The L0
//!    pipeline runs as an optional, opt-in side stage gated by
//!    [`L0Config::enabled`].
//! 2. **PQC-only**: every signature carried in an [`proof::L0FinalityProof`]
//!    is post-quantum (ML-DSA-65 or ML-DSA-65). No ECDSA, no BLS.
//! 3. **Chain-agnostic**: a single proof can be re-encoded for any target
//!    via the [`encoding`] layer and an entry in the [`registry`].
//! 4. **Self-contained**: verification only depends on the validator set
//!    snapshot referenced by the proof; no external lookups are required.
//! 5. **Forward-compatible**: every wire structure is versioned through
//!    [`proof::L0_PROOF_VERSION`].
//!
//! ## High-level pipeline
//!
//! ```text
//!   ┌────────────────────┐    ┌──────────────────┐    ┌────────────────┐
//!   │  Quantos L1 DAG    │──▶│  FinalityLayer    │──▶│   L0 Hub       │
//!   │  (existing path)   │    │  (existing path)  │    │  (this crate)  │
//!   └────────────────────┘    └──────────────────┘    └────────┬───────┘
//!                                                              │
//!                                                              ▼
//!                                                ┌─────────────────────────┐
//!                                                │   L0FinalityProof       │
//!                                                │   + per-chain encoding  │
//!                                                └────────────┬────────────┘
//!                                                             │
//!                                                             ▼
//!                                            ┌────────────────────────────┐
//!                                            │   Relay / on-chain client  │
//!                                            │   (EVM, Solana, Tron, …)   │
//!                                            └────────────────────────────┘
//! ```
//!
//! ## Public entry points
//!
//! - [`hub::FinalityHub`] — builds proofs from finalized checkpoints.
//! - [`verifier::ExternalVerifier`] — stateless verifier usable off-chain
//!   or behind a smart-contract / program on any target chain.
//! - [`relay::RelayDispatcher`] — async dispatcher that ships encoded
//!   proofs to registered targets with retries and backoff.
//!
//! All entry points are safe to use across threads.

#![allow(clippy::module_name_repetitions)]

pub mod checkpoint_pool;
pub mod epoch_watcher;
pub mod config;
pub mod encoding;
pub mod error;
pub mod external;
pub mod gossip;
pub mod hub;
pub mod light_client;
pub mod proof;
pub mod registry;
pub mod relay;
pub mod stark_prover;
pub mod subnet;
pub mod verifier;

pub use checkpoint_pool::{CheckpointPool, CheckpointPoolStats, PendingCheckpoint};
pub use config::{L0Config, RelayBackoff, TargetChainConfig};
pub use encoding::{CanonicalEncoder, EncodedProof, EncodingFormat};
pub use error::{L0Error, L0Result};
pub use external::{ChainId, ExternalCheckpoint, VerificationResult, VerificationStrategy};
pub use gossip::{CheckpointGossip, CheckpointGossipMessage};
pub use hub::{FinalityHub, HubMetrics, ValidatorSetSnapshot};
pub use light_client::{
    BitcoinLightClient, CantonLightClient, CardanoLightClient, CosmosLightClient, EVMLightClient,
    GenericLightClient, HederaLightClient, IcpLightClient, AlgorandLightClient,
    LightClient, LightClientRegistry, MoveLightClient,
    NearLightClient, PolkadotLightClient, RippleLightClient, SolanaLightClient,
    StellarLightClient, TezosLightClient, TonLightClient, TronLightClient,
};
pub use proof::{
    L0FinalityProof, L0ProofHeader, L0_PROOF_VERSION, ProofSignature, ValidatorRecord,
};
pub use stark_prover::{BatchPublicInputs, SignerInput, StarkBatchProof, prove_batch, verify_batch};
pub use epoch_watcher::{ChainWatcherConfig, EpochWatcher};
pub use registry::{ChainAdapter, ChainFamily, ChainRegistry, TargetChainId};
pub use relay::{HttpRelayTransport, RelayDispatcher, RelayJob, RelayOutcome, RelayStatus};
pub use subnet::{SubnetConfig, SubnetId, SubnetManager, SubnetValidator};
pub use verifier::{ExternalVerifier, VerificationReport};
