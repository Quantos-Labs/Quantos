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
//!    is post-quantum (Falcon-512 or Dilithium-3). No ECDSA, no BLS.
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

pub mod config;
pub mod encoding;
pub mod error;
pub mod hub;
pub mod proof;
pub mod registry;
pub mod relay;
pub mod verifier;

pub use config::{L0Config, RelayBackoff, TargetChainConfig};
pub use encoding::{CanonicalEncoder, EncodedProof, EncodingFormat};
pub use error::{L0Error, L0Result};
pub use hub::{FinalityHub, HubMetrics, ValidatorSetSnapshot};
pub use proof::{
    L0FinalityProof, L0ProofHeader, L0_PROOF_VERSION, ProofSignature, ValidatorRecord,
};
pub use registry::{ChainAdapter, ChainFamily, ChainRegistry, TargetChainId};
pub use relay::{RelayDispatcher, RelayJob, RelayOutcome, RelayStatus};
pub use verifier::{ExternalVerifier, VerificationReport};
