//! Error types for the L0 finality hub.

use thiserror::Error;

use crate::l0::registry::{RegistryError, TargetChainId};

/// Convenient result alias.
pub type L0Result<T> = Result<T, L0Error>;

/// All errors emitted by the L0 finality hub and its sub-systems.
#[derive(Debug, Error)]
pub enum L0Error {
    /// The provided checkpoint cannot be turned into a proof because it
    /// is not finalized yet or carries invalid metadata.
    #[error("checkpoint not eligible for L0 proof: {0}")]
    InvalidCheckpoint(String),

    /// Not enough validator signatures were available to reach the
    /// configured stake threshold.
    #[error("insufficient stake: signed {signed} of {required}")]
    InsufficientStake {
        /// Stake actually aggregated.
        signed: u128,
        /// Stake required for finality.
        required: u128,
    },

    /// A PQC signature attached to the proof failed verification.
    #[error("post-quantum signature verification failed for validator {0}")]
    SignatureFailed(String),

    /// The validator set snapshot referenced by the proof is unknown.
    #[error("unknown validator set snapshot: {0}")]
    UnknownValidatorSet(String),

    /// Wire-level decoding of a structure failed.
    #[error("invalid wire encoding: {0}")]
    Encoding(String),

    /// The proof version is not supported by the verifier.
    #[error("unsupported proof version: {0}")]
    UnsupportedVersion(u16),

    /// The proof was already submitted to the target chain and cannot
    /// be replayed.
    #[error("proof already relayed to chain {0:?}")]
    AlreadyRelayed(TargetChainId),

    /// Configuration sanity check failed.
    #[error("invalid L0 configuration: {0}")]
    Config(String),

    /// No adapter is registered for the requested target chain.
    #[error("no adapter registered for chain {0:?}")]
    AdapterMissing(TargetChainId),

    /// The relay transport reported a recoverable failure.
    #[error("relay transport error: {0}")]
    Transport(String),

    /// The relay transport reported a permanent failure.
    #[error("permanent relay failure: {0}")]
    PermanentRelay(String),
}

impl From<RegistryError> for L0Error {
    fn from(value: RegistryError) -> Self {
        match value {
            RegistryError::Missing(id) => L0Error::AdapterMissing(id),
            RegistryError::Duplicate(id) => L0Error::Config(format!("duplicate adapter for {id:?}")),
        }
    }
}
