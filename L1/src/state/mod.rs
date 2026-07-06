mod manager;
mod executor;
pub mod compression;
mod stm;
pub mod archival_pruning;
pub mod state_rent;
pub mod flat_storage;
pub mod snapshot_sync;

pub use manager::*;
pub use executor::*;
pub use compression::*;
pub use stm::*;
pub use archival_pruning::*;
pub use state_rent::*;
pub use flat_storage::*;
pub use snapshot_sync::*;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum StateError {
    #[error("Account not found: {0}")]
    AccountNotFound(String),
    #[error("Insufficient balance")]
    InsufficientBalance,
    #[error("Invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u64, got: u64 },
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Execution error: {0}")]
    ExecutionError(String),
    #[error("Unauthorized access")]
    Unauthorized,
    #[error("Invalid amount")]
    InvalidAmount,
    #[error("Arithmetic overflow")]
    ArithmeticOverflow,
}

pub type StateResult<T> = Result<T, StateError>;
