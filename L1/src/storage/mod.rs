mod rocks;
mod keys;

pub use rocks::*;
pub use keys::*;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Corruption detected: {0}")]
    Corruption(String),
    #[error("Storage exhaustion: {0}")]
    StorageExhaustion(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Prefix collision: {0}")]
    PrefixCollision(String),
}

pub type StorageResult<T> = Result<T, StorageError>;
