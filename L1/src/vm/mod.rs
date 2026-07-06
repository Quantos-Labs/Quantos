//! # Quantos Virtual Machine
//!
//! WASM-based execution environment with bytecode protection.
//!
//! ## Bytecode Invisible Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  Smart Contract bytecode is NEVER publicly accessible       │
//! ├─────────────────────────────────────────────────────────────┤
//! │  PUBLIC:                                                     │
//! │    • Contract hash (32 bytes)                               │
//! │    • Metadata (size, deployer, timestamp)                   │
//! │    • ABI/Interface definitions                              │
//! ├─────────────────────────────────────────────────────────────┤
//! │  PRIVATE (encrypted at rest):                               │
//! │    • WASM bytecode (AES-256-GCM encrypted)                  │
//! │    • Source maps (if provided)                              │
//! │    • Debug symbols (if provided)                            │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## QuantosVM Runtime
//!
//! - **Wasmer Engine**: Production WASM execution
//! - **Sandbox Isolation**: Memory limits, CU tracking
//! - **Host Functions**: qnt_storage_*, qnt_block_*, qnt_crypto_*
//! - **Zero Gas Fees**: CU limits for resource management only

pub mod bytecode_protection;
pub mod runtime;
pub mod evm;
pub mod contract;
pub mod abi;
pub mod erc_compat;
pub mod speculative_execution;
pub mod jit_compiler;
pub mod mvcc;
pub mod tx_dependency_graph;
pub mod precompiles;
pub mod solang_compat;

pub use bytecode_protection::*;
pub use runtime::*;
pub use contract::*;
pub use abi::*;
pub use erc_compat::*;
pub use speculative_execution::*;
pub use jit_compiler::*;
pub use mvcc::*;
pub use tx_dependency_graph::*;
pub use precompiles::*;

use thiserror::Error;

/// VM errors.
#[derive(Debug, Error)]
pub enum VmError {
    #[error("Contract not found: {0}")]
    ContractNotFound(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("Integrity check failed")]
    IntegrityCheckFailed,
    
    #[error("Execution failed: {0}")]
    ExecutionFailed(String),
    
    #[error("Out of gas")]
    OutOfGas,
    
    #[error("Invalid bytecode")]
    InvalidBytecode,
    
    #[error("Access denied")]
    AccessDenied,
    
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Invalid ABI: {0}")]
    InvalidAbi(String),
    
    #[error("Function not found: {0}")]
    FunctionNotFound(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
    
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
}

pub type VmResult<T> = Result<T, VmError>;
