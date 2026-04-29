//! # Quantos Token Standards
//!
//! Resource-based token standards for Quantos blockchain.
//!
//! ## Standards
//!
//! - **QN4**: Fungible tokens (ERC20 equivalent)
//! - **QN8**: Non-fungible tokens (ERC721 equivalent)
//! - **QN12**: Multi-token standard (ERC1155 equivalent)

pub mod qn4;
pub mod qn8;
pub mod qn12;

pub use qn4::*;
pub use qn8::*;
pub use qn12::*;

use crate::types::Address;

/// Standard error type for token operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    InsufficientBalance,
    InsufficientAllowance,
    Unauthorized,
    InvalidAddress,
    TokenNotFound,
    TokenAlreadyExists,
    Overflow,
    Underflow,
    InvalidAmount,
    NotOwner,
    NotApproved,
    ArrayLengthMismatch,
    ApprovalRaceCondition,
    BatchSizeTooLarge,
    MaxSupplyExceeded,
    ReentrancyDetected,
    MaxTokensPerOwnerReached,
    DuplicateTokenId,
}

/// Event emitted by token contracts.
#[derive(Debug, Clone)]
pub enum TokenEvent {
    // QN4 Events
    Transfer {
        from: Address,
        to: Address,
        value: u64,
    },
    Approval {
        owner: Address,
        spender: Address,
        value: u64,
    },
    
    // QN8 Events
    TransferNFT {
        from: Address,
        to: Address,
        token_id: u64,
    },
    ApprovalNFT {
        owner: Address,
        approved: Address,
        token_id: u64,
    },
    ApprovalForAll {
        owner: Address,
        operator: Address,
        approved: bool,
    },
    
    // QN12 Events
    TransferSingle {
        operator: Address,
        from: Address,
        to: Address,
        token_id: u64,
        value: u64,
    },
    TransferBatch {
        operator: Address,
        from: Address,
        to: Address,
        token_ids: Vec<u64>,
        values: Vec<u64>,
    },
    
    // Administrative Events
    Paused {
        account: Address,
    },
    Unpaused {
        account: Address,
    },
    OwnershipTransferStarted {
        previous_owner: Address,
        new_owner: Address,
    },
    OwnershipTransferred {
        previous_owner: Address,
        new_owner: Address,
    },
}

pub type TokenResult<T> = Result<T, TokenError>;
