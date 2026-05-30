// src/error.rs — Unified error type for the wallet server

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Invalid PIN: must be exactly 6 digits")]
    InvalidPin,
    #[error("Wrong PIN")]
    WrongPin,
    #[error("Session not found or expired")]
    SessionNotFound,
    #[error("Session expired")]
    SessionExpired,
    #[error("Invalid address format: {0}")]
    InvalidAddress(String),
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),
    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),
    #[error("Encryption failed: {0}")]
    EncryptionError(String),
    #[error("Decryption failed — wrong PIN")]
    DecryptionFailed,
    #[error("Crypto error: {0}")]
    CryptoError(String),
    #[error("Node RPC error: {0}")]
    NodeRpcError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Transaction failed: {0}")]
    TransactionFailed(String),
    #[error("Too many attempts. Try again in {0} seconds.")]
    RateLimited(u64),
}

impl IntoResponse for WalletError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            WalletError::InvalidPin => (StatusCode::BAD_REQUEST, 400, self.to_string()),
            WalletError::WrongPin => (StatusCode::UNAUTHORIZED, 401, self.to_string()),
            WalletError::SessionNotFound => (StatusCode::UNAUTHORIZED, 401, self.to_string()),
            WalletError::SessionExpired => (StatusCode::UNAUTHORIZED, 401, self.to_string()),
            WalletError::InvalidAddress(_) => (StatusCode::BAD_REQUEST, 400, self.to_string()),
            WalletError::InvalidAmount(_) => (StatusCode::BAD_REQUEST, 400, self.to_string()),
            WalletError::InvalidSecretKey(_) => (StatusCode::BAD_REQUEST, 400, self.to_string()),
            WalletError::DecryptionFailed => (StatusCode::UNAUTHORIZED, 401, self.to_string()),
            WalletError::NodeRpcError(_) => (StatusCode::BAD_GATEWAY, 502, self.to_string()),
            WalletError::TransactionFailed(_) => (StatusCode::BAD_REQUEST, 400, self.to_string()),
            WalletError::RateLimited(_) => (StatusCode::TOO_MANY_REQUESTS, 429, self.to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, 500, self.to_string()),
        };
        let body = Json(json!({ "error": { "code": code, "message": message } }));
        (status, body).into_response()
    }
}

pub type WalletResult<T> = Result<T, WalletError>;
