mod server;
mod handlers;
mod atomic_swap;
pub mod metrics;

pub use server::*;
pub use handlers::*;
pub use atomic_swap::*;
pub use metrics::QuantosMetrics;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Transaction failed: {0}")]
    TransactionFailed(String),
}

pub type RpcResult<T> = Result<T, RpcError>;
