// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

mod server;
mod handlers;
mod atomic_swap;
pub mod metrics;
pub mod subscriptions;

pub use server::*;
pub use handlers::*;
pub use atomic_swap::*;
pub use metrics::QuantosMetrics;
pub use subscriptions::{SubscriptionManager, SubscriptionNotification};

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
