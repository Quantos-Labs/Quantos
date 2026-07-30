// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use crate::stacc::quota::{StakeProvider, AncienneteProvider};
use crate::types::Address;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum MempoolError {
    #[error("Transaction already exists")]
    DuplicateTransaction,
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),
    #[error("Mempool full")]
    MempoolFull,
    #[error("Nonce too low")]
    NonceTooLow,
    #[error("Nonce gap detected")]
    NonceGap,
}

pub type MempoolResult<T> = Result<T, MempoolError>;

#[derive(Clone)]
pub struct ZeroStakeProvider;
impl StakeProvider for ZeroStakeProvider {
    fn stake_of(&self, _addr: &Address) -> u128 { 0 }
    fn total_stake(&self) -> u128 { 0 }
}

#[derive(Clone)]
pub struct FixedAgeProvider;
impl AncienneteProvider for FixedAgeProvider {
    fn anciennete_factor(&self, _addr: &Address, _now_block: u64) -> f64 { 1.0 }
}
