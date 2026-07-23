// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use crate::stacc::cu_metering::block_cu_limit;
use crate::types::SignedTransaction;

pub const SYSTEM_LANE_PCT: u64 = 5;

pub fn system_lane_limit() -> u64 {
    (block_cu_limit() * SYSTEM_LANE_PCT) / 100
}

pub fn stacc_lane_limit() -> u64 {
    block_cu_limit().saturating_sub(system_lane_limit())
}

/// Classifies system transactions that bypass STACC ordering/quota.
pub fn is_system_tx(tx: &SignedTransaction) -> bool {
    use crate::types::TransactionType::*;
    matches!(
        tx.transaction.tx_type,
        ValidatorRegister | ValidatorExit
    )
}

