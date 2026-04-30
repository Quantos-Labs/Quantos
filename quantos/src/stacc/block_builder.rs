use crate::stacc::cu_metering::BLOCK_CU_LIMIT;
use crate::types::SignedTransaction;

pub const SYSTEM_LANE_PCT: u64 = 5;

pub fn system_lane_limit() -> u64 {
    (BLOCK_CU_LIMIT * SYSTEM_LANE_PCT) / 100
}

pub fn stacc_lane_limit() -> u64 {
    BLOCK_CU_LIMIT.saturating_sub(system_lane_limit())
}

/// Classifies system transactions that bypass STACC ordering/quota.
pub fn is_system_tx(tx: &SignedTransaction) -> bool {
    use crate::types::TransactionType::*;
    matches!(
        tx.transaction.tx_type,
        ValidatorRegister | ValidatorExit
    )
}

