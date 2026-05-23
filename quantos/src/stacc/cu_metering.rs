/// Protocol-level CU accounting.
///
/// In this codebase, the WASM VM enforces CU limits via `max_compute_units`.
/// This module centralizes network-level CU parameters such as block limits.
use std::sync::OnceLock;

pub const DEFAULT_BLOCK_CU_LIMIT: u64 = 300_000_000;

#[inline]
pub fn block_cu_limit() -> u64 {
    static BLOCK_CU_LIMIT: OnceLock<u64> = OnceLock::new();
    *BLOCK_CU_LIMIT.get_or_init(|| {
        std::env::var("QUANTOS_BLOCK_CU_LIMIT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_BLOCK_CU_LIMIT)
    })
}

#[inline]
pub fn clamp_tx_cu(max_compute_units: u64) -> u64 {
    // Prevent absurdly large CU that could overflow downstream accounting.
    max_compute_units.min(block_cu_limit())
}

