/// Protocol-level CU accounting.
///
/// In this codebase, the WASM VM enforces CU limits via `max_compute_units`.
/// This module centralizes network-level CU parameters such as block limits.

pub const BLOCK_CU_LIMIT: u64 = 30_000_000;

#[inline]
pub fn clamp_tx_cu(max_compute_units: u64) -> u64 {
    // Prevent absurdly large CU that could overflow downstream accounting.
    max_compute_units.min(BLOCK_CU_LIMIT)
}

