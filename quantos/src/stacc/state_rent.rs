//! # State Rent — Storage Pricing
//!
//! Solves the unbounded state growth problem: bandwidth limits throughput
//! but not permanent storage occupation. Without state rent, actors can
//! create millions of dormant accounts and bloat the state indefinitely.
//!
//! ## Mechanism
//!
//! Each byte of occupied state costs a micro-deduction from the owner's
//! quota per slot:
//!
//! ```text
//! quota_rent(slot) = state_bytes × RENT_RATE_PER_SLOT
//! ```
//!
//! - Empty account → no rent
//! - Account with 1 KB storage → passive quota deduction each slot
//! - Account with quota = 0 for N_EXPIRE_SLOTS → state archived (read-only)
//! - Archived state can be restored by depositing quota
//!
//! ## Archive and Restore
//!
//! Inspired by Ethereum's state expiry proposals (EIP-4444, Verkle trees).
//! - Active state: in hot storage (RocksDB)
//! - Archived state: in cold storage (off-chain with Merkle proof)
//! - Restore: provide Merkle proof + pay restore cost in quota

use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;
use tracing::{debug, info, warn};

use crate::types::Address;

/// Rent rate: CU deducted per byte per slot.
/// At 1 KB storage and 5 slots/s: 1024 × 1 × 5 = 5120 CU/s drain.
/// Adjusted so typical accounts with < 256 bytes pay negligible rent.
pub const RENT_RATE_PER_SLOT_PER_BYTE: u64 = 1;

/// Slots before an account with zero quota is archived.
pub const N_EXPIRE_SLOTS: u64 = 172_800; // ~48h at 200ms/slot

/// Minimum balance to be exempt from rent (dust prevention).
pub const MIN_BALANCE_EXEMPT_BYTES: u64 = 128;

/// Cost in quota to restore archived state (per byte).
pub const RESTORE_COST_PER_BYTE: u64 = 100;

/// Percentage of collected rent burned (deflationary).
pub const BURN_RATIO: f64 = 0.20;

/// Storage record for a single account.
#[derive(Clone, Debug)]
pub struct StorageRecord {
    /// Estimated storage used by this account (bytes)
    pub storage_bytes: u64,
    /// Slot when rent was last collected
    pub last_rent_slot: u64,
    /// Consecutive slots with zero-quota (archival countdown)
    pub zero_quota_slots: u64,
    /// Whether this account is archived
    pub archived: bool,
    /// Merkle root of archived state (if archived)
    pub archive_root: Option<[u8; 32]>,
}

impl StorageRecord {
    pub fn new(storage_bytes: u64, current_slot: u64) -> Self {
        Self {
            storage_bytes,
            last_rent_slot: current_slot,
            zero_quota_slots: 0,
            archived: false,
            archive_root: None,
        }
    }
}

/// Rent collection result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RentResult {
    /// Rent collected successfully
    Collected { cu_deducted: u64 },
    /// Account has insufficient quota, archived
    Archived,
    /// Account exempt from rent (small storage)
    Exempt,
    /// Account already archived
    AlreadyArchived,
}

/// State rent manager.
pub struct StateRentManager {
    /// Per-address storage records
    records: Arc<DashMap<Address, StorageRecord>>,
    /// Total CU collected as rent this epoch
    total_rent_collected: Arc<std::sync::atomic::AtomicU64>,
    /// Total CU burned this epoch
    total_burned: Arc<std::sync::atomic::AtomicU64>,
}

impl StateRentManager {
    pub fn new() -> Self {
        Self {
            records: Arc::new(DashMap::new()),
            total_rent_collected: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            total_burned: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Registers or updates storage usage for an account.
    pub fn update_storage(&self, addr: Address, storage_bytes: u64, current_slot: u64) {
        self.records
            .entry(addr)
            .and_modify(|r| {
                r.storage_bytes = storage_bytes;
            })
            .or_insert_with(|| StorageRecord::new(storage_bytes, current_slot));

        debug!(
            addr = %hex::encode(addr),
            bytes = storage_bytes,
            "Storage updated"
        );
    }

    /// Computes rent due for an account since last collection.
    pub fn rent_due(&self, addr: &Address, current_slot: u64) -> u64 {
        let Some(record) = self.records.get(addr) else {
            return 0;
        };

        if record.archived {
            return 0;
        }

        // Exempt small accounts
        if record.storage_bytes <= MIN_BALANCE_EXEMPT_BYTES {
            return 0;
        }

        let elapsed_slots = current_slot.saturating_sub(record.last_rent_slot);
        record.storage_bytes
            .saturating_mul(RENT_RATE_PER_SLOT_PER_BYTE)
            .saturating_mul(elapsed_slots)
    }

    /// Collects rent from an account's quota.
    ///
    /// Returns the CU deducted. Caller is responsible for deducting from
    /// the account's quota bucket.
    pub fn collect_rent(
        &self,
        addr: &Address,
        available_quota: u64,
        current_slot: u64,
    ) -> RentResult {
        let Some(mut record) = self.records.get_mut(addr) else {
            return RentResult::Exempt;
        };

        if record.archived {
            return RentResult::AlreadyArchived;
        }

        if record.storage_bytes <= MIN_BALANCE_EXEMPT_BYTES {
            return RentResult::Exempt;
        }

        let due = {
            let elapsed = current_slot.saturating_sub(record.last_rent_slot);
            record.storage_bytes
                .saturating_mul(RENT_RATE_PER_SLOT_PER_BYTE)
                .saturating_mul(elapsed)
        };

        if due == 0 {
            return RentResult::Exempt;
        }

        if available_quota >= due {
            // Enough quota → collect
            record.last_rent_slot = current_slot;
            record.zero_quota_slots = 0;

            // Track burned portion
            let burned = (due as f64 * BURN_RATIO).round() as u64;
            let validator_share = due - burned;

            self.total_rent_collected
                .fetch_add(validator_share, std::sync::atomic::Ordering::Relaxed);
            self.total_burned
                .fetch_add(burned, std::sync::atomic::Ordering::Relaxed);

            debug!(
                addr = %hex::encode(addr),
                cu_deducted = due,
                burned,
                validator_share,
                "Rent collected"
            );

            RentResult::Collected { cu_deducted: due }
        } else {
            // Insufficient quota → increment zero_quota counter
            record.zero_quota_slots += 1;

            if record.zero_quota_slots >= N_EXPIRE_SLOTS {
                // Archive the account
                record.archived = true;
                warn!(
                    addr = %hex::encode(addr),
                    storage_bytes = record.storage_bytes,
                    zero_quota_slots = record.zero_quota_slots,
                    "Account archived due to unpaid rent"
                );
                RentResult::Archived
            } else {
                // Partial deduction (take what's available)
                record.last_rent_slot = current_slot;

                let partial = available_quota.min(due);
                let burned = (partial as f64 * BURN_RATIO).round() as u64;
                self.total_rent_collected
                    .fetch_add(partial - burned, std::sync::atomic::Ordering::Relaxed);
                self.total_burned
                    .fetch_add(burned, std::sync::atomic::Ordering::Relaxed);

                RentResult::Collected { cu_deducted: partial }
            }
        }
    }

    /// Restores an archived account (requires paying restore cost in quota).
    pub fn restore_account(
        &self,
        addr: &Address,
        available_quota: u64,
        archive_root: [u8; 32],
        current_slot: u64,
    ) -> Result<u64, StateRentError> {
        let mut record = self.records.get_mut(addr)
            .ok_or(StateRentError::AccountNotFound)?;

        if !record.archived {
            return Err(StateRentError::NotArchived);
        }

        let restore_cost = record.storage_bytes.saturating_mul(RESTORE_COST_PER_BYTE);
        if available_quota < restore_cost {
            return Err(StateRentError::InsufficientQuota {
                need: restore_cost,
                have: available_quota,
            });
        }

        // Verify archive root matches
        if let Some(stored_root) = record.archive_root {
            if stored_root != archive_root {
                return Err(StateRentError::InvalidArchiveRoot);
            }
        }

        record.archived = false;
        record.archive_root = None;
        record.last_rent_slot = current_slot;
        record.zero_quota_slots = 0;

        info!(
            addr = %hex::encode(addr),
            restore_cost,
            "Account restored from archive"
        );

        Ok(restore_cost)
    }

    /// Returns total CU collected as rent (for validator distribution).
    pub fn total_rent_for_validators(&self) -> u64 {
        self.total_rent_collected.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Returns total CU burned.
    pub fn total_burned(&self) -> u64 {
        self.total_burned.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Resets epoch counters (call at epoch boundary).
    pub fn reset_epoch(&self) {
        self.total_rent_collected.store(0, std::sync::atomic::Ordering::Relaxed);
        self.total_burned.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    /// Returns all archived accounts (for pruning from hot storage).
    pub fn archived_accounts(&self) -> Vec<Address> {
        self.records
            .iter()
            .filter(|e| e.value().archived)
            .map(|e| *e.key())
            .collect()
    }

    /// Returns storage stats for an account.
    pub fn get_record(&self, addr: &Address) -> Option<StorageRecord> {
        self.records.get(addr).map(|r| r.clone())
    }
}

impl Default for StateRentManager {
    fn default() -> Self {
        Self::new()
    }
}

/// State rent errors.
#[derive(Debug, thiserror::Error)]
pub enum StateRentError {
    #[error("Account not found")]
    AccountNotFound,

    #[error("Account is not archived")]
    NotArchived,

    #[error("Insufficient quota to restore: need {need}, have {have}")]
    InsufficientQuota { need: u64, have: u64 },

    #[error("Invalid archive root")]
    InvalidArchiveRoot,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exempt_small_account() {
        let mgr = StateRentManager::new();
        let addr = [1u8; 20];
        mgr.update_storage(addr, 64, 0); // 64 bytes ≤ MIN_BALANCE_EXEMPT_BYTES

        let result = mgr.collect_rent(&addr, 100_000, 1000);
        assert_eq!(result, RentResult::Exempt);
    }

    #[test]
    fn test_rent_collection() {
        let mgr = StateRentManager::new();
        let addr = [2u8; 20];
        mgr.update_storage(addr, 1024, 0); // 1 KB

        // After 100 slots: rent = 1024 × 1 × 100 = 102400 CU
        let result = mgr.collect_rent(&addr, 200_000, 100);
        match result {
            RentResult::Collected { cu_deducted } => {
                assert_eq!(cu_deducted, 1024 * 100);
            }
            _ => panic!("Expected Collected"),
        }
    }

    #[test]
    fn test_archival_after_zero_quota() {
        let mgr = StateRentManager::new();
        let addr = [3u8; 20];
        mgr.update_storage(addr, 512, 0);

        // No quota → increment zero_quota_slots repeatedly
        for slot in 1..=N_EXPIRE_SLOTS {
            mgr.collect_rent(&addr, 0, slot);
        }

        let record = mgr.get_record(&addr).unwrap();
        assert!(record.archived);
    }

    #[test]
    fn test_burn_ratio() {
        let mgr = StateRentManager::new();
        let addr = [4u8; 20];
        mgr.update_storage(addr, 1024, 0);

        mgr.collect_rent(&addr, 200_000, 100);

        let rent = 1024u64 * 100;
        let expected_burned = (rent as f64 * BURN_RATIO).round() as u64;
        assert_eq!(mgr.total_burned(), expected_burned);
    }
}
