// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Relay Bonding & Slashing Registry (native Quantos)
//!
//! On-chain registry for relay operators.  Implements the **base bond**
//! layer of the two-tier bonding model described in the whitepaper
//! (§8.4 — Relay Bonding & Slashing).
//!
//! ## Invariants
//!
//! * **INV-B1** : A relay is whitelisted only if `base_bond >= MIN_BOND_QTS`.
//! * **INV-B2** : Unbonding requests are delayed by `UNBONDING_PERIOD_SECONDS`.
//! * **INV-B3** : A jailed relay is immediately de-whitelisted.
//! * **INV-B4** : The base bond is **never** used as financial guarantee for
//!   relayed value; it is reputation / anti-spam only.
//!
//! The financial guarantee lives in the L2 bridge contract (`QuantosL0Verifier`)
//! as per-`proofHash` escrow in the target-chain asset.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

use crate::types::{Address, Amount};

// ── Constants ─────────────────────────────────────────────────────────────

/// Minimum base bond to register as a relay (QTS).
/// This is a *reputation* threshold, not a financial guarantee.
pub const MIN_BOND_QTS: u128 = 10_000 * 10u128.pow(18); // 10 000 QTS

/// Unbonding delay (seconds).  Must match `ChainConfig::unbonding_period_seconds`.
pub const UNBONDING_PERIOD_SECONDS: u64 = 7 * 24 * 3600; // 7 days

/// Maximum simultaneous unbonding requests per relay.
pub const MAX_CONCURRENT_UNBONDS: usize = 1;

// ── Errors ─────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum RelayBondError {
    #[error("Insufficient base bond: required {required}, provided {provided}")]
    InsufficientBond { required: u128, provided: u128 },

    #[error("Relay already registered: {0:?}")]
    AlreadyRegistered(Address),

    #[error("Relay not registered: {0:?}")]
    NotRegistered(Address),

    #[error("Unbonding already in progress")]
    UnbondingInProgress,

    #[error("Unbonding period not elapsed: unbonded_at {unbonded_at}, now {now}")]
    UnbondingNotElapsed { unbonded_at: u64, now: u64 },

    #[error("Relay is jailed")]
    Jailed,

    #[error("Nothing to withdraw")]
    NothingToWithdraw,

    #[error("Self-slash not allowed")]
    SelfSlash,
}

pub type RelayBondResult<T> = Result<T, RelayBondError>;

// ── Types ─────────────────────────────────────────────────────────────────

/// Current operational status of a relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayBondStatus {
    /// Active and whitelisted.
    Active,
    /// Unbonding request submitted; will become `Withdrawable` after delay.
    Unbonding { request_time: u64 },
    /// Bond may be withdrawn.
    Withdrawable,
    /// Jailed (malicious or negligent behaviour).  Manual unjail required.
    Jailed,
}

/// On-chain record for a single relay operator.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayRecord {
    /// Address of the relay operator.
    pub address: Address,
    /// Amount of QTS currently bonded.
    pub bond: Amount,
    /// Current status.
    pub status: RelayBondStatus,
    /// Number of successful relays (reputation metric).
    pub successful_relays: u64,
    /// Number of fraud challenges won against this relay.
    pub fraud_count: u64,
    /// Timestamp of last activity (used for liveness checks).
    pub last_activity: u64,
}

// ── Registry ───────────────────────────────────────────────────────────────

/// Global relay bonding registry.
///
/// Thread-safe via `DashMap` for concurrent reads/writes.
#[derive(Clone, Debug)]
pub struct RelayBondRegistry {
    inner: Arc<DashMap<Address, RelayRecord>>,
}

impl Default for RelayBondRegistry {
    fn default() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }
}

impl RelayBondRegistry {
    // ── Registration ────────────────────────────────────────────────────

    /// Register a new relay by depositing the base bond.
    ///
    /// # Invariant
    /// `bond >= MIN_BOND_QTS` (INV-B1).
    pub fn bond(&self, address: Address, bond: Amount) -> RelayBondResult<()> {
        if bond.0 < MIN_BOND_QTS {
            return Err(RelayBondError::InsufficientBond {
                required: MIN_BOND_QTS,
                provided: bond.0,
            });
        }

        if self.inner.contains_key(&address) {
            return Err(RelayBondError::AlreadyRegistered(address));
        }

        let now = now_secs();
        let bond_value = bond.0;
        let record = RelayRecord {
            address,
            bond,
            status: RelayBondStatus::Active,
            successful_relays: 0,
            fraud_count: 0,
            last_activity: now,
        };

        self.inner.insert(address, record);
        info!(address = %hex::encode(&address), bond = %bond_value, "relay registered");
        Ok(())
    }

    /// Initiate unbonding.  The bond becomes withdrawable after
    /// `UNBONDING_PERIOD_SECONDS`.
    ///
    /// # Invariant
    /// Only one unbonding request at a time (INV-B2).
    pub fn unbond(&self, address: Address) -> RelayBondResult<()> {
        let mut entry = self.inner.get_mut(&address).ok_or(RelayBondError::NotRegistered(address))?;

        match entry.status {
            RelayBondStatus::Active => {
                let now = now_secs();
                entry.status = RelayBondStatus::Unbonding { request_time: now };
                info!(address = %hex::encode(&address), request_time = now, "relay unbonding started");
                Ok(())
            }
            RelayBondStatus::Unbonding { .. } => Err(RelayBondError::UnbondingInProgress),
            RelayBondStatus::Withdrawable => Err(RelayBondError::NothingToWithdraw),
            RelayBondStatus::Jailed => Err(RelayBondError::Jailed),
        }
    }

    /// Withdraw the bonded QTS after the unbonding period elapsed.
    ///
    /// # Invariant
    /// `now >= request_time + UNBONDING_PERIOD_SECONDS` (INV-B2).
    pub fn withdraw(&self, address: Address) -> RelayBondResult<Amount> {
        let mut entry = self.inner.get_mut(&address).ok_or(RelayBondError::NotRegistered(address))?;

        match entry.status {
            RelayBondStatus::Unbonding { request_time } => {
                let now = now_secs();
                if now < request_time + UNBONDING_PERIOD_SECONDS {
                    return Err(RelayBondError::UnbondingNotElapsed {
                        unbonded_at: request_time,
                        now,
                    });
                }
                let amount = entry.bond.clone();
                entry.status = RelayBondStatus::Withdrawable;
                entry.bond = Amount(0);
                info!(address = %hex::encode(&address), amount = %amount.0, "relay bond withdrawn");
                Ok(amount)
            }
            RelayBondStatus::Withdrawable => {
                let amount = entry.bond.clone();
                entry.bond = Amount(0);
                self.inner.remove(&address);
                info!(address = %hex::encode(&address), amount = %amount.0, "relay deregistered after withdrawal");
                Ok(amount)
            }
            _ => Err(RelayBondError::NothingToWithdraw),
        }
    }

    // ── Slashing & Jailing ──────────────────────────────────────────────

    /// Slash a portion of the base bond (used for non-financial penalties,
    /// e.g. downtime, missed checkpoints).  **Never** used for fraud on
    /// relayed value — that is covered by the per-proof escrow on L2.
    pub fn slash_bond(&self, address: Address, penalty: Amount, beneficiary: Address) -> RelayBondResult<Amount> {
        let mut entry = self.inner.get_mut(&address).ok_or(RelayBondError::NotRegistered(address))?;

        let current = entry.bond.clone();
        let actual_penalty = if current.0 < penalty.0 {
            current.clone()
        } else {
            penalty
        };

        entry.bond = Amount(current.0.saturating_sub(actual_penalty.0));
        entry.fraud_count += 1;

        if entry.bond.0 < MIN_BOND_QTS {
            entry.status = RelayBondStatus::Jailed;
            warn!(address = %hex::encode(&address), remaining = %entry.bond.0, "relay jailed after slash");
        }

        info!(address = %hex::encode(&address), penalty = %actual_penalty.0, beneficiary = %hex::encode(&beneficiary), "relay bond slashed");
        Ok(actual_penalty)
    }

    /// Jail a relay immediately (governance or automated decision).
    ///
    /// # Invariant
    /// Jailed relays are de-whitelisted (INV-B3).
    pub fn jail(&self, address: Address) -> RelayBondResult<()> {
        let mut entry = self.inner.get_mut(&address).ok_or(RelayBondError::NotRegistered(address))?;
        entry.status = RelayBondStatus::Jailed;
        warn!(address = %hex::encode(&address), "relay jailed");
        Ok(())
    }

    /// Unjail a relay (governance only).
    pub fn unjail(&self, address: Address, required_bond: Amount) -> RelayBondResult<()> {
        let mut entry = self.inner.get_mut(&address).ok_or(RelayBondError::NotRegistered(address))?;
        if entry.bond.0 < required_bond.0 {
            return Err(RelayBondError::InsufficientBond {
                required: required_bond.0,
                provided: entry.bond.0,
            });
        }
        entry.status = RelayBondStatus::Active;
        info!(address = %hex::encode(&address), "relay unjailed");
        Ok(())
    }

    // ── Queries ─────────────────────────────────────────────────────────

    /// Check whether a relay is whitelisted (active and bonded).
    pub fn is_whitelisted(&self, address: &Address) -> bool {
        self.inner
            .get(address)
            .map(|r| matches!(r.status, RelayBondStatus::Active) && r.bond.0 >= MIN_BOND_QTS)
            .unwrap_or(false)
    }

    /// Get a relay record (read-only).
    pub fn get(&self, address: &Address) -> Option<RelayRecord> {
        self.inner.get(address).map(|r| r.clone())
    }

    /// Total number of registered relays.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Increment successful relay counter (called by the hub after
    /// an L0 proof is successfully dispatched).
    pub fn record_success(&self, address: Address) {
        if let Some(mut r) = self.inner.get_mut(&address) {
            r.successful_relays += 1;
            r.last_activity = now_secs();
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        let mut a = [0u8; 20];
        a[19] = n;
        a
    }

    fn amt(v: u128) -> Amount {
        Amount(v)
    }

    #[test]
    fn test_bond_and_whitelist() {
        let reg = RelayBondRegistry::default();
        let a = addr(1);

        // Bond too low → rejected
        assert!(reg.bond(a, amt(MIN_BOND_QTS - 1)).is_err());

        // Bond minimum → accepted, whitelisted
        assert!(reg.bond(a, amt(MIN_BOND_QTS)).is_ok());
        assert!(reg.is_whitelisted(&a));
    }

    #[test]
    fn test_unbond_withdraw() {
        let reg = RelayBondRegistry::default();
        let a = addr(1);
        reg.bond(a, amt(MIN_BOND_QTS * 2)).unwrap();

        // Start unbonding
        assert!(reg.unbond(a).is_ok());
        assert!(!reg.is_whitelisted(&a));

        // Withdraw too early → rejected
        assert!(matches!(
            reg.withdraw(a),
            Err(RelayBondError::UnbondingNotElapsed { .. })
        ));

        // (In a real test we would mock time.)
    }

    #[test]
    fn test_jail_de_whitelists() {
        let reg = RelayBondRegistry::default();
        let a = addr(1);
        reg.bond(a, amt(MIN_BOND_QTS * 2)).unwrap();
        assert!(reg.is_whitelisted(&a));

        reg.jail(a).unwrap();
        assert!(!reg.is_whitelisted(&a));
    }

    #[test]
    fn test_double_register_rejected() {
        let reg = RelayBondRegistry::default();
        let a = addr(1);
        reg.bond(a, amt(MIN_BOND_QTS)).unwrap();
        assert!(matches!(reg.bond(a, amt(MIN_BOND_QTS)), Err(RelayBondError::AlreadyRegistered(_))));
    }
}
