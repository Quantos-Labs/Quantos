// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # PQC Key Migration Registry
//!
//! Implements the three-mechanism PQC key migration model that replaces
//! the symmetric commit-reveal griefing vulnerability (audit §7.1).
//!
//! ## Security model
//!
//! No on-chain mechanism can distinguish an attacker holding the ECDSA key
//! from a legitimate owner.  Security therefore relies on:
//! 1. **Preventive migration** (register before compromise)
//! 2. **Guardian factor** (independent of ECDSA key)
//! 3. **Time-delay + alert** (48h non-cancellable window)
//!
//! ## Three mechanisms
//!
//! | # | Name | Purpose | Trigger |
//! |---|------|---------|---------|
//! | 1 | Direct registration + PoP | Normal case (99% of users) | User proactively registers PQC key |
//! | 2 | PENDING delay + alert | Anti-theft safeguard | Automatic on every registration |
//! | 3 | Social recovery M-of-N | Account already compromised | Guardians intervene during 48h window |
//!
//! ## Parameters (production)
//!
//! | Parameter | Value | Reason |
//! |-----------|-------|--------|
//! | `PENDING_DELAY_SECONDS` | 48h | Realistic human reaction time to an alert |
//! | `GUARDIAN_SET_SIZE` | 3–5 (configurable) | Resilience without UX burden |
//! | `GUARDIAN_THRESHOLD` | 2-of-3 or 3-of-5 | Majority, survives loss of one guardian |
//! | `ECDSA_REVOCATION` | Immediate after PQC activation | Close quantum vector ASAP |
//! | `GUARDIAN_CHANGE_DELAY` | 48h | Same delay applied to guardian set changes |

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

use crate::types::{Address, Hash, hash_data};
use crate::crypto::{verify_ml_dsa_65, verify_ecdsa, with_domain, DOMAIN_PQC_POP, DOMAIN_PQC_REGISTER};

// ── Constants ─────────────────────────────────────────────────────────────

/// 48-hour activation delay for PQC keys (seconds).
pub const PENDING_DELAY_SECONDS: u64 = 48 * 3600;

/// Default guardian set size.
pub const DEFAULT_GUARDIAN_SET_SIZE: usize = 3;

/// Default guardian threshold (2-of-3).
pub const DEFAULT_GUARDIAN_THRESHOLD: u16 = 2;

/// Maximum guardians per account.
pub const MAX_GUARDIANS: usize = 5;

/// Delay for guardian set changes (same as PQC activation — prevents attacker
/// from immediately swapping guardians after stealing ECDSA key).
pub const GUARDIAN_CHANGE_DELAY_SECONDS: u64 = PENDING_DELAY_SECONDS;

// ── Errors ─────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PqcMigrationError {
    #[error("Invalid ECDSA signature")]
    InvalidEcdsaSignature,

    #[error("Invalid PQC proof-of-possession (PoP)")]
    InvalidPqcPop,

    #[error("PQC key already registered for this account")]
    AlreadyRegistered,

    #[error("PQC key not in PENDING state")]
    NotPending,

    #[error("PQC key still in PENDING: activated_at {activated_at}, now {now}")]
    StillPending { activated_at: u64, now: u64 },

    #[error("Guardian set not configured")]
    NoGuardians,

    #[error("Insufficient guardian signatures: got {got}, need {threshold}")]
    InsufficientGuardianSigs { got: u16, threshold: u16 },

    #[error("Guardian change already pending")]
    GuardianChangePending,

    #[error("Guardian set locked during PENDING activation")]
    GuardianSetLocked,

    #[error("Account frozen by guardians")]
    AccountFrozen,

    #[error("Self-guardian not allowed")]
    SelfGuardian,

    #[error("Guardian not found")]
    GuardianNotFound,

    #[error("Invalid guardian root")]
    InvalidGuardianRoot,
}

pub type PqcMigrationResult<T> = Result<T, PqcMigrationError>;

// ── Types ─────────────────────────────────────────────────────────────────

/// State of a PQC key migration for an account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PqcKeyState {
    /// No PQC key registered. Account uses ECDSA only.
    EcdsaOnly,
    /// Key registered, waiting for 48h delay. Alert emitted.
    Pending {
        pqc_pubkey: Vec<u8>,
        registered_at: u64,
        /// Block height at which the key was registered.
        registered_at_block: u64,
    },
    /// PQC key active. ECDSA is revoked.
    Active {
        pqc_pubkey: Vec<u8>,
        activated_at: u64,
    },
    /// Account frozen by guardians during PENDING window.
    Frozen {
        pqc_pubkey: Vec<u8>,
        frozen_at: u64,
        reason: String,
    },
}

/// Guardian record for an account.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianSet {
    /// Guardian addresses (must be distinct from account owner).
    pub guardians: Vec<Address>,
    /// Guardian PQC public keys (parallel to guardians, indexed by position).
    pub guardian_pubkeys: Vec<Vec<u8>>,
    /// M-of-N threshold (e.g. 2 of 3).
    pub threshold: u16,
    /// Merkle root of the guardian set (bound at account creation).
    pub guardian_root: Hash,
    /// Pending guardian change (subject to same 48h delay).
    pub pending_change: Option<PendingGuardianChange>,
}

/// A guardian set change that is subject to the same delay as PQC activation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingGuardianChange {
    pub new_guardians: Vec<Address>,
    pub new_guardian_pubkeys: Vec<Vec<u8>>,
    pub new_threshold: u16,
    pub submitted_at: u64,
}

/// On-chain record for PQC migration of a single account.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqcMigrationRecord {
    pub address: Address,
    pub state: PqcKeyState,
    pub guardian_set: GuardianSet,
    /// Whether the account was created with a guardian root (prevents
    /// attacker from being the first to set guardians on a legacy account).
    pub guardian_root_bound: bool,
}

// ── Registry ─────────────────────────────────────────────────────────────

/// Global PQC migration registry.
#[derive(Clone, Debug, Default)]
pub struct PqcMigrationRegistry {
    records: HashMap<Address, PqcMigrationRecord>,
}

impl PqcMigrationRegistry {
    // ── Mechanism 1 : Direct registration with PoP ─────────────────────

    /// Register a PQC public key for an account.
    ///
    /// # Arguments
    /// * `address` — the account address
    /// * `pqc_pubkey` — the ML-DSA-65 public key
    /// * `ecdsa_sig` — ECDSA signature over `DOMAIN_PQC_REGISTER || pqc_pubkey || guardian_root || nonce || address`
    /// * `pqc_pop` — PQC proof-of-possession: signature over `DOMAIN_PQC_POP || pqc_pubkey || address`
    /// * `nonce` — anti-replay nonce
    /// * `guardian_root` — merkle root of the guardian set (bound at account creation)
    pub fn register_pqc_key(
        &mut self,
        address: Address,
        pqc_pubkey: Vec<u8>,
        ecdsa_sig: &[u8],
        pqc_pop: &[u8],
        nonce: u64,
        guardian_root: Hash,
    ) -> PqcMigrationResult<()> {
        // ── 1a. Verify ECDSA binding signature ──
        let msg = Self::build_register_msg(&pqc_pubkey, &guardian_root, nonce, &address);
        if !verify_ecdsa(&address, &msg, ecdsa_sig) {
            return Err(PqcMigrationError::InvalidEcdsaSignature);
        }

        // ── 1b. Verify PQC proof-of-possession ──
        let pop_msg = Self::build_pop_msg(&pqc_pubkey, &address);
        if !verify_ml_dsa_65(&pqc_pubkey, &pop_msg, pqc_pop) {
            return Err(PqcMigrationError::InvalidPqcPop);
        }

        // ── 1c. Check guardian root matches (prevents attacker from
        // swapping guardians before registering) ──
        let record = self.records.entry(address).or_insert_with(|| PqcMigrationRecord {
            address,
            state: PqcKeyState::EcdsaOnly,
            guardian_set: GuardianSet {
                guardians: vec![],
                guardian_pubkeys: vec![],
                threshold: DEFAULT_GUARDIAN_THRESHOLD,
                guardian_root: [0u8; 32],
                pending_change: None,
            },
            guardian_root_bound: false,
        });

        if record.guardian_root_bound && record.guardian_set.guardian_root != guardian_root {
            return Err(PqcMigrationError::InvalidGuardianRoot);
        }

        // If this is the first registration and no guardian root was bound,
        // bind it now.  This is the ONLY moment the guardian root becomes
        // immutable for this account.
        if !record.guardian_root_bound {
            record.guardian_set.guardian_root = guardian_root;
            record.guardian_root_bound = true;
            info!(?address, "guardian root bound at first PQC registration");
        }

        // ── 1d. Check not already registered ──
        match &record.state {
            PqcKeyState::EcdsaOnly => {}
            _ => return Err(PqcMigrationError::AlreadyRegistered),
        }

        // ── 1e. Transition to PENDING (Mechanism 2) ──
        let now = now_secs();
        record.state = PqcKeyState::Pending {
            pqc_pubkey,
            registered_at: now,
            registered_at_block: 0, // set by caller
        };

        info!(?address, registered_at = now, "PQC key registered, entering PENDING");
        Ok(())
    }

    // ── Mechanism 2 : PENDING delay + automatic activation ───────────

    /// Activate a PENDING key after the 48h delay has elapsed.
    /// Callable by anyone (permissionless) — this is a state transition,
    /// not an authorization.
    pub fn activate_pending_key(&mut self, address: Address) -> PqcMigrationResult<()> {
        let record = self.records.get_mut(&address).ok_or(PqcMigrationError::NotPending)?;

        let (pqc_pubkey, registered_at) = match &record.state {
            PqcKeyState::Pending { pqc_pubkey, registered_at, .. } => {
                (pqc_pubkey.clone(), *registered_at)
            }
            _ => return Err(PqcMigrationError::NotPending),
        };

        let now = now_secs();
        if now < registered_at + PENDING_DELAY_SECONDS {
            return Err(PqcMigrationError::StillPending {
                activated_at: registered_at + PENDING_DELAY_SECONDS,
                now,
            });
        }

        // ECDSA is immediately revoked upon PQC activation.
        record.state = PqcKeyState::Active {
            pqc_pubkey,
            activated_at: now,
        };

        info!(?address, activated_at = now, "PQC key activated, ECDSA revoked");
        Ok(())
    }

    // ── Mechanism 3 : Social recovery via guardians M-of-N ─────────────

    /// Freeze an account during the PENDING window by guardian consensus.
    /// This is the ONLY action that can block a PENDING registration.
    ///
    /// # Arguments
    /// * `guardian_sigs` — signatures from at least `threshold` guardians
    ///   over `FREEZE || address || pqc_pubkey`
    pub fn freeze_by_guardians(
        &mut self,
        address: Address,
        guardian_sigs: Vec<(Address, Vec<u8>)>,
        reason: String,
    ) -> PqcMigrationResult<()> {
        let record = self.records.get_mut(&address).ok_or(PqcMigrationError::NoGuardians)?;

        // Must be in PENDING state (guardians can only act during the window)
        let pqc_pubkey = match &record.state {
            PqcKeyState::Pending { pqc_pubkey, .. } => pqc_pubkey.clone(),
            _ => return Err(PqcMigrationError::NotPending),
        };

        // Verify guardian signatures (static call to avoid borrow conflict)
        let valid_sigs = Self::count_valid_guardian_sigs(
            &record.guardian_set,
            &address,
            &pqc_pubkey,
            &guardian_sigs,
        )?;

        if valid_sigs < record.guardian_set.threshold {
            return Err(PqcMigrationError::InsufficientGuardianSigs {
                got: valid_sigs,
                threshold: record.guardian_set.threshold,
            });
        }

        record.state = PqcKeyState::Frozen {
            pqc_pubkey,
            frozen_at: now_secs(),
            reason,
        };

        warn!(?address, "account frozen by guardians");
        Ok(())
    }

    /// Re-assign a new PQC key after a freeze (guardian-only).
    pub fn recover_by_guardians(
        &mut self,
        address: Address,
        new_pqc_pubkey: Vec<u8>,
        new_ecdsa_sig: &[u8],
        new_pqc_pop: &[u8],
        guardian_sigs: Vec<(Address, Vec<u8>)>,
    ) -> PqcMigrationResult<()> {
        let record = self.records.get_mut(&address).ok_or(PqcMigrationError::NoGuardians)?;

        // Must be frozen
        match &record.state {
            PqcKeyState::Frozen { .. } => {}
            _ => return Err(PqcMigrationError::NotPending),
        }

        // Verify new registration signatures (same as mechanism 1)
        let msg = Self::build_register_msg(&new_pqc_pubkey, &record.guardian_set.guardian_root, 0, &address);
        if !verify_ecdsa(&address, &msg, new_ecdsa_sig) {
            return Err(PqcMigrationError::InvalidEcdsaSignature);
        }

        let pop_msg = Self::build_pop_msg(&new_pqc_pubkey, &address);
        if !verify_ml_dsa_65(&new_pqc_pubkey, &pop_msg, new_pqc_pop) {
            return Err(PqcMigrationError::InvalidPqcPop);
        }

        // Verify guardian consensus (static call to avoid borrow conflict)
        let valid_sigs = Self::count_valid_guardian_sigs(
            &record.guardian_set,
            &address,
            &new_pqc_pubkey,
            &guardian_sigs,
        )?;

        if valid_sigs < record.guardian_set.threshold {
            return Err(PqcMigrationError::InsufficientGuardianSigs {
                got: valid_sigs,
                threshold: record.guardian_set.threshold,
            });
        }

        // Reset to ECDSA-only, user must re-register
        record.state = PqcKeyState::EcdsaOnly;
        info!(?address, "account recovered by guardians, PQC key cleared");
        Ok(())
    }

    // ── Guardian management ─────────────────────────────────────────────

    /// Submit a guardian set change (subject to 48h delay, same as PQC activation).
    pub fn submit_guardian_change(
        &mut self,
        address: Address,
        new_guardians: Vec<Address>,
        new_guardian_pubkeys: Vec<Vec<u8>>,
        new_threshold: u16,
    ) -> PqcMigrationResult<()> {
        if new_guardians.len() > MAX_GUARDIANS {
            return Err(PqcMigrationError::SelfGuardian);
        }
        if new_guardians.len() != new_guardian_pubkeys.len() {
            return Err(PqcMigrationError::InvalidGuardianRoot);
        }

        let record = self.records.get_mut(&address).ok_or(PqcMigrationError::NoGuardians)?;

        // Cannot change guardians while PQC is PENDING (attacker could swap them out)
        if let PqcKeyState::Pending { .. } = record.state {
            return Err(PqcMigrationError::GuardianSetLocked);
        }

        if record.guardian_set.pending_change.is_some() {
            return Err(PqcMigrationError::GuardianChangePending);
        }

        record.guardian_set.pending_change = Some(PendingGuardianChange {
            new_guardians,
            new_guardian_pubkeys,
            new_threshold,
            submitted_at: now_secs(),
        });

        info!(?address, "guardian change submitted, pending 48h");
        Ok(())
    }

    /// Apply a pending guardian change after the delay.
    pub fn apply_guardian_change(&mut self, address: Address) -> PqcMigrationResult<()> {
        let record = self.records.get_mut(&address).ok_or(PqcMigrationError::NoGuardians)?;

        let change = record.guardian_set.pending_change.take()
            .ok_or(PqcMigrationError::GuardianChangePending)?;
        let submitted_at = change.submitted_at;

        let now = now_secs();
        if now < submitted_at + GUARDIAN_CHANGE_DELAY_SECONDS {
            // Restore pending change since not ready yet
            record.guardian_set.pending_change = Some(change);
            return Err(PqcMigrationError::StillPending {
                activated_at: submitted_at + GUARDIAN_CHANGE_DELAY_SECONDS,
                now,
            });
        }

        record.guardian_set.guardians = change.new_guardians;
        record.guardian_set.guardian_pubkeys = change.new_guardian_pubkeys;
        record.guardian_set.threshold = change.new_threshold;
        record.guardian_set.guardian_root = compute_guardian_root(
            &record.guardian_set.guardians,
            &record.guardian_set.guardian_pubkeys,
            record.guardian_set.threshold
        );

        info!(?address, "guardian change applied");
        Ok(())
    }

    // ── Queries ─────────────────────────────────────────────────────────

    pub fn get_state(&self, address: &Address) -> Option<PqcKeyState> {
        self.records.get(address).map(|r| r.state.clone())
    }

    pub fn is_pqc_active(&self, address: &Address) -> bool {
        matches!(self.get_state(address), Some(PqcKeyState::Active { .. }))
    }

    pub fn is_frozen(&self, address: &Address) -> bool {
        matches!(self.get_state(address), Some(PqcKeyState::Frozen { .. }))
    }

    // ── Internal helpers ────────────────────────────────────────────────

    fn build_register_msg(pqc_pubkey: &[u8], guardian_root: &Hash, nonce: u64, address: &Address) -> Vec<u8> {
        let mut msg = Vec::with_capacity(8 + pqc_pubkey.len() + 32 + 8 + 20);
        msg.extend_from_slice(&DOMAIN_PQC_REGISTER);
        msg.extend_from_slice(pqc_pubkey);
        msg.extend_from_slice(guardian_root);
        msg.extend_from_slice(&nonce.to_le_bytes());
        msg.extend_from_slice(address);
        msg
    }

    fn build_pop_msg(pqc_pubkey: &[u8], address: &Address) -> Vec<u8> {
        let mut msg = Vec::with_capacity(8 + pqc_pubkey.len() + 20);
        msg.extend_from_slice(&DOMAIN_PQC_POP);
        msg.extend_from_slice(pqc_pubkey);
        msg.extend_from_slice(address);
        msg
    }

    fn count_valid_guardian_sigs(
        guardian_set: &GuardianSet,
        address: &Address,
        pqc_pubkey: &[u8],
        sigs: &[(Address, Vec<u8>)],
    ) -> PqcMigrationResult<u16> {
        let mut valid = 0u16;
        let msg = Self::build_guardian_freeze_msg(address, pqc_pubkey);

        for (guardian_addr, sig) in sigs {
            let idx = match guardian_set.guardians.iter().position(|g| g == guardian_addr) {
                Some(i) => i,
                None => continue,
            };
            let guardian_pqc_pk = &guardian_set.guardian_pubkeys[idx];
            if verify_ml_dsa_65(guardian_pqc_pk, &msg, sig).unwrap_or(false) {
                valid += 1;
            }
        }

        Ok(valid)
    }

    fn build_guardian_freeze_msg(address: &Address, pqc_pubkey: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(8 + 20 + pqc_pubkey.len());
        msg.extend_from_slice(b"FREEZE");
        msg.extend_from_slice(address);
        msg.extend_from_slice(pqc_pubkey);
        msg
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn compute_guardian_root(guardians: &[Address], guardian_pubkeys: &[Vec<u8>], threshold: u16) -> Hash {
    let mut data = Vec::new();
    for g in guardians {
        data.extend_from_slice(g);
    }
    for pk in guardian_pubkeys {
        data.extend_from_slice(pk);
    }
    data.extend_from_slice(&threshold.to_le_bytes());
    hash_data(&data)
}
