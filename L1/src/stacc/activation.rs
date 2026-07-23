// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use std::collections::HashMap;
use crate::types::Address;

pub const BASIC_TIER_STAKE: u64 = 10;
pub const BUILDER_TIER_STAKE: u64 = 100;
pub const ENTERPRISE_TIER_STAKE: u64 = 1_000;

pub const ACTIVATION_DEPOSIT: u64 = BASIC_TIER_STAKE;
pub const COOLDOWN_BLOCKS: u64 = 50_400;
pub const MAX_ANCIENNETE_FACTOR: f64 = 3.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaccTier {
    Basic,
    Builder,
    Enterprise,
}

impl StaccTier {
    pub fn from_stake(stake: u128) -> Option<Self> {
        if stake >= ENTERPRISE_TIER_STAKE as u128 {
            Some(Self::Enterprise)
        } else if stake >= BUILDER_TIER_STAKE as u128 {
            Some(Self::Builder)
        } else if stake >= BASIC_TIER_STAKE as u128 {
            Some(Self::Basic)
        } else {
            None
        }
    }

    pub fn quota_base(&self) -> u64 {
        match self {
            StaccTier::Basic => 10_000,
            StaccTier::Builder => 30_000,
            StaccTier::Enterprise => 100_000,
        }
    }

    pub fn priority_weight_boost(&self) -> f64 {
        match self {
            StaccTier::Enterprise => 20_000.0,
            _ => 0.0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ActivationState {
    pub activated_at_block: u64,
    pub cooldown_until_block: Option<u64>,
}

/// Minimal in-memory activation ledger.
///
/// Production note: in a full node, this should be persisted in state and
/// advanced deterministically per block.
#[derive(Clone, Default)]
pub struct ActivationLedger {
    states: HashMap<Address, ActivationState>,
}

impl ActivationLedger {
    pub fn is_active(&self, addr: &Address) -> bool {
        self.states.contains_key(addr)
    }

    pub fn activate(&mut self, addr: Address, now_block: u64) {
        self.states.entry(addr).or_insert(ActivationState {
            activated_at_block: now_block,
            cooldown_until_block: None,
        });
    }

    pub fn request_withdraw(&mut self, addr: &Address, now_block: u64) -> Option<u64> {
        let st = self.states.get_mut(addr)?;
        let until = now_block.saturating_add(COOLDOWN_BLOCKS);
        st.cooldown_until_block = Some(until);
        Some(until)
    }

    pub fn finalize_withdraw(&mut self, addr: &Address, now_block: u64) -> bool {
        let Some(st) = self.states.get(addr) else { return false; };
        let Some(until) = st.cooldown_until_block else { return false; };
        if now_block < until {
            return false;
        }
        self.states.remove(addr);
        true
    }

    /// Returns ancienneté factor in [1.0, MAX_ANCIENNETE_FACTOR] that grows
    /// logarithmically and plateaus around ~6 months (assume 1 block ~ 12s).
    pub fn anciennete_factor(&self, addr: &Address, now_block: u64) -> f64 {
        let Some(st) = self.states.get(addr) else { return 1.0; };
        let age_blocks = now_block.saturating_sub(st.activated_at_block) as f64;
        // 6 months approx: 6*30*24*3600 / 12 = 1_296_000 blocks
        let six_months = 1_296_000.0;
        let x = (age_blocks / six_months).max(0.0);
        // log growth from 1.0 → 3.0: 1 + 2*log1p(k*x)/log1p(k)
        let k = 50.0;
        let num = (1.0 + k * x).ln();
        let den = (1.0 + k).ln();
        let factor = 1.0 + 2.0 * (num / den);
        factor.clamp(1.0, MAX_ANCIENNETE_FACTOR)
    }
}

