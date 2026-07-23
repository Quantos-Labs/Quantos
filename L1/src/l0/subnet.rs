// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Sovereign Subnets module for L0 finality anchoring.
//!
//! Subnets are sovereign application chains that register on Quantos L0.
//! They can define their own validation rules, validator keys, and gas models,
//! and leverage Quantos consensus for post-quantum finality guarantees.

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::l0::external::{ChainId, ExternalCheckpoint};
use crate::types::Address;

/// Unique identifier for a sovereign subnet
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SubnetId(pub String);

/// Configuration details of a sovereign subnet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubnetConfig {
    /// Human-readable name of the subnet
    pub name: String,
    /// Token used for transaction fees within the subnet (e.g., custom gas token)
    pub fee_token: String,
    /// Optional custom validators. If None, the subnet relies on the main Quantos validator set.
    pub custom_validators: Option<Vec<SubnetValidator>>,
    /// Multiplier for the finality fee paid to Quantos validators in QTS
    pub reward_multiplier: u64,
    /// [Option 1] STACC Security Leasing: Amount of $QTS collateral leased/locked to secure this subnet
    pub stacc_collateral_leased: u128,
    /// [Option 3] STACC Double-Staking: Minimum $QTS required to be staked on Quantos per custom validator
    pub min_double_stake_qts: u128,
}

/// A validator specifically registered for a sovereign subnet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubnetValidator {
    /// Validator address
    pub address: Address,
    /// Voting power / stake of the validator inside the subnet
    pub stake: u128,
    /// [Option 3] STACC Double-Staking: Amount of $QTS staked in the main Quantos protocol
    pub qts_double_stake: u128,
}

/// Sovereign Subnet manager
pub struct SubnetManager {
    subnets: Arc<RwLock<HashMap<SubnetId, SubnetConfig>>>,
}

impl SubnetManager {
    /// Create a new SubnetManager
    pub fn new() -> Self {
        Self {
            subnets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new sovereign subnet
    pub fn register_subnet(&self, id: SubnetId, config: SubnetConfig) -> Result<(), String> {
        let mut subnets = self.subnets.write();
        if subnets.contains_key(&id) {
            return Err(format!("Subnet with ID '{}' is already registered", id.0));
        }
        subnets.insert(id, config);
        Ok(())
    }

    /// Get the configuration of a subnet
    pub fn get_subnet(&self, id: &SubnetId) -> Option<SubnetConfig> {
        self.subnets.read().get(id).cloned()
    }

    /// Update the configuration of a subnet
    pub fn update_subnet(&self, id: &SubnetId, config: SubnetConfig) -> Result<(), String> {
        let mut subnets = self.subnets.write();
        if !subnets.contains_key(id) {
            return Err(format!("Subnet with ID '{}' does not exist", id.0));
        }
        subnets.insert(id.clone(), config);
        Ok(())
    }

    /// List all registered subnets
    pub fn list_subnets(&self) -> Vec<(SubnetId, SubnetConfig)> {
        self.subnets.read().iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    /// Verify a subnet checkpoint's metadata
    pub fn verify_subnet_checkpoint(&self, subnet_id: &SubnetId, checkpoint: &ExternalCheckpoint) -> Result<(), String> {
        let subnet = match self.get_subnet(subnet_id) {
            Some(s) => s,
            None => return Err(format!("Subnet '{}' not registered", subnet_id.0)),
        };

        // [Option 1] STACC Security Leasing Validation:
        // A sovereign subnet must lease a minimum amount of $QTS collateral to remain active.
        // The system minimum threshold is 100,000 QTS locked per month (represented with 18 decimals)
        let min_required_lease = 100_000 * 1_000_000_000_000_000_000u128;
        if subnet.stacc_collateral_leased < min_required_lease {
            return Err(format!(
                "Subnet '{}' has insufficient STACC collateral leased: {} QTS. Minimum required is 100,000 QTS locked per month.",
                subnet_id.0,
                subnet.stacc_collateral_leased / 1_000_000_000_000_000_000
            ));
        }

        // [Option 3] STACC Double-Staking Validation:
        // Verify that custom validators (if any) are maintaining their minimum required double-stake in $QTS on Quantos.
        if let Some(ref validators) = subnet.custom_validators {
            for val in validators {
                if val.qts_double_stake < subnet.min_double_stake_qts {
                    return Err(format!(
                        "Subnet validator 'QTS:{}' has insufficient double-stake: {} QTS. Required minimum per validator is {} QTS.",
                        hex::encode(val.address),
                        val.qts_double_stake / 1_000_000_000_000_000_000,
                        subnet.min_double_stake_qts / 1_000_000_000_000_000_000
                    ));
                }
            }
        }

        // Check if the checkpoint's ChainId corresponds to this subnet (must be Custom or match subnet)
        match &checkpoint.chain_id {
            ChainId::Custom(s) if s == &subnet_id.0 => {}
            _ => {
                return Err(format!("Checkpoint chain_id mismatch for subnet '{}'", subnet_id.0));
            }
        }

        Ok(())
    }
}

impl Default for SubnetManager {
    fn default() -> Self {
        Self::new()
    }
}
