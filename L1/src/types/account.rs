// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use serde::{Deserialize, Serialize};
use crate::types::{Address, Amount, Hash, hash_data};

/// Maximum commission rate (100% = 10000 basis points)
const MAX_COMMISSION_RATE: u16 = 10000;
/// Maximum validators in a set
const MAX_VALIDATORS: usize = 1000;
/// MEDIUM (z9): Minimum VRF public key size
const MIN_VRF_KEY_SIZE: usize = 32;
/// MEDIUM (z9): Maximum VRF public key size
const MAX_VRF_KEY_SIZE: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub address: Address,
    pub balance: Amount,
    pub nonce: u64,
    pub code_hash: Option<Hash>,
    pub storage_root: Hash,
    pub stake: Amount,
    pub is_validator: bool,
}

impl Account {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            balance: Amount::zero(),
            nonce: 0,
            code_hash: None,
            storage_root: [0u8; 32],
            stake: Amount::zero(),
            is_validator: false,
        }
    }

    pub fn with_balance(address: Address, balance: Amount) -> Self {
        Self {
            address,
            balance,
            nonce: 0,
            code_hash: None,
            storage_root: [0u8; 32],
            stake: Amount::zero(),
            is_validator: false,
        }
    }

    pub fn hash(&self) -> Hash {
        // CRITICAL: Use deterministic serialization instead of bincode
        let mut data = Vec::new();
        data.extend_from_slice(&self.address);
        data.extend_from_slice(&self.balance.0.to_le_bytes());
        data.extend_from_slice(&self.nonce.to_le_bytes());
        if let Some(code_hash) = &self.code_hash {
            data.extend_from_slice(code_hash);
        }
        data.extend_from_slice(&self.storage_root);
        data.extend_from_slice(&self.stake.0.to_le_bytes());
        data.push(self.is_validator as u8);
        hash_data(&data)
    }

    /// MEDIUM (z8): Use checked increment to prevent nonce overflow/replay
    pub fn increment_nonce(&mut self) -> Result<(), String> {
        self.nonce = self.nonce.checked_add(1)
            .ok_or_else(|| "Nonce overflow: account has reached maximum nonce".to_string())?;
        Ok(())
    }

    pub fn add_balance(&mut self, amount: &Amount) -> bool {
        if let Some(new_balance) = self.balance.checked_add(amount) {
            self.balance = new_balance;
            true
        } else {
            false
        }
    }

    pub fn sub_balance(&mut self, amount: &Amount) -> bool {
        if let Some(new_balance) = self.balance.checked_sub(amount) {
            self.balance = new_balance;
            true
        } else {
            false
        }
    }

    /// HIGH (z6): Atomic staking — compute both new values before mutating
    pub fn add_stake(&mut self, amount: &Amount) -> bool {
        let new_stake = match self.stake.checked_add(amount) {
            Some(s) => s,
            None => return false,
        };
        let new_balance = match self.balance.checked_sub(amount) {
            Some(b) => b,
            None => return false,
        };
        // Apply both atomically — no partial mutation on failure
        self.stake = new_stake;
        self.balance = new_balance;
        true
    }

    pub fn remove_stake(&mut self, amount: &Amount) -> bool {
        if let Some(new_stake) = self.stake.checked_sub(amount) {
            self.stake = new_stake;
            self.add_balance(amount)
        } else {
            false
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Validator {
    pub address: Address,
    pub public_key: Vec<u8>,
    /// ML-DSA-65 public key used for checkpoint/finality signatures.
    #[serde(default)]
    pub finality_public_key: Vec<u8>,
    pub stake: Amount,
    pub commission_rate: u16,
    pub active: bool,
    pub jailed: bool,
    pub slash_count: u32,
    pub last_active_slot: u64,
    pub vrf_public_key: Vec<u8>,
}

impl Validator {
    /// MEDIUM (z9): Validates key sizes before constructing Validator
    pub fn new(address: Address, public_key: Vec<u8>, stake: Amount, vrf_public_key: Vec<u8>) -> Result<Self, String> {
        if vrf_public_key.len() < MIN_VRF_KEY_SIZE || vrf_public_key.len() > MAX_VRF_KEY_SIZE {
            return Err(format!(
                "Invalid VRF public key size: {} (expected {}-{} bytes)",
                vrf_public_key.len(), MIN_VRF_KEY_SIZE, MAX_VRF_KEY_SIZE
            ));
        }
        if vrf_public_key.iter().all(|&b| b == 0) {
            return Err("VRF public key is all zeros".to_string());
        }
        
        Ok(Self {
            address,
            public_key,
            finality_public_key: Vec::new(),
            stake,
            commission_rate: 500,
            active: true,
            jailed: false,
            slash_count: 0,
            last_active_slot: 0,
            vrf_public_key,
        })
    }

    pub(crate) fn slash(&mut self, percentage: u16) -> Result<Amount, String> {
        if percentage > MAX_COMMISSION_RATE {
            return Err(format!("Slash percentage {} exceeds maximum {}", percentage, MAX_COMMISSION_RATE));
        }
        
        let percentage_u128 = percentage as u128;
        let slash_amount = self.stake.0
            .checked_mul(percentage_u128)
            .and_then(|v| v.checked_div(10000))
            .map(Amount)
            .unwrap_or(Amount::zero());
        
        if let Some(new_stake) = self.stake.checked_sub(&slash_amount) {
            self.stake = new_stake;
            self.slash_count = self.slash_count.saturating_add(1);
            if self.slash_count >= 3 {
                self.jailed = true;
                self.active = false;
            }
            Ok(slash_amount)
        } else {
            Ok(Amount::zero())
        }
    }
    
    pub fn set_commission_rate(&mut self, rate: u16) -> Result<(), String> {
        if rate > MAX_COMMISSION_RATE {
            return Err(format!("Commission rate {} exceeds maximum {}", rate, MAX_COMMISSION_RATE));
        }
        self.commission_rate = rate;
        Ok(())
    }

    pub fn effective_stake(&self) -> u128 {
        if self.active && !self.jailed {
            self.stake.0
        } else {
            0
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub validators: Vec<Validator>,
    pub total_stake: Amount,
    pub epoch: u64,
}

impl ValidatorSet {
    pub fn new() -> Self {
        Self {
            validators: Vec::new(),
            total_stake: Amount::zero(),
            epoch: 0,
        }
    }

    pub fn add_validator(&mut self, validator: Validator) -> Result<(), String> {
        if self.validators.len() >= MAX_VALIDATORS {
            return Err(format!("Validator set full: {} validators", MAX_VALIDATORS));
        }
        
        if self.validators.iter().any(|v| v.address == validator.address) {
            return Err("Validator already exists".to_string());
        }
        
        self.total_stake = self.total_stake.checked_add(&validator.stake)
            .ok_or("Total stake overflow")?;
        self.validators.push(validator);
        Ok(())
    }
    
    pub(crate) fn slash_validator(&mut self, address: &Address, percentage: u16) -> Result<Amount, String> {
        let validator = self.validators.iter_mut()
            .find(|v| &v.address == address)
            .ok_or("Validator not found")?;
        
        let slashed_amount = validator.slash(percentage)?;
        
        self.total_stake = self.total_stake.checked_sub(&slashed_amount)
            .unwrap_or(Amount::zero());
        
        Ok(slashed_amount)
    }

    pub fn get_validator(&self, address: &Address) -> Option<&Validator> {
        self.validators.iter().find(|v| &v.address == address)
    }

    pub fn get_validator_mut(&mut self, address: &Address) -> Option<&mut Validator> {
        self.validators.iter_mut().find(|v| &v.address == address)
    }

    pub fn active_validators(&self) -> Vec<&Validator> {
        self.validators.iter().filter(|v| v.active && !v.jailed).collect()
    }

    pub fn total_active_stake(&self) -> u128 {
        self.validators.iter().map(|v| v.effective_stake()).sum()
    }
}

impl Default for ValidatorSet {
    fn default() -> Self {
        Self::new()
    }
}
