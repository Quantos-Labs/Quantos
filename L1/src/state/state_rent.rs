//! # State Rent Model
//!
//! Economic model for on-chain storage with rent-based pricing.
//! Incentivizes efficient storage usage and enables sustainable state growth.
//!
//! ## Features
//!
//! - **Rent Per Byte**: Continuous rent based on storage size
//! - **Deposit System**: Prepaid rent with refund on deletion
//! - **Expiration**: Automatic cleanup of expired entries
//! - **Exemption Thresholds**: Minimum balance for rent-free storage
//! - **Grace Periods**: Time before expiration enforcement

use std::collections::HashMap;
use parking_lot::{Mutex, RwLock};

use crate::types::{Address, Amount};
use crate::state::{StateError, StateResult};

/// Slot number for rent calculation
pub type Slot = u64;

/// Rent configuration
#[derive(Clone, Debug)]
pub struct RentConfig {
    /// Rent rate in lamports per byte per epoch
    pub lamports_per_byte_epoch: u64,
    /// Minimum balance for rent exemption (2 years worth)
    pub exemption_threshold_years: f64,
    /// Slots per epoch for rent calculation
    pub slots_per_epoch: u64,
    /// Grace period in epochs before expiration
    pub grace_period_epochs: u64,
    /// Minimum account size for rent calculation
    pub min_account_size: u64,
    /// Account metadata overhead
    pub account_overhead: u64,
    /// Enable rent collection
    pub enabled: bool,
}

impl Default for RentConfig {
    fn default() -> Self {
        Self {
            lamports_per_byte_epoch: 3480,  // ~$0.01 per KB per year at $100/token
            exemption_threshold_years: 2.0,
            slots_per_epoch: 432000,         // ~2 days
            grace_period_epochs: 2,
            min_account_size: 128,
            account_overhead: 128,           // Metadata overhead
            enabled: true,
        }
    }
}

/// Rent status for an account
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RentStatus {
    /// Account is rent-exempt (has sufficient balance)
    Exempt,
    /// Account is paying rent
    Paying,
    /// Account is in grace period (will expire soon)
    GracePeriod,
    /// Account has expired (can be collected)
    Expired,
}

/// Account storage metadata for rent tracking
#[derive(Clone, Debug)]
pub struct StorageAccount {
    /// Account address
    pub address: Address,
    /// Data size in bytes
    pub data_size: u64,
    /// Current balance
    pub balance: Amount,
    /// Rent deposit paid
    pub rent_deposit: Amount,
    /// Last rent collection slot
    pub last_rent_slot: Slot,
    /// Account creation slot
    pub created_slot: Slot,
    /// Is rent exempt
    pub rent_exempt: bool,
    /// Expiration slot (if not exempt)
    pub expires_at: Option<Slot>,
}

impl StorageAccount {
    pub fn new(address: Address, data_size: u64, balance: Amount, slot: Slot) -> Self {
        Self {
            address,
            data_size,
            balance,
            rent_deposit: Amount::zero(),
            last_rent_slot: slot,
            created_slot: slot,
            rent_exempt: false,
            expires_at: None,
        }
    }
    
    /// Total storage size including overhead
    pub fn total_size(&self, overhead: u64) -> u64 {
        self.data_size + overhead
    }
}

/// Rent calculation result
#[derive(Debug, Clone)]
pub struct RentCalculation {
    /// Rent due for the period
    pub rent_due: Amount,
    /// New balance after rent
    pub new_balance: Amount,
    /// Rent status
    pub status: RentStatus,
    /// Slots until expiration (if applicable)
    pub slots_until_expiration: Option<u64>,
    /// Minimum balance for exemption
    pub exemption_balance: Amount,
}

/// Rent collector for batch processing
pub struct RentCollector {
    config: RentConfig,
    /// Current slot
    current_slot: RwLock<Slot>,
    /// Accounts being tracked
    accounts: RwLock<HashMap<Address, StorageAccount>>,
    /// Expired accounts pending collection
    expired_accounts: Mutex<Vec<Address>>,
    /// Total rent collected
    total_collected: Mutex<Amount>,
    /// Accounts collected (removed)
    accounts_collected: Mutex<u64>,
}

impl RentCollector {
    pub fn new(config: RentConfig) -> Self {
        Self {
            config,
            current_slot: RwLock::new(0),
            accounts: RwLock::new(HashMap::new()),
            expired_accounts: Mutex::new(Vec::new()),
            total_collected: Mutex::new(Amount::zero()),
            accounts_collected: Mutex::new(0),
        }
    }
    
    /// Updates current slot
    pub fn set_slot(&self, slot: Slot) {
        *self.current_slot.write() = slot;
    }
    
    /// Gets current slot
    pub fn current_slot(&self) -> Slot {
        *self.current_slot.read()
    }
    
    /// Calculates minimum balance for rent exemption
    pub fn minimum_balance(&self, data_size: u64) -> Amount {
        let total_size = data_size + self.config.account_overhead;
        let rent_per_epoch = total_size * self.config.lamports_per_byte_epoch;
        let epochs_per_year = 365.0 * 24.0 * 60.0 * 60.0 / 
            (self.config.slots_per_epoch as f64 * 0.4); // ~400ms slots
        
        let years = self.config.exemption_threshold_years;
        let exemption = (rent_per_epoch as f64 * epochs_per_year * years) as u128;
        
        Amount(exemption)
    }
    
    /// Calculates rent due for an account
    pub fn calculate_rent(&self, account: &StorageAccount, current_slot: Slot) -> RentCalculation {
        // Check exemption first
        let exemption_balance = self.minimum_balance(account.data_size);
        
        if account.balance.0 >= exemption_balance.0 {
            return RentCalculation {
                rent_due: Amount::zero(),
                new_balance: account.balance.clone(),
                status: RentStatus::Exempt,
                slots_until_expiration: None,
                exemption_balance,
            };
        }
        
        // Calculate epochs since last collection
        let slots_elapsed = current_slot.saturating_sub(account.last_rent_slot);
        let epochs_elapsed = slots_elapsed / self.config.slots_per_epoch;
        
        if epochs_elapsed == 0 {
            return RentCalculation {
                rent_due: Amount::zero(),
                new_balance: account.balance.clone(),
                status: RentStatus::Paying,
                slots_until_expiration: account.expires_at.map(|e| e.saturating_sub(current_slot)),
                exemption_balance,
            };
        }
        
        // MEDIUM (w9): Cast to u128 BEFORE multiplication to prevent u64 overflow
        let total_size = account.data_size as u128 + self.config.account_overhead as u128;
        let rent_per_epoch = total_size * self.config.lamports_per_byte_epoch as u128;
        let rent_due = Amount(rent_per_epoch.saturating_mul(epochs_elapsed as u128));
        
        // Deduct rent
        let (new_balance, status, expires_at) = if account.balance.0 >= rent_due.0 {
            let new_bal = account.balance.checked_sub(&rent_due)
                .unwrap_or(Amount::zero());
            (new_bal, RentStatus::Paying, None)
        } else {
            // Not enough balance - enter grace period or expire
            let deficit = rent_due.checked_sub(&account.balance)
                .unwrap_or(Amount::zero());
            let deficit_epochs = deficit.0 / rent_per_epoch.max(1);
            
            let grace_slots = self.config.grace_period_epochs * self.config.slots_per_epoch;
            let expiration = current_slot + grace_slots;
            
            if deficit_epochs > self.config.grace_period_epochs as u128 {
                (Amount::zero(), RentStatus::Expired, Some(current_slot))
            } else {
                (Amount::zero(), RentStatus::GracePeriod, Some(expiration))
            }
        };
        
        RentCalculation {
            rent_due,
            new_balance,
            status,
            slots_until_expiration: expires_at.map(|e| e.saturating_sub(current_slot)),
            exemption_balance,
        }
    }
    
    /// Registers an account for rent tracking
    pub fn register_account(&self, mut account: StorageAccount) -> StateResult<RentCalculation> {
        let current_slot = self.current_slot();
        
        // Check if rent exempt
        let exemption_balance = self.minimum_balance(account.data_size);
        account.rent_exempt = account.balance.0 >= exemption_balance.0;
        
        if !account.rent_exempt {
            // Calculate expiration
            let total_size = account.data_size + self.config.account_overhead;
            let rent_per_epoch = total_size * self.config.lamports_per_byte_epoch;
            let epochs_covered = account.balance.0 as u64 / rent_per_epoch.max(1);
            let expiration = current_slot + (epochs_covered * self.config.slots_per_epoch);
            account.expires_at = Some(expiration);
        }
        
        let calc = self.calculate_rent(&account, current_slot);
        
        self.accounts.write().insert(account.address, account);
        
        Ok(calc)
    }
    
    /// Collects rent from an account
    pub fn collect_rent(&self, address: &Address) -> StateResult<RentCalculation> {
        let current_slot = self.current_slot();
        let mut accounts = self.accounts.write();
        
        let account = accounts.get_mut(address)
            .ok_or_else(|| StateError::AccountNotFound(hex::encode(address)))?;
        
        let calc = self.calculate_rent(account, current_slot);
        
        // Update account
        account.balance = calc.new_balance.clone();
        account.last_rent_slot = current_slot;
        account.rent_exempt = calc.status == RentStatus::Exempt;
        
        if calc.status == RentStatus::Expired {
            self.expired_accounts.lock().push(*address);
        } else if calc.status == RentStatus::GracePeriod {
            account.expires_at = Some(current_slot + 
                self.config.grace_period_epochs * self.config.slots_per_epoch);
        }
        
        // Track collection
        if calc.rent_due.0 > 0 {
            let mut total = self.total_collected.lock();
            *total = total.checked_add(&calc.rent_due).unwrap_or(total.clone());
        }
        
        Ok(calc)
    }
    
    /// Collects rent from all accounts
    pub fn collect_all_rent(&self) -> Vec<(Address, RentCalculation)> {
        let current_slot = self.current_slot();
        let mut accounts = self.accounts.write();
        let mut results = Vec::new();
        
        for (address, account) in accounts.iter_mut() {
            let calc = self.calculate_rent(account, current_slot);
            
            account.balance = calc.new_balance.clone();
            account.last_rent_slot = current_slot;
            account.rent_exempt = calc.status == RentStatus::Exempt;
            
            if calc.status == RentStatus::Expired {
                self.expired_accounts.lock().push(*address);
            }
            
            if calc.rent_due.0 > 0 {
                let mut total = self.total_collected.lock();
                *total = total.checked_add(&calc.rent_due).unwrap_or(total.clone());
            }
            
            results.push((*address, calc));
        }
        
        results
    }
    
    /// Removes expired accounts and returns reclaimed storage
    pub fn collect_expired(&self) -> Vec<StorageAccount> {
        let mut expired = self.expired_accounts.lock();
        let addresses: Vec<_> = expired.drain(..).collect();
        drop(expired);
        
        let mut accounts = self.accounts.write();
        let mut collected = Vec::new();
        
        for address in addresses {
            if let Some(account) = accounts.remove(&address) {
                collected.push(account);
                *self.accounts_collected.lock() += 1;
            }
        }
        
        collected
    }
    
    /// Deposits rent for an account
    pub fn deposit_rent(&self, address: &Address, amount: Amount) -> StateResult<RentCalculation> {
        let mut accounts = self.accounts.write();
        
        let account = accounts.get_mut(address)
            .ok_or_else(|| StateError::AccountNotFound(hex::encode(address)))?;
        
        // Add to balance
        account.balance = account.balance.checked_add(&amount)
            .ok_or(StateError::ArithmeticOverflow)?;
        account.rent_deposit = account.rent_deposit.checked_add(&amount)
            .ok_or(StateError::ArithmeticOverflow)?;
        
        // Recalculate status
        let current_slot = self.current_slot();
        let calc = self.calculate_rent(account, current_slot);
        
        // Update exemption status
        account.rent_exempt = calc.status == RentStatus::Exempt;
        if account.rent_exempt {
            account.expires_at = None;
        }
        
        Ok(calc)
    }
    
    /// Updates account data size and recalculates rent
    pub fn update_data_size(&self, address: &Address, new_size: u64) -> StateResult<RentCalculation> {
        let mut accounts = self.accounts.write();
        
        let account = accounts.get_mut(address)
            .ok_or_else(|| StateError::AccountNotFound(hex::encode(address)))?;
        
        account.data_size = new_size;
        
        // Recalculate
        let current_slot = self.current_slot();
        let calc = self.calculate_rent(account, current_slot);
        
        account.rent_exempt = calc.status == RentStatus::Exempt;
        
        Ok(calc)
    }
    
    /// Returns statistics
    pub fn stats(&self) -> RentStats {
        let accounts = self.accounts.read();
        
        let total_accounts = accounts.len() as u64;
        let exempt_accounts = accounts.values().filter(|a| a.rent_exempt).count() as u64;
        let total_storage: u64 = accounts.values().map(|a| a.data_size).sum();
        
        RentStats {
            total_accounts,
            exempt_accounts,
            paying_accounts: total_accounts - exempt_accounts,
            total_storage_bytes: total_storage,
            total_rent_collected: self.total_collected.lock().clone(),
            accounts_collected: *self.accounts_collected.lock(),
            pending_expired: self.expired_accounts.lock().len() as u64,
        }
    }
}

/// Rent statistics
#[derive(Debug, Clone)]
pub struct RentStats {
    pub total_accounts: u64,
    pub exempt_accounts: u64,
    pub paying_accounts: u64,
    pub total_storage_bytes: u64,
    pub total_rent_collected: Amount,
    pub accounts_collected: u64,
    pub pending_expired: u64,
}

/// Storage pricing for different data types
#[derive(Clone, Debug)]
pub struct StoragePricing {
    /// Base rent config
    pub base_config: RentConfig,
    /// Multiplier for contract code
    pub code_multiplier: f64,
    /// Multiplier for contract storage
    pub contract_storage_multiplier: f64,
    /// Multiplier for NFT metadata
    pub nft_multiplier: f64,
}

impl Default for StoragePricing {
    fn default() -> Self {
        Self {
            base_config: RentConfig::default(),
            code_multiplier: 0.5,           // Cheaper for code (rarely changes)
            contract_storage_multiplier: 1.5, // More expensive for mutable storage
            nft_multiplier: 0.8,            // Slightly cheaper for NFTs
        }
    }
}

impl StoragePricing {
    /// Calculates rent for different storage types
    pub fn calculate_rent(&self, storage_type: StorageType, size: u64, epochs: u64) -> Amount {
        let base_rate = self.base_config.lamports_per_byte_epoch;
        
        let multiplier = match storage_type {
            StorageType::Account => 1.0,
            StorageType::ContractCode => self.code_multiplier,
            StorageType::ContractStorage => self.contract_storage_multiplier,
            StorageType::NFTMetadata => self.nft_multiplier,
        };
        
        let rate = (base_rate as f64 * multiplier) as u64;
        let total_size = size as u128 + self.base_config.account_overhead as u128;
        
        // MEDIUM (w9): Use u128 arithmetic to prevent overflow
        Amount((rate as u128).saturating_mul(total_size).saturating_mul(epochs as u128))
    }
}

/// Types of storage for pricing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageType {
    Account,
    ContractCode,
    ContractStorage,
    NFTMetadata,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rent_exemption() {
        let config = RentConfig::default();
        let collector = RentCollector::new(config);
        
        let min_balance = collector.minimum_balance(1000); // 1KB account
        
        // Account with enough balance should be exempt
        let account = StorageAccount::new(
            [1u8; 32],
            1000,
            min_balance.clone(),
            0,
        );
        
        let calc = collector.calculate_rent(&account, 1000000);
        assert_eq!(calc.status, RentStatus::Exempt);
        assert_eq!(calc.rent_due, Amount::zero());
    }
    
    #[test]
    fn test_rent_collection() {
        let config = RentConfig {
            slots_per_epoch: 100,
            lamports_per_byte_epoch: 100,
            ..Default::default()
        };
        let collector = RentCollector::new(config);
        collector.set_slot(1000);
        
        // Account with small balance
        let account = StorageAccount::new(
            [1u8; 32],
            100,
            Amount(10000),
            0, // Created at slot 0
        );
        
        collector.register_account(account).unwrap();
        
        // Move forward 10 epochs
        collector.set_slot(1000);
        
        let calc = collector.collect_rent(&[1u8; 32]).unwrap();
        
        // Should have collected some rent
        assert!(calc.rent_due.0 > 0);
    }
    
    #[test]
    fn test_storage_pricing() {
        let pricing = StoragePricing::default();
        
        let account_rent = pricing.calculate_rent(StorageType::Account, 1000, 10);
        let code_rent = pricing.calculate_rent(StorageType::ContractCode, 1000, 10);
        let storage_rent = pricing.calculate_rent(StorageType::ContractStorage, 1000, 10);
        
        // Code should be cheaper than accounts
        assert!(code_rent.0 < account_rent.0);
        // Contract storage should be more expensive
        assert!(storage_rent.0 > account_rent.0);
    }
}
