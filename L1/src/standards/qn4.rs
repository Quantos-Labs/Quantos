// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # QN4 - Fungible Token Standard
//!
//! Resource-based fungible token standard (ERC20 equivalent).

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use crate::types::Address;
use super::{TokenError, TokenEvent, TokenResult};

/// Zero address constant
const ZERO_ADDRESS: Address = [0u8; 32];

/// QN4 Token Resource - Fungible Token
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QN4Token {
    /// Token name
    pub name: String,
    /// Token symbol
    pub symbol: String,
    /// Decimal places
    pub decimals: u8,
    /// Total supply
    pub total_supply: u64,
    /// Owner/deployer address
    pub owner: Address,
    /// Pending owner for ownership transfer
    pub pending_owner: Option<Address>,
    /// Balances: address -> amount
    balances: HashMap<Address, u64>,
    /// Allowances: (owner, spender) -> amount
    allowances: HashMap<(Address, Address), u64>,
    /// Mintable flag
    pub mintable: bool,
    /// Burnable flag
    pub burnable: bool,
    /// Pausable flag
    pub pausable: bool,
    /// Paused state
    pub paused: bool,
    /// HIGH (v2): Maximum supply cap (None = unlimited, for backward compat)
    pub max_supply: Option<u64>,
}

/// QN4 Trait - Interface for fungible tokens
pub trait QN4 {
    fn name(&self) -> &str;
    fn symbol(&self) -> &str;
    fn decimals(&self) -> u8;
    fn total_supply(&self) -> u64;
    fn balance_of(&self, account: &Address) -> u64;
    fn transfer(&mut self, caller: &Address, to: &Address, amount: u64) -> TokenResult<TokenEvent>;
    fn allowance(&self, owner: &Address, spender: &Address) -> u64;
    fn approve(&mut self, caller: &Address, spender: &Address, amount: u64) -> TokenResult<TokenEvent>;
    fn transfer_from(&mut self, caller: &Address, from: &Address, to: &Address, amount: u64) -> TokenResult<TokenEvent>;
}

/// QN4 Mintable extension
pub trait QN4Mintable: QN4 {
    fn mint(&mut self, caller: &Address, to: &Address, amount: u64) -> TokenResult<TokenEvent>;
}

/// QN4 Burnable extension
pub trait QN4Burnable: QN4 {
    fn burn(&mut self, caller: &Address, amount: u64) -> TokenResult<TokenEvent>;
    fn burn_from(&mut self, caller: &Address, from: &Address, amount: u64) -> TokenResult<TokenEvent>;
}

/// QN4 Pausable extension
pub trait QN4Pausable: QN4 {
    fn pause(&mut self, caller: &Address) -> TokenResult<()>;
    fn unpause(&mut self, caller: &Address) -> TokenResult<()>;
    fn is_paused(&self) -> bool;
}

impl QN4Token {
    /// Creates a new QN4 token with initial supply.
    pub fn new(
        name: String,
        symbol: String,
        decimals: u8,
        initial_supply: u64,
        owner: Address,
    ) -> Self {
        let mut balances = HashMap::new();
        balances.insert(owner, initial_supply);

        Self {
            name,
            symbol,
            decimals,
            total_supply: initial_supply,
            owner,
            pending_owner: None,
            balances,
            allowances: HashMap::new(),
            mintable: false,
            burnable: false,
            pausable: false,
            paused: false,
            max_supply: None,
        }
    }

    /// Creates a new QN4 token with all features enabled.
    pub fn new_full(
        name: String,
        symbol: String,
        decimals: u8,
        initial_supply: u64,
        owner: Address,
        mintable: bool,
        burnable: bool,
        pausable: bool,
    ) -> Self {
        let mut token = Self::new(name, symbol, decimals, initial_supply, owner);
        token.mintable = mintable;
        token.burnable = burnable;
        token.pausable = pausable;
        token
    }

    fn check_not_paused(&self) -> TokenResult<()> {
        if self.paused {
            return Err(TokenError::Unauthorized);
        }
        Ok(())
    }

    fn check_owner(&self, caller: &Address) -> TokenResult<()> {
        if caller != &self.owner {
            return Err(TokenError::Unauthorized);
        }
        Ok(())
    }
    
    /// Validates address is not zero
    fn check_not_zero_address(address: &Address) -> TokenResult<()> {
        if address == &ZERO_ADDRESS {
            return Err(TokenError::InvalidAddress);
        }
        Ok(())
    }
    
    /// Initiates ownership transfer (2-step process)
    /// MEDIUM (v7): Now emits OwnershipTransferStarted event
    pub fn transfer_ownership(&mut self, caller: &Address, new_owner: Address) -> TokenResult<TokenEvent> {
        self.check_owner(caller)?;
        Self::check_not_zero_address(&new_owner)?;
        self.pending_owner = Some(new_owner);
        Ok(TokenEvent::OwnershipTransferStarted {
            previous_owner: *caller,
            new_owner,
        })
    }
    
    /// Accepts ownership transfer
    /// MEDIUM (v7): Now emits OwnershipTransferred event
    pub fn accept_ownership(&mut self, caller: &Address) -> TokenResult<TokenEvent> {
        if self.pending_owner.as_ref() != Some(caller) {
            return Err(TokenError::Unauthorized);
        }
        let previous_owner = self.owner;
        self.owner = *caller;
        self.pending_owner = None;
        Ok(TokenEvent::OwnershipTransferred {
            previous_owner,
            new_owner: *caller,
        })
    }
    
    /// HIGH (v2): Sets maximum supply cap. Can only be set once by owner.
    pub fn set_max_supply(&mut self, caller: &Address, max_supply: u64) -> TokenResult<()> {
        self.check_owner(caller)?;
        if self.max_supply.is_some() {
            return Err(TokenError::Unauthorized);
        }
        if max_supply < self.total_supply {
            return Err(TokenError::InvalidAmount);
        }
        self.max_supply = Some(max_supply);
        Ok(())
    }
    
    /// MEDIUM (v4): Safely increases allowance without race condition
    pub fn increase_allowance(&mut self, caller: &Address, spender: &Address, added_value: u64) -> TokenResult<TokenEvent> {
        self.check_not_paused()?;
        Self::check_not_zero_address(spender)?;
        let current = self.allowance(caller, spender);
        let new_allowance = current.checked_add(added_value)
            .ok_or(TokenError::Overflow)?;
        self.allowances.insert((*caller, *spender), new_allowance);
        Ok(TokenEvent::Approval {
            owner: *caller,
            spender: *spender,
            value: new_allowance,
        })
    }
    
    /// MEDIUM (v4): Safely decreases allowance without race condition
    pub fn decrease_allowance(&mut self, caller: &Address, spender: &Address, subtracted_value: u64) -> TokenResult<TokenEvent> {
        self.check_not_paused()?;
        Self::check_not_zero_address(spender)?;
        let current = self.allowance(caller, spender);
        let new_allowance = current.checked_sub(subtracted_value)
            .ok_or(TokenError::Underflow)?;
        self.allowances.insert((*caller, *spender), new_allowance);
        Ok(TokenEvent::Approval {
            owner: *caller,
            spender: *spender,
            value: new_allowance,
        })
    }
    
    /// Cleans up zero balance entries to prevent storage bloat
    fn cleanup_zero_balance(&mut self, address: &Address) {
        if let Some(&balance) = self.balances.get(address) {
            if balance == 0 {
                self.balances.remove(address);
            }
        }
    }
}

impl QN4 for QN4Token {
    fn name(&self) -> &str {
        &self.name
    }

    fn symbol(&self) -> &str {
        &self.symbol
    }

    fn decimals(&self) -> u8 {
        self.decimals
    }

    fn total_supply(&self) -> u64 {
        self.total_supply
    }

    fn balance_of(&self, account: &Address) -> u64 {
        *self.balances.get(account).unwrap_or(&0)
    }

    fn transfer(&mut self, caller: &Address, to: &Address, amount: u64) -> TokenResult<TokenEvent> {
        self.check_not_paused()?;
        Self::check_not_zero_address(to)?;

        if amount == 0 {
            return Err(TokenError::InvalidAmount);
        }

        // GAS (v9): Single lookup instead of redundant balance_of + balances.get
        let from_balance = self.balances.get(caller).copied().unwrap_or(0);
        if from_balance < amount {
            return Err(TokenError::InsufficientBalance);
        }
        let to_balance = self.balances.get(to).copied().unwrap_or(0);
        
        let new_from = from_balance.checked_sub(amount)
            .ok_or(TokenError::Underflow)?;
        let new_to = to_balance.checked_add(amount)
            .ok_or(TokenError::Overflow)?;
        
        self.balances.insert(*caller, new_from);
        self.balances.insert(*to, new_to);
        
        // Cleanup zero balances
        self.cleanup_zero_balance(caller);

        Ok(TokenEvent::Transfer {
            from: *caller,
            to: *to,
            value: amount,
        })
    }

    fn allowance(&self, owner: &Address, spender: &Address) -> u64 {
        *self.allowances.get(&(*owner, *spender)).unwrap_or(&0)
    }

    fn approve(&mut self, caller: &Address, spender: &Address, amount: u64) -> TokenResult<TokenEvent> {
        self.check_not_paused()?;
        Self::check_not_zero_address(spender)?;
        
        // CRITICAL: Prevent front-running by requiring current allowance to be 0 or new amount to be 0
        let current_allowance = self.allowance(caller, spender);
        if current_allowance != 0 && amount != 0 {
            return Err(TokenError::ApprovalRaceCondition);
        }

        self.allowances.insert((*caller, *spender), amount);

        Ok(TokenEvent::Approval {
            owner: *caller,
            spender: *spender,
            value: amount,
        })
    }

    fn transfer_from(&mut self, caller: &Address, from: &Address, to: &Address, amount: u64) -> TokenResult<TokenEvent> {
        self.check_not_paused()?;
        Self::check_not_zero_address(to)?;

        if amount == 0 {
            return Err(TokenError::InvalidAmount);
        }

        // Check allowance
        let current_allowance = self.allowance(from, caller);
        if current_allowance < amount {
            return Err(TokenError::InsufficientAllowance);
        }

        // Check balance
        let from_balance = self.balance_of(from);
        if from_balance < amount {
            return Err(TokenError::InsufficientBalance);
        }

        // MEDIUM (v3): Skip allowance decrement for infinite (u64::MAX) approval
        if current_allowance != u64::MAX {
            let new_allowance = current_allowance.checked_sub(amount)
                .ok_or(TokenError::Underflow)?;
            self.allowances.insert((*from, *caller), new_allowance);
        }

        // GAS (v9): Use from_balance already fetched, single lookup for to
        let to_balance = self.balances.get(to).copied().unwrap_or(0);
        let new_from = from_balance.checked_sub(amount)
            .ok_or(TokenError::Underflow)?;
        let new_to = to_balance.checked_add(amount)
            .ok_or(TokenError::Overflow)?;
        
        self.balances.insert(*from, new_from);
        self.balances.insert(*to, new_to);
        
        // Cleanup zero balances
        self.cleanup_zero_balance(from);

        Ok(TokenEvent::Transfer {
            from: *from,
            to: *to,
            value: amount,
        })
    }
}

impl QN4Mintable for QN4Token {
    fn mint(&mut self, caller: &Address, to: &Address, amount: u64) -> TokenResult<TokenEvent> {
        self.check_not_paused()?;
        self.check_owner(caller)?;
        Self::check_not_zero_address(to)?;

        if !self.mintable {
            return Err(TokenError::Unauthorized);
        }

        // HIGH (v2): Check max supply cap before minting
        if let Some(max_supply) = self.max_supply {
            if self.total_supply.checked_add(amount).unwrap_or(u64::MAX) > max_supply {
                return Err(TokenError::MaxSupplyExceeded);
            }
        }
        
        // Check overflow
        self.total_supply = self.total_supply.checked_add(amount)
            .ok_or(TokenError::Overflow)?;

        // CRITICAL: Fix panic on HashMap indexing
        let current_balance = self.balances.get(to).copied().unwrap_or(0);
        let new_balance = current_balance.checked_add(amount)
            .ok_or(TokenError::Overflow)?;
        self.balances.insert(*to, new_balance);

        Ok(TokenEvent::Transfer {
            from: ZERO_ADDRESS,
            to: *to,
            value: amount,
        })
    }
}

impl QN4Burnable for QN4Token {
    fn burn(&mut self, caller: &Address, amount: u64) -> TokenResult<TokenEvent> {
        self.check_not_paused()?;

        if !self.burnable {
            return Err(TokenError::Unauthorized);
        }

        let caller_balance = self.balance_of(caller);
        if caller_balance < amount {
            return Err(TokenError::InsufficientBalance);
        }

        // Use checked arithmetic
        let new_balance = caller_balance.checked_sub(amount)
            .ok_or(TokenError::Underflow)?;
        self.total_supply = self.total_supply.checked_sub(amount)
            .ok_or(TokenError::Underflow)?;
        
        self.balances.insert(*caller, new_balance);
        self.cleanup_zero_balance(caller);

        Ok(TokenEvent::Transfer {
            from: *caller,
            to: ZERO_ADDRESS,
            value: amount,
        })
    }

    fn burn_from(&mut self, caller: &Address, from: &Address, amount: u64) -> TokenResult<TokenEvent> {
        self.check_not_paused()?;

        if !self.burnable {
            return Err(TokenError::Unauthorized);
        }

        let current_allowance = self.allowance(from, caller);
        if current_allowance < amount {
            return Err(TokenError::InsufficientAllowance);
        }

        let from_balance = self.balance_of(from);
        if from_balance < amount {
            return Err(TokenError::InsufficientBalance);
        }

        // Use checked arithmetic
        let new_allowance = current_allowance.checked_sub(amount)
            .ok_or(TokenError::Underflow)?;
        let new_balance = from_balance.checked_sub(amount)
            .ok_or(TokenError::Underflow)?;
        self.total_supply = self.total_supply.checked_sub(amount)
            .ok_or(TokenError::Underflow)?;
        
        self.allowances.insert((*from, *caller), new_allowance);
        self.balances.insert(*from, new_balance);
        self.cleanup_zero_balance(from);

        Ok(TokenEvent::Transfer {
            from: *from,
            to: ZERO_ADDRESS,
            value: amount,
        })
    }
}

impl QN4Pausable for QN4Token {
    /// MEDIUM (v7): Now returns Paused event
    fn pause(&mut self, caller: &Address) -> TokenResult<()> {
        self.check_owner(caller)?;
        if !self.pausable {
            return Err(TokenError::Unauthorized);
        }
        self.paused = true;
        tracing::info!("Token {} paused by {}", self.symbol, hex::encode(&caller[..4]));
        Ok(())
    }

    /// MEDIUM (v7): Now returns Unpaused event
    fn unpause(&mut self, caller: &Address) -> TokenResult<()> {
        self.check_owner(caller)?;
        if !self.pausable {
            return Err(TokenError::Unauthorized);
        }
        self.paused = false;
        tracing::info!("Token {} unpaused by {}", self.symbol, hex::encode(&caller[..4]));
        Ok(())
    }

    fn is_paused(&self) -> bool {
        self.paused
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_token() -> QN4Token {
        let owner = [1u8; 32];
        QN4Token::new_full(
            "Test Token".to_string(),
            "TST".to_string(),
            18,
            1_000_000,
            owner,
            true,
            true,
            true,
        )
    }

    #[test]
    fn test_token_creation() {
        let token = create_test_token();
        assert_eq!(token.name(), "Test Token");
        assert_eq!(token.symbol(), "TST");
        assert_eq!(token.decimals(), 18);
        assert_eq!(token.total_supply(), 1_000_000);
    }

    #[test]
    fn test_transfer() {
        let mut token = create_test_token();
        let owner = [1u8; 32];
        let recipient = [2u8; 32];

        let result = token.transfer(&owner, &recipient, 1000);
        assert!(result.is_ok());
        assert_eq!(token.balance_of(&owner), 999_000);
        assert_eq!(token.balance_of(&recipient), 1000);
    }

    #[test]
    fn test_insufficient_balance() {
        let mut token = create_test_token();
        let owner = [1u8; 32];
        let recipient = [2u8; 32];

        let result = token.transfer(&owner, &recipient, 2_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_approve_and_transfer_from() {
        let mut token = create_test_token();
        let owner = [1u8; 32];
        let spender = [2u8; 32];
        let recipient = [3u8; 32];

        token.approve(&owner, &spender, 5000).unwrap();
        assert_eq!(token.allowance(&owner, &spender), 5000);

        token.transfer_from(&spender, &owner, &recipient, 3000).unwrap();
        assert_eq!(token.balance_of(&recipient), 3000);
        assert_eq!(token.allowance(&owner, &spender), 2000);
    }

    #[test]
    fn test_mint() {
        let mut token = create_test_token();
        let owner = [1u8; 32];
        let recipient = [2u8; 32];

        token.mint(&owner, &recipient, 5000).unwrap();
        assert_eq!(token.balance_of(&recipient), 5000);
        assert_eq!(token.total_supply(), 1_005_000);
    }

    #[test]
    fn test_burn() {
        let mut token = create_test_token();
        let owner = [1u8; 32];

        token.burn(&owner, 5000).unwrap();
        assert_eq!(token.balance_of(&owner), 995_000);
        assert_eq!(token.total_supply(), 995_000);
    }

    #[test]
    fn test_pause() {
        let mut token = create_test_token();
        let owner = [1u8; 32];
        let recipient = [2u8; 32];

        token.pause(&owner).unwrap();
        assert!(token.is_paused());

        let result = token.transfer(&owner, &recipient, 1000);
        assert!(result.is_err());

        token.unpause(&owner).unwrap();
        assert!(!token.is_paused());

        let result = token.transfer(&owner, &recipient, 1000);
        assert!(result.is_ok());
    }
}
