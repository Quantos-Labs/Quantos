// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # QN12 - Multi-Token Standard
//!
//! Resource-based multi-token standard (ERC1155 equivalent).

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use crate::types::Address;
use super::{TokenError, TokenEvent, TokenResult};

/// Zero address constant
const ZERO_ADDRESS: Address = [0u8; 32];
/// Maximum batch size to prevent DoS
const MAX_BATCH_SIZE: usize = 1000;

/// QN12 Token Resource - Multi-Token (FT + NFT + SFT)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QN12Token {
    /// Collection name
    pub name: String,
    /// Owner/deployer address
    pub owner: Address,
    /// Pending owner for ownership transfer
    pub pending_owner: Option<Address>,
    /// Balances: (token_id, account) -> amount
    balances: HashMap<(u64, Address), u64>,
    /// Operator approvals: (owner, operator) -> approved
    operator_approvals: HashMap<(Address, Address), bool>,
    /// Token URIs: token_id -> URI
    token_uris: HashMap<u64, String>,
    /// Token supplies: token_id -> total supply
    token_supplies: HashMap<u64, u64>,
    /// Base URI for metadata
    pub base_uri: String,
    /// Next token ID for minting new types
    next_token_id: u64,
}

/// QN12 Trait - Interface for multi-tokens
pub trait QN12 {
    fn name(&self) -> &str;
    fn uri(&self, token_id: u64) -> String;
    fn balance_of(&self, account: &Address, token_id: u64) -> u64;
    fn balance_of_batch(&self, accounts: &[Address], token_ids: &[u64]) -> TokenResult<Vec<u64>>;
    fn set_approval_for_all(&mut self, caller: &Address, operator: &Address, approved: bool) -> TokenResult<TokenEvent>;
    fn is_approved_for_all(&self, account: &Address, operator: &Address) -> bool;
    fn safe_transfer_from(&mut self, caller: &Address, from: &Address, to: &Address, token_id: u64, amount: u64, data: &[u8]) -> TokenResult<TokenEvent>;
    fn safe_batch_transfer_from(&mut self, caller: &Address, from: &Address, to: &Address, token_ids: &[u64], amounts: &[u64], data: &[u8]) -> TokenResult<TokenEvent>;
}

/// QN12 Mintable extension
pub trait QN12Mintable: QN12 {
    fn mint(&mut self, caller: &Address, to: &Address, token_id: u64, amount: u64, uri: Option<String>) -> TokenResult<TokenEvent>;
    fn mint_batch(&mut self, caller: &Address, to: &Address, token_ids: &[u64], amounts: &[u64]) -> TokenResult<TokenEvent>;
    fn create_token(&mut self, caller: &Address, initial_supply: u64, uri: String) -> TokenResult<u64>;
}

/// QN12 Burnable extension
pub trait QN12Burnable: QN12 {
    fn burn(&mut self, caller: &Address, from: &Address, token_id: u64, amount: u64) -> TokenResult<TokenEvent>;
    fn burn_batch(&mut self, caller: &Address, from: &Address, token_ids: &[u64], amounts: &[u64]) -> TokenResult<TokenEvent>;
}

/// QN12 Supply extension
pub trait QN12Supply: QN12 {
    fn total_supply(&self, token_id: u64) -> u64;
    fn exists(&self, token_id: u64) -> bool;
}

impl QN12Token {
    /// Creates a new QN12 multi-token contract.
    pub fn new(name: String, owner: Address, base_uri: String) -> Self {
        Self {
            name,
            owner,
            pending_owner: None,
            balances: HashMap::new(),
            operator_approvals: HashMap::new(),
            token_uris: HashMap::new(),
            token_supplies: HashMap::new(),
            base_uri,
            next_token_id: 1,
        }
    }

    fn check_owner(&self, caller: &Address) -> TokenResult<()> {
        if caller != &self.owner {
            return Err(TokenError::Unauthorized);
        }
        Ok(())
    }

    fn is_approved_or_owner(&self, caller: &Address, from: &Address) -> bool {
        caller == from || self.is_approved_for_all(from, caller)
    }
    
    /// Validates address is not zero
    fn check_not_zero_address(address: &Address) -> TokenResult<()> {
        if address == &ZERO_ADDRESS {
            return Err(TokenError::InvalidAddress);
        }
        Ok(())
    }
    
    /// Initiates ownership transfer (2-step process)
    pub fn transfer_ownership(&mut self, caller: &Address, new_owner: Address) -> TokenResult<()> {
        self.check_owner(caller)?;
        Self::check_not_zero_address(&new_owner)?;
        self.pending_owner = Some(new_owner);
        Ok(())
    }
    
    /// Accepts ownership transfer
    pub fn accept_ownership(&mut self, caller: &Address) -> TokenResult<()> {
        if self.pending_owner.as_ref() != Some(caller) {
            return Err(TokenError::Unauthorized);
        }
        self.owner = *caller;
        self.pending_owner = None;
        Ok(())
    }
}

impl QN12 for QN12Token {
    fn name(&self) -> &str {
        &self.name
    }

    fn uri(&self, token_id: u64) -> String {
        if let Some(uri) = self.token_uris.get(&token_id) {
            uri.clone()
        } else {
            format!("{}{}.json", self.base_uri, token_id)
        }
    }

    fn balance_of(&self, account: &Address, token_id: u64) -> u64 {
        *self.balances.get(&(token_id, *account)).unwrap_or(&0)
    }

    fn balance_of_batch(&self, accounts: &[Address], token_ids: &[u64]) -> TokenResult<Vec<u64>> {
        if accounts.len() != token_ids.len() {
            return Err(TokenError::ArrayLengthMismatch);
        }

        Ok(accounts.iter()
            .zip(token_ids.iter())
            .map(|(account, token_id)| self.balance_of(account, *token_id))
            .collect())
    }

    fn set_approval_for_all(&mut self, caller: &Address, operator: &Address, approved: bool) -> TokenResult<TokenEvent> {
        if caller == operator {
            return Err(TokenError::InvalidAddress);
        }

        self.operator_approvals.insert((*caller, *operator), approved);

        Ok(TokenEvent::ApprovalForAll {
            owner: *caller,
            operator: *operator,
            approved,
        })
    }

    fn is_approved_for_all(&self, account: &Address, operator: &Address) -> bool {
        *self.operator_approvals.get(&(*account, *operator)).unwrap_or(&false)
    }

    fn safe_transfer_from(
        &mut self,
        caller: &Address,
        from: &Address,
        to: &Address,
        token_id: u64,
        amount: u64,
        _data: &[u8],
    ) -> TokenResult<TokenEvent> {
        Self::check_not_zero_address(to)?;
        
        if !self.is_approved_or_owner(caller, from) {
            return Err(TokenError::NotApproved);
        }

        let from_balance = self.balance_of(from, token_id);
        if from_balance < amount {
            return Err(TokenError::InsufficientBalance);
        }

        // Update balances with checked arithmetic
        let to_balance = self.balance_of(to, token_id);
        let new_from = from_balance.checked_sub(amount)
            .ok_or(TokenError::Underflow)?;
        let new_to = to_balance.checked_add(amount)
            .ok_or(TokenError::Overflow)?;
        
        self.balances.insert((token_id, *from), new_from);
        self.balances.insert((token_id, *to), new_to);

        Ok(TokenEvent::TransferSingle {
            operator: *caller,
            from: *from,
            to: *to,
            token_id,
            value: amount,
        })
    }

    fn safe_batch_transfer_from(
        &mut self,
        caller: &Address,
        from: &Address,
        to: &Address,
        token_ids: &[u64],
        amounts: &[u64],
        _data: &[u8],
    ) -> TokenResult<TokenEvent> {
        Self::check_not_zero_address(to)?;
        
        // CRITICAL: Prevent DoS via unbounded batch operations
        if token_ids.len() > MAX_BATCH_SIZE {
            return Err(TokenError::BatchSizeTooLarge);
        }
        
        if token_ids.len() != amounts.len() {
            return Err(TokenError::ArrayLengthMismatch);
        }

        if !self.is_approved_or_owner(caller, from) {
            return Err(TokenError::NotApproved);
        }

        // Check all balances first
        for (token_id, amount) in token_ids.iter().zip(amounts.iter()) {
            let from_balance = self.balance_of(from, *token_id);
            if from_balance < *amount {
                return Err(TokenError::InsufficientBalance);
            }
        }

        // Perform transfers with checked arithmetic
        for (token_id, amount) in token_ids.iter().zip(amounts.iter()) {
            let from_bal = self.balance_of(from, *token_id);
            let to_bal = self.balance_of(to, *token_id);
            
            let new_from = from_bal.checked_sub(*amount)
                .ok_or(TokenError::Underflow)?;
            let new_to = to_bal.checked_add(*amount)
                .ok_or(TokenError::Overflow)?;
            
            self.balances.insert((*token_id, *from), new_from);
            self.balances.insert((*token_id, *to), new_to);
        }

        Ok(TokenEvent::TransferBatch {
            operator: *caller,
            from: *from,
            to: *to,
            token_ids: token_ids.to_vec(),
            values: amounts.to_vec(),
        })
    }
}

impl QN12Mintable for QN12Token {
    fn mint(
        &mut self,
        caller: &Address,
        to: &Address,
        token_id: u64,
        amount: u64,
        uri: Option<String>,
    ) -> TokenResult<TokenEvent> {
        self.check_owner(caller)?;
        Self::check_not_zero_address(to)?;

        // Update balance
        *self.balances.entry((token_id, *to)).or_insert(0) = self.balances
            .get(&(token_id, *to))
            .unwrap_or(&0)
            .checked_add(amount)
            .ok_or(TokenError::Overflow)?;

        // Update supply
        *self.token_supplies.entry(token_id).or_insert(0) = self.token_supplies
            .get(&token_id)
            .unwrap_or(&0)
            .checked_add(amount)
            .ok_or(TokenError::Overflow)?;

        // Set URI if provided
        if let Some(uri) = uri {
            self.token_uris.insert(token_id, uri);
        }

        Ok(TokenEvent::TransferSingle {
            operator: *caller,
            from: ZERO_ADDRESS,
            to: *to,
            token_id,
            value: amount,
        })
    }

    fn mint_batch(
        &mut self,
        caller: &Address,
        to: &Address,
        token_ids: &[u64],
        amounts: &[u64],
    ) -> TokenResult<TokenEvent> {
        self.check_owner(caller)?;
        Self::check_not_zero_address(to)?;

        if token_ids.len() != amounts.len() {
            return Err(TokenError::ArrayLengthMismatch);
        }
        
        // CRITICAL: Prevent DoS via unbounded batch operations
        if token_ids.len() > MAX_BATCH_SIZE {
            return Err(TokenError::BatchSizeTooLarge);
        }
        
        // LOW (v8): Check for duplicate token_ids which could cause unexpected overwrites
        {
            let mut seen = std::collections::HashSet::with_capacity(token_ids.len());
            for id in token_ids {
                if !seen.insert(id) {
                    return Err(TokenError::DuplicateTokenId);
                }
            }
        }

        for (token_id, amount) in token_ids.iter().zip(amounts.iter()) {
            *self.balances.entry((*token_id, *to)).or_insert(0) = self.balances
                .get(&(*token_id, *to))
                .unwrap_or(&0)
                .checked_add(*amount)
                .ok_or(TokenError::Overflow)?;

            *self.token_supplies.entry(*token_id).or_insert(0) = self.token_supplies
                .get(token_id)
                .unwrap_or(&0)
                .checked_add(*amount)
                .ok_or(TokenError::Overflow)?;
        }

        Ok(TokenEvent::TransferBatch {
            operator: *caller,
            from: ZERO_ADDRESS,
            to: *to,
            token_ids: token_ids.to_vec(),
            values: amounts.to_vec(),
        })
    }

    fn create_token(&mut self, caller: &Address, initial_supply: u64, uri: String) -> TokenResult<u64> {
        self.check_owner(caller)?;

        // CRITICAL: Check for token ID overflow
        let token_id = self.next_token_id;
        self.next_token_id = self.next_token_id.checked_add(1)
            .ok_or(TokenError::Overflow)?;

        self.token_uris.insert(token_id, uri);

        if initial_supply > 0 {
            *self.balances.entry((token_id, *caller)).or_insert(0) = initial_supply;
            *self.token_supplies.entry(token_id).or_insert(0) = initial_supply;
        }

        Ok(token_id)
    }
}

impl QN12Burnable for QN12Token {
    fn burn(
        &mut self,
        caller: &Address,
        from: &Address,
        token_id: u64,
        amount: u64,
    ) -> TokenResult<TokenEvent> {
        if !self.is_approved_or_owner(caller, from) {
            return Err(TokenError::NotApproved);
        }

        let from_balance = self.balance_of(from, token_id);
        if from_balance < amount {
            return Err(TokenError::InsufficientBalance);
        }

        // Use checked arithmetic
        let new_balance = from_balance.checked_sub(amount)
            .ok_or(TokenError::Underflow)?;
        let current_supply = self.token_supplies.get(&token_id).copied().unwrap_or(0);
        let new_supply = current_supply.checked_sub(amount)
            .ok_or(TokenError::Underflow)?;
        
        self.balances.insert((token_id, *from), new_balance);
        self.token_supplies.insert(token_id, new_supply);

        Ok(TokenEvent::TransferSingle {
            operator: *caller,
            from: *from,
            to: ZERO_ADDRESS,
            token_id,
            value: amount,
        })
    }

    fn burn_batch(
        &mut self,
        caller: &Address,
        from: &Address,
        token_ids: &[u64],
        amounts: &[u64],
    ) -> TokenResult<TokenEvent> {
        // CRITICAL: Prevent DoS via unbounded batch operations
        if token_ids.len() > MAX_BATCH_SIZE {
            return Err(TokenError::BatchSizeTooLarge);
        }
        
        if token_ids.len() != amounts.len() {
            return Err(TokenError::ArrayLengthMismatch);
        }

        if !self.is_approved_or_owner(caller, from) {
            return Err(TokenError::NotApproved);
        }

        // Check balances
        for (token_id, amount) in token_ids.iter().zip(amounts.iter()) {
            let from_balance = self.balance_of(from, *token_id);
            if from_balance < *amount {
                return Err(TokenError::InsufficientBalance);
            }
        }

        // HIGH (v1): Perform burns with checked arithmetic to prevent underflow
        for (token_id, amount) in token_ids.iter().zip(amounts.iter()) {
            let balance = self.balances.get(&(*token_id, *from)).copied().unwrap_or(0);
            let new_balance = balance.checked_sub(*amount)
                .ok_or(TokenError::Underflow)?;
            self.balances.insert((*token_id, *from), new_balance);
            
            let supply = self.token_supplies.get(token_id).copied().unwrap_or(0);
            let new_supply = supply.checked_sub(*amount)
                .ok_or(TokenError::Underflow)?;
            self.token_supplies.insert(*token_id, new_supply);
        }

        Ok(TokenEvent::TransferBatch {
            operator: *caller,
            from: *from,
            to: [0u8; 32],
            token_ids: token_ids.to_vec(),
            values: amounts.to_vec(),
        })
    }
}

impl QN12Supply for QN12Token {
    fn total_supply(&self, token_id: u64) -> u64 {
        *self.token_supplies.get(&token_id).unwrap_or(&0)
    }

    fn exists(&self, token_id: u64) -> bool {
        self.token_supplies.contains_key(&token_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_multi_token() -> QN12Token {
        let owner = [1u8; 32];
        QN12Token::new(
            "Multi Token".to_string(),
            owner,
            "ipfs://".to_string(),
        )
    }

    #[test]
    fn test_creation() {
        let token = create_test_multi_token();
        assert_eq!(token.name(), "Multi Token");
    }

    #[test]
    fn test_create_and_mint() {
        let mut token = create_test_multi_token();
        let owner = [1u8; 32];
        let alice = [2u8; 32];

        // Create a new token type
        let token_id = token.create_token(&owner, 1000, "ipfs://gold.json".to_string()).unwrap();
        assert_eq!(token_id, 1);
        assert_eq!(token.balance_of(&owner, token_id), 1000);
        assert_eq!(token.total_supply(token_id), 1000);

        // Mint more
        token.mint(&owner, &alice, token_id, 500, None).unwrap();
        assert_eq!(token.balance_of(&alice, token_id), 500);
        assert_eq!(token.total_supply(token_id), 1500);
    }

    #[test]
    fn test_transfer() {
        let mut token = create_test_multi_token();
        let owner = [1u8; 32];
        let alice = [2u8; 32];

        token.create_token(&owner, 1000, "ipfs://coin.json".to_string()).unwrap();
        
        token.safe_transfer_from(&owner, &owner, &alice, 1, 300, &[]).unwrap();
        
        assert_eq!(token.balance_of(&owner, 1), 700);
        assert_eq!(token.balance_of(&alice, 1), 300);
    }

    #[test]
    fn test_batch_transfer() {
        let mut token = create_test_multi_token();
        let owner = [1u8; 32];
        let alice = [2u8; 32];

        token.create_token(&owner, 1000, "".to_string()).unwrap(); // Token 1
        token.create_token(&owner, 500, "".to_string()).unwrap();  // Token 2
        token.create_token(&owner, 100, "".to_string()).unwrap();  // Token 3

        token.safe_batch_transfer_from(
            &owner,
            &owner,
            &alice,
            &[1, 2, 3],
            &[100, 50, 10],
            &[],
        ).unwrap();

        assert_eq!(token.balance_of(&alice, 1), 100);
        assert_eq!(token.balance_of(&alice, 2), 50);
        assert_eq!(token.balance_of(&alice, 3), 10);
    }

    #[test]
    fn test_balance_of_batch() {
        let mut token = create_test_multi_token();
        let owner = [1u8; 32];
        let alice = [2u8; 32];

        token.create_token(&owner, 1000, "".to_string()).unwrap();
        token.mint(&owner, &alice, 1, 500, None).unwrap();

        let balances = token.balance_of_batch(
            &[owner, alice],
            &[1, 1],
        ).unwrap();

        assert_eq!(balances, vec![1000, 500]);
    }

    #[test]
    fn test_burn() {
        let mut token = create_test_multi_token();
        let owner = [1u8; 32];

        token.create_token(&owner, 1000, "".to_string()).unwrap();
        
        token.burn(&owner, &owner, 1, 300).unwrap();
        
        assert_eq!(token.balance_of(&owner, 1), 700);
        assert_eq!(token.total_supply(1), 700);
    }

    #[test]
    fn test_approval_for_all() {
        let mut token = create_test_multi_token();
        let owner = [1u8; 32];
        let alice = [2u8; 32];
        let operator = [3u8; 32];

        token.create_token(&owner, 1000, "".to_string()).unwrap();
        token.safe_transfer_from(&owner, &owner, &alice, 1, 500, &[]).unwrap();

        token.set_approval_for_all(&alice, &operator, true).unwrap();
        assert!(token.is_approved_for_all(&alice, &operator));

        // Operator can transfer Alice's tokens
        token.safe_transfer_from(&operator, &alice, &owner, 1, 100, &[]).unwrap();
        assert_eq!(token.balance_of(&alice, 1), 400);
    }

    #[test]
    fn test_array_length_mismatch() {
        let mut token = create_test_multi_token();
        let owner = [1u8; 32];
        let alice = [2u8; 32];

        let result = token.safe_batch_transfer_from(
            &owner,
            &owner,
            &alice,
            &[1, 2],
            &[100], // Mismatch!
            &[],
        );

        assert!(result.is_err());
    }
}
