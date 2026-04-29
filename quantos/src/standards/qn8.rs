//! # QN8 - Non-Fungible Token Standard
//!
//! Resource-based NFT standard (ERC721 equivalent).

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

use crate::types::Address;
use super::{TokenError, TokenEvent, TokenResult};

/// Zero address constant
const ZERO_ADDRESS: Address = [0u8; 32];
/// Maximum batch size to prevent DoS
const MAX_BATCH_SIZE: u64 = 1000;
/// MEDIUM (v6): Maximum tokens per owner to prevent storage exhaustion
const MAX_TOKENS_PER_OWNER: usize = 100_000;

/// QN8 Token Resource - Non-Fungible Token
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QN8Token {
    /// Collection name
    pub name: String,
    /// Collection symbol
    pub symbol: String,
    /// Owner/deployer address
    pub owner: Address,
    /// Pending owner for ownership transfer
    pub pending_owner: Option<Address>,
    /// Token owners: token_id -> owner
    owners: HashMap<u64, Address>,
    /// Owner to tokens mapping for efficient enumeration
    owner_tokens: HashMap<Address, HashSet<u64>>,
    /// Balance per address
    balances: HashMap<Address, u64>,
    /// Token approvals: token_id -> approved address
    token_approvals: HashMap<u64, Address>,
    /// Operator approvals: (owner, operator) -> approved
    operator_approvals: HashMap<(Address, Address), bool>,
    /// Token URIs: token_id -> URI
    token_uris: HashMap<u64, String>,
    /// Next token ID
    next_token_id: u64,
    /// Base URI for metadata
    pub base_uri: String,
    /// Known contract addresses (have code deployed)
    contract_addresses: HashSet<Address>,
    /// Contracts that registered as NFT receivers (implement onERC721Received)
    nft_receivers: HashSet<Address>,
    /// MEDIUM (v5): Reentrancy guard
    _reentrancy_guard: bool,
}

/// QN8 Trait - Interface for non-fungible tokens
pub trait QN8 {
    fn name(&self) -> &str;
    fn symbol(&self) -> &str;
    fn total_supply(&self) -> u64;
    fn balance_of(&self, owner: &Address) -> u64;
    fn owner_of(&self, token_id: u64) -> TokenResult<Address>;
    fn token_uri(&self, token_id: u64) -> TokenResult<String>;
    fn approve(&mut self, caller: &Address, to: &Address, token_id: u64) -> TokenResult<TokenEvent>;
    fn get_approved(&self, token_id: u64) -> Option<Address>;
    fn set_approval_for_all(&mut self, caller: &Address, operator: &Address, approved: bool) -> TokenResult<TokenEvent>;
    fn is_approved_for_all(&self, owner: &Address, operator: &Address) -> bool;
    fn transfer_from(&mut self, caller: &Address, from: &Address, to: &Address, token_id: u64) -> TokenResult<TokenEvent>;
    fn safe_transfer_from(&mut self, caller: &Address, from: &Address, to: &Address, token_id: u64, data: &[u8]) -> TokenResult<TokenEvent>;
}

/// QN8 Mintable extension
pub trait QN8Mintable: QN8 {
    fn mint(&mut self, caller: &Address, to: &Address, uri: Option<String>) -> TokenResult<(u64, TokenEvent)>;
    fn mint_batch(&mut self, caller: &Address, to: &Address, count: u64, uris: Vec<String>) -> TokenResult<Vec<u64>>;
}

/// QN8 Burnable extension
pub trait QN8Burnable: QN8 {
    fn burn(&mut self, caller: &Address, token_id: u64) -> TokenResult<TokenEvent>;
}

/// QN8 Enumerable extension
pub trait QN8Enumerable: QN8 {
    fn token_by_index(&self, index: u64) -> TokenResult<u64>;
    fn token_of_owner_by_index(&self, owner: &Address, index: u64) -> TokenResult<u64>;
    fn all_tokens(&self) -> Vec<u64>;
    fn tokens_of_owner(&self, owner: &Address) -> Vec<u64>;
}

impl QN8Token {
    /// Creates a new QN8 collection.
    pub fn new(name: String, symbol: String, owner: Address, base_uri: String) -> Self {
        Self {
            name,
            symbol,
            owner,
            pending_owner: None,
            owners: HashMap::new(),
            owner_tokens: HashMap::new(),
            balances: HashMap::new(),
            token_approvals: HashMap::new(),
            operator_approvals: HashMap::new(),
            token_uris: HashMap::new(),
            next_token_id: 1,
            base_uri,
            contract_addresses: HashSet::new(),
            nft_receivers: HashSet::new(),
            _reentrancy_guard: false,
        }
    }
    
    /// Registers an address as a contract (has code deployed).
    pub fn register_contract(&mut self, address: Address) {
        self.contract_addresses.insert(address);
    }
    
    /// Registers a contract as an NFT receiver (implements onERC721Received).
    pub fn register_nft_receiver(&mut self, address: Address) {
        self.nft_receivers.insert(address);
    }
    
    /// Checks if an address is a known contract.
    fn is_contract(&self, address: &Address) -> bool {
        self.contract_addresses.contains(address)
    }
    
    /// Checks if a contract supports receiving NFTs.
    fn supports_nft_receive(&self, address: &Address) -> bool {
        self.nft_receivers.contains(address)
    }

    fn check_owner(&self, caller: &Address) -> TokenResult<()> {
        if caller != &self.owner {
            return Err(TokenError::Unauthorized);
        }
        Ok(())
    }

    fn is_approved_or_owner(&self, spender: &Address, token_id: u64) -> TokenResult<bool> {
        let owner = self.owner_of(token_id)?;
        Ok(
            spender == &owner ||
            self.get_approved(token_id).map(|a| &a == spender).unwrap_or(false) ||
            self.is_approved_for_all(&owner, spender)
        )
    }

    fn exists(&self, token_id: u64) -> bool {
        self.owners.contains_key(&token_id)
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

impl QN8 for QN8Token {
    fn name(&self) -> &str {
        &self.name
    }

    fn symbol(&self) -> &str {
        &self.symbol
    }

    fn total_supply(&self) -> u64 {
        self.owners.len() as u64
    }

    fn balance_of(&self, owner: &Address) -> u64 {
        *self.balances.get(owner).unwrap_or(&0)
    }

    fn owner_of(&self, token_id: u64) -> TokenResult<Address> {
        self.owners.get(&token_id)
            .copied()
            .ok_or(TokenError::TokenNotFound)
    }

    fn token_uri(&self, token_id: u64) -> TokenResult<String> {
        if !self.exists(token_id) {
            return Err(TokenError::TokenNotFound);
        }

        if let Some(uri) = self.token_uris.get(&token_id) {
            Ok(uri.clone())
        } else {
            Ok(format!("{}{}", self.base_uri, token_id))
        }
    }

    fn approve(&mut self, caller: &Address, to: &Address, token_id: u64) -> TokenResult<TokenEvent> {
        let owner = self.owner_of(token_id)?;
        
        if caller != &owner && !self.is_approved_for_all(&owner, caller) {
            return Err(TokenError::Unauthorized);
        }

        self.token_approvals.insert(token_id, *to);

        Ok(TokenEvent::ApprovalNFT {
            owner,
            approved: *to,
            token_id,
        })
    }

    fn get_approved(&self, token_id: u64) -> Option<Address> {
        self.token_approvals.get(&token_id).copied()
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

    fn is_approved_for_all(&self, owner: &Address, operator: &Address) -> bool {
        *self.operator_approvals.get(&(*owner, *operator)).unwrap_or(&false)
    }

    fn transfer_from(&mut self, caller: &Address, from: &Address, to: &Address, token_id: u64) -> TokenResult<TokenEvent> {
        Self::check_not_zero_address(to)?;
        
        if !self.is_approved_or_owner(caller, token_id)? {
            return Err(TokenError::NotApproved);
        }

        let owner = self.owner_of(token_id)?;
        if &owner != from {
            return Err(TokenError::NotOwner);
        }

        // Clear approval
        self.token_approvals.remove(&token_id);

        // Update ownership
        self.owners.insert(token_id, *to);
        
        // Update owner_tokens mapping
        if let Some(tokens) = self.owner_tokens.get_mut(from) {
            tokens.remove(&token_id);
            // Clean up empty sets to prevent storage bloat
            if tokens.is_empty() {
                self.owner_tokens.remove(from);
            }
        }
        // MEDIUM (v6): Check per-owner token limit
        let to_token_count = self.owner_tokens.get(to).map(|t| t.len()).unwrap_or(0);
        if to_token_count >= MAX_TOKENS_PER_OWNER {
            return Err(TokenError::MaxTokensPerOwnerReached);
        }
        self.owner_tokens.entry(*to).or_insert_with(HashSet::new).insert(token_id);

        // Update balances with checked arithmetic
        let from_balance = self.balance_of(from);
        let to_balance = self.balance_of(to);
        let new_from = from_balance.checked_sub(1).ok_or(TokenError::Underflow)?;
        let new_to = to_balance.checked_add(1).ok_or(TokenError::Overflow)?;
        
        self.balances.insert(*from, new_from);
        self.balances.insert(*to, new_to);

        Ok(TokenEvent::TransferNFT {
            from: *from,
            to: *to,
            token_id,
        })
    }

    fn safe_transfer_from(&mut self, caller: &Address, from: &Address, to: &Address, token_id: u64, _data: &[u8]) -> TokenResult<TokenEvent> {
        // MEDIUM (v5): Reentrancy guard
        if self._reentrancy_guard {
            return Err(TokenError::ReentrancyDetected);
        }
        self._reentrancy_guard = true;
        
        // Reject transfers to the zero address (would burn the NFT)
        Self::check_not_zero_address(to)?;
        
        // Check if receiver is a contract by verifying it has registered
        // as an NFT-capable receiver (ERC721Received pattern).
        // Externally-owned accounts (no code) always pass this check.
        if self.is_contract(to) && !self.supports_nft_receive(to) {
            self._reentrancy_guard = false;
            return Err(TokenError::Unauthorized);
        }
        
        let result = self.transfer_from(caller, from, to, token_id);
        self._reentrancy_guard = false;
        result
    }
}

impl QN8Mintable for QN8Token {
    fn mint(&mut self, caller: &Address, to: &Address, uri: Option<String>) -> TokenResult<(u64, TokenEvent)> {
        self.check_owner(caller)?;
        Self::check_not_zero_address(to)?;

        // CRITICAL: Check for token ID overflow
        let token_id = self.next_token_id;
        self.next_token_id = self.next_token_id.checked_add(1)
            .ok_or(TokenError::Overflow)?;

        self.owners.insert(token_id, *to);
        
        // MEDIUM (v6): Check per-owner token limit before minting
        let to_token_count = self.owner_tokens.get(to).map(|t| t.len()).unwrap_or(0);
        if to_token_count >= MAX_TOKENS_PER_OWNER {
            return Err(TokenError::MaxTokensPerOwnerReached);
        }
        
        // Update owner_tokens mapping
        self.owner_tokens.entry(*to).or_insert_with(HashSet::new).insert(token_id);
        
        // Use checked arithmetic for balance
        let current_balance = self.balance_of(to);
        let new_balance = current_balance.checked_add(1)
            .ok_or(TokenError::Overflow)?;
        self.balances.insert(*to, new_balance);

        if let Some(uri) = uri {
            self.token_uris.insert(token_id, uri);
        }

        let event = TokenEvent::TransferNFT {
            from: ZERO_ADDRESS,
            to: *to,
            token_id,
        };

        Ok((token_id, event))
    }

    fn mint_batch(&mut self, caller: &Address, to: &Address, count: u64, uris: Vec<String>) -> TokenResult<Vec<u64>> {
        self.check_owner(caller)?;
        
        // CRITICAL: Prevent DoS via unbounded batch operations
        if count > MAX_BATCH_SIZE {
            return Err(TokenError::BatchSizeTooLarge);
        }

        let mut token_ids = Vec::new();
        
        for i in 0..count {
            let uri = uris.get(i as usize).cloned();
            let (token_id, _) = self.mint(caller, to, uri)?;
            token_ids.push(token_id);
        }

        Ok(token_ids)
    }
}

impl QN8Burnable for QN8Token {
    fn burn(&mut self, caller: &Address, token_id: u64) -> TokenResult<TokenEvent> {
        let owner = self.owner_of(token_id)?;

        if !self.is_approved_or_owner(caller, token_id)? {
            return Err(TokenError::NotApproved);
        }

        // Clear approval
        self.token_approvals.remove(&token_id);

        // Remove ownership
        self.owners.remove(&token_id);
        self.token_uris.remove(&token_id);
        
        // Update owner_tokens mapping
        if let Some(tokens) = self.owner_tokens.get_mut(&owner) {
            tokens.remove(&token_id);
        }

        // Update balance with checked arithmetic
        let current_balance = self.balance_of(&owner);
        let new_balance = current_balance.checked_sub(1)
            .ok_or(TokenError::Underflow)?;
        self.balances.insert(owner, new_balance);

        Ok(TokenEvent::TransferNFT {
            from: owner,
            to: ZERO_ADDRESS,
            token_id,
        })
    }
}

impl QN8Enumerable for QN8Token {
    fn token_by_index(&self, index: u64) -> TokenResult<u64> {
        self.owners.keys()
            .nth(index as usize)
            .copied()
            .ok_or(TokenError::TokenNotFound)
    }

    fn token_of_owner_by_index(&self, owner: &Address, index: u64) -> TokenResult<u64> {
        self.tokens_of_owner(owner)
            .get(index as usize)
            .copied()
            .ok_or(TokenError::TokenNotFound)
    }

    fn all_tokens(&self) -> Vec<u64> {
        self.owners.keys().copied().collect()
    }

    fn tokens_of_owner(&self, owner: &Address) -> Vec<u64> {
        // CRITICAL: Use efficient owner_tokens mapping instead of iterating all tokens
        self.owner_tokens.get(owner)
            .map(|tokens| tokens.iter().copied().collect())
            .unwrap_or_else(Vec::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_nft() -> QN8Token {
        let owner = [1u8; 32];
        QN8Token::new(
            "Test NFT".to_string(),
            "TNFT".to_string(),
            owner,
            "ipfs://".to_string(),
        )
    }

    #[test]
    fn test_nft_creation() {
        let nft = create_test_nft();
        assert_eq!(nft.name(), "Test NFT");
        assert_eq!(nft.symbol(), "TNFT");
        assert_eq!(nft.total_supply(), 0);
    }

    #[test]
    fn test_mint() {
        let mut nft = create_test_nft();
        let owner = [1u8; 32];
        let recipient = [2u8; 32];

        let (token_id, _) = nft.mint(&owner, &recipient, Some("ipfs://metadata/1".to_string())).unwrap();
        
        assert_eq!(token_id, 1);
        assert_eq!(nft.owner_of(token_id).unwrap(), recipient);
        assert_eq!(nft.balance_of(&recipient), 1);
        assert_eq!(nft.token_uri(token_id).unwrap(), "ipfs://metadata/1");
    }

    #[test]
    fn test_transfer() {
        let mut nft = create_test_nft();
        let owner = [1u8; 32];
        let alice = [2u8; 32];
        let bob = [3u8; 32];

        let (token_id, _) = nft.mint(&owner, &alice, None).unwrap();
        
        nft.transfer_from(&alice, &alice, &bob, token_id).unwrap();
        
        assert_eq!(nft.owner_of(token_id).unwrap(), bob);
        assert_eq!(nft.balance_of(&alice), 0);
        assert_eq!(nft.balance_of(&bob), 1);
    }

    #[test]
    fn test_approval() {
        let mut nft = create_test_nft();
        let owner = [1u8; 32];
        let alice = [2u8; 32];
        let bob = [3u8; 32];

        let (token_id, _) = nft.mint(&owner, &alice, None).unwrap();
        
        nft.approve(&alice, &bob, token_id).unwrap();
        assert_eq!(nft.get_approved(token_id), Some(bob));

        // Bob can now transfer
        nft.transfer_from(&bob, &alice, &bob, token_id).unwrap();
        assert_eq!(nft.owner_of(token_id).unwrap(), bob);
    }

    #[test]
    fn test_approval_for_all() {
        let mut nft = create_test_nft();
        let owner = [1u8; 32];
        let alice = [2u8; 32];
        let operator = [3u8; 32];

        nft.mint(&owner, &alice, None).unwrap();
        nft.mint(&owner, &alice, None).unwrap();

        nft.set_approval_for_all(&alice, &operator, true).unwrap();
        assert!(nft.is_approved_for_all(&alice, &operator));
    }

    #[test]
    fn test_burn() {
        let mut nft = create_test_nft();
        let owner = [1u8; 32];
        let alice = [2u8; 32];

        let (token_id, _) = nft.mint(&owner, &alice, None).unwrap();
        assert_eq!(nft.total_supply(), 1);

        nft.burn(&alice, token_id).unwrap();
        assert_eq!(nft.total_supply(), 0);
        assert!(nft.owner_of(token_id).is_err());
    }
}
