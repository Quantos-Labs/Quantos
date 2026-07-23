// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Proposer-Builder Separation (PBS)
//!
//! Separates block proposal from block building to democratize MEV extraction
//! and prevent proposer centralization.
//!
//! ## Features
//!
//! - **Builder Market**: Competitive block building market
//! - **Sealed-Bid Auctions**: Prevent bid manipulation
//! - **Builder Reputation**: Track builder performance
//! - **Proposer Protection**: Guaranteed minimum payment
//! - **Relay Network**: Trusted intermediaries for privacy

use std::collections::{HashMap, BTreeMap};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use parking_lot::{Mutex, RwLock};

use crate::types::{Hash, Address, SignedTransaction};
use crate::crypto::sha3_256;

/// Block builder identity
#[derive(Clone, Debug)]
pub struct Builder {
    /// Builder address
    pub address: Address,
    /// Public key for bid verification
    pub public_key: Vec<u8>,
    /// Reputation score (0-1000)
    pub reputation: u32,
    /// Total blocks built
    pub blocks_built: u64,
    /// Total value delivered
    pub total_value: u64,
    /// Collateral staked
    pub collateral: u64,
    /// Registration timestamp
    pub registered_at: u64,
    /// Active status
    pub active: bool,
}

/// Block bid from builder
#[derive(Clone)]
pub struct BlockBid {
    /// Builder address
    pub builder: Address,
    /// Slot number
    pub slot: u64,
    /// Parent block hash
    pub parent_hash: Hash,
    /// Bid value (payment to proposer)
    pub value: u64,
    /// Block CU limit (STACC)
    pub block_cu_limit: u64,
    /// Block CU used (STACC)
    pub block_cu_used: u64,
    /// Block hash (commitment)
    pub block_hash: Hash,
    /// Transaction root
    pub transactions_root: Hash,
    /// State root (post-execution)
    pub state_root: Hash,
    /// Number of transactions
    pub tx_count: u32,
    /// Timestamp
    pub timestamp: u64,
    /// Builder signature
    pub signature: Vec<u8>,
}

impl BlockBid {
    /// Computes bid commitment hash
    pub fn commitment(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&self.builder);
        data.extend_from_slice(&self.slot.to_le_bytes());
        data.extend_from_slice(&self.parent_hash);
        data.extend_from_slice(&self.value.to_le_bytes());
        data.extend_from_slice(&self.block_hash);
        sha3_256(&data)
    }
}

/// Built block content (revealed after winning)
#[derive(Clone)]
pub struct BuiltBlock {
    /// Bid that won
    pub bid: BlockBid,
    /// Full block header
    pub header: BlockHeader,
    /// Transactions (ordered)
    pub transactions: Vec<SignedTransaction>,
    /// Execution proof
    pub execution_proof: Vec<u8>,
}

/// Block header
#[derive(Clone, Debug)]
pub struct BlockHeader {
    pub slot: u64,
    pub parent_hash: Hash,
    pub state_root: Hash,
    pub transactions_root: Hash,
    pub receipts_root: Hash,
    pub block_cu_limit: u64,
    pub block_cu_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
}

/// Proposer registration
#[derive(Clone, Debug)]
pub struct Proposer {
    /// Proposer address
    pub address: Address,
    /// Public key
    pub public_key: Vec<u8>,
    /// Fee recipient address
    pub fee_recipient: Address,
    /// Minimum bid threshold
    pub min_bid: u64,
    /// Preferred builders (if any)
    pub preferred_builders: Vec<Address>,
    /// Active status
    pub active: bool,
}

/// Relay for builder-proposer communication
#[derive(Clone, Debug)]
pub struct Relay {
    /// Relay ID
    pub id: [u8; 32],
    /// Relay URL
    pub url: String,
    /// Public key
    pub public_key: Vec<u8>,
    /// Reputation
    pub reputation: u32,
    /// Active status
    pub active: bool,
}

/// Auction state for a slot
#[derive(Clone)]
pub struct SlotAuction {
    /// Slot number
    pub slot: u64,
    /// Parent hash
    pub parent_hash: Hash,
    /// Proposer for this slot
    pub proposer: Address,
    /// Sealed bids (commitment only)
    pub sealed_bids: Vec<SealedBid>,
    /// Revealed bids
    pub revealed_bids: Vec<BlockBid>,
    /// Winning bid
    pub winning_bid: Option<BlockBid>,
    /// Winning block
    pub winning_block: Option<BuiltBlock>,
    /// Auction state
    pub state: AuctionState,
    /// Bid deadline
    pub bid_deadline: u64,
    /// Reveal deadline
    pub reveal_deadline: u64,
}

/// Sealed bid (before reveal)
#[derive(Clone, Debug)]
pub struct SealedBid {
    /// Builder address
    pub builder: Address,
    /// Bid commitment
    pub commitment: Hash,
    /// Timestamp
    pub timestamp: u64,
}

/// Auction state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuctionState {
    /// Accepting sealed bids
    Bidding,
    /// Revealing bids
    Revealing,
    /// Selecting winner
    Selecting,
    /// Winner selected, awaiting block
    AwaitingBlock,
    /// Block received and verified
    Completed,
    /// Auction failed (no valid bids)
    Failed,
}

/// PBS configuration
#[derive(Clone, Debug)]
pub struct PBSConfig {
    /// Minimum builder collateral
    pub min_builder_collateral: u64,
    /// Minimum proposer min_bid
    pub default_min_bid: u64,
    /// Bid submission window (ms before slot)
    pub bid_window_ms: u64,
    /// Reveal window (ms)
    pub reveal_window_ms: u64,
    /// Block delivery timeout (ms)
    pub delivery_timeout_ms: u64,
    /// Enable sealed-bid auctions
    pub sealed_bids: bool,
    /// Penalty for missing block delivery
    pub delivery_penalty_percent: u32,
    /// Maximum builders per auction
    pub max_builders: usize,
}

impl Default for PBSConfig {
    fn default() -> Self {
        Self {
            min_builder_collateral: 100_000,
            default_min_bid: 0,
            bid_window_ms: 4000,
            reveal_window_ms: 1000,
            delivery_timeout_ms: 2000,
            sealed_bids: true,
            delivery_penalty_percent: 10,
            max_builders: 100,
        }
    }
}

/// Proposer-Builder Separation Manager
pub struct PBSManager {
    config: PBSConfig,
    /// Current slot
    current_slot: AtomicU64,
    /// Registered builders
    builders: RwLock<HashMap<Address, Builder>>,
    /// Registered proposers
    proposers: RwLock<HashMap<Address, Proposer>>,
    /// Active relays
    relays: RwLock<Vec<Relay>>,
    /// Active auctions by slot
    auctions: RwLock<BTreeMap<u64, SlotAuction>>,
    /// Proposer schedule (slot -> proposer)
    schedule: RwLock<HashMap<u64, Address>>,
    /// Completed blocks
    completed_blocks: RwLock<HashMap<u64, BuiltBlock>>,
    /// Statistics
    stats: Mutex<PBSStats>,
}

/// PBS statistics
#[derive(Default, Clone, Debug)]
pub struct PBSStats {
    pub total_auctions: u64,
    pub successful_auctions: u64,
    pub failed_auctions: u64,
    pub total_bids: u64,
    pub total_value_paid: u64,
    pub builders_slashed: u64,
    pub avg_winning_bid: u64,
}

impl PBSManager {
    pub fn new(config: PBSConfig) -> Self {
        Self {
            config,
            current_slot: AtomicU64::new(0),
            builders: RwLock::new(HashMap::new()),
            proposers: RwLock::new(HashMap::new()),
            relays: RwLock::new(Vec::new()),
            auctions: RwLock::new(BTreeMap::new()),
            schedule: RwLock::new(HashMap::new()),
            completed_blocks: RwLock::new(HashMap::new()),
            stats: Mutex::new(PBSStats::default()),
        }
    }
    
    /// Registers a block builder
    pub fn register_builder(&self, builder: Builder) -> Result<(), PBSError> {
        if builder.collateral < self.config.min_builder_collateral {
            return Err(PBSError::InsufficientCollateral);
        }
        
        if self.builders.read().len() >= self.config.max_builders {
            return Err(PBSError::TooManyBuilders);
        }
        
        self.builders.write().insert(builder.address, builder);
        Ok(())
    }
    
    /// Registers a proposer
    pub fn register_proposer(&self, proposer: Proposer) {
        self.proposers.write().insert(proposer.address, proposer);
    }
    
    /// Adds a relay
    pub fn add_relay(&self, relay: Relay) {
        self.relays.write().push(relay);
    }
    
    /// Sets proposer schedule
    pub fn set_schedule(&self, slot: u64, proposer: Address) {
        self.schedule.write().insert(slot, proposer);
    }
    
    /// Advances to new slot
    pub fn advance_slot(&self, slot: u64, parent_hash: Hash) {
        self.current_slot.store(slot, AtomicOrdering::SeqCst);
        
        // Process previous auctions
        self.finalize_auctions(slot);
        
        // Create auction for new slot
        self.create_auction(slot, parent_hash);
    }
    
    /// Creates auction for a slot
    fn create_auction(&self, slot: u64, parent_hash: Hash) {
        let proposer = self.schedule.read()
            .get(&slot)
            .copied()
            .unwrap_or([0u8; 32]);
        
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        
        let auction = SlotAuction {
            slot,
            parent_hash,
            proposer,
            sealed_bids: Vec::new(),
            revealed_bids: Vec::new(),
            winning_bid: None,
            winning_block: None,
            state: AuctionState::Bidding,
            bid_deadline: now_ms + self.config.bid_window_ms,
            reveal_deadline: now_ms + self.config.bid_window_ms + self.config.reveal_window_ms,
        };
        
        self.auctions.write().insert(slot, auction);
        self.stats.lock().total_auctions += 1;
    }
    
    /// Submits a sealed bid
    pub fn submit_sealed_bid(&self, slot: u64, builder: Address, commitment: Hash) -> Result<(), PBSError> {
        // Verify builder is registered and has sufficient collateral
        {
            let builders = self.builders.read();
            let builder_info = builders.get(&builder)
                .ok_or(PBSError::UnregisteredBuilder)?;
            if !builder_info.active {
                return Err(PBSError::BuilderInactive);
            }
            if builder_info.collateral < self.config.min_builder_collateral {
                return Err(PBSError::InsufficientCollateral);
            }
        }
        
        let mut auctions = self.auctions.write();
        let auction = auctions.get_mut(&slot)
            .ok_or(PBSError::AuctionNotFound)?;
        
        if auction.state != AuctionState::Bidding {
            return Err(PBSError::BiddingClosed);
        }
        
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        if now_ms > auction.bid_deadline {
            return Err(PBSError::BiddingClosed);
        }
        
        // Check for duplicate bid
        if auction.sealed_bids.iter().any(|b| b.builder == builder) {
            return Err(PBSError::DuplicateBid);
        }
        
        auction.sealed_bids.push(SealedBid {
            builder,
            commitment,
            timestamp: now_ms,
        });
        
        self.stats.lock().total_bids += 1;
        
        Ok(())
    }
    
    /// Submits a revealed bid (full bid)
    pub fn submit_bid(&self, bid: BlockBid) -> Result<(), PBSError> {
        // Verify builder is registered, active, and has sufficient collateral
        let builders = self.builders.read();
        let builder = builders.get(&bid.builder)
            .ok_or(PBSError::UnregisteredBuilder)?;
        
        if !builder.active {
            return Err(PBSError::BuilderInactive);
        }
        
        // CRITICAL: Prevent builders with drained collateral from bidding
        if builder.collateral < self.config.min_builder_collateral {
            return Err(PBSError::InsufficientCollateral);
        }
        drop(builders);
        
        // Verify bid signature
        if !self.verify_bid_signature(&bid) {
            return Err(PBSError::InvalidSignature);
        }
        
        let mut auctions = self.auctions.write();
        let auction = auctions.get_mut(&bid.slot)
            .ok_or(PBSError::AuctionNotFound)?;
        
        // Check proposer min_bid
        let proposers = self.proposers.read();
        if let Some(proposer) = proposers.get(&auction.proposer) {
            if bid.value < proposer.min_bid {
                return Err(PBSError::BidTooLow);
            }
        }
        drop(proposers);
        
        if self.config.sealed_bids {
            // Verify commitment matches
            if auction.state != AuctionState::Revealing {
                return Err(PBSError::RevealNotOpen);
            }
            
            let commitment = bid.commitment();
            if !auction.sealed_bids.iter().any(|sb| sb.builder == bid.builder && sb.commitment == commitment) {
                return Err(PBSError::CommitmentMismatch);
            }
        } else {
            // Direct bidding
            if auction.state != AuctionState::Bidding {
                return Err(PBSError::BiddingClosed);
            }
        }
        
        auction.revealed_bids.push(bid);
        
        Ok(())
    }
    
    /// Selects winning bid for a slot
    pub fn select_winner(&self, slot: u64) -> Result<BlockBid, PBSError> {
        let mut auctions = self.auctions.write();
        let auction = auctions.get_mut(&slot)
            .ok_or(PBSError::AuctionNotFound)?;
        
        if auction.revealed_bids.is_empty() {
            auction.state = AuctionState::Failed;
            self.stats.lock().failed_auctions += 1;
            return Err(PBSError::NoBids);
        }
        
        // Select highest valid bid
        let mut valid_bids: Vec<_> = auction.revealed_bids.iter()
            .filter(|b| b.parent_hash == auction.parent_hash)
            .cloned()
            .collect();
        
        valid_bids.sort_by(|a, b| b.value.cmp(&a.value));
        
        let winner = valid_bids.first()
            .ok_or(PBSError::NoValidBids)?
            .clone();
        
        auction.winning_bid = Some(winner.clone());
        auction.state = AuctionState::AwaitingBlock;
        
        // Update stats
        {
            let mut stats = self.stats.lock();
            stats.avg_winning_bid = (stats.avg_winning_bid * stats.successful_auctions + winner.value) 
                / (stats.successful_auctions + 1);
        }
        
        Ok(winner)
    }
    
    /// Submits winning block
    pub fn submit_block(&self, block: BuiltBlock) -> Result<(), PBSError> {
        let slot = block.bid.slot;
        
        // Verify block matches winning bid
        let mut auctions = self.auctions.write();
        let auction = auctions.get_mut(&slot)
            .ok_or(PBSError::AuctionNotFound)?;
        
        let winning_bid = auction.winning_bid.as_ref()
            .ok_or(PBSError::NoWinner)?;
        
        // Verify block hash
        if block.bid.block_hash != winning_bid.block_hash {
            return Err(PBSError::BlockMismatch);
        }
        
        // Verify state root
        if block.header.state_root != winning_bid.state_root {
            return Err(PBSError::StateRootMismatch);
        }
        
        // Verify transactions root
        let computed_root = self.compute_transactions_root(&block.transactions);
        if computed_root != winning_bid.transactions_root {
            return Err(PBSError::TransactionsRootMismatch);
        }
        
        auction.winning_block = Some(block.clone());
        auction.state = AuctionState::Completed;
        
        // Store completed block
        self.completed_blocks.write().insert(slot, block);
        
        // Update builder reputation
        self.update_builder_reputation(&winning_bid.builder, true);
        
        // Update stats
        {
            let mut stats = self.stats.lock();
            stats.successful_auctions += 1;
            stats.total_value_paid += winning_bid.value;
        }
        
        Ok(())
    }
    
    /// Handles block delivery timeout
    pub fn handle_timeout(&self, slot: u64) -> Result<(), PBSError> {
        let mut auctions = self.auctions.write();
        let auction = auctions.get_mut(&slot)
            .ok_or(PBSError::AuctionNotFound)?;
        
        if auction.state != AuctionState::AwaitingBlock {
            return Ok(());
        }
        
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        if now_ms < auction.reveal_deadline + self.config.delivery_timeout_ms {
            return Ok(());
        }
        
        // Timeout - slash builder
        if let Some(ref winning_bid) = auction.winning_bid {
            self.slash_builder(&winning_bid.builder, winning_bid.value);
            self.update_builder_reputation(&winning_bid.builder, false);
        }
        
        auction.state = AuctionState::Failed;
        self.stats.lock().failed_auctions += 1;
        
        Ok(())
    }
    
    /// Slashes builder for failed delivery.
    /// Immediately deactivates builder if collateral drops below minimum.
    fn slash_builder(&self, builder: &Address, bid_value: u64) {
        let penalty = bid_value * self.config.delivery_penalty_percent as u64 / 100;
        
        let mut builders = self.builders.write();
        if let Some(b) = builders.get_mut(builder) {
            b.collateral = b.collateral.saturating_sub(penalty);
            // Immediately deactivate if below minimum — prevents further auction participation
            if b.collateral < self.config.min_builder_collateral {
                b.active = false;
                tracing::warn!(
                    "Builder {:?} deactivated: collateral {} < minimum {}",
                    builder, b.collateral, self.config.min_builder_collateral
                );
            }
        }
        
        self.stats.lock().builders_slashed += 1;
    }
    
    /// Updates builder reputation
    fn update_builder_reputation(&self, builder: &Address, success: bool) {
        let mut builders = self.builders.write();
        if let Some(b) = builders.get_mut(builder) {
            if success {
                b.blocks_built += 1;
                b.reputation = (b.reputation + 10).min(1000);
            } else {
                b.reputation = b.reputation.saturating_sub(50);
            }
        }
    }
    
    /// Computes transactions root
    fn compute_transactions_root(&self, txs: &[SignedTransaction]) -> Hash {
        if txs.is_empty() {
            return [0u8; 32];
        }
        
        let hashes: Vec<Hash> = txs.iter().map(|tx| tx.hash).collect();
        crate::crypto::merkle_root(&hashes)
    }
    
    /// Verifies bid signature
    fn verify_bid_signature(&self, bid: &BlockBid) -> bool {
        // Would verify signature against builder's public key
        !bid.signature.is_empty()
    }
    
    /// Finalizes auctions for completed slots
    fn finalize_auctions(&self, current_slot: u64) {
        let mut auctions = self.auctions.write();
        
        let old_slots: Vec<_> = auctions.keys()
            .filter(|&&s| s < current_slot.saturating_sub(10))
            .copied()
            .collect();
        
        for slot in old_slots {
            auctions.remove(&slot);
        }
        
        // Transition auction states
        for (_, auction) in auctions.iter_mut() {
            let now_ms = chrono::Utc::now().timestamp_millis() as u64;
            
            match auction.state {
                AuctionState::Bidding => {
                    if now_ms > auction.bid_deadline {
                        auction.state = if self.config.sealed_bids {
                            AuctionState::Revealing
                        } else {
                            AuctionState::Selecting
                        };
                    }
                }
                AuctionState::Revealing => {
                    if now_ms > auction.reveal_deadline {
                        auction.state = AuctionState::Selecting;
                    }
                }
                _ => {}
            }
        }
    }
    
    /// Gets current auction for a slot
    pub fn get_auction(&self, slot: u64) -> Option<SlotAuction> {
        self.auctions.read().get(&slot).cloned()
    }
    
    /// Gets winning block for a slot
    pub fn get_block(&self, slot: u64) -> Option<BuiltBlock> {
        self.completed_blocks.read().get(&slot).cloned()
    }
    
    /// Gets builder info
    pub fn get_builder(&self, address: &Address) -> Option<Builder> {
        self.builders.read().get(address).cloned()
    }
    
    /// Gets all active builders sorted by reputation
    pub fn get_top_builders(&self, limit: usize) -> Vec<Builder> {
        let mut builders: Vec<_> = self.builders.read()
            .values()
            .filter(|b| b.active)
            .cloned()
            .collect();
        
        builders.sort_by(|a, b| b.reputation.cmp(&a.reputation));
        builders.truncate(limit);
        builders
    }
    
    /// Returns statistics
    pub fn stats(&self) -> PBSStats {
        self.stats.lock().clone()
    }
}

/// PBS errors
#[derive(Debug, Clone)]
pub enum PBSError {
    InsufficientCollateral,
    TooManyBuilders,
    UnregisteredBuilder,
    BuilderInactive,
    InvalidSignature,
    AuctionNotFound,
    BiddingClosed,
    RevealNotOpen,
    DuplicateBid,
    BidTooLow,
    CommitmentMismatch,
    NoBids,
    NoValidBids,
    NoWinner,
    BlockMismatch,
    StateRootMismatch,
    TransactionsRootMismatch,
}

impl std::fmt::Display for PBSError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PBSError::InsufficientCollateral => write!(f, "Insufficient collateral"),
            PBSError::TooManyBuilders => write!(f, "Too many builders"),
            PBSError::UnregisteredBuilder => write!(f, "Unregistered builder"),
            PBSError::BuilderInactive => write!(f, "Builder inactive"),
            PBSError::InvalidSignature => write!(f, "Invalid signature"),
            PBSError::AuctionNotFound => write!(f, "Auction not found"),
            PBSError::BiddingClosed => write!(f, "Bidding closed"),
            PBSError::RevealNotOpen => write!(f, "Reveal not open"),
            PBSError::DuplicateBid => write!(f, "Duplicate bid"),
            PBSError::BidTooLow => write!(f, "Bid too low"),
            PBSError::CommitmentMismatch => write!(f, "Commitment mismatch"),
            PBSError::NoBids => write!(f, "No bids"),
            PBSError::NoValidBids => write!(f, "No valid bids"),
            PBSError::NoWinner => write!(f, "No winner"),
            PBSError::BlockMismatch => write!(f, "Block mismatch"),
            PBSError::StateRootMismatch => write!(f, "State root mismatch"),
            PBSError::TransactionsRootMismatch => write!(f, "Transactions root mismatch"),
        }
    }
}

impl std::error::Error for PBSError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Transaction, TransactionType, Amount};
    
    fn make_test_tx() -> SignedTransaction {
        let tx = Transaction::new(
            TransactionType::Transfer,
            [1u8; 32],
            [2u8; 32],
            Amount(100),
            0,
            21000,
            None,
            Vec::new(),
            0,
        );
        SignedTransaction::new(tx)
    }
    
    #[test]
    fn test_builder_registration() {
        let pbs = PBSManager::new(PBSConfig::default());
        
        let builder = Builder {
            address: [1u8; 32],
            public_key: vec![1, 2, 3],
            reputation: 500,
            blocks_built: 0,
            total_value: 0,
            collateral: 200_000,
            registered_at: 0,
            active: true,
        };
        
        pbs.register_builder(builder).unwrap();
        
        let retrieved = pbs.get_builder(&[1u8; 32]).unwrap();
        assert_eq!(retrieved.reputation, 500);
    }
    
    #[test]
    fn test_auction_flow() {
        let pbs = PBSManager::new(PBSConfig {
            sealed_bids: false,
            ..Default::default()
        });
        
        // Register builder
        let builder = Builder {
            address: [1u8; 32],
            public_key: vec![1, 2, 3],
            reputation: 500,
            blocks_built: 0,
            total_value: 0,
            collateral: 200_000,
            registered_at: 0,
            active: true,
        };
        pbs.register_builder(builder).unwrap();
        
        // Set schedule
        pbs.set_schedule(100, [2u8; 32]);
        
        // Create auction
        pbs.advance_slot(100, [0u8; 32]);
        
        // Submit bid
        let bid = BlockBid {
            builder: [1u8; 32],
            slot: 100,
            parent_hash: [0u8; 32],
            value: 10000,
            block_cu_limit: 30_000_000,
            block_cu_used: 15_000_000,
            block_hash: [3u8; 32],
            transactions_root: [4u8; 32],
            state_root: [5u8; 32],
            tx_count: 100,
            timestamp: 0,
            signature: vec![1, 2, 3],
        };
        
        pbs.submit_bid(bid).unwrap();
        
        // Select winner
        let winner = pbs.select_winner(100).unwrap();
        assert_eq!(winner.value, 10000);
    }
}
