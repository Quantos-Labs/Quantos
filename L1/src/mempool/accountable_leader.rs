// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Front-Running Protection with Accountable Leader
//!
//! **Mainnet default** mempool policy.
//!
//! Instead of encrypting transactions, this mode relies on:
//! - A **rotating block proposer** selected deterministically from the active
//!   validator set (consensus VRF / round-robin schedule).
//! - A **canonical transaction order** derived from `H(ordering_beacon || tx_hash)`,
//!   where `ordering_beacon` is chain randomness fixed after the submission window
//!   closes (same grinding-resistance property as the encrypted mempool).
//! - **Accountability**: the proposer signs a block header binding to the ordered
//!   transaction list; any deviation from the canonical order is slashable as
//!   proven front-running (`OffenseType::FrontRunning`).
//!
//! This uses only standard primitives (hash-based ordering, ML-DSA-65 signatures,
//! existing slashing pipeline).

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use parking_lot::RwLock;

use crate::consensus::{EvidenceData, OffenseType, SlashingEvidence};
use crate::crypto::{sha3_256, with_domain, DOMAIN_SLASH_FRONT_RUN};
use crate::types::{Address, Hash, SignedTransaction, hash_data};

/// Configuration for accountable-leader mempool protection.
#[derive(Clone, Debug)]
pub struct AccountableLeaderConfig {
    /// Maximum transactions retained per target block.
    pub max_txs_per_block: usize,
}

impl Default for AccountableLeaderConfig {
    fn default() -> Self {
        Self {
            max_txs_per_block: 10_000,
        }
    }
}

/// A transaction waiting in the mempool with metadata for fair ordering.
#[derive(Clone, Debug)]
pub struct PendingLeaderTx {
    pub transaction: SignedTransaction,
    /// Wall-clock receive time (seconds); tie-breaker after ordering key.
    pub received_at: u64,
}

/// Signed block order commitment from the rotating leader.
#[derive(Clone, Debug)]
pub struct LeaderBlockOrder {
    pub block: u64,
    pub leader: Address,
    /// Ordered transaction hashes proposed by the leader.
    pub tx_order: Vec<Hash>,
    /// Ordering beacon used for this block (must match chain randomness).
    pub ordering_beacon: Hash,
    /// ML-DSA-65 signature over the order binding.
    pub signature: Vec<u8>,
}

/// Detected deviation between canonical and leader-proposed order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderViolation {
    pub block: u64,
    pub leader: Address,
    /// Index in canonical order where the leader diverged.
    pub divergence_index: usize,
    pub expected_tx: Hash,
    pub proposed_tx: Hash,
}

/// Accountable-leader mempool manager.
pub struct AccountableLeaderMempool {
    config: AccountableLeaderConfig,
    current_block: AtomicU64,
    /// Active validator set (sorted for deterministic leader rotation).
    validators: RwLock<Vec<Address>>,
    /// Pending txs keyed by target block.
    pending: RwLock<BTreeMap<u64, Vec<PendingLeaderTx>>>,
    /// Per-block ordering beacons (immutable once set).
    ordering_beacons: RwLock<HashMap<u64, Hash>>,
}

#[derive(Debug, Clone)]
pub enum AccountableLeaderError {
    InvalidTargetBlock,
    BlockFull,
    OrderingBeaconTooEarly,
    OrderingBeaconImmutable,
    OrderingBeaconNotReady,
    UnknownLeader,
    OrderViolation(OrderViolation),
}

impl std::fmt::Display for AccountableLeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTargetBlock => write!(f, "invalid target block"),
            Self::BlockFull => write!(f, "block transaction cap reached"),
            Self::OrderingBeaconTooEarly => write!(f, "ordering beacon set too early"),
            Self::OrderingBeaconImmutable => write!(f, "ordering beacon already fixed"),
            Self::OrderingBeaconNotReady => write!(f, "ordering beacon not ready"),
            Self::UnknownLeader => write!(f, "proposer not in validator set"),
            Self::OrderViolation(v) => write!(
                f,
                "order violation at index {}: expected {:?}, got {:?}",
                v.divergence_index,
                &v.expected_tx[..4],
                &v.proposed_tx[..4]
            ),
        }
    }
}

impl std::error::Error for AccountableLeaderError {}

impl AccountableLeaderMempool {
    pub fn new(config: AccountableLeaderConfig) -> Self {
        Self {
            config,
            current_block: AtomicU64::new(0),
            validators: RwLock::new(Vec::new()),
            pending: RwLock::new(BTreeMap::new()),
            ordering_beacons: RwLock::new(HashMap::new()),
        }
    }

    /// Installs the sorted validator set used for leader rotation.
    pub fn set_validators(&self, mut validators: Vec<Address>) {
        validators.sort();
        *self.validators.write() = validators;
    }

    pub fn advance_block(&self, block: u64) {
        self.current_block.store(block, AtomicOrdering::SeqCst);
        let cutoff = block.saturating_sub(256);
        self.pending.write().retain(|&k, _| k >= cutoff);
        self.ordering_beacons.write().retain(|&k, _| k >= cutoff);
    }

    /// Returns the deterministic leader for `block` via round-robin over validators.
    pub fn leader_for_block(&self, block: u64) -> Option<Address> {
        let validators = self.validators.read();
        if validators.is_empty() {
            return None;
        }
        let idx = (block as usize) % validators.len();
        Some(validators[idx])
    }

    pub fn submit(&self, tx: SignedTransaction, target_block: u64) -> Result<(), AccountableLeaderError> {
        let current = self.current_block.load(AtomicOrdering::SeqCst);
        if target_block <= current {
            return Err(AccountableLeaderError::InvalidTargetBlock);
        }

        let mut pending = self.pending.write();
        let bucket = pending.entry(target_block).or_default();
        if bucket.len() >= self.config.max_txs_per_block {
            return Err(AccountableLeaderError::BlockFull);
        }

        bucket.push(PendingLeaderTx {
            transaction: tx,
            received_at: chrono::Utc::now().timestamp() as u64,
        });
        Ok(())
    }

    /// Registers chain randomness for `target_block` (immutable once set).
    pub fn set_ordering_beacon(&self, target_block: u64, beacon: Hash) -> Result<(), AccountableLeaderError> {
        let current = self.current_block.load(AtomicOrdering::SeqCst);
        if current < target_block {
            return Err(AccountableLeaderError::OrderingBeaconTooEarly);
        }
        let mut beacons = self.ordering_beacons.write();
        if beacons.contains_key(&target_block) {
            return Err(AccountableLeaderError::OrderingBeaconImmutable);
        }
        beacons.insert(target_block, beacon);
        Ok(())
    }

    pub fn ordering_beacon(&self, block: u64) -> Option<Hash> {
        self.ordering_beacons.read().get(&block).copied()
    }

    /// Grinding-resistant ordering key (identical semantics to encrypted mempool).
    pub fn ordering_key(beacon: &Hash, tx_hash: &Hash) -> Hash {
        let mut data = Vec::with_capacity(beacon.len() + tx_hash.len());
        data.extend_from_slice(beacon);
        data.extend_from_slice(tx_hash);
        sha3_256(&data)
    }

    /// Canonical fair order for `block` given the registered beacon.
    pub fn canonical_order(&self, block: u64) -> Result<Vec<Hash>, AccountableLeaderError> {
        let beacon = self
            .ordering_beacon(block)
            .ok_or(AccountableLeaderError::OrderingBeaconNotReady)?;

        let txs = self
            .pending
            .read()
            .get(&block)
            .cloned()
            .unwrap_or_default();

        let mut keyed: Vec<(Hash, Hash, u64)> = txs
            .iter()
            .map(|p| {
                let h = p.transaction.hash;
                (
                    Self::ordering_key(&beacon, &h),
                    h,
                    p.received_at,
                )
            })
            .collect();

        keyed.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.cmp(&b.1))
                .then_with(|| a.2.cmp(&b.2))
        });

        Ok(keyed.into_iter().map(|(_, h, _)| h).collect())
    }

    /// Verifies that `proposal` matches the canonical order for its block.
    pub fn verify_leader_order(
        &self,
        proposal: &LeaderBlockOrder,
    ) -> Result<Vec<Hash>, AccountableLeaderError> {
        let expected_leader = self
            .leader_for_block(proposal.block)
            .ok_or(AccountableLeaderError::UnknownLeader)?;
        if proposal.leader != expected_leader {
            return Err(AccountableLeaderError::UnknownLeader);
        }

        let canonical = self.canonical_order(proposal.block)?;
        if proposal.tx_order != canonical {
            let divergence_index = canonical
                .iter()
                .zip(proposal.tx_order.iter())
                .position(|(a, b)| a != b)
                .unwrap_or_else(|| canonical.len().min(proposal.tx_order.len()));

            let expected_tx = canonical.get(divergence_index).copied().unwrap_or([0u8; 32]);
            let proposed_tx = proposal.tx_order.get(divergence_index).copied().unwrap_or([0u8; 32]);

            return Err(AccountableLeaderError::OrderViolation(OrderViolation {
                block: proposal.block,
                leader: proposal.leader,
                divergence_index,
                expected_tx,
                proposed_tx,
            }));
        }

        Ok(canonical)
    }

    /// Message bytes the leader must sign over `(block, beacon, tx_order)`.
    pub fn order_signing_payload(block: u64, beacon: &Hash, tx_order: &[Hash]) -> Vec<u8> {
        let mut raw = Vec::with_capacity(8 + 32 + tx_order.len() * 32);
        raw.extend_from_slice(&block.to_le_bytes());
        raw.extend_from_slice(beacon);
        for h in tx_order {
            raw.extend_from_slice(h);
        }
        with_domain(DOMAIN_SLASH_FRONT_RUN, &raw)
    }

    /// Builds slashable evidence from an order violation.
    pub fn front_running_evidence(
        violation: &OrderViolation,
        beacon: Hash,
        canonical_order: &[Hash],
        proposed_order: &[Hash],
        leader_signature: Vec<u8>,
        reporter: Address,
        submission_slot: u64,
    ) -> SlashingEvidence {
        let evidence_data = EvidenceData::FrontRunning {
            block: violation.block,
            ordering_beacon: beacon,
            canonical_order: canonical_order.to_vec(),
            proposed_order: proposed_order.to_vec(),
            leader_signature,
        };

        let mut id_material = Vec::new();
        id_material.extend_from_slice(&violation.leader);
        id_material.extend_from_slice(&violation.block.to_le_bytes());
        id_material.extend_from_slice(&violation.expected_tx);
        id_material.extend_from_slice(&violation.proposed_tx);
        let id = hash_data(&id_material);

        SlashingEvidence {
            id,
            offense_type: OffenseType::FrontRunning,
            validator: violation.leader,
            offense_slot: violation.block,
            submission_slot,
            reporter,
            evidence_data,
            evidence_hash: id,
        }
    }

    /// Convenience wrapper: verify proposal and return slashing evidence on violation.
    pub fn check_and_build_evidence(
        &self,
        proposal: &LeaderBlockOrder,
        reporter: Address,
        submission_slot: u64,
    ) -> Result<(), SlashingEvidence> {
        match self.verify_leader_order(proposal) {
            Ok(_) => Ok(()),
            Err(AccountableLeaderError::OrderViolation(v)) => {
                let beacon = self
                    .ordering_beacon(v.block)
                    .unwrap_or([0u8; 32]);
                let canonical = self.canonical_order(v.block).unwrap_or_default();
                Err(Self::front_running_evidence(
                    &v,
                    beacon,
                    &canonical,
                    &proposal.tx_order,
                    proposal.signature.clone(),
                    reporter,
                    submission_slot,
                ))
            }
            Err(_) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Amount, Transaction, TransactionType};

    fn make_tx(nonce: u8) -> SignedTransaction {
        SignedTransaction::new(Transaction::new(
            TransactionType::Transfer,
            [nonce; 32],
            [0xFF; 32],
            Amount(1),
            nonce as u64,
            100_000,
            None,
            Vec::new(),
            0,
        ))
    }

    #[test]
    fn test_leader_rotation() {
        let pool = AccountableLeaderMempool::new(AccountableLeaderConfig::default());
        pool.set_validators(vec![[1u8; 32], [2u8; 32], [3u8; 32]]);
        assert_eq!(pool.leader_for_block(0), Some([1u8; 32]));
        assert_eq!(pool.leader_for_block(1), Some([2u8; 32]));
        assert_eq!(pool.leader_for_block(3), Some([1u8; 32]));
    }

    #[test]
    fn test_canonical_order_and_slashing_evidence() {
        let pool = AccountableLeaderMempool::new(AccountableLeaderConfig::default());
        pool.set_validators(vec![[1u8; 32], [2u8; 32]]);
        pool.advance_block(0);

        let tx_a = make_tx(1);
        let tx_b = make_tx(2);
        pool.submit(tx_a.clone(), 5).unwrap();
        pool.submit(tx_b.clone(), 5).unwrap();

        pool.advance_block(5);
        let beacon = [0xABu8; 32];
        pool.set_ordering_beacon(5, beacon).unwrap();

        let canonical = pool.canonical_order(5).unwrap();
        assert_eq!(canonical.len(), 2);

        // Leader permutes order → violation
        let mut bad_order = canonical.clone();
        bad_order.reverse();
        let proposal = LeaderBlockOrder {
            block: 5,
            leader: [1u8; 32],
            tx_order: bad_order,
            ordering_beacon: beacon,
            signature: vec![0x01, 0x02],
        };

        let err = pool.verify_leader_order(&proposal);
        assert!(matches!(err, Err(AccountableLeaderError::OrderViolation(_))));

        if let Err(AccountableLeaderError::OrderViolation(v)) = err {
            let evidence = AccountableLeaderMempool::front_running_evidence(
                &v,
                beacon,
                &canonical,
                &proposal.tx_order,
                proposal.signature,
                [9u8; 32],
                6,
            );
            assert_eq!(evidence.offense_type, OffenseType::FrontRunning);
        }
    }

    #[test]
    fn test_beacon_immutability() {
        let pool = AccountableLeaderMempool::new(AccountableLeaderConfig::default());
        pool.advance_block(10);
        assert!(pool.set_ordering_beacon(10, [1u8; 32]).is_ok());
        assert!(matches!(
            pool.set_ordering_beacon(10, [2u8; 32]),
            Err(AccountableLeaderError::OrderingBeaconImmutable)
        ));
    }
}
