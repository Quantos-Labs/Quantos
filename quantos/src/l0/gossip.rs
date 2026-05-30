//! Gossip protocol for propagating external checkpoints to validators.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tokio::sync::mpsc;

use crate::l0::checkpoint_pool::CheckpointPool;
use crate::l0::external::ExternalCheckpoint;
use crate::l0::hub::SignatureContribution;
use crate::types::Hash;

/// Message types for checkpoint gossip
#[derive(Clone, Debug)]
pub enum CheckpointGossipMessage {
    /// New checkpoint announcement
    NewCheckpoint {
        digest: Hash,
        checkpoint: ExternalCheckpoint,
    },
    /// Signature contribution from a validator
    Signature {
        digest: Hash,
        contribution: SignatureContribution,
        stake: u128,
    },
    /// Request for checkpoint data
    RequestCheckpoint { digest: Hash },
    /// Request for all pending checkpoints
    RequestPending,
}

/// Gossip handler for external checkpoints
pub struct CheckpointGossip {
    /// Checkpoint pool
    pool: Arc<CheckpointPool>,
    /// Channel for outgoing gossip messages
    outgoing_tx: mpsc::UnboundedSender<(Vec<u8>, CheckpointGossipMessage)>,
    /// Channel for incoming gossip messages
    incoming_rx: Arc<RwLock<Option<mpsc::UnboundedReceiver<CheckpointGossipMessage>>>>,
    /// Recently seen checkpoint digests (for deduplication)
    seen_checkpoints: Arc<RwLock<HashSet<Hash>>>,
    /// Recently seen signatures (for deduplication)
    seen_signatures: Arc<RwLock<HashSet<(Hash, [u8; 32])>>>, // (checkpoint_digest, validator_address)
    /// Last cleanup time
    last_cleanup: Arc<RwLock<Instant>>,
}

impl CheckpointGossip {
    pub fn new(pool: Arc<CheckpointPool>) -> (Self, mpsc::UnboundedReceiver<(Vec<u8>, CheckpointGossipMessage)>) {
        let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel();
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();

        let gossip = Self {
            pool,
            outgoing_tx,
            incoming_rx: Arc::new(RwLock::new(Some(incoming_rx))),
            seen_checkpoints: Arc::new(RwLock::new(HashSet::new())),
            seen_signatures: Arc::new(RwLock::new(HashSet::new())),
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
        };

        (gossip, outgoing_rx)
    }

    /// Broadcast a new checkpoint to all validators
    pub fn broadcast_checkpoint(&self, digest: Hash, checkpoint: ExternalCheckpoint, peers: Vec<Vec<u8>>) {
        // Mark as seen
        self.seen_checkpoints.write().insert(digest);

        let msg = CheckpointGossipMessage::NewCheckpoint { digest, checkpoint };

        // Send to all peers
        for peer in peers {
            let _ = self.outgoing_tx.send((peer, msg.clone()));
        }
    }

    /// Broadcast a signature to all validators
    pub fn broadcast_signature(
        &self,
        digest: Hash,
        contribution: SignatureContribution,
        stake: u128,
        peers: Vec<Vec<u8>>,
    ) {
        // Mark as seen
        self.seen_signatures.write().insert((digest, contribution.validator));

        let msg = CheckpointGossipMessage::Signature {
            digest,
            contribution,
            stake,
        };

        // Send to all peers
        for peer in peers {
            let _ = self.outgoing_tx.send((peer, msg.clone()));
        }
    }

    /// Handle incoming gossip message
    pub fn handle_message(&self, msg: CheckpointGossipMessage, sender_peer: Vec<u8>) -> Result<(), String> {
        match msg {
            CheckpointGossipMessage::NewCheckpoint { digest, checkpoint } => {
                // Check if already seen
                if self.seen_checkpoints.read().contains(&digest) {
                    return Ok(());
                }

                // Add to pool
                self.pool.add_checkpoint(checkpoint.clone(), digest)?;
                
                // Mark as seen
                self.seen_checkpoints.write().insert(digest);

                // Propagate to other peers (gossip)
                // This would be done by the network layer
                
                Ok(())
            }

            CheckpointGossipMessage::Signature { digest, contribution, stake } => {
                // Check if already seen
                let key = (digest, contribution.validator);
                if self.seen_signatures.read().contains(&key) {
                    return Ok(());
                }

                // Add signature to pool
                self.pool.add_signature(&digest, contribution.clone(), stake)?;

                // Mark as seen
                self.seen_signatures.write().insert(key);

                // Propagate to other peers (gossip)
                // This would be done by the network layer

                Ok(())
            }

            CheckpointGossipMessage::RequestCheckpoint { digest } => {
                // Send checkpoint if we have it
                if let Some(pending) = self.pool.get(&digest) {
                    let msg = CheckpointGossipMessage::NewCheckpoint {
                        digest,
                        checkpoint: pending.checkpoint,
                    };
                    let _ = self.outgoing_tx.send((sender_peer, msg));
                }
                Ok(())
            }

            CheckpointGossipMessage::RequestPending => {
                // Send all pending checkpoints
                for (digest, checkpoint) in self.pool.get_pending() {
                    let msg = CheckpointGossipMessage::NewCheckpoint { digest, checkpoint };
                    let _ = self.outgoing_tx.send((sender_peer.clone(), msg));
                }
                Ok(())
            }
        }
    }

    /// Periodic cleanup of seen sets
    pub fn cleanup(&self) {
        let mut last_cleanup = self.last_cleanup.write();
        if last_cleanup.elapsed() < Duration::from_secs(300) {
            return;
        }

        // Clear seen sets (keep only recent ones)
        self.seen_checkpoints.write().clear();
        self.seen_signatures.write().clear();

        *last_cleanup = Instant::now();
    }

    /// Start gossip handler task
    pub async fn run(self: Arc<Self>) {
        let mut incoming_rx = self.incoming_rx.write().take().expect("Gossip already running");

        while let Some(msg) = incoming_rx.recv().await {
            if let Err(e) = self.handle_message(msg, vec![]) {
                tracing::warn!("Failed to handle gossip message: {}", e);
            }

            // Periodic cleanup
            self.cleanup();
        }
    }

    /// Get channel for sending incoming messages
    pub fn incoming_sender(&self) -> mpsc::UnboundedSender<CheckpointGossipMessage> {
        let (tx, rx) = mpsc::unbounded_channel();
        *self.incoming_rx.write() = Some(rx);
        tx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l0::external::ChainId;

    #[test]
    fn test_gossip_deduplication() {
        let pool = Arc::new(CheckpointPool::new(3600, 1000));
        let (gossip, _rx) = CheckpointGossip::new(pool);

        let checkpoint = ExternalCheckpoint {
            chain_id: ChainId::Ethereum,
            block_number: 1000,
            block_hash: [1u8; 32],
            state_root: [2u8; 32],
            timestamp_ms: 1000000,
            native_finality_proof: vec![],
            metadata: None,
        };

        let digest = checkpoint.digest();

        // First message should be processed
        let result = gossip.handle_message(
            CheckpointGossipMessage::NewCheckpoint {
                digest,
                checkpoint: checkpoint.clone(),
            },
            vec![],
        );
        assert!(result.is_ok());

        // Second message should be deduplicated
        assert!(gossip.seen_checkpoints.read().contains(&digest));
    }
}
