// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Peer slot accounting and ban list (shared between API and PQ runtime).

use std::collections::HashSet;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::network::{NetworkError, PeerId};

/// Minimum reasonable peer count
pub(crate) const MIN_PEER_COUNT: usize = 1;
/// Maximum reasonable peer count
pub(crate) const MAX_PEER_COUNT: usize = 10_000;

pub struct PeerManager {
    peers: Arc<RwLock<HashSet<PeerId>>>,
    max_peers: usize,
    banned_peers: Arc<RwLock<HashSet<PeerId>>>,
}

impl PeerManager {
    pub fn new(max_peers: usize) -> Result<Self, NetworkError> {
        if max_peers < MIN_PEER_COUNT {
            return Err(NetworkError::InvalidMessage(format!(
                "max_peers {} below minimum {}",
                max_peers, MIN_PEER_COUNT
            )));
        }
        if max_peers > MAX_PEER_COUNT {
            return Err(NetworkError::InvalidMessage(format!(
                "max_peers {} above maximum {}",
                max_peers, MAX_PEER_COUNT
            )));
        }

        Ok(Self {
            peers: Arc::new(RwLock::new(HashSet::new())),
            max_peers,
            banned_peers: Arc::new(RwLock::new(HashSet::new())),
        })
    }

    pub fn max_peers(&self) -> usize {
        self.max_peers
    }

    pub fn load_banned(&self, banned: impl IntoIterator<Item = PeerId>) {
        let mut b = self.banned_peers.write();
        for p in banned {
            b.insert(p);
        }
    }

    pub fn add_peer(&self, peer_id: PeerId) -> bool {
        if self.banned_peers.read().contains(&peer_id) {
            return false;
        }

        let mut peers = self.peers.write();
        if peers.len() >= self.max_peers {
            return false;
        }

        peers.insert(peer_id)
    }

    pub fn remove_peer(&self, peer_id: &PeerId) {
        self.peers.write().remove(peer_id);
    }

    pub fn ban_peer(&self, peer_id: PeerId) {
        self.remove_peer(&peer_id);
        self.banned_peers.write().insert(peer_id);
    }

    pub fn is_banned(&self, peer_id: &PeerId) -> bool {
        self.banned_peers.read().contains(peer_id)
    }

    pub fn tracked_peer_count(&self) -> usize {
        self.peers.read().len()
    }
}
