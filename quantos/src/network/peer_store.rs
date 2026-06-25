//! Persistent peer policy store (bans + basic reputation) for PQ P2P.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::network::{NetworkError, NetworkResult, PeerId};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PeerStoreFile {
    /// Base58 PeerId strings.
    banned: Vec<String>,
    /// Base58 PeerId -> reputation score.
    reputation: HashMap<String, i32>,
    /// Known peer multiaddrs discovered from previous sessions.
    known_peers: Vec<String>,
}

fn default_path(db_path: &str) -> PathBuf {
    Path::new(db_path).join("p2p").join("peers.json")
}

pub struct PeerStore {
    path: PathBuf,
    banned: Arc<RwLock<HashSet<PeerId>>>,
    reputation: Arc<RwLock<HashMap<PeerId, i32>>>,
    known_peers: Arc<RwLock<Vec<String>>>,
}

impl PeerStore {
    pub fn load_or_create(db_path: &str) -> NetworkResult<Self> {
        let path = if let Ok(p) = std::env::var("QUANTOS_P2P_PEERS_PATH") {
            PathBuf::from(p.trim())
        } else {
            default_path(db_path)
        };

        if path.is_file() {
            let s = fs::read_to_string(&path).map_err(|e| NetworkError::IoError(e.to_string()))?;
            let file: PeerStoreFile =
                serde_json::from_str(&s).map_err(|e| NetworkError::InvalidMessage(e.to_string()))?;
            let mut banned = HashSet::new();
            for b in file.banned {
                if let Ok(pid) = b.parse::<PeerId>() {
                    banned.insert(pid);
                }
            }
            let mut rep = HashMap::new();
            for (k, v) in file.reputation {
                if let Ok(pid) = k.parse::<PeerId>() {
                    rep.insert(pid, v);
                }
            }

            let known = file.known_peers;

            return Ok(Self {
                path,
                banned: Arc::new(RwLock::new(banned)),
                reputation: Arc::new(RwLock::new(rep)),
                known_peers: Arc::new(RwLock::new(known)),
            });
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| NetworkError::IoError(e.to_string()))?;
        }

        let st = Self {
            path,
            banned: Arc::new(RwLock::new(HashSet::new())),
            reputation: Arc::new(RwLock::new(HashMap::new())),
            known_peers: Arc::new(RwLock::new(Vec::new())),
        };
        st.flush()?;
        Ok(st)
    }

    pub fn banned_peers(&self) -> HashSet<PeerId> {
        self.banned.read().clone()
    }

    pub fn is_banned(&self, peer_id: &PeerId) -> bool {
        self.banned.read().contains(peer_id)
    }

    pub fn ban(&self, peer_id: PeerId) -> NetworkResult<()> {
        self.banned.write().insert(peer_id);
        self.flush()
    }

    pub fn set_reputation(&self, peer_id: PeerId, rep: i32) -> NetworkResult<()> {
        self.reputation.write().insert(peer_id, rep);
        self.flush()
    }

    pub fn known_peers(&self) -> Vec<String> {
        self.known_peers.read().clone()
    }

    pub fn add_known_peer(&self, addr: String) -> NetworkResult<()> {
        let mut peers = self.known_peers.write();
        if !peers.contains(&addr) {
            peers.push(addr);
        }
        self.flush()
    }

    pub fn add_known_peers(&self, addrs: Vec<String>) -> NetworkResult<()> {
        let mut peers = self.known_peers.write();
        for addr in addrs {
            if !peers.contains(&addr) {
                peers.push(addr);
            }
        }
        self.flush()
    }

    pub fn remove_known_peer(&self, addr: &str) -> NetworkResult<()> {
        let mut peers = self.known_peers.write();
        peers.retain(|p| p != addr);
        self.flush()
    }

    fn flush(&self) -> NetworkResult<()> {
        let banned: Vec<String> = self.banned.read().iter().map(|p| p.to_string()).collect();
        let reputation: HashMap<String, i32> = self
            .reputation
            .read()
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect();
        let known_peers: Vec<String> = self.known_peers.read().clone();
        let file = PeerStoreFile {
            banned,
            reputation,
            known_peers,
        };
        let out =
            serde_json::to_string_pretty(&file).map_err(|e| NetworkError::SerializationError(e.to_string()))?;
        fs::write(&self.path, out).map_err(|e| NetworkError::IoError(e.to_string()))?;
        Ok(())
    }
}

