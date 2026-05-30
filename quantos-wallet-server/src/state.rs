// src/state.rs — Shared application state (passed to all Axum handlers)

use std::sync::Arc;
use dashmap::DashMap;
use std::time::Instant;
use crate::node_rpc::NodeRpcClient;
use crate::session::SessionStore;
use crate::Config;

/// Tracks PIN brute-force attempts per address.
pub struct PinAttempts {
    pub failures: u32,
    pub locked_until: Option<Instant>,
}

/// Stores a login challenge (nonce) for challenge-response auth.
pub struct AuthChallenge {
    pub nonce: String,
    pub address: String,
    pub created_at: Instant,
}

pub struct AppState {
    pub node_client: Arc<NodeRpcClient>,
    pub sessions: SessionStore,
    pub config: Config,
    /// Tracks which wallet addresses have claimed from the faucet
    pub faucet_claims: DashMap<String, Instant>,
    /// Tracks PIN failures per address for brute-force protection
    pub pin_attempts: DashMap<String, PinAttempts>,
    /// Pending login challenges: nonce -> AuthChallenge (TTL 5 min)
    pub auth_challenges: DashMap<String, AuthChallenge>,
}
