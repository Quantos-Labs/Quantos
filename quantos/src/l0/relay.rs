//! Relay dispatcher for [`L0FinalityProof`].
//!
//! The dispatcher is intentionally transport-agnostic. A [`RelayTransport`]
//! implementation handles the actual network call (HTTP, JSON-RPC, gRPC,
//! native chain client, etc.). The dispatcher takes care of:
//!
//! * picking the right adapter from the [`ChainRegistry`],
//! * encoding the proof for the target family,
//! * retrying with exponential backoff,
//! * reporting structured outcomes back to the caller.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use reqwest::blocking::Client;
use serde_json::json;

use crate::l0::config::{L0Config, RelayBackoff};
use crate::l0::encoding::{CanonicalEncoder, EncodedProof};
use crate::l0::error::{L0Error, L0Result};
use crate::l0::proof::L0FinalityProof;
use crate::l0::registry::{ChainAdapter, ChainRegistry, TargetChainId};
use crate::types::Hash;

/// Status of a single relay attempt.
#[derive(Clone, Debug)]
pub enum RelayStatus {
    /// Submission succeeded. Transport returned the given receipt id.
    Delivered {
        /// Identifier returned by the transport (tx hash, sequence id…).
        receipt: String,
    },
    /// Submission failed permanently. No further retry will be attempted.
    Failed {
        /// Human-readable failure reason.
        reason: String,
    },
    /// Submission is pending another retry.
    Pending {
        /// Number of attempts performed so far.
        attempts: u32,
    },
}

/// Aggregated outcome of dispatching a single proof to a single chain.
#[derive(Clone, Debug)]
pub struct RelayOutcome {
    /// Target chain.
    pub chain: TargetChainId,
    /// Hash of the proof that was dispatched.
    pub proof_hash: Hash,
    /// Final status.
    pub status: RelayStatus,
    /// Number of attempts performed.
    pub attempts: u32,
}

/// Description of a relay job, mostly used for logging / metrics.
#[derive(Clone, Debug)]
pub struct RelayJob {
    /// Target chain.
    pub chain: TargetChainId,
    /// Hash of the proof.
    pub proof_hash: Hash,
}

/// Abstract relay transport. Implementors typically wrap an HTTP /
/// JSON-RPC / gRPC client specific to the target chain.
pub trait RelayTransport: Send + Sync {
    /// Submits the encoded proof and returns either a receipt id or a
    /// transport error.
    fn submit(
        &self,
        adapter: &ChainAdapter,
        payload: &EncodedProof,
    ) -> Result<String, RelayTransportError>;
}

/// Error reported by a [`RelayTransport`] implementation.
#[derive(Debug)]
pub enum RelayTransportError {
    /// Transient failure. The dispatcher will retry.
    Transient(String),
    /// Permanent failure. The dispatcher will stop retrying.
    Permanent(String),
}

impl From<RelayTransportError> for L0Error {
    fn from(value: RelayTransportError) -> Self {
        match value {
            RelayTransportError::Transient(msg) => L0Error::Transport(msg),
            RelayTransportError::Permanent(msg) => L0Error::PermanentRelay(msg),
        }
    }
}

/// HTTP relay transport for submitting proofs to remote operator endpoints.
///
/// This is a simple default transport implementation for target chains
/// that expose a JSON acceptance endpoint.
pub struct HttpRelayTransport {
    client: Client,
}

impl HttpRelayTransport {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }
}

impl RelayTransport for HttpRelayTransport {
    fn submit(
        &self,
        adapter: &ChainAdapter,
        payload: &EncodedProof,
    ) -> Result<String, RelayTransportError> {
        let body = json!({
            "chain_id": adapter.id.as_str(),
            "chain_family": format!("{:?}", adapter.family),
            "receiver_address": adapter.receiver_address,
            "proof_hash": hex::encode(payload.proof_hash),
            "format": format!("{:?}", payload.format),
            "payload": hex::encode(&payload.payload),
        });

        let response = self
            .client
            .post(&adapter.endpoint)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .map_err(|e| RelayTransportError::Transient(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().unwrap_or_else(|_| "<unreadable>".to_string());
            return Err(RelayTransportError::Permanent(format!(
                "remote rejected proof: {} - {}",
                status, text
            )));
        }

        response
            .text()
            .map_err(|e| RelayTransportError::Transient(e.to_string()))
    }
}

/// Relay dispatcher.
#[derive(Clone)]
pub struct RelayDispatcher {
    config: L0Config,
    registry: ChainRegistry,
    encoder: CanonicalEncoder,
    transports: Arc<HashMap<TargetChainId, Arc<dyn RelayTransport>>>,
    delivered: Arc<Mutex<HashMap<(TargetChainId, Hash), String>>>,
}

impl RelayDispatcher {
    /// Builds a new dispatcher. `transports` maps a chain id to the
    /// transport implementation responsible for actually shipping the
    /// payload.
    pub fn new(
        config: L0Config,
        registry: ChainRegistry,
        transports: HashMap<TargetChainId, Arc<dyn RelayTransport>>,
    ) -> Self {
        Self {
            config,
            registry,
            encoder: CanonicalEncoder::new(),
            transports: Arc::new(transports),
            delivered: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns the list of chains this dispatcher will attempt to
    /// publish to, taking both the registry and the configuration into
    /// account.
    pub fn live_targets(&self) -> Vec<ChainAdapter> {
        let configured: HashMap<&TargetChainId, bool> = self
            .config
            .targets
            .iter()
            .map(|t| (&t.chain_id, t.enabled))
            .collect();

        self.registry
            .live_targets()
            .into_iter()
            .filter(|adapter| configured.get(&adapter.id).copied().unwrap_or(true))
            .collect()
    }

    /// Dispatches `proof` to every live target. Returns one
    /// [`RelayOutcome`] per attempted target.
    pub fn dispatch(&self, proof: &L0FinalityProof) -> Vec<RelayOutcome> {
        let mut outcomes = Vec::new();
        for adapter in self.live_targets() {
            outcomes.push(self.dispatch_to(adapter, proof));
        }
        outcomes
    }

    /// Dispatches `proof` to a single chain.
    pub fn dispatch_to(
        &self,
        adapter: ChainAdapter,
        proof: &L0FinalityProof,
    ) -> RelayOutcome {
        let proof_hash = proof.proof_hash();
        let key = (adapter.id.clone(), proof_hash);

        if let Some(receipt) = self.delivered.lock().get(&key).cloned() {
            return RelayOutcome {
                chain: adapter.id.clone(),
                proof_hash,
                status: RelayStatus::Delivered { receipt },
                attempts: 0,
            };
        }

        let Some(transport) = self.transports.get(&adapter.id).cloned() else {
            return RelayOutcome {
                chain: adapter.id.clone(),
                proof_hash,
                status: RelayStatus::Failed {
                    reason: "no transport bound".into(),
                },
                attempts: 0,
            };
        };

        let encoded = match self.encoder.encode(proof, &adapter) {
            Ok(payload) => payload,
            Err(err) => {
                return RelayOutcome {
                    chain: adapter.id.clone(),
                    proof_hash,
                    status: RelayStatus::Failed {
                        reason: err.to_string(),
                    },
                    attempts: 0,
                }
            }
        };

        let backoff = self.backoff_for(&adapter.id);
        let mut attempts: u32 = 0;
        loop {
            attempts += 1;
            match transport.submit(&adapter, &encoded) {
                Ok(receipt) => {
                    self.delivered
                        .lock()
                        .insert(key, receipt.clone());
                    return RelayOutcome {
                        chain: adapter.id.clone(),
                        proof_hash,
                        status: RelayStatus::Delivered { receipt },
                        attempts,
                    };
                }
                Err(RelayTransportError::Transient(msg)) => {
                    if attempts >= backoff.max_retries {
                        return RelayOutcome {
                            chain: adapter.id.clone(),
                            proof_hash,
                            status: RelayStatus::Failed {
                                reason: format!("max retries exceeded: {msg}"),
                            },
                            attempts,
                        };
                    }
                    let delay = backoff.delay_for(attempts);
                    std::thread::sleep(clamp_delay(delay));
                }
                Err(RelayTransportError::Permanent(msg)) => {
                    return RelayOutcome {
                        chain: adapter.id.clone(),
                        proof_hash,
                        status: RelayStatus::Failed { reason: msg },
                        attempts,
                    };
                }
            }
        }
    }

    fn backoff_for(&self, id: &TargetChainId) -> RelayBackoff {
        self.config
            .targets
            .iter()
            .find(|t| &t.chain_id == id)
            .and_then(|t| t.backoff.clone())
            .unwrap_or_else(|| self.config.default_backoff.clone())
    }
}

fn clamp_delay(delay: Duration) -> Duration {
    // We never want to block the dispatcher thread for more than 5
    // minutes, even if a misconfigured backoff says otherwise.
    if delay > Duration::from_secs(300) {
        Duration::from_secs(300)
    } else {
        delay
    }
}
