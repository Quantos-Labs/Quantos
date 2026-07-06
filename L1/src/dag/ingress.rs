use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use crossbeam_channel::{bounded, Receiver, Sender};
use dashmap::DashMap;
use parking_lot::Mutex;
use tracing::{debug, warn};

use crate::crypto::verify_dilithium_batch;

fn short_hex(a: &[u8]) -> String {
    a.iter().take(4).map(|b| format!("{:02x}", b)).collect()
}
use crate::network::prefilter_tx_bytes as network_prefilter;
use crate::state::StateManager;
use crate::stacc::{ActivationLedger, QuotaManager, StaccAdmission, StaccTier};
use crate::stacc::quota::{StakeProvider, AncienneteProvider};
use crate::types::{Address, Hash, ShardId, SignedTransaction};

/// Maximum transactions in the ingress buffer per shard.
/// When full, new incoming transactions are dropped (back-pressure).
const INGRESS_BUFFER_SIZE: usize = 10_000;

/// DAG-native transaction ingress buffer.
///
/// Design principles:
/// 1. **No persistent storage** — transactions live only in the bounded channel.
///    If the buffer is full, transactions are dropped. The DAG itself is the
///    only durable record.
/// 2. **Local validation only** — signature, nonce, prefilter, balance checks
///    happen at ingress. STACC quota/activation checks happen later at
///    vertex-assembly time (where the quota burn is applied).
/// 3. **One channel per shard** — deterministic routing by `tx.shard_id`.
/// 4. **No ordering guarantees** — the vertex builder applies nonce ordering
///    and conflict detection when assembling the vertex.
pub struct TxIngressBuffer {
    shards: Arc<DashMap<ShardId, (Sender<SignedTransaction>, Receiver<SignedTransaction>)>>,
    state_manager: StateManager,
    /// Cached nonce per sender for fast local validation.
    nonce_cache: Arc<Mutex<HashMap<Address, u64>>>,
    /// Public key cache for signature verification.
    pubkey_cache: Arc<DashMap<Address, Vec<u8>>>,
    /// Total pending transactions across all shards (approximate, relaxed ordering).
    total_pending: Arc<AtomicUsize>,
    /// Per-shard pending counters.
    pending_by_shard: Arc<DashMap<ShardId, AtomicUsize>>,
}

impl TxIngressBuffer {
    pub fn new(state_manager: StateManager, num_shards: u16) -> Self {
        let shards = Arc::new(DashMap::new());
        for i in 0..num_shards {
            let (tx, rx) = bounded(INGRESS_BUFFER_SIZE);
            shards.insert(i, (tx, rx));
        }
        let pending_by_shard = Arc::new(DashMap::new());
        for i in 0..num_shards {
            pending_by_shard.insert(i, AtomicUsize::new(0));
        }
        Self {
            shards,
            state_manager,
            nonce_cache: Arc::new(Mutex::new(HashMap::new())),
            pubkey_cache: Arc::new(DashMap::new()),
            total_pending: Arc::new(AtomicUsize::new(0)),
            pending_by_shard,
        }
    }

    /// Receive a transaction from P2P gossip or RPC.
    /// Performs fast local validation; if valid, pushes into the shard channel.
    /// Returns `true` if accepted into the buffer.
    pub fn ingest(&self, tx: SignedTransaction) -> bool {
        // 1. Prefilter (cheap size/format checks)
        if let Err(e) = network_prefilter(&bincode::serialize(&tx).unwrap_or_default()) {
            warn!(hash = %short_hex(&tx.hash), "ingress prefilter drop: {}", e);
            return false;
        }

        // 2. Signature verification
        let pk = if tx.transaction.public_key.is_empty() {
            match self.pubkey_cache.get(&tx.transaction.from) {
                Some(cached) => cached.clone(),
                None => {
                    warn!(addr = %short_hex(&tx.transaction.from), "ingress: unknown pubkey");
                    return false;
                }
            }
        } else {
            let pk = tx.transaction.public_key.clone();
            self.pubkey_cache.insert(tx.transaction.from, pk.clone());
            pk
        };

        let signing_data = tx.transaction.signing_data();
        if !verify_dilithium_batch(pk, signing_data, tx.transaction.signature.clone()) {
            warn!(hash = %short_hex(&tx.hash), "ingress: invalid signature");
            return false;
        }

        // 3. Nonce check (against local cache + state fallback)
        let expected = {
            let cache = self.nonce_cache.lock();
            *cache.get(&tx.transaction.from).unwrap_or(&0)
        };
        if tx.transaction.nonce != expected {
            // Fallback to state manager if cache stale
            let state_nonce = self.state_manager.get_nonce(&tx.transaction.from).unwrap_or(0);
            if tx.transaction.nonce != state_nonce {
                warn!(
                    hash = %short_hex(&tx.hash),
                    expected = expected,
                    got = tx.transaction.nonce,
                    "ingress: nonce mismatch"
                );
                return false;
            }
            // Update cache
            self.nonce_cache.lock().insert(tx.transaction.from, state_nonce);
        }

        // 4. Route to shard channel (non-blocking; drops if full)
        let shard_id = tx.transaction.shard_id;
        let tx_hash = short_hex(&tx.hash);
        if let Some(entry) = self.shards.get(&shard_id) {
            let (sender, _) = entry.value();
            if sender.try_send(tx).is_ok() {
                self.total_pending.fetch_add(1, Ordering::Relaxed);
                if let Some(c) = self.pending_by_shard.get(&shard_id) {
                    c.fetch_add(1, Ordering::Relaxed);
                }
                debug!(hash = %tx_hash, shard = shard_id, "ingress accepted");
                return true;
            } else {
                warn!(shard = shard_id, "ingress buffer full, dropping tx");
            }
        } else {
            warn!(shard = shard_id, "ingress: unknown shard");
        }
        false
    }

    /// Drain up to `limit` transactions from a shard's ingress buffer.
    /// Called by the vertex builder to assemble a vertex.
    pub fn drain_shard(&self, shard_id: ShardId, limit: usize) -> Vec<SignedTransaction> {
        let mut txs = Vec::with_capacity(limit);
        if let Some(entry) = self.shards.get(&shard_id) {
            let (_, receiver) = entry.value();
            while txs.len() < limit {
                match receiver.try_recv() {
                    Ok(tx) => {
                        self.total_pending.fetch_sub(1, Ordering::Relaxed);
                        if let Some(c) = self.pending_by_shard.get(&shard_id) {
                            c.fetch_sub(1, Ordering::Relaxed);
                        }
                        txs.push(tx);
                    }
                    Err(_) => break,
                }
            }
        }
        txs
    }

    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    pub fn total_pending(&self) -> usize {
        self.total_pending.load(Ordering::Relaxed)
    }

    pub fn get_pending_for_shard(&self, shard_id: ShardId, _limit: usize) -> Vec<SignedTransaction> {
        // In DAG-native mode we don't expose raw transactions from the ingress buffer.
        // Return empty for API compatibility; metrics use pending_by_shard.
        Vec::new()
    }

    pub fn pending_for_shard(&self, shard_id: ShardId) -> usize {
        self.pending_by_shard.get(&shard_id)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

/// Vertex builder with STACC quota enforcement.
///
/// This is where the "mempool logic" moves in a DAG-native design:
/// - Pull transactions from the ingress buffer.
/// - Apply STACC activation + quota checks.
/// - Resolve nonce ordering and conflict sets.
/// - Assemble the vertex payload.
pub struct VertexBuilder<S: StakeProvider, A: AncienneteProvider> {
    ingress: Arc<TxIngressBuffer>,
    state_manager: StateManager,
    stacc: StaccAdmission<S, A>,
    /// How many transactions to pull per vertex attempt.
    pub batch_size: usize,
}

impl<S: StakeProvider + Clone, A: AncienneteProvider + Clone> VertexBuilder<S, A> {
    pub fn new(
        ingress: Arc<TxIngressBuffer>,
        state_manager: StateManager,
        stacc: StaccAdmission<S, A>,
    ) -> Self {
        Self {
            ingress,
            state_manager,
            stacc,
            batch_size: 10_000,
        }
    }

    /// Build a candidate transaction set for a vertex.
    ///
    /// Steps:
    /// 1. Drain `batch_size` transactions from the shard ingress buffer.
    /// 2. Apply STACC activation + quota admission (burns CU tokens).
    /// 3. Order by nonce and filter conflicts.
    /// 4. Return the ordered, validated list.
    pub fn build_vertex_payload(
        &mut self,
        shard_id: ShardId,
        now_block: u64,
    ) -> Vec<SignedTransaction> {
        let raw_txs = self.ingress.drain_shard(shard_id, self.batch_size);
        if raw_txs.is_empty() {
            return Vec::new();
        }

        // Score and sort by priority (boost + fee / cu)
        let mut scored: Vec<(SignedTransaction, u128)> = raw_txs
            .into_iter()
            .map(|tx| {
                let fee = tx.transaction.amount.0 as u128;
                let cu = tx.transaction.max_compute_units.max(1) as u128;
                let boost = tx.transaction.boost.as_ref().map_or(0, |b| b.locked_tokens) as u128;
                let score = (boost.saturating_mul(10).saturating_add(fee.saturating_mul(2)))
                    .saturating_mul(1_000_000)
                    / cu;
                (tx, score)
            })
            .collect();
        scored.sort_by(|a, b| b.1.cmp(&a.1));

        let mut selected = Vec::new();
        let mut expected_nonce: BTreeMap<Address, u64> = BTreeMap::new();
        let mut account_locks: BTreeMap<Address, ()> = BTreeMap::new();
        let mut resource_locks: BTreeMap<Hash, ()> = BTreeMap::new();

        for (tx, _score) in scored {
            let sender = tx.transaction.from;

            // STACC admission (activation + quota burn)
            if let Err(e) = self.stacc.admit(tx.clone(), now_block) {
                debug!(
                    hash = %hex::encode(&tx.hash[..4]),
                    sender = %hex::encode(&sender[..4]),
                    "stacc rejected: {:?}",
                    e
                );
                continue;
            }

            // Nonce ordering
            let exp = *expected_nonce
                .entry(sender)
                .or_insert_with(|| self.state_manager.get_nonce(&sender).unwrap_or(0));
            if tx.transaction.nonce != exp {
                continue;
            }

            // Conflict detection (account + resource locks)
            let to = tx.transaction.to;
            if account_locks.contains_key(&sender) || account_locks.contains_key(&to) {
                continue;
            }
            let rkey = resource_conflict_key(&tx);
            if resource_locks.contains_key(&rkey) {
                continue;
            }

            account_locks.insert(sender, ());
            account_locks.insert(to, ());
            resource_locks.insert(rkey, ());
            expected_nonce.insert(sender, exp + 1);
            selected.push(tx);
        }

        selected
    }
}

fn resource_conflict_key(tx: &SignedTransaction) -> Hash {
    crate::types::hash_data(&bincode::serialize(&[
        tx.transaction.from.as_slice(),
        tx.transaction.to.as_slice(),
        &tx.transaction.data,
    ]).unwrap_or_default())
}
