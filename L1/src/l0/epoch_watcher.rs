//! Epoch Watcher — automatic validator set updates for all supported chains.
//!
//! When a source chain transitions to a new epoch (Cosmos, Solana, NEAR, Tezos…),
//! its active validator set changes. Without updates, the L0 light clients would
//! verify checkpoints against stale pubkeys and reject valid proofs.
//!
//! `EpochWatcher` runs as a background tokio task: it polls each registered chain
//! at a configurable interval, fetches the current validator set via RPC, and
//! calls `ValidatorSetRegistry::insert()` when a change is detected.
//! Because `ValidatorSetRegistry` uses an `Arc<RwLock<…>>` internally, all
//! live `LightClient` instances immediately see the new validator set — no
//! restart required.
//!
//! # Usage
//! ```rust,no_run
//! let watcher = EpochWatcher::new(registry.validator_registry.clone());
//! watcher.watch(ChainWatcherConfig {
//!     chain_id: ChainId::Cosmos,
//!     rpc_url: "https://rpc.cosmos.network".to_string(),
//!     poll_interval_ms: 30_000,
//!     threshold_bps: 6667,
//! });
//! tokio::spawn(watcher.run());
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use serde::Deserialize;
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::l0::external::ChainId;
use crate::l0::light_client::{ValidatorSet, ValidatorSetRegistry};
use crate::l0::registry::ChainFamily;

// ── Configuration ────────────────────────────────────────────────────────────

/// Per-chain watcher configuration.
#[derive(Clone, Debug)]
pub struct ChainWatcherConfig {
    /// Chain to watch.
    pub chain_id: ChainId,
    /// RPC/REST endpoint for the source chain.
    pub rpc_url: String,
    /// How often to poll for epoch changes (milliseconds).
    pub poll_interval_ms: u64,
    /// Minimum signed-power basis points required (default 6667 = 2/3).
    pub threshold_bps: u16,
}

impl ChainWatcherConfig {
    pub fn new(chain_id: ChainId, rpc_url: impl Into<String>) -> Self {
        Self {
            chain_id,
            rpc_url: rpc_url.into(),
            poll_interval_ms: 30_000,
            threshold_bps: 6667,
        }
    }

    pub fn with_interval(mut self, ms: u64) -> Self { self.poll_interval_ms = ms; self }
    pub fn with_threshold(mut self, bps: u16) -> Self { self.threshold_bps = bps; self }
}

// ── EpochWatcher ─────────────────────────────────────────────────────────────

pub struct EpochWatcher {
    registry: ValidatorSetRegistry,
    configs: Arc<RwLock<Vec<ChainWatcherConfig>>>,
    http: reqwest::Client,
}

impl EpochWatcher {
    pub fn new(registry: ValidatorSetRegistry) -> Self {
        Self {
            registry,
            configs: Arc::new(RwLock::new(Vec::new())),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("reqwest client"),
        }
    }

    /// Register a chain to watch. Can be called before or after `run()`.
    pub fn watch(&self, config: ChainWatcherConfig) {
        self.configs.write().push(config);
    }

    /// Consume the watcher and run the polling loop forever.
    /// Spawn with `tokio::spawn(watcher.run())`.
    pub async fn run(self) {
        info!("[EpochWatcher] started");
        loop {
            let configs = self.configs.read().clone();
            let mut handles = Vec::with_capacity(configs.len());

            for cfg in configs {
                let registry = self.registry.clone();
                let http = self.http.clone();
                handles.push(tokio::spawn(async move {
                    poll_chain(http, registry, cfg).await;
                }));
            }

            for h in handles {
                let _ = h.await;
            }

            sleep(Duration::from_millis(100)).await;
        }
    }
}

// ── Per-chain poll ────────────────────────────────────────────────────────────

async fn poll_chain(http: reqwest::Client, registry: ValidatorSetRegistry, cfg: ChainWatcherConfig) {
    sleep(Duration::from_millis(cfg.poll_interval_ms)).await;

    let family = cfg.chain_id.family();
    let result = match family {
        ChainFamily::Cosmos   => fetch_cosmos(&http, &cfg).await,
        ChainFamily::Svm      => fetch_solana(&http, &cfg).await,
        ChainFamily::Near     => fetch_near(&http, &cfg).await,
        ChainFamily::Move     => fetch_move(&http, &cfg).await,
        ChainFamily::Ton      => fetch_ton(&http, &cfg).await,
        ChainFamily::Tvm      => fetch_tron(&http, &cfg).await,
        ChainFamily::Substrate => fetch_polkadot(&http, &cfg).await,
        ChainFamily::Stellar  => fetch_stellar(&http, &cfg).await,
        ChainFamily::Tezos    => fetch_tezos(&http, &cfg).await,
        ChainFamily::Cardano  => fetch_cardano(&http, &cfg).await,
        // EVM and Bitcoin don't use a validator registry
        _ => return,
    };

    match result {
        Ok(new_set) => {
            let current = registry.get_cloned(&cfg.chain_id);
            let changed = current.map(|c| c.pubkeys != new_set.pubkeys).unwrap_or(true);
            if changed {
                info!(
                    "[EpochWatcher] {:?}: validator set updated ({} validators)",
                    cfg.chain_id,
                    new_set.pubkeys.len()
                );
                registry.insert(cfg.chain_id, new_set);
            }
        }
        Err(e) => {
            warn!("[EpochWatcher] {:?}: fetch failed — {}", cfg.chain_id, e);
        }
    }
}

// ── Chain-specific fetchers ──────────────────────────────────────────────────

/// Cosmos: GET /cosmos/staking/v1beta1/validators?status=BOND_STATUS_BONDED
async fn fetch_cosmos(http: &reqwest::Client, cfg: &ChainWatcherConfig) -> Result<ValidatorSet, String> {
    #[derive(Deserialize)]
    struct Response { validators: Vec<CosmosValidator> }
    #[derive(Deserialize)]
    struct CosmosValidator {
        consensus_pubkey: ConsensusPubkey,
        tokens: String,
    }
    #[derive(Deserialize)]
    struct ConsensusPubkey { key: String }

    let url = format!(
        "{}/cosmos/staking/v1beta1/validators?status=BOND_STATUS_BONDED&pagination.limit=200",
        cfg.rpc_url.trim_end_matches('/')
    );
    let resp: Response = http.get(&url).send().await
        .map_err(|e| e.to_string())?
        .json().await
        .map_err(|e| e.to_string())?;

    let mut pubkeys = Vec::new();
    let mut stakes = Vec::new();
    for v in &resp.validators {
        let pk = base64_to_bytes(&v.consensus_pubkey.key)
            .map_err(|e| format!("pubkey decode: {}", e))?;
        pubkeys.push(pk);
        let stake: u64 = v.tokens.parse().unwrap_or(0);
        stakes.push(stake);
    }
    Ok(ValidatorSet { pubkeys, stakes, threshold_bps: cfg.threshold_bps })
}

/// Solana: getVoteAccounts RPC (JSON-RPC 2.0)
async fn fetch_solana(http: &reqwest::Client, cfg: &ChainWatcherConfig) -> Result<ValidatorSet, String> {
    #[derive(Deserialize)]
    struct Response { result: VoteAccounts }
    #[derive(Deserialize)]
    struct VoteAccounts { current: Vec<VoteAccount> }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct VoteAccount { node_pubkey: String, activated_stake: u64 }

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getVoteAccounts",
        "params": [{ "commitment": "finalized" }]
    });
    let resp: Response = http.post(cfg.rpc_url.trim_end_matches('/'))
        .json(&body).send().await
        .map_err(|e| e.to_string())?
        .json().await
        .map_err(|e| e.to_string())?;

    let mut pubkeys = Vec::new();
    let mut stakes = Vec::new();
    for v in &resp.result.current {
        let pk = bs58_decode(&v.node_pubkey)?;
        pubkeys.push(pk);
        stakes.push(v.activated_stake);
    }
    Ok(ValidatorSet { pubkeys, stakes, threshold_bps: cfg.threshold_bps })
}

/// NEAR: POST validators(null) JSON-RPC
async fn fetch_near(http: &reqwest::Client, cfg: &ChainWatcherConfig) -> Result<ValidatorSet, String> {
    #[derive(Deserialize)]
    struct Response { result: NearValidatorsResult }
    #[derive(Deserialize)]
    struct NearValidatorsResult { current_validators: Vec<NearValidator> }
    #[derive(Deserialize)]
    struct NearValidator { public_key: String, stake: String }

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "dontcare",
        "method": "validators",
        "params": [null]
    });
    let resp: Response = http.post(cfg.rpc_url.trim_end_matches('/'))
        .json(&body).send().await
        .map_err(|e| e.to_string())?
        .json().await
        .map_err(|e| e.to_string())?;

    let mut pubkeys = Vec::new();
    let mut stakes = Vec::new();
    for v in &resp.result.current_validators {
        // NEAR public_key format: "ed25519:<base58>"
        let pk_b58 = v.public_key.strip_prefix("ed25519:").unwrap_or(&v.public_key);
        pubkeys.push(bs58_decode(pk_b58)?);
        let stake: u64 = v.stake.parse::<u128>().unwrap_or(0) as u64;
        stakes.push(stake);
    }
    Ok(ValidatorSet { pubkeys, stakes, threshold_bps: cfg.threshold_bps })
}

/// Aptos/Sui (Move): GET /v1/accounts/<framework>/resource/<ValidatorSet>
async fn fetch_move(http: &reqwest::Client, cfg: &ChainWatcherConfig) -> Result<ValidatorSet, String> {
    // Aptos: /v1/accounts/0x1/resource/0x1::stake::ValidatorSet
    #[derive(Deserialize)]
    struct AptosResponse { data: AptosValidatorSet }
    #[derive(Deserialize)]
    struct AptosValidatorSet { active_validators: Vec<AptosValidator> }
    #[derive(Deserialize)]
    struct AptosValidator { config: AptosValidatorConfig, voting_power: String }
    #[derive(Deserialize)]
    struct AptosValidatorConfig { consensus_public_key: String }

    let url = format!(
        "{}/v1/accounts/0x1/resource/0x1::stake::ValidatorSet",
        cfg.rpc_url.trim_end_matches('/')
    );
    let resp: AptosResponse = http.get(&url).send().await
        .map_err(|e| e.to_string())?
        .json().await
        .map_err(|e| e.to_string())?;

    let mut pubkeys = Vec::new();
    let mut stakes = Vec::new();
    for v in &resp.data.active_validators {
        let pk = hex_to_bytes(v.config.consensus_public_key.trim_start_matches("0x"))?;
        pubkeys.push(pk);
        let stake: u64 = v.voting_power.parse().unwrap_or(0);
        stakes.push(stake);
    }
    Ok(ValidatorSet { pubkeys, stakes, threshold_bps: cfg.threshold_bps })
}

/// TON: /api/v2/getValidators (toncenter.com)
async fn fetch_ton(http: &reqwest::Client, cfg: &ChainWatcherConfig) -> Result<ValidatorSet, String> {
    #[derive(Deserialize)]
    struct Response { result: TonValidators }
    #[derive(Deserialize)]
    struct TonValidators { validators: Vec<TonValidator> }
    #[derive(Deserialize)]
    struct TonValidator { public_key: String, weight: u64 }

    let url = format!("{}/api/v2/getValidators", cfg.rpc_url.trim_end_matches('/'));
    let resp: Response = http.get(&url).send().await
        .map_err(|e| e.to_string())?
        .json().await
        .map_err(|e| e.to_string())?;

    let mut pubkeys = Vec::new();
    let mut stakes = Vec::new();
    for v in &resp.result.validators {
        pubkeys.push(hex_to_bytes(&v.public_key)?);
        stakes.push(v.weight);
    }
    Ok(ValidatorSet { pubkeys, stakes, threshold_bps: cfg.threshold_bps })
}

/// Tron: POST /wallet/getdelegatedresource (super representatives)
async fn fetch_tron(http: &reqwest::Client, cfg: &ChainWatcherConfig) -> Result<ValidatorSet, String> {
    #[derive(Deserialize)]
    struct Response { witnesses: Vec<TronWitness> }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TronWitness { address: String, vote_count: u64 }

    let url = format!("{}/wallet/listwitnesses", cfg.rpc_url.trim_end_matches('/'));
    let resp: Response = http.get(&url).send().await
        .map_err(|e| e.to_string())?
        .json().await
        .map_err(|e| e.to_string())?;

    let mut pubkeys = Vec::new();
    let mut stakes = Vec::new();
    // Tron addresses are base58check; we store the raw 21 bytes as the "pubkey"
    // (the ECDSA pubkey lookup happens off-chain; here we register by address)
    for w in resp.witnesses.iter().take(27) { // top 27 SRs vote
        pubkeys.push(bs58_decode(&w.address)?);
        stakes.push(w.vote_count);
    }
    Ok(ValidatorSet { pubkeys, stakes, threshold_bps: cfg.threshold_bps })
}

/// Polkadot: POST JSON-RPC session_validators
async fn fetch_polkadot(http: &reqwest::Client, cfg: &ChainWatcherConfig) -> Result<ValidatorSet, String> {
    #[derive(Deserialize)]
    struct Response { result: Vec<String> }

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "state_call",
        "params": ["SessionApi_validators", "0x"]
    });
    let resp: Response = http.post(cfg.rpc_url.trim_end_matches('/'))
        .json(&body).send().await
        .map_err(|e| e.to_string())?
        .json().await
        .map_err(|e| e.to_string())?;

    // result is a hex-encoded SCALE-encoded Vec<AccountId32>; each is 32 bytes
    let raw = hex_to_bytes(resp.result.first().map(|s| s.trim_start_matches("0x")).unwrap_or(""))?;
    let count = if raw.len() >= 2 { raw[0] as usize } else { 0 };
    let mut pubkeys = Vec::with_capacity(count);
    let mut stakes = Vec::with_capacity(count);
    let mut offset = 1; // compact length prefix: single-byte encoding for count ≤63
    for _ in 0..count {
        if offset + 32 > raw.len() { break; }
        pubkeys.push(raw[offset..offset + 32].to_vec());
        stakes.push(1u64); // equal weight in session validator list
        offset += 32;
    }
    Ok(ValidatorSet { pubkeys, stakes, threshold_bps: cfg.threshold_bps })
}

/// Stellar: GET /quorum via Horizon API
async fn fetch_stellar(http: &reqwest::Client, cfg: &ChainWatcherConfig) -> Result<ValidatorSet, String> {
    // Use Stellar Core's /quorum endpoint which lists trusted validators
    #[derive(Deserialize)]
    struct QuorumResponse { nodes: Vec<StellarNode> }
    #[derive(Deserialize)]
    struct StellarNode { node: String, #[serde(default)] weight: u64 }

    let url = format!("{}/quorum", cfg.rpc_url.trim_end_matches('/'));
    let resp: QuorumResponse = http.get(&url).send().await
        .map_err(|e| e.to_string())?
        .json().await
        .map_err(|e| e.to_string())?;

    let mut pubkeys = Vec::new();
    let mut stakes = Vec::new();
    for n in &resp.nodes {
        // Stellar node IDs are G-addresses, which are base32-encoded Ed25519 pubkeys
        pubkeys.push(stellar_address_to_pubkey(&n.node)?);
        stakes.push(n.weight.max(1));
    }
    Ok(ValidatorSet { pubkeys, stakes, threshold_bps: cfg.threshold_bps })
}

/// Tezos: GET /chains/main/blocks/head/context/selected_snapshot
/// Baker set fetched from /chains/main/blocks/head/helpers/baking_rights
async fn fetch_tezos(http: &reqwest::Client, cfg: &ChainWatcherConfig) -> Result<ValidatorSet, String> {
    #[derive(Deserialize)]
    struct BakingRight { delegate: String, priority: u32 }

    let url = format!(
        "{}/chains/main/blocks/head/helpers/baking_rights?max_priority=32&all=true",
        cfg.rpc_url.trim_end_matches('/')
    );
    let rights: Vec<BakingRight> = http.get(&url).send().await
        .map_err(|e| e.to_string())?
        .json().await
        .map_err(|e| e.to_string())?;

    // Collect unique baker addresses with their lowest priority (higher = more rights)
    let mut baker_map: HashMap<String, u32> = HashMap::new();
    for r in &rights {
        baker_map.entry(r.delegate.clone())
            .and_modify(|p| *p += 1)
            .or_insert(1);
    }

    let mut pubkeys = Vec::new();
    let mut stakes = Vec::new();
    for (addr, weight) in baker_map {
        // Tezos addresses are tz1/tz2/tz3 base58check; get the Ed25519 pubkey via RPC
        match fetch_tezos_pubkey(http, cfg, &addr).await {
            Ok(pk) => { pubkeys.push(pk); stakes.push(weight as u64); }
            Err(e) => warn!("[EpochWatcher] Tezos pubkey fetch for {}: {}", addr, e),
        }
    }
    Ok(ValidatorSet { pubkeys, stakes, threshold_bps: cfg.threshold_bps })
}

async fn fetch_tezos_pubkey(
    http: &reqwest::Client,
    cfg: &ChainWatcherConfig,
    address: &str,
) -> Result<Vec<u8>, String> {
    #[derive(Deserialize)]
    struct DelegateInfo { consensus_key: ConsensusKey }
    #[derive(Deserialize)]
    struct ConsensusKey { pk: String }

    let url = format!(
        "{}/chains/main/blocks/head/context/delegates/{}/consensus_key",
        cfg.rpc_url.trim_end_matches('/'),
        address
    );
    let info: DelegateInfo = http.get(&url).send().await
        .map_err(|e| e.to_string())?
        .json().await
        .map_err(|e| e.to_string())?;

    // Tezos Ed25519 pubkeys: "edpk..." base58check with 4-byte prefix stripped
    tezos_pk_to_bytes(&info.consensus_key.pk)
}

/// Cardano: GET /api/core/epochs/latest/stake_distribution (cardano-db-sync API)
async fn fetch_cardano(http: &reqwest::Client, cfg: &ChainWatcherConfig) -> Result<ValidatorSet, String> {
    #[derive(Deserialize)]
    struct StakePool { pool_id: String, active_stake: Option<String> }

    let url = format!("{}/api/core/epochs/latest/stake_distribution?limit=200", cfg.rpc_url.trim_end_matches('/'));
    let pools: Vec<StakePool> = http.get(&url).send().await
        .map_err(|e| e.to_string())?
        .json().await
        .map_err(|e| e.to_string())?;

    let mut pubkeys = Vec::new();
    let mut stakes = Vec::new();
    for p in &pools {
        // Pool ID is bech32 "pool1..." — use raw bytes as identifier
        if let Ok(pk) = bech32_payload(&p.pool_id) {
            pubkeys.push(pk);
            let stake = p.active_stake.as_deref()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            stakes.push(stake);
        }
    }
    Ok(ValidatorSet { pubkeys, stakes, threshold_bps: cfg.threshold_bps })
}

// ── Encoding helpers ──────────────────────────────────────────────────────────

fn base64_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    use data_encoding::BASE64;
    BASE64.decode(s.as_bytes()).map_err(|e| e.to_string())
}

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| e.to_string())
}

fn bs58_decode(s: &str) -> Result<Vec<u8>, String> {
    bs58::decode(s).into_vec().map_err(|e| e.to_string())
}

/// Stellar G-address → raw 32-byte Ed25519 pubkey.
/// G-addresses are base32-encoded: 1 byte version + 32 bytes pubkey + 2 bytes checksum.
fn stellar_address_to_pubkey(addr: &str) -> Result<Vec<u8>, String> {
    use data_encoding::BASE32_NOPAD;
    let decoded = BASE32_NOPAD.decode(addr.to_uppercase().as_bytes())
        .map_err(|e| format!("Stellar base32 decode: {}", e))?;
    if decoded.len() != 35 {
        return Err(format!("Stellar address wrong length: {}", decoded.len()));
    }
    Ok(decoded[1..33].to_vec()) // bytes 1..33 are the Ed25519 pubkey
}

/// Tezos edpk... base58check pubkey → raw 32-byte Ed25519 pubkey.
/// edpk prefix bytes: [13, 15, 37, 217] (4 bytes).
fn tezos_pk_to_bytes(pk: &str) -> Result<Vec<u8>, String> {
    let decoded = bs58::decode(pk).into_vec().map_err(|e| e.to_string())?;
    // Format: 4-byte prefix + 32 bytes pubkey + 4-byte checksum = 40 bytes
    if decoded.len() < 36 {
        return Err(format!("Tezos pubkey too short: {}", decoded.len()));
    }
    Ok(decoded[4..36].to_vec())
}

/// Bech32 string → payload bytes (without HRP and checksum).
fn bech32_payload(s: &str) -> Result<Vec<u8>, String> {
    let (_, data, _) = bech32::decode(s).map_err(|e| e.to_string())?;
    bech32::convert_bits(&data, 5, 8, false).map_err(|e| e.to_string())
}
