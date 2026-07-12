//! # Quantos Real-Time Stress Test
//!
//! Sends PQC-signed transactions against a live Quantos node over JSON-RPC
//! and reports live TPS, latency (p50/p95/p99), rejection rate and mempool depth.
//!
//! ## Usage
//!
//! ```bash
//! # Devnet local (default)
//! cargo run --release --bin stress-test
//!
//! # Custom
//! cargo run --release --bin stress-test -- \
//!   --rpc http://localhost:8545 \
//!   --tps 5000 \
//!   --duration 60 \
//!   --wallets 200 \
//!   --chain-id 3
//! ```
//!
//! ## Rate-limit note
//!
//! The RPC server applies 100 req/min + burst 20 per source IP.
//! Each `qnt_sendRawTransactionBatch` call carries up to 100 txs, so effective
//! throughput before hitting the limiter is ~100 × 100 = 10 000 tx/min ≈ 167 TPS.
//! For higher TPS, start the node with `QUANTOS_RATELIMIT_DISABLED=1`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tokio::time::sleep;

use quantos::crypto::DilithiumKeypair;
use quantos::types::{Amount, SignedTransaction, Transaction, TransactionType, VmKind};

const BATCH_SIZE: usize = 100;
const LATENCY_WINDOW: usize = 10_000;
const DASHBOARD_INTERVAL_MS: u64 = 1_000;

// ─────────────────────────────────────────────────────────────────────────────
// CLI
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug, Clone)]
#[command(name = "stress-test")]
#[command(about = "Quantos real-time TPS stress tester")]
struct Args {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Target transactions per second to attempt
    #[arg(long, default_value = "1000")]
    tps: u64,

    /// Test duration in seconds (0 = run until Ctrl-C)
    #[arg(long, default_value = "60")]
    duration: u64,

    /// Number of sender wallets (each wallet sends in parallel)
    #[arg(long, default_value = "50")]
    wallets: usize,

    /// Chain ID (1=mainnet 2=testnet 3=devnet)
    #[arg(long, default_value = "3")]
    chain_id: u64,

    /// Number of shards on the target node
    #[arg(long, default_value = "16")]
    shards: u16,

    /// Transfer amount per tx (in smallest unit)
    #[arg(long, default_value = "1")]
    amount: u128,

    /// Starting nonce for all wallets (useful to resume)
    #[arg(long, default_value = "0")]
    start_nonce: u64,

    /// Show verbose errors
    #[arg(long)]
    verbose: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Stats (shared across all worker tasks)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Stats {
    sent: AtomicU64,
    accepted: AtomicU64,
    rejected: AtomicU64,
    ratelimited: AtomicU64,
    errors: AtomicU64,
    /// Confirmed (receipt received with success=true)
    confirmed: AtomicU64,
    /// Sum of confirmation latencies in ms
    latency_sum_ms: AtomicU64,
    latency_count: AtomicU64,
}

/// Rolling window of latency samples for percentile calculation.
type LatencyWindow = Arc<Mutex<VecDeque<u64>>>;

// ─────────────────────────────────────────────────────────────────────────────
// Lightweight JSON-RPC client (reqwest)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct RpcClient {
    endpoint: String,
    http: reqwest::Client,
}

impl RpcClient {
    fn new(endpoint: &str) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(64)
            .build()
            .expect("failed to build reqwest client");
        Self {
            endpoint: endpoint.to_string(),
            http,
        }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });

        let resp = self
            .http
            .post(&self.endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("http error: {e}"))?;

        let status = resp.status();
        let json: Value = resp
            .json()
            .await
            .map_err(|e| format!("json parse error: {e}"))?;

        if status == 429 {
            return Err("rate-limited".to_string());
        }

        if let Some(err) = json.get("error") {
            return Err(err.to_string());
        }

        json.get("result")
            .cloned()
            .ok_or_else(|| "missing result".to_string())
    }

    async fn send_batch(&self, txs_hex: Vec<String>) -> Result<Vec<String>, String> {
        let result = self
            .call("qnt_sendRawTransactionBatch", json!([txs_hex]))
            .await?;
        serde_json::from_value::<Vec<String>>(result)
            .map_err(|e| format!("deserialize batch result: {e}"))
    }

    async fn get_receipt(&self, hash: &str) -> Result<Option<Value>, String> {
        let result = self
            .call("qnt_getTransactionReceipt", json!([hash]))
            .await?;
        if result.is_null() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    async fn get_metrics(&self) -> Result<Value, String> {
        self.call("qnt_getMetrics", json!([])).await
    }

    async fn tx_pool_status(&self) -> Result<Value, String> {
        self.call("qnt_txPoolStatus", json!([])).await
    }

    async fn get_slot(&self) -> Result<u64, String> {
        let v = self.call("qnt_getSlot", json!([])).await?;
        v.as_u64().ok_or_else(|| "invalid slot".to_string())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Wallet
// ─────────────────────────────────────────────────────────────────────────────

struct Wallet {
    keypair: DilithiumKeypair,
    address: [u8; 32],
    nonce: AtomicU64,
}

impl Wallet {
    fn new(start_nonce: u64) -> Self {
        let keypair = DilithiumKeypair::generate().expect("keygen failed");
        let address = quantos::crypto::sha3_256(&keypair.public_key);
        Self {
            keypair,
            address,
            nonce: AtomicU64::new(start_nonce),
        }
    }

    fn next_nonce(&self) -> u64 {
        self.nonce.fetch_add(1, AtomicOrdering::Relaxed)
    }

    fn build_tx(
        &self,
        to: &[u8; 32],
        amount: u128,
        chain_id: u64,
        shards: u16,
    ) -> Option<SignedTransaction> {
        let nonce = self.next_nonce();
        let shard_id = Transaction::target_shard(&self.address, shards);

        let mut tx = Transaction {
            tx_type: TransactionType::Transfer,
            from: self.address,
            to: *to,
            amount: Amount(amount),
            nonce,
            max_compute_units: 21_000,
            boost: None,
            vm_kind: VmKind::Qvm,
            data: Vec::new(),
            shard_id,
            timestamp: chrono::Utc::now().timestamp() as u64,
            signature: Vec::new(),
            public_key: Vec::new(),
            chain_id,
        };

        let signing_data = tx.signing_data();
        let sig = self.keypair.sign(&signing_data).ok()?;
        tx.set_signature(sig, self.keypair.public_key.clone()).ok()?;
        Some(SignedTransaction::new(tx))
    }
}

fn encode_tx(stx: &SignedTransaction) -> Option<String> {
    let bytes = bincode::serialize(stx).ok()?;
    Some(format!("QTS:{}", hex::encode(bytes)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Percentile helper
// ─────────────────────────────────────────────────────────────────────────────

fn percentile(samples: &[u64], p: f64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

// ─────────────────────────────────────────────────────────────────────────────
// Dashboard
// ─────────────────────────────────────────────────────────────────────────────

async fn dashboard_task(
    stats: Arc<Stats>,
    latencies: LatencyWindow,
    rpc: RpcClient,
    start: Instant,
    duration_secs: u64,
    verbose: bool,
) {
    let mut prev_sent = 0u64;
    let mut prev_confirmed = 0u64;
    let mut tick = tokio::time::interval(Duration::from_millis(DASHBOARD_INTERVAL_MS));

    println!(
        "\n\x1b[1;36m╔══════════════════════════════════════════════════════════════════╗\x1b[0m"
    );
    println!(
        "\x1b[1;36m║          QUANTOS REAL-TIME STRESS TEST — LIVE DASHBOARD          ║\x1b[0m"
    );
    println!(
        "\x1b[1;36m╚══════════════════════════════════════════════════════════════════╝\x1b[0m\n"
    );

    loop {
        tick.tick().await;
        let elapsed = start.elapsed().as_secs();

        if duration_secs > 0 && elapsed >= duration_secs + 2 {
            break;
        }

        let sent = stats.sent.load(AtomicOrdering::Relaxed);
        let accepted = stats.accepted.load(AtomicOrdering::Relaxed);
        let rejected = stats.rejected.load(AtomicOrdering::Relaxed);
        let ratelimited = stats.ratelimited.load(AtomicOrdering::Relaxed);
        let errors = stats.errors.load(AtomicOrdering::Relaxed);
        let confirmed = stats.confirmed.load(AtomicOrdering::Relaxed);

        let send_tps = (sent - prev_sent) as f64;
        let confirm_tps = (confirmed - prev_confirmed) as f64;
        prev_sent = sent;
        prev_confirmed = confirmed;

        let samples: Vec<u64> = latencies.lock().await.iter().copied().collect();
        let p50 = percentile(&samples, 50.0);
        let p95 = percentile(&samples, 95.0);
        let p99 = percentile(&samples, 99.0);

        let mempool_size = match rpc.tx_pool_status().await {
            Ok(v) => v
                .get("pending")
                .and_then(|p| p.as_u64())
                .unwrap_or(0),
            Err(_) => 0,
        };

        let slot = rpc.get_slot().await.unwrap_or(0);

        print!("\x1b[2K\r");
        println!(
            "\x1b[1;33m[{elapsed:>4}s]\x1b[0m  \
             Sent \x1b[32m{send_tps:>7.0}/s\x1b[0m  \
             Confirmed \x1b[32m{confirm_tps:>7.0}/s\x1b[0m  \
             Accepted \x1b[32m{accepted}\x1b[0m  \
             Rejected \x1b[31m{rejected}\x1b[0m  \
             RateLim \x1b[33m{ratelimited}\x1b[0m  \
             Errors \x1b[31m{errors}\x1b[0m"
        );
        println!(
            "         \
             Latency p50 \x1b[36m{p50}ms\x1b[0m  \
             p95 \x1b[36m{p95}ms\x1b[0m  \
             p99 \x1b[36m{p99}ms\x1b[0m  \
             Mempool \x1b[35m{mempool_size}\x1b[0m  \
             Slot \x1b[37m{slot}\x1b[0m"
        );

        if verbose && errors > 0 {
            println!(
                "\x1b[31m         [verbose] total errors: {errors}, ratelimited: {ratelimited}\x1b[0m"
            );
        }
    }

    print_final_report(&stats, &latencies, start).await;
}

async fn print_final_report(stats: &Stats, latencies: &LatencyWindow, start: Instant) {
    let elapsed = start.elapsed().as_secs_f64();
    let sent = stats.sent.load(AtomicOrdering::Relaxed);
    let accepted = stats.accepted.load(AtomicOrdering::Relaxed);
    let confirmed = stats.confirmed.load(AtomicOrdering::Relaxed);
    let rejected = stats.rejected.load(AtomicOrdering::Relaxed);
    let ratelimited = stats.ratelimited.load(AtomicOrdering::Relaxed);

    let samples: Vec<u64> = latencies.lock().await.iter().copied().collect();
    let p50 = percentile(&samples, 50.0);
    let p95 = percentile(&samples, 95.0);
    let p99 = percentile(&samples, 99.0);
    let avg_confirm_tps = confirmed as f64 / elapsed.max(1.0);

    println!(
        "\n\x1b[1;36m╔══════════════════════════════════════════════════════════════════╗\x1b[0m"
    );
    println!(
        "\x1b[1;36m║                       FINAL RESULTS                              ║\x1b[0m"
    );
    println!(
        "\x1b[1;36m╚══════════════════════════════════════════════════════════════════╝\x1b[0m"
    );
    println!("  Duration        : {elapsed:.1}s");
    println!("  Total sent      : \x1b[32m{sent}\x1b[0m");
    println!("  Total accepted  : \x1b[32m{accepted}\x1b[0m");
    println!("  Total confirmed : \x1b[32m{confirmed}\x1b[0m");
    println!("  Rejected        : \x1b[31m{rejected}\x1b[0m");
    println!("  Rate-limited    : \x1b[33m{ratelimited}\x1b[0m");
    println!("  Avg confirm TPS : \x1b[1;32m{avg_confirm_tps:.1}\x1b[0m");
    println!("  Latency p50     : {p50}ms");
    println!("  Latency p95     : {p95}ms");
    println!("  Latency p99     : {p99}ms");
    println!();
}

// ─────────────────────────────────────────────────────────────────────────────
// Worker task — generates and sends transactions from one wallet
// ─────────────────────────────────────────────────────────────────────────────

async fn worker_task(
    wallet: Arc<Wallet>,
    recipient: [u8; 32],
    rpc: RpcClient,
    stats: Arc<Stats>,
    latencies: LatencyWindow,
    args: Arc<Args>,
    stop: Arc<AtomicU64>,
) {
    // Each worker targets its own send rate = total_tps / wallets
    let tx_per_sec = (args.tps as f64 / args.wallets as f64).max(1.0);
    let interval_ns = (1_000_000_000.0 / tx_per_sec) as u64 * BATCH_SIZE as u64;
    let interval = Duration::from_nanos(interval_ns.max(1_000_000));

    let mut pending: Vec<(String, Instant)> = Vec::new();

    loop {
        if stop.load(AtomicOrdering::Relaxed) == 1 {
            break;
        }

        // Build a batch
        let mut batch_hex = Vec::with_capacity(BATCH_SIZE);
        let mut batch_sent_at = Vec::with_capacity(BATCH_SIZE);

        for _ in 0..BATCH_SIZE {
            match wallet.build_tx(&recipient, args.amount, args.chain_id, args.shards) {
                Some(stx) => {
                    if let Some(hex) = encode_tx(&stx) {
                        batch_hex.push(hex);
                        batch_sent_at.push(Instant::now());
                    }
                }
                None => {
                    stats.errors.fetch_add(1, AtomicOrdering::Relaxed);
                }
            }
        }

        if batch_hex.is_empty() {
            sleep(interval).await;
            continue;
        }

        stats
            .sent
            .fetch_add(batch_hex.len() as u64, AtomicOrdering::Relaxed);

        match rpc.send_batch(batch_hex.clone()).await {
            Ok(results) => {
                for (i, result) in results.iter().enumerate() {
                    if result.starts_with("error:") || result.starts_with("QTS:error") {
                        stats.rejected.fetch_add(1, AtomicOrdering::Relaxed);
                    } else {
                        stats.accepted.fetch_add(1, AtomicOrdering::Relaxed);
                        if i < batch_sent_at.len() {
                            pending.push((result.clone(), batch_sent_at[i]));
                        }
                    }
                }
            }
            Err(e) => {
                if e.contains("rate-limited") || e.contains("rate_limit") {
                    stats
                        .ratelimited
                        .fetch_add(batch_hex.len() as u64, AtomicOrdering::Relaxed);
                    sleep(Duration::from_millis(500)).await;
                } else {
                    stats
                        .errors
                        .fetch_add(batch_hex.len() as u64, AtomicOrdering::Relaxed);
                }
            }
        }

        // Poll pending receipts (non-blocking — just check a few)
        let mut still_pending = Vec::new();
        for (hash, sent_at) in pending.drain(..).take(50) {
            let age = sent_at.elapsed();
            if age > Duration::from_secs(30) {
                // Timeout
                continue;
            }
            match rpc.get_receipt(&hash).await {
                Ok(Some(receipt)) => {
                    let success = receipt
                        .get("success")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);
                    if success {
                        stats.confirmed.fetch_add(1, AtomicOrdering::Relaxed);
                        let lat_ms = age.as_millis() as u64;
                        let mut lw = latencies.lock().await;
                        if lw.len() >= LATENCY_WINDOW {
                            lw.pop_front();
                        }
                        lw.push_back(lat_ms);
                    } else {
                        stats.rejected.fetch_add(1, AtomicOrdering::Relaxed);
                    }
                }
                Ok(None) => still_pending.push((hash, sent_at)),
                Err(_) => still_pending.push((hash, sent_at)),
            }
        }
        pending.extend(still_pending);

        sleep(interval).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Arc::new(Args::parse());

    println!(
        "\n\x1b[1;32m╔══════════════════════════════════════════════════════════════════╗\x1b[0m"
    );
    println!(
        "\x1b[1;32m║            QUANTOS STRESS TEST — INITIALISING                    ║\x1b[0m"
    );
    println!(
        "\x1b[1;32m╚══════════════════════════════════════════════════════════════════╝\x1b[0m"
    );
    println!("  RPC         : {}", args.rpc);
    println!("  Target TPS  : {}", args.tps);
    println!(
        "  Duration    : {}",
        if args.duration == 0 {
            "∞ (Ctrl-C to stop)".to_string()
        } else {
            format!("{}s", args.duration)
        }
    );
    println!("  Wallets     : {}", args.wallets);
    println!("  Chain ID    : {}", args.chain_id);
    println!("  Shards      : {}", args.shards);
    println!("  Batch size  : {BATCH_SIZE} tx/call");
    println!();

    // Health check
    let rpc = RpcClient::new(&args.rpc);
    print!("  Checking node health … ");
    match rpc.get_slot().await {
        Ok(slot) => println!("\x1b[32mOK\x1b[0m (slot={slot})"),
        Err(e) => {
            println!("\x1b[31mFAILED\x1b[0m: {e}");
            println!("  Make sure the node is running: cargo run --release -- --network devnet");
            anyhow::bail!("node unreachable");
        }
    }

    // Generate wallets
    print!("  Generating {} Dilithium keypairs … ", args.wallets);
    let wallets: Vec<Arc<Wallet>> = (0..args.wallets)
        .map(|_| Arc::new(Wallet::new(args.start_nonce)))
        .collect();
    println!("\x1b[32mDone\x1b[0m");

    // Use wallet[0] as recipient for all transfers
    let recipient = wallets[0].address;

    let stats = Arc::new(Stats::default());
    let latencies: LatencyWindow = Arc::new(Mutex::new(VecDeque::with_capacity(LATENCY_WINDOW)));
    let stop = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    // Spawn workers
    let mut handles = Vec::new();
    for wallet in &wallets {
        let w = wallet.clone();
        let r = rpc.clone();
        let s = stats.clone();
        let l = latencies.clone();
        let a = args.clone();
        let stop_c = stop.clone();
        handles.push(tokio::spawn(worker_task(w, recipient, r, s, l, a, stop_c)));
    }

    // Spawn dashboard
    let dash_rpc = rpc.clone();
    let dash_stats = stats.clone();
    let dash_lat = latencies.clone();
    let dash_args = args.clone();
    let dash_handle = tokio::spawn(dashboard_task(
        dash_stats,
        dash_lat,
        dash_rpc,
        start,
        dash_args.duration,
        dash_args.verbose,
    ));

    // Stop after duration
    if args.duration > 0 {
        sleep(Duration::from_secs(args.duration)).await;
        stop.store(1, AtomicOrdering::Relaxed);
        // Wait briefly for workers to finish
        sleep(Duration::from_secs(2)).await;
        for h in handles {
            h.abort();
        }
        dash_handle.await.ok();
    } else {
        // Run until Ctrl-C
        tokio::signal::ctrl_c().await.ok();
        stop.store(1, AtomicOrdering::Relaxed);
        sleep(Duration::from_secs(2)).await;
        for h in handles {
            h.abort();
        }
        dash_handle.abort();
        print_final_report(&stats, &latencies, start).await;
    }

    Ok(())
}
