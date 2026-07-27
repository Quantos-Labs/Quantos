// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Live TPS Benchmark — sends real transactions to a running Quantos node.
//!
//! Usage:
//!   cargo run --release --bin live_tps_bench -- --url http://164.132.99.87:8545 --txs 1000
//!
//! Measures:
//!   - Transaction generation + signing rate
//!   - RPC submission rate (batch)
//!   - Node-side acceptance rate
//!   - Finalization rate (polls qnt_getMetrics)

use clap::Parser;
use quantos::crypto::MlDsa65Keypair;
use quantos::types::{Transaction, TransactionType, Amount, SignedTransaction};
use rayon::prelude::*;
use std::time::{Duration, Instant};
use std::collections::HashMap;

#[derive(Parser, Debug)]
#[command(name = "live-tps-bench")]
struct Args {
    /// RPC endpoint URL
    #[arg(long, default_value = "http://164.132.99.87:8545")]
    url: String,

    /// Total number of transactions to send
    #[arg(long, default_value_t = 1000)]
    txs: usize,

    /// Batch size per RPC call
    #[arg(long, default_value_t = 50)]
    batch_size: usize,

    /// Number of shards to distribute across. Defaults to the node's own shard
    /// count, which is what you want unless you are deliberately testing a
    /// mismatch (see --force-shards).
    #[arg(long)]
    shards: Option<u16>,

    /// Send to --shards even when it disagrees with the node's shard count.
    /// Transactions routed to shards the node does not serve are never mined,
    /// so this will produce an incomplete run by construction.
    #[arg(long, default_value_t = false)]
    force_shards: bool,

    /// Number of unique senders (keypairs). More senders = more txs per vertex.
    #[arg(long, default_value_t = 100)]
    senders: usize,

    /// Maximum time to wait for submitted txs to drain (seconds)
    #[arg(long = "max-wait", alias = "poll-interval", default_value_t = 120)]
    max_wait: u64,

    /// Abort the wait after this many seconds with no drain progress (seconds)
    #[arg(long, default_value_t = 15)]
    stall_timeout: u64,
}

#[derive(serde::Deserialize, Debug, Default)]
struct RpcResponse<T> {
    #[serde(default)]
    result: Option<T>,
    #[serde(default)]
    error: Option<RpcError>,
}

#[derive(serde::Deserialize, Debug)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(serde::Deserialize, Debug, Default, Clone)]
struct Metrics {
    current_slot: u64,
    current_epoch: u64,
    finalized_slot: u64,
    pending_transactions: usize,
    pending_vertices: usize,
    confirmed_vertices: usize,
    total_validators: usize,
    /// Absent on nodes older than the metrics change that added it.
    #[serde(default)]
    num_shards: usize,
}

/// How the run ended. Only `Complete` yields a TPS figure worth quoting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Every accepted transaction left the mempool.
    Complete,
    /// The node stopped draining before finishing.
    Stalled,
    /// Ran out of the allotted wait window.
    Timeout,
    /// The node accepted nothing, so there was nothing to measure.
    NothingAccepted,
}

/// Fetch node metrics, surfacing every failure mode instead of silently
/// degrading to `Default`. A benchmark that treats an unreachable node as
/// "zero pending transactions" reports success for a run that never happened.
fn fetch_metrics(client: &reqwest::blocking::Client, url: &str) -> Result<Metrics, String> {
    let raw = rpc_call(client, url, "qnt_getMetrics", "");
    let parsed: RpcResponse<Metrics> = serde_json::from_str(&raw).map_err(|e| {
        let snippet: String = raw.chars().take(160).collect();
        format!("malformed metrics response: {} (raw: {})", e, snippet)
    })?;
    if let Some(err) = parsed.error {
        return Err(format!("RPC error {}: {}", err.code, err.message));
    }
    parsed.result.ok_or_else(|| "metrics response contained no result".to_string())
}

fn rpc_call(client: &reqwest::blocking::Client, url: &str, method: &str, params: &str) -> String {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"{}","params":[{}],"id":1}}"#,
        method, params
    );
    let resp = client.post(url).header("Content-Type", "application/json").body(body).send();
    match resp {
        Ok(r) => r.text().unwrap_or_default(),
        Err(e) => format!(r#"{{"error":{{"code":-1,"message":"{}"}}}}"#, e),
    }
}

fn main() {
    let args = Args::parse();
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("🚀 QUANTOS LIVE TPS BENCHMARK");
    println!("═══════════════════════════════════════════════════════════════");
    println!("  Endpoint:    {}", args.url);
    println!("  Total txs:   {}", args.txs);
    println!("  Batch size:  {}", args.batch_size);
    println!("  Senders:     {}", args.senders);
    println!();

    // ── Get initial metrics ──
    let initial_m = match fetch_metrics(&client, &args.url) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("❌ Cannot read node metrics: {}", e);
            eprintln!("   Refusing to benchmark a node we cannot measure.");
            std::process::exit(1);
        }
    };
    let initial_slot = initial_m.current_slot;
    let initial_finalized = initial_m.finalized_slot;
    // Transactions already stuck in the mempool before we start. They are not
    // ours and may never drain, so every measurement below is relative to this.
    let baseline_pending = initial_m.pending_transactions;

    // ── Resolve shard count against what the node actually serves ──
    let node_shards = initial_m.num_shards;
    let shards: u16 = match (args.shards, node_shards) {
        (Some(requested), node) if node > 0 && requested as usize != node => {
            if args.force_shards {
                println!("⚠️  Shard mismatch forced: sending to {} shards, node serves {}.", requested, node);
                println!("    Transactions in shards >= {} will never be mined.\n", node);
                requested
            } else {
                println!("⚠️  Requested {} shards but node serves {} — using {}.", requested, node, node);
                println!("    Pass --force-shards to override (produces an incomplete run).\n");
                node as u16
            }
        }
        (Some(requested), _) => requested,
        (None, node) if node > 0 => node as u16,
        (None, _) => {
            println!("⚠️  Node does not report num_shards (old build); defaulting to 4.\n");
            4
        }
    };
    if shards == 0 {
        eprintln!("❌ Resolved shard count is 0 — nothing to send to.");
        std::process::exit(1);
    }

    println!("📊 Initial state:");
    println!("   Slot: {} | Finalized: {} | Pending: {}", initial_slot, initial_finalized, baseline_pending);
    println!("   Shards: {} (node reports {})", shards, node_shards);
    if baseline_pending > 0 {
        println!("   ℹ️  {} txs were already pending; they are excluded from this run's totals.", baseline_pending);
    }
    println!();

    // ── Generate + sign transactions ──
    println!("🔑 Generating {} keypairs + signing {} txs...", args.senders, args.txs);
    let gen_start = Instant::now();

    let num_keypairs = args.senders.min(args.txs);
    let keypairs: Vec<MlDsa65Keypair> = (0..num_keypairs)
        .into_par_iter()
        .map(|_| MlDsa65Keypair::generate().unwrap())
        .collect();

    let txs: Vec<SignedTransaction> = (0..args.txs)
        .into_par_iter()
        .map(|i| {
            let kp_idx = i % keypairs.len();
            let kp = &keypairs[kp_idx];
            // Each sender's txs are at indices kp_idx, kp_idx+senders,
            // kp_idx+2*senders, …  The nonce must be sequential per sender
            // (the node increments it after every tx regardless of shard).
            let per_sender_nonce = (i / keypairs.len()) as u64;
            // All txs from the same sender must go to the SAME shard.  If they
            // were spread across shards the node would not find nonce N+1 in
            // the shard that just processed nonce N, because the mempool is
            // bucketed by shard and the nonce order is global per sender.
            let shard_id = (kp_idx % shards as usize) as u16;

            let mut tx = Transaction::new(
                TransactionType::Transfer,
                kp.address(),
                [(i % 256) as u8; 32],
                Amount((1000 + i as u64) as u128),
                per_sender_nonce,
                21000,
                None,
                Vec::new(),
                shard_id,
            );

            let sig = kp.sign(&tx.signing_data()).unwrap();
            tx.signature = sig;
            tx.public_key = kp.public_key.clone();
            SignedTransaction::new(tx)
        })
        .collect();

    let gen_time = gen_start.elapsed();
    println!("   Done in {:?}", gen_time);
    println!("   Gen rate: {:.0} tx/s\n", args.txs as f64 / gen_time.as_secs_f64());

    // ── Serialize to bincode hex (parallel) ──
    println!("📦 Serializing {} txs to bincode...", txs.len());
    let ser_start = Instant::now();
    let hex_txs: Vec<String> = txs.par_iter()
        .map(|stx| {
            let bytes = bincode::serialize(stx).unwrap();
            hex::encode(&bytes)
        })
        .collect();
    let ser_time = ser_start.elapsed();
    println!("   Done in {:?}\n", ser_time);

    // ── Submit via batch RPC (parallel HTTP) ──
    println!("📡 Submitting {} txs in batches of {} (parallel HTTP)...", args.txs, args.batch_size);
    let submit_start = Instant::now();

    let chunks: Vec<Vec<String>> = hex_txs.chunks(args.batch_size).map(|c| c.to_vec()).collect();
    let results: Vec<(usize, Option<String>)> = chunks.par_iter().map(|chunk| {
        let local_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build().unwrap();
        let params = format!(
            r#"[{}]"#,
            chunk.iter().map(|h| format!(r#""{}""#, h)).collect::<Vec<_>>().join(",")
        );
        let resp = rpc_call(&local_client, &args.url, "qnt_sendRawTransactionBatch", &params);
        let parsed: RpcResponse<Vec<String>> = serde_json::from_str(&resp).unwrap_or(RpcResponse::<Vec<String>>::default());
        let count = parsed.result.map(|h| h.len()).unwrap_or(0);
        let err = parsed.error.map(|e| e.message);
        (count, err)
    }).collect();

    let mut accepted = 0usize;
    let mut errors: HashMap<String, usize> = HashMap::new();
    for (count, err) in results {
        accepted += count;
        if let Some(msg) = err {
            *errors.entry(msg).or_insert(0) += 1;
        }
    }

    let submit_time = submit_start.elapsed();
    let submit_tps = accepted as f64 / submit_time.as_secs_f64();

    println!("   Accepted: {}/{}", accepted, args.txs);
    if !errors.is_empty() {
        println!("   Errors:");
        for (msg, count) in errors.iter().take(5) {
            println!("     • {} (x{})", msg, count);
        }
    }
    println!("   Submit time: {:?}", submit_time);
    println!("   Submit TPS:  {:.0} tx/s\n", submit_tps);

    // ── Wait for our transactions to drain out of the mempool ──
    //
    // "Drained" is measured against the pre-run baseline: txs that were already
    // stuck before we started are not ours and may never clear, so waiting for
    // pending == 0 would hang forever and waiting for a fixed window would just
    // time out. We track how many of *our* accepted txs have left the mempool.
    println!(
        "⏳ Waiting for {} txs to drain (200ms polls, max {}s, stall abort after {}s)...",
        accepted, args.max_wait, args.stall_timeout
    );
    let poll_start = Instant::now();
    let max_wait = Duration::from_secs(args.max_wait);
    let stall_timeout = Duration::from_secs(args.stall_timeout);

    let mut drained = 0usize;
    let mut last_progress_at = Duration::ZERO;
    let mut last_reported_drained = usize::MAX;
    let mut rpc_failures = 0usize;
    let mut last_rpc_error: Option<String> = None;
    let mut last_metrics = initial_m.clone();
    // Stays as-is unless the loop reaches a more specific conclusion.
    let mut outcome = if accepted == 0 { Outcome::NothingAccepted } else { Outcome::Timeout };

    if accepted > 0 {
        loop {
            let elapsed = poll_start.elapsed();
            if elapsed >= max_wait {
                break;
            }

            std::thread::sleep(Duration::from_millis(200));

            let m = match fetch_metrics(&client, &args.url) {
                Ok(m) => m,
                Err(e) => {
                    rpc_failures += 1;
                    last_rpc_error = Some(e);
                    continue;
                }
            };
            let elapsed = poll_start.elapsed();
            last_metrics = m.clone();

            // Anything above the baseline is still-unprocessed work from this run.
            let ours_left = m.pending_transactions.saturating_sub(baseline_pending).min(accepted);
            let now_drained = accepted - ours_left;

            if now_drained > drained {
                drained = now_drained;
                last_progress_at = elapsed;
            }

            if drained != last_reported_drained {
                println!(
                    "   [{:>5.1}s] drained {}/{} ({:.0}%) | slot {} | finalized {} | mempool {} | vertices {}",
                    elapsed.as_secs_f64(),
                    drained,
                    accepted,
                    100.0 * drained as f64 / accepted as f64,
                    m.current_slot,
                    m.finalized_slot,
                    m.pending_transactions,
                    m.confirmed_vertices,
                );
                last_reported_drained = drained;
            }

            if drained >= accepted {
                outcome = Outcome::Complete;
                println!("   ✅ All {} submitted txs drained at {:.1}s", accepted, elapsed.as_secs_f64());
                break;
            }

            if elapsed.saturating_sub(last_progress_at) >= stall_timeout {
                outcome = Outcome::Stalled;
                break;
            }
        }
    }

    // ── Final metrics ──
    match fetch_metrics(&client, &args.url) {
        Ok(m) => last_metrics = m,
        Err(e) => {
            rpc_failures += 1;
            last_rpc_error = Some(e);
        }
    }
    let final_m = last_metrics;

    let slots_advanced = final_m.current_slot.saturating_sub(initial_slot);
    let finalized_advanced = final_m.finalized_slot.saturating_sub(initial_finalized);
    let poll_elapsed = poll_start.elapsed();
    let stranded = accepted - drained;

    // End-to-end time covers submission plus the drain, but stops at the last
    // observed progress: idle time spent waiting on a stalled node is not work.
    let processing_time = submit_time + last_progress_at;
    let real_tps = if drained > 0 && processing_time.as_secs_f64() > 0.0 {
        drained as f64 / processing_time.as_secs_f64()
    } else {
        0.0
    };

    println!();
    println!("═══════════════════════════════════════════════════════════════");
    println!("📊 LIVE TPS BENCHMARK RESULTS");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    println!("┌──────────────────────────────────────────────────────────────┐");
    println!("│ Metric                        │ Value                        │");
    println!("├──────────────────────────────────────────────────────────────┤");
    println!("│ Transactions generated        │ {:>28} │", args.txs);
    println!("│ Transactions accepted by node │ {:>28} │", accepted);
    println!("│ Transactions drained          │ {:>28} │", drained);
    println!("│ Transactions stranded         │ {:>28} │", stranded);
    println!("│ Generation + signing rate     │ {:>23.0} tx/s │", args.txs as f64 / gen_time.as_secs_f64());
    println!("│ RPC submission rate           │ {:>23.0} tx/s │", submit_tps);
    println!("│ Submit time                   │ {:>28?} │", submit_time);
    println!("│ Drain time (to last progress) │ {:>28?} │", last_progress_at);
    println!("│ Processing time (submit→done) │ {:>28?} │", processing_time);
    println!("│ Slots advanced                │ {:>28} │", slots_advanced);
    println!("│ Slots finalized               │ {:>28} │", finalized_advanced);
    println!("│ Mempool pending (baseline)    │ {:>28} │", baseline_pending);
    println!("│ Mempool pending (final)       │ {:>28} │", final_m.pending_transactions);
    println!("│ Confirmed vertices            │ {:>28} │", final_m.confirmed_vertices);
    println!("│ Metrics RPC failures          │ {:>28} │", rpc_failures);
    println!("└──────────────────────────────────────────────────────────────┘");
    println!();

    match outcome {
        Outcome::Complete => {
            println!("🎯 REAL TPS (submit→drained): {:.0} tx/s", real_tps);
            println!("🎯 Submission TPS:            {:.0} tx/s", submit_tps);
            println!("🎯 Total wall time:           {:?}", gen_time + submit_time + poll_elapsed);
            println!();
            if real_tps >= 10000.0 {
                println!("✅ EXCELLENT: {:.0} TPS", real_tps);
            } else if real_tps >= 1000.0 {
                println!("✅ GOOD: {:.0} TPS — node processing well", real_tps);
            } else {
                println!("📈 {:.0} TPS — node is processing but below target", real_tps);
            }
        }
        Outcome::Stalled => {
            println!("❌ INVALID RUN — node stopped making progress");
            println!();
            println!(
                "   {} of {} txs drained, then no progress for {}s.",
                drained, accepted, args.stall_timeout
            );
            println!("   {} txs are stranded in the mempool.", stranded);
            println!();
            println!("   Partial rate before the stall: {:.0} tx/s (NOT a valid TPS figure).", real_tps);
            println!();
            println!("   Common causes:");
            println!("     • Transactions routed to shards the node does not serve");
            println!("       (node reports {} shards, run used {}).", node_shards, shards);
            println!("     • Nonce gaps: txs whose sender nonce never becomes current.");
            println!("     • Vertex production failing — check the node log for");
            println!("       repeated \"Creating vertices\" with no \"Committed vertex\".");
        }
        Outcome::Timeout => {
            println!("❌ INVALID RUN — timed out after {}s", args.max_wait);
            println!();
            println!("   {} of {} txs drained, {} still stranded.", drained, accepted, stranded);
            println!("   Partial rate: {:.0} tx/s (NOT a valid TPS figure).", real_tps);
            println!("   Raise --max-wait if the node is simply slower than the window.");
        }
        Outcome::NothingAccepted => {
            println!("❌ INVALID RUN — the node accepted 0 transactions");
            println!("   Check the submission errors above and the node log.");
        }
    }

    if rpc_failures > 0 {
        println!();
        println!("⚠️  {} metrics RPC call(s) failed during the run.", rpc_failures);
        if let Some(err) = last_rpc_error {
            println!("    Last error: {}", err);
        }
        println!("    Figures above may be based on stale readings.");
    }

    println!();
    println!("═══════════════════════════════════════════════════════════════");

    if !matches!(outcome, Outcome::Complete) {
        std::process::exit(2);
    }
}
