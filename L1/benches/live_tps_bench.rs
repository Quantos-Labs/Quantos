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

    /// Number of shards to distribute across
    #[arg(long, default_value_t = 16)]
    shards: u16,

    /// Number of unique senders (keypairs). More senders = more txs per vertex.
    #[arg(long, default_value_t = 100)]
    senders: usize,

    /// Poll interval for metrics (seconds)
    #[arg(long, default_value_t = 5)]
    poll_interval: u64,
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
    println!("  Shards:      {}", args.shards);
    println!("  Senders:     {}", args.senders);
    println!();

    // ── Get initial metrics ──
    let initial = rpc_call(&client, &args.url, "qnt_getMetrics", "");
    let initial_metrics: RpcResponse<Metrics> = serde_json::from_str(&initial).unwrap_or(RpcResponse::<Metrics>::default());
    let initial_slot = initial_metrics.result.as_ref().map(|m| m.current_slot).unwrap_or(0);
    let initial_finalized = initial_metrics.result.as_ref().map(|m| m.finalized_slot).unwrap_or(0);
    let initial_pending = initial_metrics.result.as_ref().map(|m| m.pending_transactions).unwrap_or(0);

    println!("📊 Initial state:");
    println!("   Slot: {} | Finalized: {} | Pending: {}", initial_slot, initial_finalized, initial_pending);
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
            let shard_id = (i % args.shards as usize) as u16;
            let per_sender_nonce = (i / keypairs.len()) as u64;

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

    // ── Poll metrics for finalization (fast polling) ──
    println!("⏳ Polling finalization (200ms interval, max {}s)...", args.poll_interval);
    let poll_start = Instant::now();
    let mut last_pending = usize::MAX;
    let mut first_zero_pending: Option<Duration> = None;

    while poll_start.elapsed() < Duration::from_secs(args.poll_interval) {
        std::thread::sleep(Duration::from_millis(200));
        let resp = rpc_call(&client, &args.url, "qnt_getMetrics", "");
        let parsed: RpcResponse<Metrics> = serde_json::from_str(&resp).unwrap_or(RpcResponse::<Metrics>::default());
        if let Some(m) = parsed.result {
            let elapsed = poll_start.elapsed();
            let pending = m.pending_transactions;
            if pending != last_pending {
                println!("   [{:.1}s] Slot: {} | Finalized: {} | Pending: {} | Vertices: {}",
                    elapsed.as_secs_f64(), m.current_slot, m.finalized_slot, pending, m.confirmed_vertices);
                last_pending = pending;
            }
            if pending == 0 && first_zero_pending.is_none() {
                first_zero_pending = Some(elapsed);
                println!("   ✅ All pending cleared at {:.1}s", elapsed.as_secs_f64());
                break;
            }
        }
    }

    // ── Final metrics ──
    let final_resp = rpc_call(&client, &args.url, "qnt_getMetrics", "");
    let final_metrics: RpcResponse<Metrics> = serde_json::from_str(&final_resp).unwrap_or(RpcResponse::<Metrics>::default());
    let final_m = final_metrics.result.unwrap_or_default();

    let slots_advanced = final_m.current_slot.saturating_sub(initial_slot);
    let finalized_advanced = final_m.finalized_slot.saturating_sub(initial_finalized);
    let poll_elapsed = poll_start.elapsed();

    // Real processing time = submission time + time until pending=0
    let processing_time = first_zero_pending
        .map(|d| submit_time + d)
        .unwrap_or(submit_time + poll_elapsed);
    let txs_finalized = accepted.saturating_sub(final_m.pending_transactions);
    let real_tps = if processing_time.as_secs_f64() > 0.0 {
        txs_finalized as f64 / processing_time.as_secs_f64()
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
    println!("│ Transactions finalized        │ {:>28} │", txs_finalized);
    println!("│ Generation + signing rate     │ {:>23.0} tx/s │", args.txs as f64 / gen_time.as_secs_f64());
    println!("│ RPC submission rate           │ {:>23.0} tx/s │", submit_tps);
    println!("│ Submit time                   │ {:>28?} │", submit_time);
    println!("│ Processing time (submit→done) │ {:>28?} │", processing_time);
    println!("│ Slots advanced                │ {:>28} │", slots_advanced);
    println!("│ Slots finalized               │ {:>28} │", finalized_advanced);
    println!("│ Final pending txs             │ {:>28} │", final_m.pending_transactions);
    println!("│ Confirmed vertices            │ {:>28} │", final_m.confirmed_vertices);
    println!("└──────────────────────────────────────────────────────────────┘");
    println!();

    println!("🎯 REAL TPS (submit→finalized): {:.0} tx/s", real_tps);
    println!("🎯 Submission TPS:              {:.0} tx/s", submit_tps);
    println!("🎯 Total wall time:             {:?}", gen_time + submit_time + poll_elapsed);
    println!();

    if real_tps >= 10000.0 {
        println!("✅ EXCELLENT: {:.0} TPS — STARK batch aggregation working", real_tps);
    } else if real_tps >= 1000.0 {
        println!("✅ GOOD: {:.0} TPS — node processing well", real_tps);
    } else if real_tps > 0.0 {
        println!("📈 {:.0} TPS — node is processing but below target", real_tps);
    } else if accepted == 0 {
        println!("⚠️  No transactions accepted — check node logs");
    }
    println!();
    println!("═══════════════════════════════════════════════════════════════");
}
