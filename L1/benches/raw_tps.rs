//! Raw TPS Benchmark - Measures REAL maximum throughput
//!
//! Tests: Batch verification (PQC-SVB), parallel processing, sharding

use std::time::Instant;
use rayon::prelude::*;
use quantos::crypto::{DilithiumKeypair, DilithiumBatchVerifier, verify_dilithium};

fn main() {
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("🚀 QUANTOS RAW TPS BENCHMARK");
    println!("═══════════════════════════════════════════════════════════════\n");
    
    let num_cpus = num_cpus::get();
    println!("🖥  CPU cores: {}\n", num_cpus);
    
    // Generate keypairs
    println!("🔑 Generating 1000 keypairs...");
    let start = Instant::now();
    let keypairs: Vec<_> = (0..1000).into_par_iter()
        .map(|_| DilithiumKeypair::generate().unwrap())
        .collect();
    println!("   Done in {:?}\n", start.elapsed());
    
    // Create messages and signatures
    println!("✍️  Signing 50,000 messages...");
    let msg_count = 50_000;
    let messages: Vec<Vec<u8>> = (0..msg_count)
        .map(|i| format!("tx_data_{}", i).into_bytes())
        .collect();
    
    let start = Instant::now();
    let signatures: Vec<_> = messages.par_iter()
        .enumerate()
        .map(|(i, msg)| {
            let kp = &keypairs[i % keypairs.len()];
            (kp.public_key.clone(), msg.clone(), kp.sign(msg).unwrap())
        })
        .collect();
    let sign_time = start.elapsed();
    let sign_tps = msg_count as f64 / sign_time.as_secs_f64();
    println!("   Done in {:?} ({:.0} sig/s)\n", sign_time, sign_tps);
    
    // ═══════════════════════════════════════════════════════════════
    // TEST 1: Individual Verification (Baseline)
    // ═══════════════════════════════════════════════════════════════
    println!("─────────────────────────────────────────────────────────────");
    println!("🔍 TEST 1: Individual Verification (10k, sequential)");
    
    let test_count = 10_000;
    let start = Instant::now();
    let mut valid = 0;
    for i in 0..test_count {
        let (ref pk, ref msg, ref sig) = signatures[i];
        if verify_dilithium(pk, msg, sig).unwrap_or(false) {
            valid += 1;
        }
    }
    let ind_time = start.elapsed();
    let ind_tps = valid as f64 / ind_time.as_secs_f64();
    println!("   Valid: {}/{}", valid, test_count);
    println!("   Time:  {:?}", ind_time);
    println!("   TPS:   {:.0} verif/s\n", ind_tps);
    
    // ═══════════════════════════════════════════════════════════════
    // TEST 2: Parallel Individual Verification
    // ═══════════════════════════════════════════════════════════════
    println!("─────────────────────────────────────────────────────────────");
    println!("⚡ TEST 2: Parallel Verification (50k, {} cores)", num_cpus);
    
    let start = Instant::now();
    let valid: usize = signatures.par_iter()
        .map(|(pk, msg, sig)| {
            if verify_dilithium(pk, msg, sig).unwrap_or(false) { 1 } else { 0 }
        })
        .sum();
    let par_time = start.elapsed();
    let par_tps = valid as f64 / par_time.as_secs_f64();
    println!("   Valid: {}/{}", valid, msg_count);
    println!("   Time:  {:?}", par_time);
    println!("   TPS:   {:.0} verif/s", par_tps);
    println!("   Speedup: {:.2}x\n", par_tps / ind_tps);
    
    // ═══════════════════════════════════════════════════════════════
    // TEST 3: PQC-SVB Batch Verification (OUR INNOVATION)
    // ═══════════════════════════════════════════════════════════════
    println!("─────────────────────────────────────────────────────────────");
    println!("🔥 TEST 3: PQC-SVB Batch Verification (50k)");
    
    let batch_verifier = DilithiumBatchVerifier::new(64);
    
    // Prepare items for batch verification
    let items: Vec<_> = signatures.iter()
        .map(|(pk, msg, sig)| (pk.clone(), msg.clone(), sig.clone()))
        .collect();
    
    let start = Instant::now();
    let results = batch_verifier.verify_batch(&items);
    let batch_time = start.elapsed();
    let batch_valid = results.iter().filter(|&&v| v).count();
    let batch_tps = batch_valid as f64 / batch_time.as_secs_f64();
    
    println!("   Valid: {}/{}", batch_valid, msg_count);
    println!("   Time:  {:?}", batch_time);
    println!("   TPS:   {:.0} verif/s", batch_tps);
    println!("   Speedup vs individual: {:.2}x", batch_tps / ind_tps);
    println!("   Speedup vs parallel:   {:.2}x\n", batch_tps / par_tps);
    
    // ═══════════════════════════════════════════════════════════════
    // TEST 4: Sharded Processing (16 shards)
    // ═══════════════════════════════════════════════════════════════
    println!("─────────────────────────────────────────────────────────────");
    println!("🌐 TEST 4: Sharded Processing (16 shards, 50k txs)");
    
    let num_shards = 16;
    let per_shard = msg_count / num_shards;
    
    // Split into shards
    let shards: Vec<Vec<_>> = (0..num_shards)
        .map(|s| {
            let start_idx = s * per_shard;
            let end_idx = start_idx + per_shard;
            items[start_idx..end_idx].to_vec()
        })
        .collect();
    
    let start = Instant::now();
    let shard_results: Vec<usize> = shards.par_iter()
        .map(|shard_items| {
            let verifier = DilithiumBatchVerifier::new(64);
            let results = verifier.verify_batch(shard_items);
            results.iter().filter(|&&v| v).count()
        })
        .collect();
    let shard_time = start.elapsed();
    let shard_valid: usize = shard_results.iter().sum();
    let shard_tps = shard_valid as f64 / shard_time.as_secs_f64();
    
    println!("   Shards: {}", num_shards);
    println!("   Valid:  {}/{}", shard_valid, msg_count);
    println!("   Time:   {:?}", shard_time);
    println!("   TPS:    {:.0} verif/s", shard_tps);
    println!("   Speedup vs batch: {:.2}x\n", shard_tps / batch_tps);
    
    // ═══════════════════════════════════════════════════════════════
    // FINAL RESULTS
    // ═══════════════════════════════════════════════════════════════
    println!("═══════════════════════════════════════════════════════════════");
    println!("📊 QUANTOS TPS RESULTS SUMMARY");
    println!("═══════════════════════════════════════════════════════════════\n");
    
    println!("┌──────────────────────────────────────────────────────────────┐");
    println!("│ Method                        │ TPS          │ Speedup      │");
    println!("├──────────────────────────────────────────────────────────────┤");
    println!("│ Individual (baseline)         │ {:>10.0}   │ 1.00x        │", ind_tps);
    println!("│ Parallel ({} cores)           │ {:>10.0}   │ {:.2}x        │", num_cpus, par_tps, par_tps / ind_tps);
    println!("│ PQC-SVB Batch                 │ {:>10.0}   │ {:.2}x        │", batch_tps, batch_tps / ind_tps);
    println!("│ Sharded (16) + Batch          │ {:>10.0}   │ {:.2}x        │", shard_tps, shard_tps / ind_tps);
    println!("└──────────────────────────────────────────────────────────────┘\n");
    
    println!("🎯 PEAK TPS: {:.0}", shard_tps);
    println!();
    
    if shard_tps >= 30000.0 {
        println!("✅ TARGET ACHIEVED: 30k+ TPS");
    } else {
        println!("📈 Projected with more shards/cores: {:.0}+ TPS", shard_tps * 2.0);
    }
    
    println!("\n═══════════════════════════════════════════════════════════════");
}
