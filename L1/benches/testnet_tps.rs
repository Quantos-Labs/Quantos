// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Testnet TPS Benchmark - Uses REAL production components
//!
//! This benchmark tests the ACTUAL testnet pipeline:
//! - ShardedMempool with AMR routing
//! - FastPath consensus
//! - DAGGraph vertex management  
//! - OptimisticExecutor for state
//! - MlDsa65BatchVerifier (PQC-SVB)
//! - CommitteeManager

use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;
use tokio::sync::mpsc;
use rayon::prelude::*;

use quantos::crypto::MlDsa65Keypair;
use quantos::storage::Storage;
use quantos::state::{StateManager, OptimisticExecutor};
use quantos::mempool::ShardedMempool;
use quantos::dag::DAGGraph;
use quantos::consensus::{FastPath, CommitteeManager};
use quantos::types::{Transaction, TransactionType, Amount, SignedTransaction, Hash};

const NUM_SHARDS: u16 = 16;

#[tokio::main]
async fn main() {
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("🚀 QUANTOS TESTNET TPS BENCHMARK - REAL COMPONENTS");
    println!("═══════════════════════════════════════════════════════════════\n");
    
    // ═══════════════════════════════════════════════════════════════
    // SETUP: Initialize ALL real production components
    // ═══════════════════════════════════════════════════════════════
    println!("📦 Initializing production components...");
    
    let dir = tempdir().unwrap();
    let storage = Storage::new(dir.path()).unwrap();
    let state_manager = StateManager::new(storage.clone());
    
    // Create DAG (min_parents=2, max_parents=10)
    let dag = Arc::new(DAGGraph::new(storage.clone(), 2, 10));
    
    // Create Mempool with 16 shards
    let mempool = Arc::new(ShardedMempool::new(state_manager.clone(), NUM_SHARDS, 500_000));
    
    // Create OptimisticExecutor
    let executor = Arc::new(OptimisticExecutor::new(state_manager.clone(), NUM_SHARDS));
    
    // Create CommitteeManager (storage, num_committees, validators_per_committee)
    let committee_manager = Arc::new(CommitteeManager::new(storage.clone(), NUM_SHARDS, 100));
    
    // Create FastPath (consensus layer with PQC-SVB)
    let (vertex_tx, mut _vertex_rx) = mpsc::channel(10000);
    let fast_path = Arc::new(FastPath::new(
        dag.clone(),
        mempool.clone(),
        executor.clone(),
        committee_manager.clone(),
        vertex_tx,
    ));
    
    println!("✅ All components initialized:");
    println!("   • Storage: RocksDB");
    println!("   • StateManager: Production");
    println!("   • DAGGraph: {} shards", NUM_SHARDS);
    println!("   • ShardedMempool: {} shards, 500k capacity", NUM_SHARDS);
    println!("   • OptimisticExecutor: Parallel execution");
    println!("   • CommitteeManager: VRF-based");
    println!("   • FastPath: PQC-SVB + QRSA enabled\n");
    
    // ═══════════════════════════════════════════════════════════════
    // Generate validator keypairs
    // ═══════════════════════════════════════════════════════════════
    println!("🔑 Generating validator keypairs...");
    let validators: Vec<MlDsa65Keypair> = (0..NUM_SHARDS)
        .into_par_iter()
        .map(|_| MlDsa65Keypair::generate().unwrap())
        .collect();
    println!("   Generated {} validator keys\n", validators.len());
    
    // ═══════════════════════════════════════════════════════════════
    // DEBUG: Test signature verification consistency
    // ═══════════════════════════════════════════════════════════════
    println!("🔍 DEBUG: Testing signature verification...");
    {
        let keypair = MlDsa65Keypair::generate().unwrap();
        let mut tx = Transaction::new(
            TransactionType::Transfer,
            keypair.address(),
            [1u8; 32],
            Amount(1000),
            0,
            21000,
            10,
            Vec::new(),
            0,
        );
        
        let signing_data_before = tx.signing_data();
        let sig = keypair.sign(&signing_data_before).unwrap();
        
        // Verify immediately
        let verify1 = quantos::crypto::verify_ml_dsa_65(&keypair.public_key, &signing_data_before, &sig).unwrap();
        println!("   Direct verify (before set_signature): {}", verify1);
        
        // set_signature verifies internally
        let set_result = tx.set_signature(sig.clone(), keypair.public_key.clone());
        println!("   set_signature result: {:?}", set_result.is_ok());
        
        // Verify after (like mempool does)
        let signing_data_after = tx.signing_data();
        let verify2 = quantos::crypto::verify_ml_dsa_65(&tx.public_key, &signing_data_after, &tx.signature).unwrap();
        println!("   Mempool-style verify (after): {}", verify2);
        
        // Compare signing data
        println!("   signing_data matches: {}", signing_data_before == signing_data_after);
        println!();
    }
    
    // ═══════════════════════════════════════════════════════════════
    // Generate test transactions (pre-signed) - SEQUENTIAL to avoid race conditions
    // ═══════════════════════════════════════════════════════════════
    println!("✍️  Pre-signing transactions (sequential for consistency)...");
    let tx_count = 10_000; // Reduced for debugging
    
    let tx_start = Instant::now();
    let mut transactions: Vec<SignedTransaction> = Vec::with_capacity(tx_count);
    let mut sign_failures = 0;
    
    for i in 0..tx_count {
        let keypair = MlDsa65Keypair::generate().unwrap();
        let shard_id = (i % NUM_SHARDS as usize) as u16;
        
        let mut tx = Transaction::new(
            TransactionType::Transfer,
            keypair.address(),
            [(i % 256) as u8; 32],
            Amount(1000 + i as u128),
            0,
            21000,
            10,
            Vec::new(),
            shard_id,
        );
        
        let sig = keypair.sign(&tx.signing_data()).unwrap();
        match tx.set_signature(sig, keypair.public_key.clone()) {
            Ok(_) => transactions.push(SignedTransaction::new(tx)),
            Err(_) => sign_failures += 1,
        }
    }
    
    let tx_time = tx_start.elapsed();
    println!("   Created {} transactions, {} sign failures", transactions.len(), sign_failures);
    println!("   Time: {:?}", tx_time);
    println!("   Rate: {:.0} tx/s\n", transactions.len() as f64 / tx_time.as_secs_f64());
    
    // ═══════════════════════════════════════════════════════════════
    // TEST 1: Mempool Ingestion - Sequential per shard (avoid contention)
    // ═══════════════════════════════════════════════════════════════
    println!("─────────────────────────────────────────────────────────────");
    println!("📥 TEST 1: Mempool Ingestion (sequential, 10k txs)");
    
    let mempool_start = Instant::now();
    let mut accepted = 0;
    let mut errors: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    
    for tx in &transactions {
        match mempool.add_transaction(tx.clone()) {
            Ok(_) => accepted += 1,
            Err(e) => {
                let msg = format!("{:?}", e);
                *errors.entry(msg).or_insert(0) += 1;
            }
        }
    }
    let mempool_time = mempool_start.elapsed();
    let mempool_tps = accepted as f64 / mempool_time.as_secs_f64();
    
    println!("   Accepted: {}/{}", accepted, transactions.len());
    if !errors.is_empty() {
        println!("   Errors:");
        for (e, count) in errors.iter().take(3) {
            println!("      • {}: {}", e, count);
        }
    }
    println!("   Time:     {:?}", mempool_time);
    println!("   TPS:      {:.0} tx/s\n", mempool_tps);
    
    // ═══════════════════════════════════════════════════════════════
    // TEST 2: FastPath Transaction Processing
    // ═══════════════════════════════════════════════════════════════
    println!("─────────────────────────────────────────────────────────────");
    println!("⚡ TEST 2: FastPath Transaction Processing");
    
    // Re-create mempool for clean test
    let mempool2 = Arc::new(ShardedMempool::new(state_manager.clone(), NUM_SHARDS, 500_000));
    let (vertex_tx2, _) = mpsc::channel(10000);
    let fast_path2 = Arc::new(FastPath::new(
        dag.clone(),
        mempool2.clone(),
        executor.clone(),
        committee_manager.clone(),
        vertex_tx2,
    ));
    
    let fp_start = Instant::now();
    let mut fp_accepted = 0;
    
    for tx in transactions.iter().take(50000) {
        if fast_path2.process_transaction(tx.clone()).await.is_ok() {
            fp_accepted += 1;
        }
    }
    let fp_time = fp_start.elapsed();
    let fp_tps = fp_accepted as f64 / fp_time.as_secs_f64();
    
    println!("   Processed: {}/50000", fp_accepted);
    println!("   Time:      {:?}", fp_time);
    println!("   TPS:       {:.0} tx/s\n", fp_tps);
    
    // ═══════════════════════════════════════════════════════════════
    // TEST 3: Vertex Creation (consensus block production)
    // ═══════════════════════════════════════════════════════════════
    println!("─────────────────────────────────────────────────────────────");
    println!("🔨 TEST 3: Vertex Creation (block production)");
    
    let vertex_start = Instant::now();
    let mut vertices_created = 0;
    let mut txs_in_vertices = 0;
    
    let mut vertex_errors: Vec<String> = Vec::new();
    for shard_id in 0..NUM_SHARDS {
        let validator = &validators[shard_id as usize];
        match fast_path2.create_vertex(shard_id, validator.address(), &validator.secret_key).await {
            Ok(vertex) => {
                vertices_created += 1;
                txs_in_vertices += vertex.transactions.len();
            }
            Err(e) => {
                if vertex_errors.len() < 3 {
                    vertex_errors.push(format!("Shard {}: {:?}", shard_id, e));
                }
            }
        }
    }
    if !vertex_errors.is_empty() {
        println!("   Errors: {:?}", vertex_errors);
    }
    let vertex_time = vertex_start.elapsed();
    
    println!("   Vertices: {}/{}", vertices_created, NUM_SHARDS);
    println!("   Txs in vertices: {}", txs_in_vertices);
    println!("   Time:     {:?}", vertex_time);
    if vertices_created > 0 {
        println!("   Avg per vertex: {:?}\n", vertex_time / vertices_created as u32);
    }
    
    // ═══════════════════════════════════════════════════════════════
    // TEST 4: Full Pipeline (submit → mempool → vertex)
    // ═══════════════════════════════════════════════════════════════
    println!("─────────────────────────────────────────────────────────────");
    println!("🏁 TEST 4: Full E2E Pipeline (50k txs)");
    
    let mempool3 = Arc::new(ShardedMempool::new(state_manager.clone(), NUM_SHARDS, 500_000));
    let (vertex_tx3, _) = mpsc::channel(10000);
    let fast_path3 = Arc::new(FastPath::new(
        dag.clone(),
        mempool3.clone(),
        executor.clone(),
        committee_manager.clone(),
        vertex_tx3,
    ));
    
    let e2e_txs: Vec<_> = transactions.iter().take(50000).cloned().collect();
    
    let e2e_start = Instant::now();
    
    // Step 1: Submit all transactions
    let submit_start = Instant::now();
    for tx in &e2e_txs {
        let _ = fast_path3.process_transaction(tx.clone()).await;
    }
    let submit_time = submit_start.elapsed();
    
    // Step 2: Create vertices for all shards
    let vertex_start = Instant::now();
    let mut total_finalized = 0;
    for shard_id in 0..NUM_SHARDS {
        let validator = &validators[shard_id as usize];
        if let Ok(vertex) = fast_path3.create_vertex(shard_id, validator.address(), &validator.secret_key).await {
            total_finalized += vertex.transactions.len();
        }
    }
    let vertex_time = vertex_start.elapsed();
    
    let e2e_time = e2e_start.elapsed();
    let e2e_tps = total_finalized as f64 / e2e_time.as_secs_f64();
    
    println!("   Submit:     {:?} ({:.0} tx/s)", submit_time, 50000.0 / submit_time.as_secs_f64());
    println!("   Vertices:   {:?}", vertex_time);
    println!("   Finalized:  {} txs", total_finalized);
    println!("   Total E2E:  {:?}", e2e_time);
    println!("   E2E TPS:    {:.0} tx/s\n", e2e_tps);
    
    // ═══════════════════════════════════════════════════════════════
    // RESULTS SUMMARY
    // ═══════════════════════════════════════════════════════════════
    println!("═══════════════════════════════════════════════════════════════");
    println!("📊 QUANTOS TESTNET TPS RESULTS");
    println!("═══════════════════════════════════════════════════════════════\n");
    
    println!("┌──────────────────────────────────────────────────────────────┐");
    println!("│ Component                     │ TPS                          │");
    println!("├──────────────────────────────────────────────────────────────┤");
    println!("│ Mempool Ingestion (parallel)  │ {:>10.0} tx/s              │", mempool_tps);
    println!("│ FastPath Processing           │ {:>10.0} tx/s              │", fp_tps);
    println!("│ Full E2E Pipeline             │ {:>10.0} tx/s              │", e2e_tps);
    println!("└──────────────────────────────────────────────────────────────┘\n");
    
    // Analysis
    let bottleneck = if mempool_tps < fp_tps && mempool_tps < e2e_tps {
        "Mempool validation (signature verification)"
    } else if fp_tps < mempool_tps && fp_tps < e2e_tps {
        "FastPath consensus layer"
    } else {
        "Vertex creation / State execution"
    };
    
    println!("🔍 BOTTLENECK: {}", bottleneck);
    println!();
    
    if e2e_tps >= 30000.0 {
        println!("✅ TARGET ACHIEVED: {:.0} TPS (≥30k)", e2e_tps);
    } else {
        println!("📈 Current: {:.0} TPS", e2e_tps);
        println!("   Bottleneck analysis needed for optimization");
    }
    
    println!("\n═══════════════════════════════════════════════════════════════");
}
