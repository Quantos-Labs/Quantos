// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! PQC Bloat Benchmark — Measures signature sizes, aggregation compression,
//! and verification throughput for ML-DSA-65, Falcon-512, and SPHINCS+.
//!
//! Run with: cargo bench --bench pqc_bloat

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use rayon::prelude::*;
use std::time::Instant;

use quantos::crypto::{
    MlDsa65Keypair, FalconKeypair,
    verify_ml_dsa_65, verify_falcon,
    MlDsa65BatchVerifier,
    signature_aggregation::{
        SignatureAggregator, CompressionMetrics,
        MLDSA65_SIG_SIZE, MLDSA65_PK_SIZE,
        FALCON512_SIG_SIZE, FALCON512_PK_SIZE,
        SPHINCS_SIG_SIZE,
    },
};

// ══════════════════════════════════════════════════════════
//  Size report (not timed — just prints facts)
// ══════════════════════════════════════════════════════════

fn bench_size_report(c: &mut Criterion) {
    // Generate one keypair of each type to get real sizes
    let dil_kp = MlDsa65Keypair::generate().unwrap();
    let fal_kp = FalconKeypair::generate().unwrap();
    let msg = b"benchmark_block_hash_32_bytes!!!";
    let dil_sig = dil_kp.sign(msg).unwrap();
    let fal_sig = fal_kp.sign(msg).unwrap();

    println!("\n═══════════════════════════════════════════════════════");
    println!("  PQC SIGNATURE SIZE REPORT");
    println!("═══════════════════════════════════════════════════════");
    println!("  ML-DSA-65  sig: {:>6} bytes  pk: {:>5} bytes", dil_sig.len(), dil_kp.public_key.len());
    println!("  Falcon-512   sig: {:>6} bytes  pk: {:>5} bytes", fal_sig.len(), fal_kp.public_key.len());
    println!("  SPHINCS+128s sig: {:>6} bytes  pk: {:>5} bytes (constant)", SPHINCS_SIG_SIZE, 32);
    println!("  ECDSA (ref)  sig:     64 bytes  pk:    33 bytes");
    println!("───────────────────────────────────────────────────────");

    for &committee in &[21, 100, 534, 800] {
        let signers = committee; // assume full participation
        let d = CompressionMetrics::mldsa65(signers, committee);
        let f = CompressionMetrics::falcon(signers, committee);
        println!(
            "  Committee {:>4}:  ML-DSA-65 {:.1} MB → {:>4} B ({:.0}x)  |  Falcon {:.1} KB → {:>4} B ({:.0}x)",
            committee,
            d.individual_bytes as f64 / 1_048_576.0,
            d.compact_bytes,
            d.ratio,
            f.individual_bytes as f64 / 1024.0,
            f.compact_bytes,
            f.ratio,
        );
    }
    println!("═══════════════════════════════════════════════════════\n");

    // Dummy benchmark so criterion doesn't complain
    c.bench_function("pqc_size_report", |b| b.iter(|| 1 + 1));
}

// ══════════════════════════════════════════════════════════
//  Signature generation throughput
// ══════════════════════════════════════════════════════════

fn bench_sign_throughput(c: &mut Criterion) {
    let dil_kp = MlDsa65Keypair::generate().unwrap();
    let fal_kp = FalconKeypair::generate().unwrap();
    let msg = b"benchmark_transaction_payload_here";

    let mut group = c.benchmark_group("sign_throughput");

    group.bench_function("mldsa65_sign", |b| {
        b.iter(|| dil_kp.sign(msg).unwrap())
    });

    group.bench_function("falcon512_sign", |b| {
        b.iter(|| fal_kp.sign(msg).unwrap())
    });

    group.finish();
}

// ══════════════════════════════════════════════════════════
//  Signature verification throughput (single)
// ══════════════════════════════════════════════════════════

fn bench_verify_throughput(c: &mut Criterion) {
    let dil_kp = MlDsa65Keypair::generate().unwrap();
    let fal_kp = FalconKeypair::generate().unwrap();
    let msg = b"benchmark_transaction_payload_here";
    let dil_sig = dil_kp.sign(msg).unwrap();
    let fal_sig = fal_kp.sign(msg).unwrap();

    let mut group = c.benchmark_group("verify_throughput");

    group.bench_function("mldsa65_verify", |b| {
        b.iter(|| verify_ml_dsa_65(&dil_kp.public_key, msg, &dil_sig).unwrap())
    });

    group.bench_function("falcon512_verify", |b| {
        b.iter(|| verify_falcon(&fal_kp.public_key, msg, &fal_sig).unwrap())
    });

    group.finish();
}

// ══════════════════════════════════════════════════════════
//  Batch verification throughput (rayon parallel)
// ══════════════════════════════════════════════════════════

fn bench_batch_verify(c: &mut Criterion) {
    let msg = b"batch_benchmark_msg";

    // Pre-generate signatures
    let items: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = (0..200)
        .into_par_iter()
        .map(|_| {
            let kp = MlDsa65Keypair::generate().unwrap();
            let sig = kp.sign(msg).unwrap();
            (kp.public_key.clone(), msg.to_vec(), sig)
        })
        .collect();

    let mut group = c.benchmark_group("batch_verify");

    for &batch_size in &[10, 50, 100, 200] {
        let batch = &items[..batch_size];
        let verifier = MlDsa65BatchVerifier::new(batch_size);

        group.bench_with_input(
            BenchmarkId::new("mldsa65_batch", batch_size),
            &batch_size,
            |b, _| {
                b.iter(|| verifier.verify_all_valid(batch))
            },
        );
    }

    group.finish();
}

// ══════════════════════════════════════════════════════════
//  Aggregation + compaction throughput
// ══════════════════════════════════════════════════════════

fn bench_aggregation(c: &mut Criterion) {
    let mut group = c.benchmark_group("aggregation");

    for &n in &[21, 100, 534] {
        // Synthetic signatures (real crypto is tested above)
        let sigs: Vec<Vec<u8>> = (0..n).map(|i| vec![i as u8; MLDSA65_SIG_SIZE]).collect();
        let pks: Vec<Vec<u8>> = (0..n).map(|i| vec![i as u8; MLDSA65_PK_SIZE]).collect();
        let aggregator = SignatureAggregator::new(1000);

        group.bench_with_input(
            BenchmarkId::new("aggregate", n),
            &n,
            |b, _| {
                b.iter(|| {
                    aggregator.aggregate(sigs.clone(), pks.clone(), b"block").unwrap()
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("compact", n),
            &n,
            |b, _| {
                let agg = aggregator.aggregate(sigs.clone(), pks.clone(), b"block").unwrap();
                let indices: Vec<usize> = (0..n).collect();
                b.iter(|| {
                    aggregator.compact(&agg, 800, &indices)
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_size_report,
    bench_sign_throughput,
    bench_verify_throughput,
    bench_batch_verify,
    bench_aggregation,
);
criterion_main!(benches);
