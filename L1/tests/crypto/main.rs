//! Comprehensive tests for the Crypto module

use quantos::crypto::*;
use quantos::types::*;

// ══════════════════════════════════════════════════════════
//  Hashing
// ══════════════════════════════════════════════════════════

#[test]
fn test_sha3_256_deterministic() {
    let data = b"hello quantos";
    let h1 = sha3_256(data);
    let h2 = sha3_256(data);
    assert_eq!(h1, h2);
}

#[test]
fn test_sha3_256_different_inputs() {
    let h1 = sha3_256(b"hello");
    let h2 = sha3_256(b"world");
    assert_ne!(h1, h2);
}

#[test]
fn test_sha3_256_empty() {
    let h = sha3_256(b"");
    assert_ne!(h, [0u8; 32]);
}

#[test]
fn test_sha3_256_length() {
    let h = sha3_256(b"test");
    assert_eq!(h.len(), 32);
}

// ══════════════════════════════════════════════════════════
//  ML-DSA-65 Keypair
// ══════════════════════════════════════════════════════════

#[test]
fn test_mldsa65_keypair_generation() {
    let kp = MlDsa65Keypair::generate().unwrap();
    assert!(!kp.public_key.is_empty());
    assert!(!kp.secret_key.is_empty());
}

#[test]
fn test_mldsa65_keypair_unique() {
    let kp1 = MlDsa65Keypair::generate().unwrap();
    let kp2 = MlDsa65Keypair::generate().unwrap();
    assert_ne!(kp1.public_key, kp2.public_key);
}

#[test]
fn test_mldsa65_sign_verify() {
    let kp = MlDsa65Keypair::generate().unwrap();
    let message = b"quantos transaction data";
    let signature = kp.sign(message).unwrap();
    assert!(!signature.is_empty());

    let valid = verify_ml_dsa_65(&kp.public_key, message, &signature);
    assert!(valid.is_ok());
    assert!(valid.unwrap());
}

#[test]
fn test_mldsa65_wrong_message() {
    let kp = MlDsa65Keypair::generate().unwrap();
    let signature = kp.sign(b"original message").unwrap();
    let valid = verify_ml_dsa_65(&kp.public_key, b"wrong message", &signature);
    // Should be Ok(false) or Err
    match valid {
        Ok(v) => assert!(!v),
        Err(_) => {} // Also acceptable
    }
}

#[test]
fn test_mldsa65_wrong_key() {
    let kp1 = MlDsa65Keypair::generate().unwrap();
    let kp2 = MlDsa65Keypair::generate().unwrap();
    let message = b"test message";
    let signature = kp1.sign(message).unwrap();
    let valid = verify_ml_dsa_65(&kp2.public_key, message, &signature);
    match valid {
        Ok(v) => assert!(!v),
        Err(_) => {}
    }
}

#[test]
fn test_mldsa65_empty_message() {
    let kp = MlDsa65Keypair::generate().unwrap();
    let signature = kp.sign(b"").unwrap();
    let valid = verify_ml_dsa_65(&kp.public_key, b"", &signature);
    assert!(valid.is_ok());
    assert!(valid.unwrap());
}

// ══════════════════════════════════════════════════════════
//  Falcon Keypair
// ══════════════════════════════════════════════════════════

#[test]
fn test_falcon_keypair_generation() {
    let kp = FalconKeypair::generate().unwrap();
    assert!(!kp.public_key.is_empty());
    assert!(!kp.secret_key.is_empty());
}

#[test]
fn test_falcon_sign_verify() {
    let kp = FalconKeypair::generate().unwrap();
    let message = b"falcon test message";
    let signature = kp.sign(message).unwrap();
    let valid = verify_falcon(&kp.public_key, message, &signature);
    assert!(valid.is_ok());
    assert!(valid.unwrap());
}

#[test]
fn test_falcon_wrong_message() {
    let kp = FalconKeypair::generate().unwrap();
    let signature = kp.sign(b"correct").unwrap();
    let valid = verify_falcon(&kp.public_key, b"wrong", &signature);
    match valid {
        Ok(v) => assert!(!v),
        Err(_) => {}
    }
}

// ══════════════════════════════════════════════════════════
//  VRF
// ══════════════════════════════════════════════════════════

#[test]
fn test_vrf_keypair_generation() {
    let kp = VRFKeypair::generate().unwrap();
    // VRFKeypair wraps SphincsKeypair
    let _ = kp;
}

#[test]
fn test_vrf_prove_produces_output() {
    let kp = VRFKeypair::generate().unwrap();
    let seed = b"vrf input data";
    let proof = kp.prove(seed).unwrap();
    assert_ne!(proof.output, [0u8; 32]);
    assert!(!proof.proof.is_empty());
}

#[test]
fn test_vrf_different_inputs() {
    let kp = VRFKeypair::generate().unwrap();
    let p1 = kp.prove(b"input1").unwrap();
    let p2 = kp.prove(b"input2").unwrap();
    assert_ne!(p1.output, p2.output);
}

#[test]
fn test_vrf_different_keys() {
    let kp1 = VRFKeypair::generate().unwrap();
    let kp2 = VRFKeypair::generate().unwrap();
    let seed = b"same input";
    let p1 = kp1.prove(seed).unwrap();
    let p2 = kp2.prove(seed).unwrap();
    assert_ne!(p1.output, p2.output);
}

#[test]
fn test_vrf_verify() {
    let kp = VRFKeypair::generate().unwrap();
    let seed = b"vrf verification test";
    let proof = kp.prove(seed).unwrap();
    let valid = kp.verify(seed, &proof).unwrap();
    assert!(valid);
}

#[test]
fn test_vrf_proof_to_u64() {
    let kp = VRFKeypair::generate().unwrap();
    let proof = kp.prove(b"some seed").unwrap();
    let val = proof.to_u64();
    let _ = val; // Just verify it doesn't panic
}

#[test]
fn test_vrf_proof_committee_selection() {
    let kp = VRFKeypair::generate().unwrap();
    let proof = kp.prove(b"committee seed").unwrap();
    let committee = proof.to_committee_id(100);
    assert!(committee < 100);
}

// ══════════════════════════════════════════════════════════
//  Address derivation
// ══════════════════════════════════════════════════════════

#[test]
fn test_mldsa65_address_deterministic() {
    let kp = MlDsa65Keypair::generate().unwrap();
    let a1 = kp.address();
    let a2 = kp.address();
    assert_eq!(a1, a2);
    assert_ne!(a1, [0u8; 32]);
}

#[test]
fn test_public_key_to_address() {
    let kp = MlDsa65Keypair::generate().unwrap();
    let addr = public_key_to_address(&kp.public_key);
    assert_eq!(addr, kp.address());
}

// ══════════════════════════════════════════════════════════
//  Signature Aggregation & Compact Block Signatures
// ══════════════════════════════════════════════════════════

use quantos::crypto::signature_aggregation::*;

#[test]
fn test_compact_block_signature_end_to_end() {
    let aggregator = SignatureAggregator::new(1000);

    // Simulate 21 validators signing a block
    let committee_size = 800;
    let num_signers = 21;
    let block_hash = b"block_hash_abcdef1234567890abcdef";

    // Generate real signatures
    let keypairs: Vec<MlDsa65Keypair> = (0..num_signers)
        .map(|_| MlDsa65Keypair::generate().unwrap())
        .collect();

    let signatures: Vec<Vec<u8>> = keypairs
        .iter()
        .map(|kp| kp.sign(block_hash).unwrap())
        .collect();

    let public_keys: Vec<Vec<u8>> = keypairs
        .iter()
        .map(|kp| kp.public_key.clone())
        .collect();

    // Full aggregation (for block production)
    let agg = aggregator
        .aggregate(signatures, public_keys.clone(), block_hash)
        .unwrap();

    let full_size = SignatureAggregator::full_aggregated_size(&agg);

    // Compact form (for on-chain / propagation)
    let indices: Vec<usize> = (0..num_signers).collect();
    let compact = aggregator.compact(&agg, committee_size, &indices);
    let compact_size = compact.encoded_size();

    // Compact must be dramatically smaller
    assert!(compact_size < 200, "compact should be < 200 bytes, got {}", compact_size);
    assert!(full_size > compact_size * 10, "full ({}) should be >10x compact ({})", full_size, compact_size);

    // Bitmap must reflect signers
    assert_eq!(compact.signer_bitmap.count_signers(), num_signers);
    for i in 0..num_signers {
        assert!(compact.signer_bitmap.has_signed(i));
    }
    assert!(!compact.signer_bitmap.has_signed(num_signers));
}

#[test]
fn test_compression_metrics_realistic() {
    // BFT quorum for 800-validator committee: 2/3 + 1 = 534
    let m = CompressionMetrics::mldsa65(534, 800);

    assert!(m.individual_bytes > 2_000_000, "534 ML-DSA-65 sigs > 2 MB");
    assert!(m.compact_bytes < 200, "compact < 200 bytes");
    assert!(m.ratio > 10_000.0, "ratio > 10000x");
    assert!(m.savings_percent > 99.99, "savings > 99.99%");

    // Falcon is smaller but still huge vs compact
    let f = CompressionMetrics::falcon(534, 800);
    assert!(f.individual_bytes > 800_000);
    assert!(f.compact_bytes < 200);
    assert!(f.ratio > 4_000.0);
}

#[test]
fn test_signer_bitmap_edge_cases() {
    // Empty bitmap
    let bm = SignerBitmap::from_indices(100, &[]);
    assert_eq!(bm.count_signers(), 0);
    assert!(!bm.has_signed(0));

    // Full bitmap
    let all: Vec<usize> = (0..100).collect();
    let bm = SignerBitmap::from_indices(100, &all);
    assert_eq!(bm.count_signers(), 100);

    // Duplicate indices
    let bm = SignerBitmap::from_indices(10, &[3, 3, 3]);
    assert_eq!(bm.count_signers(), 1);

    // Out-of-range indices ignored
    let bm = SignerBitmap::from_indices(10, &[5, 999]);
    assert_eq!(bm.count_signers(), 1);
    assert!(bm.has_signed(5));
}
