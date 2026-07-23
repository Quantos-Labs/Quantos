// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Quantos Native Precompiled Contracts
//!
//! Post-quantum native operations callable at reserved addresses.
//! These execute natively (not in WASM) for maximum performance.
//!
//! ## Reserved Addresses
//!
//! | Address | Operation | CU Cost |
//! |---------|-----------|---------|
//! | `0x01` | SHA3-256 Hash | 100 + 1/byte |
//! | `0x02` | Blake3 Hash | 80 + 1/byte |
//! | `0x03` | ML-DSA-65 Verify | 50,000 |
//! | `0x04` | ML-DSA-65 Verify | 30,000 |
//! | `0x05` | SPHINCS+ Verify | 80,000 |
//! | `0x06` | QR-VRF Verify | 60,000 |
//! | `0x07` | Merkle Proof Verify | 5,000 + 500/level |
//! | `0x08` | Address Derivation | 200 |
//! | `0x09` | Batch ML-DSA-65 Verify | 40,000/sig |
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                  Precompile Dispatch                         │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Contract Call to 0x01..0x09                                │
//! │       │                                                     │
//! │       ▼                                                     │
//! │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
//! │  │ SHA3-256 │  │ Blake3   │  │ML-DSA-65  │  │ ML-DSA   │  │
//! │  │  (native)│  │  (native)│  │  (native)│  │  (native)│  │
//! │  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
//! │                                                             │
//! │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
//! │  │ SPHINCS+ │  │  QR-VRF  │  │ Merkle   │  │  Batch   │  │
//! │  │  (native)│  │  (native)│  │  (native)│  │  (native)│  │
//! │  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
//! └─────────────────────────────────────────────────────────────┘
//! ```


use sha3::Digest;

use crate::crypto::{
    verify_ml_dsa_65, verify_ml_dsa_65_batch, verify_sphincs,
    sha3_256,
};
use crate::crypto::batch_verify::MlDsa65BatchVerifier;
use crate::types::{Address, address_to_qts, hash_data};

/// Precompile address range: addresses with first 31 bytes = 0, last byte = ID
const PRECOMPILE_MAX_ID: u8 = 9;

/// CU costs
const CU_SHA3_BASE: u64 = 100;
const CU_SHA3_PER_BYTE: u64 = 1;
const CU_BLAKE3_BASE: u64 = 80;
const CU_BLAKE3_PER_BYTE: u64 = 1;
const CU_MLDSA65_VERIFY_PRECOMPILE: u64 = 50_000;
const CU_MLDSA65_VERIFY: u64 = 30_000;
const CU_SPHINCS_VERIFY: u64 = 80_000;
const CU_VRF_VERIFY: u64 = 60_000;
const CU_MERKLE_BASE: u64 = 5_000;
const CU_MERKLE_PER_LEVEL: u64 = 500;
const CU_ADDRESS_DERIVE: u64 = 200;
const CU_BATCH_VERIFY_PER_SIG: u64 = 40_000;

/// Maximum input size for precompile calls (1 MB)
const MAX_INPUT_SIZE: usize = 1_048_576;

/// Result of a precompile execution.
#[derive(Debug, Clone)]
pub struct PrecompileResult {
    /// Output data
    pub output: Vec<u8>,
    /// CU consumed
    pub cu_used: u64,
    /// Success flag
    pub success: bool,
}

/// Precompile execution error.
#[derive(Debug, Clone)]
pub enum PrecompileError {
    /// Unknown precompile address
    UnknownPrecompile(u8),
    /// Invalid input format
    InvalidInput(String),
    /// Insufficient compute units
    InsufficientCU,
    /// Input too large
    InputTooLarge,
    /// Cryptographic operation failed
    CryptoError(String),
}

impl std::fmt::Display for PrecompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrecompileError::UnknownPrecompile(id) => write!(f, "Unknown precompile: 0x{:02x}", id),
            PrecompileError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            PrecompileError::InsufficientCU => write!(f, "Insufficient compute units"),
            PrecompileError::InputTooLarge => write!(f, "Input exceeds maximum size"),
            PrecompileError::CryptoError(msg) => write!(f, "Crypto error: {}", msg),
        }
    }
}

/// Checks if an address is a precompiled contract.
pub fn is_precompile(address: &Address) -> bool {
    // Precompile addresses: first 31 bytes are zero, last byte is 1..=PRECOMPILE_MAX_ID
    address[..31].iter().all(|&b| b == 0) && address[31] >= 1 && address[31] <= PRECOMPILE_MAX_ID
}

/// Returns the precompile ID for an address, or None if not a precompile.
pub fn precompile_id(address: &Address) -> Option<u8> {
    if is_precompile(address) {
        Some(address[31])
    } else {
        None
    }
}

/// Executes a precompiled contract.
///
/// # Arguments
/// * `address` - Precompile address (determines which operation to run)
/// * `input` - ABI-encoded input data
/// * `available_cu` - Available compute units
///
/// # Returns
/// `PrecompileResult` with output data, CU used, and success flag
pub fn execute_precompile(
    address: &Address,
    input: &[u8],
    available_cu: u64,
) -> Result<PrecompileResult, PrecompileError> {
    if input.len() > MAX_INPUT_SIZE {
        return Err(PrecompileError::InputTooLarge);
    }
    
    let id = precompile_id(address)
        .ok_or(PrecompileError::UnknownPrecompile(address[31]))?;
    
    match id {
        0x01 => precompile_sha3(input, available_cu),
        0x02 => precompile_blake3(input, available_cu),
        0x03 => precompile_mldsa65_verify_native(input, available_cu),
        0x04 => precompile_mldsa65_verify(input, available_cu),
        0x05 => precompile_sphincs_verify(input, available_cu),
        0x06 => precompile_vrf_verify(input, available_cu),
        0x07 => precompile_merkle_verify(input, available_cu),
        0x08 => precompile_address_derive(input, available_cu),
        0x09 => precompile_batch_mldsa65_verify(input, available_cu),
        _ => Err(PrecompileError::UnknownPrecompile(id)),
    }
}

/// Returns human-readable name for a precompile.
pub fn precompile_name(id: u8) -> &'static str {
    match id {
        0x01 => "SHA3-256",
        0x02 => "Blake3",
        0x03 => "ML-DSA-65 Verify",
        0x04 => "ML-DSA-65 Verify",
        0x05 => "SPHINCS+ Verify",
        0x06 => "QR-VRF Verify",
        0x07 => "Merkle Proof Verify",
        0x08 => "Address Derivation",
        0x09 => "Batch ML-DSA-65 Verify",
        _ => "Unknown",
    }
}

// ============================================================================
// Precompile Implementations
// ============================================================================

/// 0x01: SHA3-256 Hash
/// Input: raw data
/// Output: 32-byte hash
fn precompile_sha3(input: &[u8], available_cu: u64) -> Result<PrecompileResult, PrecompileError> {
    let cu_cost = CU_SHA3_BASE + (input.len() as u64 * CU_SHA3_PER_BYTE);
    if available_cu < cu_cost {
        return Err(PrecompileError::InsufficientCU);
    }
    
    let hash = sha3_256(input);
    
    Ok(PrecompileResult {
        output: hash.to_vec(),
        cu_used: cu_cost,
        success: true,
    })
}

/// 0x02: Blake3 Hash
/// Input: raw data
/// Output: 32-byte hash
fn precompile_blake3(input: &[u8], available_cu: u64) -> Result<PrecompileResult, PrecompileError> {
    let cu_cost = CU_BLAKE3_BASE + (input.len() as u64 * CU_BLAKE3_PER_BYTE);
    if available_cu < cu_cost {
        return Err(PrecompileError::InsufficientCU);
    }
    
    let hash = blake3::hash(input);
    
    Ok(PrecompileResult {
        output: hash.as_bytes().to_vec(),
        cu_used: cu_cost,
        success: true,
    })
}

/// 0x03: ML-DSA-65 Signature Verification
/// Input: [pubkey_len: u32][pubkey][msg_len: u32][msg][sig_len: u32][sig]
/// Output: [0x01] if valid, [0x00] if invalid
fn precompile_mldsa65_verify_native(input: &[u8], available_cu: u64) -> Result<PrecompileResult, PrecompileError> {
    if available_cu < CU_MLDSA65_VERIFY_PRECOMPILE {
        return Err(PrecompileError::InsufficientCU);
    }
    
    let (pubkey, message, signature) = parse_verify_input(input)?;
    
    let valid = if verify_ml_dsa_65_batch(pubkey.clone(), message.clone(), signature.clone()) {
        true
    } else {
        false
    };
    
    Ok(PrecompileResult {
        output: vec![if valid { 0x01 } else { 0x00 }],
        cu_used: CU_MLDSA65_VERIFY_PRECOMPILE,
        success: true,
    })
}

/// 0x04: ML-DSA-65 Signature Verification
/// Input: [pubkey_len: u32][pubkey][msg_len: u32][msg][sig_len: u32][sig]
/// Output: [0x01] if valid, [0x00] if invalid
fn precompile_mldsa65_verify(input: &[u8], available_cu: u64) -> Result<PrecompileResult, PrecompileError> {
    if available_cu < CU_MLDSA65_VERIFY {
        return Err(PrecompileError::InsufficientCU);
    }
    
    let (pubkey, message, signature) = parse_verify_input(input)?;

    let valid = match verify_ml_dsa_65(&pubkey, &message, &signature) {
        Ok(v) => v,
        Err(e) => return Err(PrecompileError::CryptoError(format!("ML-DSA-65: {}", e))),
    };
    
    Ok(PrecompileResult {
        output: vec![if valid { 0x01 } else { 0x00 }],
        cu_used: CU_MLDSA65_VERIFY,
        success: true,
    })
}

/// 0x05: SPHINCS+ Signature Verification
/// Input: [pubkey_len: u32][pubkey][msg_len: u32][msg][sig_len: u32][sig]
/// Output: [0x01] if valid, [0x00] if invalid
fn precompile_sphincs_verify(input: &[u8], available_cu: u64) -> Result<PrecompileResult, PrecompileError> {
    if available_cu < CU_SPHINCS_VERIFY {
        return Err(PrecompileError::InsufficientCU);
    }
    
    let (pubkey, message, signature) = parse_verify_input(input)?;
    
    let valid = match verify_sphincs(&pubkey, &message, &signature) {
        Ok(v) => v,
        Err(e) => return Err(PrecompileError::CryptoError(format!("SPHINCS+: {}", e))),
    };
    
    Ok(PrecompileResult {
        output: vec![if valid { 0x01 } else { 0x00 }],
        cu_used: CU_SPHINCS_VERIFY,
        success: true,
    })
}

/// 0x06: QR-VRF Output Verification
/// Input: [pubkey_len: u32][pubkey][seed_len: u32][seed][proof_len: u32][proof]
/// Output: [0x01][vrf_output: 32 bytes] if valid, [0x00] if invalid
fn precompile_vrf_verify(input: &[u8], available_cu: u64) -> Result<PrecompileResult, PrecompileError> {
    if available_cu < CU_VRF_VERIFY {
        return Err(PrecompileError::InsufficientCU);
    }
    
    let (pubkey, seed, proof) = parse_verify_input(input)?;
    
    // VRF verification: verify the SPHINCS+ signature over the seed
    let valid = match verify_sphincs(&pubkey, &seed, &proof) {
        Ok(v) => v,
        Err(_) => false,
    };
    
    if valid {
        // Derive VRF output: H(proof || seed)
        let mut vrf_input = Vec::new();
        vrf_input.extend_from_slice(&proof);
        vrf_input.extend_from_slice(&seed);
        let vrf_output = sha3_256(&vrf_input);
        
        let mut output = vec![0x01];
        output.extend_from_slice(&vrf_output);
        
        Ok(PrecompileResult {
            output,
            cu_used: CU_VRF_VERIFY,
            success: true,
        })
    } else {
        Ok(PrecompileResult {
            output: vec![0x00],
            cu_used: CU_VRF_VERIFY,
            success: true,
        })
    }
}

/// 0x07: Merkle Proof Verification
/// Input: [leaf_hash: 32][root_hash: 32][num_siblings: u32][sibling_hashes: 32*N][path_bits: N bytes]
/// Output: [0x01] if valid, [0x00] if invalid
fn precompile_merkle_verify(input: &[u8], available_cu: u64) -> Result<PrecompileResult, PrecompileError> {
    if input.len() < 68 {
        return Err(PrecompileError::InvalidInput("Merkle: need leaf + root + count".into()));
    }
    
    let mut leaf_hash = [0u8; 32];
    leaf_hash.copy_from_slice(&input[0..32]);
    
    let mut root_hash = [0u8; 32];
    root_hash.copy_from_slice(&input[32..64]);
    
    let num_siblings = u32::from_le_bytes([input[64], input[65], input[66], input[67]]) as usize;
    
    // Bound num_siblings to prevent DoS via unbounded allocation (v3)
    const MAX_MERKLE_DEPTH: usize = 256;
    if num_siblings > MAX_MERKLE_DEPTH {
        return Err(PrecompileError::InvalidInput(
            format!("Merkle: depth {} exceeds max {}", num_siblings, MAX_MERKLE_DEPTH)
        ));
    }
    
    let cu_cost = CU_MERKLE_BASE + (num_siblings as u64 * CU_MERKLE_PER_LEVEL);
    if available_cu < cu_cost {
        return Err(PrecompileError::InsufficientCU);
    }
    
    let siblings_start = 68;
    let siblings_end = siblings_start + (num_siblings * 32);
    let path_start = siblings_end;
    let path_end = path_start + num_siblings;
    
    if input.len() < path_end {
        return Err(PrecompileError::InvalidInput("Merkle: input too short for proof".into()));
    }
    
    // Verify proof by recomputing root
    let mut current = leaf_hash;
    for i in 0..num_siblings {
        let mut sibling = [0u8; 32];
        sibling.copy_from_slice(&input[siblings_start + i * 32..siblings_start + (i + 1) * 32]);
        
        let is_left = input[path_start + i] == 0;
        
        let mut combined = Vec::with_capacity(64);
        if is_left {
            combined.extend_from_slice(&current);
            combined.extend_from_slice(&sibling);
        } else {
            combined.extend_from_slice(&sibling);
            combined.extend_from_slice(&current);
        }
        current = sha3_256(&combined);
    }
    
    let valid = current == root_hash;
    
    Ok(PrecompileResult {
        output: vec![if valid { 0x01 } else { 0x00 }],
        cu_used: cu_cost,
        success: true,
    })
}

/// 0x08: Quantos Address Derivation
/// Input: [public_key: N bytes]
/// Output: [address: 32 bytes][qts1_string: variable]
fn precompile_address_derive(input: &[u8], available_cu: u64) -> Result<PrecompileResult, PrecompileError> {
    if available_cu < CU_ADDRESS_DERIVE {
        return Err(PrecompileError::InsufficientCU);
    }
    
    if input.is_empty() {
        return Err(PrecompileError::InvalidInput("Empty public key".into()));
    }
    
    // Derive address: SHA3-256 of public key
    let address = hash_data(input);
    
    // Encode to qts1 format
    let qts_string = address_to_qts(&address);
    
    let mut output = Vec::new();
    output.extend_from_slice(&address);
    output.extend_from_slice(qts_string.as_bytes());
    
    Ok(PrecompileResult {
        output,
        cu_used: CU_ADDRESS_DERIVE,
        success: true,
    })
}

/// 0x09: Batch ML-DSA-65 Verification
/// Input: [count: u32][pubkey_len: u32][pubkey][msg_len: u32][msg][sig_len: u32][sig]...repeated
/// Output: [count: u32][result_0: u8][result_1: u8]...
fn precompile_batch_mldsa65_verify(input: &[u8], available_cu: u64) -> Result<PrecompileResult, PrecompileError> {
    if input.len() < 4 {
        return Err(PrecompileError::InvalidInput("Batch: need count".into()));
    }
    
    let count = u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as usize;
    
    // Bound batch count to prevent DoS via unbounded allocation (v3)
    const MAX_BATCH_COUNT: usize = 256;
    if count > MAX_BATCH_COUNT {
        return Err(PrecompileError::InvalidInput(
            format!("Batch: count {} exceeds max {}", count, MAX_BATCH_COUNT)
        ));
    }
    
    let cu_cost = count as u64 * CU_BATCH_VERIFY_PER_SIG;
    if available_cu < cu_cost {
        return Err(PrecompileError::InsufficientCU);
    }
    
    let mut offset = 4;
    let mut results = Vec::with_capacity(4 + count);
    results.extend_from_slice(&(count as u32).to_le_bytes());
    
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        if offset + 4 > input.len() {
            return Err(PrecompileError::InvalidInput("Batch: truncated input".into()));
        }
        
        // Parse each signature triplet from remaining input
        match parse_verify_input_at(&input[offset..]) {
            Ok((pubkey, message, signature, consumed)) => {
                items.push((pubkey, message, signature));
                offset += consumed;
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    let verifier = MlDsa65BatchVerifier::new(items.len());
    let batch_results = verifier.verify_batch(&items);
    for valid in batch_results {
        results.push(if valid { 0x01 } else { 0x00 });
    }
    
    Ok(PrecompileResult {
        output: results,
        cu_used: cu_cost,
        success: true,
    })
}

// ============================================================================
// Input Parsing Helpers
// ============================================================================

/// Parses [len: u32][data]... triplet for signature verification inputs.
fn parse_verify_input(input: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), PrecompileError> {
    let (a, b, c, _) = parse_verify_input_at(input)?;
    Ok((a, b, c))
}

/// Parses [len: u32][data]... triplet at offset, returns (a, b, c, bytes_consumed).
fn parse_verify_input_at(input: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, usize), PrecompileError> {
    let mut offset = 0;
    
    let read_field = |input: &[u8], offset: &mut usize| -> Result<Vec<u8>, PrecompileError> {
        if *offset + 4 > input.len() {
            return Err(PrecompileError::InvalidInput("Truncated length field".into()));
        }
        let len = u32::from_le_bytes([
            input[*offset], input[*offset + 1], input[*offset + 2], input[*offset + 3]
        ]) as usize;
        *offset += 4;
        
        // Bound individual field length to prevent DoS (v3)
        if len > MAX_INPUT_SIZE {
            return Err(PrecompileError::InvalidInput(
                format!("Field length {} exceeds max input size", len)
            ));
        }
        
        if *offset + len > input.len() {
            return Err(PrecompileError::InvalidInput(
                format!("Field length {} exceeds remaining input {}", len, input.len() - *offset)
            ));
        }
        let data = input[*offset..*offset + len].to_vec();
        *offset += len;
        Ok(data)
    };
    
    let a = read_field(input, &mut offset)?;
    let b = read_field(input, &mut offset)?;
    let c = read_field(input, &mut offset)?;
    
    Ok((a, b, c, offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_precompile() {
        let mut addr = [0u8; 32];
        addr[31] = 0x01;
        assert!(is_precompile(&addr));

        addr[31] = 0x09;
        assert!(is_precompile(&addr));

        addr[31] = 0x0A;
        assert!(!is_precompile(&addr));

        addr[31] = 0x00;
        assert!(!is_precompile(&addr));
        
        // Non-zero prefix
        addr[0] = 0x01;
        addr[31] = 0x01;
        assert!(!is_precompile(&addr));
    }

    #[test]
    fn test_precompile_sha3() {
        let mut addr = [0u8; 32];
        addr[31] = 0x01;
        
        let input = b"hello quantos";
        let result = execute_precompile(&addr, input, 1_000_000).unwrap();
        
        assert!(result.success);
        assert_eq!(result.output.len(), 32);
        assert_eq!(result.cu_used, CU_SHA3_BASE + input.len() as u64);
    }

    #[test]
    fn test_precompile_blake3() {
        let mut addr = [0u8; 32];
        addr[31] = 0x02;
        
        let input = b"hello quantos";
        let result = execute_precompile(&addr, input, 1_000_000).unwrap();
        
        assert!(result.success);
        assert_eq!(result.output.len(), 32);
    }

    #[test]
    fn test_precompile_address_derive() {
        let mut addr = [0u8; 32];
        addr[31] = 0x08;
        
        let pubkey = vec![1u8; 64];
        let result = execute_precompile(&addr, &pubkey, 1_000_000).unwrap();
        
        assert!(result.success);
        assert!(result.output.len() > 32); // 32-byte address + qts1 string
        assert!(String::from_utf8_lossy(&result.output[32..]).starts_with("qts1"));
    }

    #[test]
    fn test_precompile_merkle_verify() {
        let mut addr = [0u8; 32];
        addr[31] = 0x07;
        
        // Build a simple 2-leaf tree
        let leaf_a = sha3_256(b"leaf_a");
        let leaf_b = sha3_256(b"leaf_b");
        
        let mut combined = Vec::new();
        combined.extend_from_slice(&leaf_a);
        combined.extend_from_slice(&leaf_b);
        let root = sha3_256(&combined);
        
        // Proof for leaf_a: sibling = leaf_b, path = left (0)
        let mut input = Vec::new();
        input.extend_from_slice(&leaf_a);       // leaf hash
        input.extend_from_slice(&root);          // root hash
        input.extend_from_slice(&1u32.to_le_bytes()); // 1 sibling
        input.extend_from_slice(&leaf_b);        // sibling hash
        input.push(0);                           // path bit: left
        
        let result = execute_precompile(&addr, &input, 1_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output, vec![0x01]); // Valid
    }

    #[test]
    fn test_insufficient_cu() {
        let mut addr = [0u8; 32];
        addr[31] = 0x03; // ML-DSA-65 verify = 50,000 CU
        
        let input = vec![0u8; 12]; // Minimal input
        let result = execute_precompile(&addr, &input, 100);
        
        assert!(result.is_err());
    }
}
