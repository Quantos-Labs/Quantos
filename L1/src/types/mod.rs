// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

mod transaction;
mod account;
mod block;
mod vertex;
mod checkpoint;

pub use transaction::*;
pub use account::*;
pub use block::*;
pub use vertex::*;
pub use checkpoint::*;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

pub type Hash = [u8; 32];
pub type Address = [u8; 32];
pub type Signature = Vec<u8>;
pub type PublicKey = Vec<u8>;
pub type PrivateKey = Vec<u8>;
pub type ShardId = u16;
pub type CommitteeId = u16;
pub type Slot = u64;
pub type Epoch = u64;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Amount(pub u128);

impl Amount {
    pub fn zero() -> Self {
        Self(0)
    }

    pub fn checked_add(&self, other: &Amount) -> Option<Amount> {
        self.0.checked_add(other.0).map(Amount)
    }

    pub fn checked_sub(&self, other: &Amount) -> Option<Amount> {
        self.0.checked_sub(other.0).map(Amount)
    }
}

pub fn hash_data(data: &[u8]) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

pub fn hash_to_hex(hash: &Hash) -> String {
    hex::encode(hash)
}

pub fn hex_to_hash(hex_str: &str) -> Result<Hash, String> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| format!("Invalid hex string: {}", e))?;
    
    // CRITICAL: Validate length before copy_from_slice to prevent panic
    if bytes.len() != 32 {
        return Err(format!("Invalid hash length: expected 32 bytes, got {}", bytes.len()));
    }
    
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

/// Encodes an address to Quantos format: qts1...
/// Uses base32 encoding with checksum for error detection
pub fn address_to_qts(address: &Address) -> String {
    // Use first 20 bytes of address (like Ethereum)
    let addr_bytes = &address[..20];
    
    // Add simple checksum (last 4 bytes of hash)
    let checksum = hash_data(addr_bytes);
    let checksum_bytes = &checksum[..4];
    
    // Combine address + checksum
    let mut data = Vec::with_capacity(24);
    data.extend_from_slice(addr_bytes);
    data.extend_from_slice(checksum_bytes);
    
    // Base32 encode (more readable than hex, shorter than base64)
    let encoded = data_encoding::BASE32_NOPAD.encode(&data).to_lowercase();
    
    format!("qts1{}", encoded)
}

/// Decodes a Quantos address from qts1... format
pub fn qts_to_address(qts_addr: &str) -> Result<Address, String> {
    // Validate prefix
    if !qts_addr.starts_with("qts1") {
        return Err("Invalid Quantos address: must start with qts1".to_string());
    }
    
    // Decode base32
    let encoded = &qts_addr[4..];
    let decoded = data_encoding::BASE32_NOPAD
        .decode(encoded.to_uppercase().as_bytes())
        .map_err(|e| format!("Invalid base32 encoding: {}", e))?;
    
    if decoded.len() != 24 {
        return Err(format!("Invalid address length: expected 24 bytes, got {}", decoded.len()));
    }
    
    // Split address and checksum
    let addr_bytes = &decoded[..20];
    let checksum_bytes = &decoded[20..24];
    
    // Verify checksum
    let expected_checksum = hash_data(addr_bytes);
    if checksum_bytes != &expected_checksum[..4] {
        return Err("Invalid address checksum".to_string());
    }
    
    // Build full 32-byte address (pad with zeros)
    let mut address = [0u8; 32];
    address[..20].copy_from_slice(addr_bytes);
    
    Ok(address)
}

/// Shortens a Quantos address for display: qts1abcd...xyz
pub fn shorten_qts_address(qts_addr: &str) -> String {
    if qts_addr.len() <= 15 {
        return qts_addr.to_string();
    }
    format!("{}...{}", &qts_addr[..8], &qts_addr[qts_addr.len()-6..])
}
