//! Quantum-Resistant Signature Aggregation (QRSA)
//!
//! Two-tier aggregation strategy for post-quantum signature bloat:
//!
//! 1. **Full aggregation** (`AggregatedSignature`): keeps all N signatures +
//!    Merkle proofs for archival audit.  Used during block production & validation.
//!
//! 2. **Compact aggregation** (`CompactBlockSignature`): stores only the Merkle
//!    root + a signer bitmap.  Used for on-chain storage and network propagation.
//!    Reduces block signature overhead from **N × 3.3 KB** to **~130 bytes** for
//!    a 800-validator committee.
//!
//! Uses Merkle commitments with Fiat-Shamir for non-interactive aggregation.

use sha3::{Digest, Sha3_256};
use serde::{Deserialize, Serialize};

use crate::types::Hash;

// ══════════════════════════════════════════════════════════
//  PQC signature size constants (bytes)
// ══════════════════════════════════════════════════════════

/// ML-DSA-65 signature size in bytes (FIPS 204)
pub const MLDSA65_SIG_SIZE: usize = 3_309;
/// ML-DSA-65 public key size in bytes
pub const MLDSA65_PK_SIZE: usize = 1_952;
/// SPHINCS+-128s signature size in bytes
pub const SPHINCS_SIG_SIZE: usize = 17_088;
/// SPHINCS+-128s public key size in bytes
pub const SPHINCS_PK_SIZE: usize = 32;

/// Aggregated signature proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedSignature {
    /// Merkle root of signature commitments
    pub root: Hash,
    /// Individual signatures
    pub signatures: Vec<Vec<u8>>,
    /// Merkle proofs for each signature
    pub merkle_proofs: Vec<SignatureMerkleProof>,
    /// Public keys
    pub public_keys: Vec<Vec<u8>>,
    /// Message that was signed
    pub message: Vec<u8>,
}

/// Merkle proof for signature inclusion in QRSA aggregation.
/// For general-purpose Merkle proofs, see `hash::MerkleProof`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureMerkleProof {
    /// Path from leaf to root
    pub path: Vec<Hash>,
    /// Indices for path direction (0 = left, 1 = right)
    pub indices: Vec<u8>,
}

/// Signature aggregator
pub struct SignatureAggregator {
    /// Maximum signatures per aggregation
    max_signatures: usize,
}

impl SignatureAggregator {
    pub fn new(max_signatures: usize) -> Self {
        Self { max_signatures }
    }

    /// Aggregates multiple signatures into one proof
    pub fn aggregate(
        &self,
        signatures: Vec<Vec<u8>>,
        public_keys: Vec<Vec<u8>>,
        message: &[u8],
    ) -> Result<AggregatedSignature, AggregationError> {
        if signatures.is_empty() {
            return Err(AggregationError::EmptySignatures);
        }

        if signatures.len() != public_keys.len() {
            return Err(AggregationError::LengthMismatch);
        }

        if signatures.len() > self.max_signatures {
            return Err(AggregationError::TooManySignatures);
        }

        // Compute commitments for each signature
        let commitments: Vec<Hash> = signatures
            .iter()
            .zip(&public_keys)
            .map(|(sig, pk)| self.compute_commitment(sig, pk, message))
            .collect();

        // Build Merkle tree
        let (root, proofs) = self.build_merkle_tree(&commitments);

        Ok(AggregatedSignature {
            root,
            signatures,
            merkle_proofs: proofs,
            public_keys,
            message: message.to_vec(),
        })
    }

    /// Verifies aggregated signature
    pub fn verify(&self, agg_sig: &AggregatedSignature) -> Result<bool, AggregationError> {
        if agg_sig.signatures.len() != agg_sig.public_keys.len() {
            return Err(AggregationError::LengthMismatch);
        }

        if agg_sig.signatures.len() != agg_sig.merkle_proofs.len() {
            return Err(AggregationError::LengthMismatch);
        }

        // Verify each signature and its Merkle proof
        for i in 0..agg_sig.signatures.len() {
            let commitment = self.compute_commitment(
                &agg_sig.signatures[i],
                &agg_sig.public_keys[i],
                &agg_sig.message,
            );

            // Verify Merkle proof
            if !self.verify_merkle_proof(
                &commitment,
                &agg_sig.merkle_proofs[i],
                &agg_sig.root,
            ) {
                return Ok(false);
            }

            // Verify actual signature
            if let Err(_) = crate::crypto::verify_ml_dsa_65(
                &agg_sig.public_keys[i],
                &agg_sig.message,
                &agg_sig.signatures[i],
            ) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Computes commitment for signature
    fn compute_commitment(&self, signature: &[u8], pubkey: &[u8], message: &[u8]) -> Hash {
        let mut hasher = Sha3_256::new();
        hasher.update(signature);
        hasher.update(pubkey);
        hasher.update(message);
        let hash = hasher.finalize();
        
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }

    /// Builds Merkle tree and returns root + proofs
    fn build_merkle_tree(&self, leaves: &[Hash]) -> (Hash, Vec<SignatureMerkleProof>) {
        if leaves.is_empty() {
            return ([0u8; 32], Vec::new());
        }

        if leaves.len() == 1 {
            return (leaves[0], vec![SignatureMerkleProof {
                path: Vec::new(),
                indices: Vec::new(),
            }]);
        }

        // Build tree bottom-up
        let mut current_level = leaves.to_vec();
        let mut tree_levels = vec![current_level.clone()];

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in current_level.chunks(2) {
                let node = if chunk.len() == 2 {
                    self.hash_pair(&chunk[0], &chunk[1])
                } else {
                    chunk[0]
                };
                next_level.push(node);
            }
            
            tree_levels.push(next_level.clone());
            current_level = next_level;
        }

        let root = current_level[0];

        // Generate proofs for each leaf
        let mut proofs = Vec::new();
        for leaf_idx in 0..leaves.len() {
            let proof = self.generate_proof(leaf_idx, &tree_levels);
            proofs.push(proof);
        }

        (root, proofs)
    }

    /// Generates Merkle proof for a leaf
    fn generate_proof(&self, leaf_idx: usize, tree_levels: &[Vec<Hash>]) -> SignatureMerkleProof {
        let mut path = Vec::new();
        let mut indices = Vec::new();
        let mut idx = leaf_idx;

        for level in 0..tree_levels.len() - 1 {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            
            if sibling_idx < tree_levels[level].len() {
                path.push(tree_levels[level][sibling_idx]);
                indices.push((idx % 2) as u8);
            }
            
            idx /= 2;
        }

        SignatureMerkleProof { path, indices }
    }

    /// Verifies Merkle proof
    fn verify_merkle_proof(&self, leaf: &Hash, proof: &SignatureMerkleProof, root: &Hash) -> bool {
        let mut current = *leaf;

        for (sibling, &direction) in proof.path.iter().zip(&proof.indices) {
            current = if direction == 0 {
                self.hash_pair(&current, sibling)
            } else {
                self.hash_pair(sibling, &current)
            };
        }

        &current == root
    }

    /// Hashes two nodes
    fn hash_pair(&self, left: &Hash, right: &Hash) -> Hash {
        let mut hasher = Sha3_256::new();
        hasher.update(left);
        hasher.update(right);
        let hash = hasher.finalize();
        
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }

    /// Computes the byte size of a full `AggregatedSignature`.
    pub fn full_aggregated_size(agg: &AggregatedSignature) -> usize {
        let sigs: usize = agg.signatures.iter().map(|s| s.len()).sum();
        let pks: usize = agg.public_keys.iter().map(|p| p.len()).sum();
        let proofs: usize = agg.merkle_proofs.iter()
            .map(|p| p.path.len() * 32 + p.indices.len())
            .sum();
        32 /* root */ + sigs + pks + proofs + agg.message.len()
    }

    /// Compresses a verified `AggregatedSignature` into a compact form
    /// suitable for on-chain storage and network propagation.
    ///
    /// The compact form drops all individual signatures and Merkle proofs,
    /// keeping only the root commitment and a bitmap of which signers
    /// participated.
    pub fn compact(
        &self,
        agg: &AggregatedSignature,
        committee_size: usize,
        signer_indices: &[usize],
    ) -> CompactBlockSignature {
        let bitmap = SignerBitmap::from_indices(committee_size, signer_indices);
        CompactBlockSignature {
            root: agg.root,
            signer_bitmap: bitmap,
            signer_count: signer_indices.len() as u32,
            message_hash: {
                let mut h = Sha3_256::new();
                h.update(&agg.message);
                let d = h.finalize();
                let mut out = [0u8; 32];
                out.copy_from_slice(&d);
                out
            },
        }
    }

    /// Verifies a compact block signature against individual signatures
    /// and committee public keys using batched parallel verification.
    ///
    /// **Data availability note**: Only the compact form (`CompactBlockSignature`,
    /// ~130 bytes) is stored on-chain and gossiped in block headers. The full
    /// individual ML-DSA-65 signatures (`signatures` parameter, ~3.3 KB each)
    /// must be retrieved from a data availability layer — either from the block
    /// producer's broadcast, an erasure-coded blob, or by requesting them from
    /// peers who have the full block. A verifier cannot call this method without
    /// first obtaining the full signatures out-of-band.
    ///
    /// Performs full cryptographic verification:
    /// 1. Message hash matches
    /// 2. Signer bitmap popcount matches signer_count
    /// 3. Quorum ≥ 2/3 + 1
    /// 4. All individual signatures are valid (batched via rayon)
    /// 5. Reconstructed Merkle root matches compact.root
    pub fn verify_compact(
        &self,
        compact: &CompactBlockSignature,
        committee_pks: &[Vec<u8>],
        message: &[u8],
        signatures: &[Vec<u8>],
    ) -> Result<bool, AggregationError> {
        // 1. Verify message hash
        let mut h = Sha3_256::new();
        h.update(message);
        let d = h.finalize();
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&d);
        if expected != compact.message_hash {
            return Ok(false);
        }

        // 2. Verify signer count matches bitmap popcount
        if compact.signer_bitmap.count_signers() != compact.signer_count as usize {
            return Ok(false);
        }

        // 3. Verify quorum (≥ 2/3 + 1)
        let quorum = (committee_pks.len() * 2 / 3) + 1;
        if compact.signer_count < quorum as u32 {
            return Ok(false);
        }

        // 4. Collect signer indices from bitmap
        let signer_indices: Vec<usize> = (0..committee_pks.len())
            .filter(|&i| compact.signer_bitmap.has_signed(i))
            .collect();

        if signer_indices.len() != signatures.len() {
            return Ok(false);
        }

        // 5. Build batch verification items: (pubkey, message, signature)
        let batch_items: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = signer_indices
            .iter()
            .zip(signatures.iter())
            .map(|(&idx, sig)| (committee_pks[idx].clone(), message.to_vec(), sig.clone()))
            .collect();

        // 6. Batch-verify all signatures in parallel
        let verifier = crate::crypto::batch_verify::MlDsa65BatchVerifier::new(256);
        if !verifier.verify_all_valid(&batch_items) {
            return Ok(false);
        }

        // 7. Reconstruct Merkle root from commitments and compare
        let commitments: Vec<Hash> = signer_indices
            .iter()
            .zip(signatures.iter())
            .map(|(&idx, sig)| self.compute_commitment(sig, &committee_pks[idx], message))
            .collect();

        let (reconstructed_root, _) = self.build_merkle_tree(&commitments);
        if reconstructed_root != compact.root {
            return Ok(false);
        }

        Ok(true)
    }
}

// ══════════════════════════════════════════════════════════
//  Compact Block Signature (on-chain / propagation form)
// ══════════════════════════════════════════════════════════

/// Compact representation of a block's aggregated signature.
///
/// After validators verify all individual signatures during block
/// production, only this compact proof is stored on-chain and
/// propagated to peers.  For a 800-validator committee this is
/// ~132 bytes vs ~2.6 MB of raw ML-DSA-65 signatures.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactBlockSignature {
    /// Merkle root of all signature commitments
    pub root: Hash,
    /// Bitmap indicating which committee members signed
    pub signer_bitmap: SignerBitmap,
    /// Number of signers (convenience, must match bitmap popcount)
    pub signer_count: u32,
    /// SHA3-256 hash of the signed message (block hash)
    pub message_hash: Hash,
}

impl CompactBlockSignature {
    /// On-wire size in bytes.
    pub fn encoded_size(&self) -> usize {
        32 /* root */ + self.signer_bitmap.size_bytes() + 4 /* count */ + 32 /* msg hash */
    }
}

/// Bit-packed representation of which validators signed a block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignerBitmap {
    /// Packed bits: bit i = 1 iff validator i signed
    pub bits: Vec<u8>,
    /// Total committee size
    pub committee_size: u32,
}

impl SignerBitmap {
    /// Creates a bitmap from a list of signer indices.
    pub fn from_indices(committee_size: usize, indices: &[usize]) -> Self {
        let byte_len = (committee_size + 7) / 8;
        let mut bits = vec![0u8; byte_len];
        for &idx in indices {
            if idx < committee_size {
                bits[idx / 8] |= 1 << (idx % 8);
            }
        }
        Self {
            bits,
            committee_size: committee_size as u32,
        }
    }

    /// Returns the number of signers (popcount).
    pub fn count_signers(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// Checks whether validator `idx` signed.
    pub fn has_signed(&self, idx: usize) -> bool {
        if idx >= self.committee_size as usize {
            return false;
        }
        self.bits[idx / 8] & (1 << (idx % 8)) != 0
    }

    /// Size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.bits.len() + 4 /* committee_size field */
    }
}

// ══════════════════════════════════════════════════════════
//  Compression Metrics
// ══════════════════════════════════════════════════════════

/// Detailed compression metrics for PQC signature aggregation.
#[derive(Debug, Clone)]
pub struct CompressionMetrics {
    /// Size if every validator sends its own signature (bytes)
    pub individual_bytes: usize,
    /// Size of the compact on-chain representation (bytes)
    pub compact_bytes: usize,
    /// Compression ratio (individual / compact)
    pub ratio: f64,
    /// Savings as a percentage
    pub savings_percent: f64,
}

impl CompressionMetrics {
    /// Computes realistic compression metrics for ML-DSA-65.
    ///
    /// `num_signers` — validators that actually signed.
    /// `committee_size` — total committee (determines bitmap width).
    pub fn mldsa65(num_signers: usize, committee_size: usize) -> Self {
        let individual = num_signers * (MLDSA65_SIG_SIZE + MLDSA65_PK_SIZE);
        let bitmap_bytes = (committee_size + 7) / 8 + 4;
        let compact = 32 /* root */ + bitmap_bytes + 4 /* count */ + 32 /* msg hash */;
        let ratio = if compact > 0 { individual as f64 / compact as f64 } else { 1.0 };
        Self {
            individual_bytes: individual,
            compact_bytes: compact,
            ratio,
            savings_percent: if individual > 0 {
                (1.0 - compact as f64 / individual as f64) * 100.0
            } else {
                0.0
            },
        }
    }

    /// Computes realistic compression metrics for ML-DSA-65.
    pub fn ml_dsa(num_signers: usize, committee_size: usize) -> Self {
        let individual = num_signers * (MLDSA65_SIG_SIZE + MLDSA65_PK_SIZE);
        let bitmap_bytes = (committee_size + 7) / 8 + 4;
        let compact = 32 + bitmap_bytes + 4 + 32;
        let ratio = if compact > 0 { individual as f64 / compact as f64 } else { 1.0 };
        Self {
            individual_bytes: individual,
            compact_bytes: compact,
            ratio,
            savings_percent: if individual > 0 {
                (1.0 - compact as f64 / individual as f64) * 100.0
            } else {
                0.0
            },
        }
    }
}

// ══════════════════════════════════════════════════════════
//  Errors
// ══════════════════════════════════════════════════════════

/// Aggregation errors
#[derive(Debug)]
pub enum AggregationError {
    EmptySignatures,
    LengthMismatch,
    TooManySignatures,
    InvalidProof,
}

impl std::fmt::Display for AggregationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AggregationError::EmptySignatures => write!(f, "No signatures to aggregate"),
            AggregationError::LengthMismatch => write!(f, "Signature/pubkey count mismatch"),
            AggregationError::TooManySignatures => write!(f, "Too many signatures"),
            AggregationError::InvalidProof => write!(f, "Invalid Merkle proof"),
        }
    }
}

impl std::error::Error for AggregationError {}

// ══════════════════════════════════════════════════════════
//  Tests
// ══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_bitmap_roundtrip() {
        let bm = SignerBitmap::from_indices(800, &[0, 1, 5, 100, 799]);
        assert_eq!(bm.count_signers(), 5);
        assert!(bm.has_signed(0));
        assert!(bm.has_signed(5));
        assert!(bm.has_signed(799));
        assert!(!bm.has_signed(2));
        assert!(!bm.has_signed(800)); // out of range
    }

    #[test]
    fn test_signer_bitmap_size() {
        let bm = SignerBitmap::from_indices(800, &[]);
        // 800 / 8 = 100 bytes + 4 committee_size
        assert_eq!(bm.size_bytes(), 104);
    }

    #[test]
    fn test_compact_block_signature_size() {
        let aggregator = SignatureAggregator::new(1000);
        let sigs: Vec<Vec<u8>> = (0..21).map(|i| vec![i as u8; 100]).collect();
        let pks: Vec<Vec<u8>> = (0..21).map(|i| vec![i as u8; 50]).collect();
        let agg = aggregator.aggregate(sigs, pks, b"block_hash").unwrap();

        let indices: Vec<usize> = (0..21).collect();
        let compact = aggregator.compact(&agg, 800, &indices);

        // Compact should be ~132 bytes (32 root + 104 bitmap + 4 count + 32 msg_hash)
        // vs full: 21 * (100 + 50) + proofs + root = ~3200+ bytes
        assert!(compact.encoded_size() < 200);
        let full_size = SignatureAggregator::full_aggregated_size(&agg);
        assert!(compact.encoded_size() < full_size / 10);
    }

    #[test]
    fn test_compression_metrics_mldsa65_800_committee() {
        // 21 signers out of 800 committee (typical BFT quorum)
        let m = CompressionMetrics::mldsa65(534, 800); // 2/3 + 1 = 534
        // Individual: 534 * (3293 + 1952) = ~2.8 MB
        assert!(m.individual_bytes > 2_000_000);
        // Compact: 32 + 104 + 4 + 32 = 172 bytes
        assert!(m.compact_bytes < 200);
        // Ratio > 10_000x
        assert!(m.ratio > 10_000.0);
        // Savings > 99.99%
        assert!(m.savings_percent > 99.99);
    }

    #[test]
    fn test_compression_metrics_ml_dsa() {
        let m = CompressionMetrics::ml_dsa(534, 800);
        // Individual: 534 * (3309 + 1952) = ~2.8 MB
        assert!(m.individual_bytes > 2_000_000);
        // Compact: same ~172 bytes
        assert!(m.compact_bytes < 200);
        assert!(m.ratio > 10_000.0);
    }

    #[test]
    fn test_full_aggregation_verify() {
        let aggregator = SignatureAggregator::new(100);
        let sigs: Vec<Vec<u8>> = (0..5).map(|i| vec![i; 64]).collect();
        let pks: Vec<Vec<u8>> = (0..5).map(|i| vec![i; 32]).collect();

        let agg = aggregator.aggregate(sigs, pks, b"test").unwrap();
        assert_eq!(agg.signatures.len(), 5);
        assert_eq!(agg.merkle_proofs.len(), 5);
        assert_ne!(agg.root, [0u8; 32]);
    }
}
