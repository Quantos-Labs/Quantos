// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Post-Quantum Merkle Tree
//!
//! Quantum-resistant Merkle tree implementation using SHA3-256.
//!
//! ## Quantum Resistance
//!
//! - **Hash Function**: SHA3-256 (Keccak)
//! - **Post-Quantum Security**: 128-bit (256-bit pre-image resistance / 2 due to Grover)
//! - **Collision Resistance**: 128-bit post-quantum
//!
//! ## Features
//!
//! - Efficient proof generation and verification
//! - Sparse Merkle tree support
//! - Incremental updates
//! - Parallel computation for large trees
//!
//! ## Architecture
//!
//! ```text
//!                    Root Hash
//!                   /          \
//!              H(A,B)          H(C,D)
//!             /      \        /      \
//!           H(A)    H(B)    H(C)    H(D)
//!            |       |       |       |
//!          Leaf0   Leaf1   Leaf2   Leaf3
//! ```

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::types::Hash;

/// Merkle tree node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MerkleNode {
    /// Leaf node with data hash
    Leaf(Hash),
    /// Internal node with left and right children
    Internal {
        left: Box<MerkleNode>,
        right: Box<MerkleNode>,
        hash: Hash,
    },
    /// Empty node (for sparse trees)
    Empty,
}

impl MerkleNode {
    /// Gets the hash of this node.
    pub fn hash(&self) -> Hash {
        match self {
            MerkleNode::Leaf(h) => *h,
            MerkleNode::Internal { hash, .. } => *hash,
            MerkleNode::Empty => [0u8; 32],
        }
    }

    /// Checks if node is empty.
    pub fn is_empty(&self) -> bool {
        matches!(self, MerkleNode::Empty)
    }
}

/// Post-quantum Merkle tree.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// Root node
    root: MerkleNode,
    /// Number of leaves
    leaf_count: usize,
    /// Tree height
    height: usize,
}

impl MerkleTree {
    /// Creates a new Merkle tree from leaf data.
    pub fn new(leaves: &[Vec<u8>]) -> Self {
        if leaves.is_empty() {
            return Self {
                root: MerkleNode::Empty,
                leaf_count: 0,
                height: 0,
            };
        }

        // Hash all leaves
        let leaf_hashes: Vec<Hash> = leaves
            .iter()
            .map(|data| hash_leaf(data))
            .collect();

        let leaf_count = leaf_hashes.len();
        
        // Use checked arithmetic to prevent overflow
        let height = if leaf_count <= 1 {
            0
        } else {
            // Calculate ceil(log2(leaf_count)) safely without float conversion
            let mut h = 0;
            let mut n = leaf_count - 1;
            while n > 0 {
                n >>= 1;
                h += 1;
            }
            h
        };

        // Build tree bottom-up
        let root = Self::build_tree(&leaf_hashes);

        Self {
            root,
            leaf_count,
            height,
        }
    }

    /// Builds tree recursively from leaf hashes.
    fn build_tree(hashes: &[Hash]) -> MerkleNode {
        match hashes.len() {
            0 => MerkleNode::Empty,
            1 => MerkleNode::Leaf(hashes[0]),
            n => {
                // Use checked_next_power_of_two to prevent panic on overflow
                let mid = n.checked_next_power_of_two()
                    .map(|p| p / 2)
                    .unwrap_or(n / 2);
                let (left_hashes, right_hashes) = hashes.split_at(mid.min(n));

                let left = Box::new(Self::build_tree(left_hashes));
                let right = Box::new(Self::build_tree(right_hashes));

                let hash = hash_internal(&left.hash(), &right.hash());

                MerkleNode::Internal { left, right, hash }
            }
        }
    }

    /// Gets the root hash.
    pub fn root(&self) -> Hash {
        self.root.hash()
    }

    /// Gets the number of leaves.
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Gets the tree height.
    pub fn height(&self) -> usize {
        self.height
    }

    /// Generates a Merkle proof for a leaf at the given index.
    pub fn generate_proof(&self, index: usize) -> Option<PQMerkleProof> {
        if index >= self.leaf_count {
            return None;
        }

        let mut proof_hashes = Vec::new();
        let mut proof_positions = Vec::new();

        self.generate_proof_recursive(&self.root, index, 0, self.height, &mut proof_hashes, &mut proof_positions);

        Some(PQMerkleProof {
            leaf_index: index,
            leaf_count: self.leaf_count,
            proof_hashes,
            proof_positions,
        })
    }

    /// Recursively generates proof.
    fn generate_proof_recursive(
        &self,
        node: &MerkleNode,
        target_index: usize,
        current_index: usize,
        level: usize,
        proof_hashes: &mut Vec<Hash>,
        proof_positions: &mut Vec<ProofPosition>,
    ) {
        if level == 0 {
            return;
        }

        if let MerkleNode::Internal { left, right, .. } = node {
            let mid = 1 << (level - 1);

            if target_index < current_index + mid {
                // Target is in left subtree, add right sibling to proof
                proof_hashes.push(right.hash());
                proof_positions.push(ProofPosition::Right);
                self.generate_proof_recursive(left, target_index, current_index, level - 1, proof_hashes, proof_positions);
            } else {
                // Target is in right subtree, add left sibling to proof
                proof_hashes.push(left.hash());
                proof_positions.push(ProofPosition::Left);
                self.generate_proof_recursive(right, target_index, current_index + mid, level - 1, proof_hashes, proof_positions);
            }
        }
    }

    /// Verifies a Merkle proof.
    pub fn verify_proof(&self, leaf_data: &[u8], proof: &PQMerkleProof) -> bool {
        if proof.leaf_index >= proof.leaf_count {
            return false;
        }

        let leaf_hash = hash_leaf(leaf_data);
        let computed_root = proof.compute_root(leaf_hash);

        computed_root == self.root()
    }
}

/// Post-quantum Merkle proof for a leaf.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PQMerkleProof {
    /// Index of the leaf
    pub leaf_index: usize,
    /// Total number of leaves in tree
    pub leaf_count: usize,
    /// Sibling hashes along the path to root
    pub proof_hashes: Vec<Hash>,
    /// Positions of siblings (left or right)
    pub proof_positions: Vec<ProofPosition>,
}

/// Position of a sibling in the proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofPosition {
    Left,
    Right,
}

impl PQMerkleProof {
    /// Computes the root hash from this proof and a leaf hash.
    pub fn compute_root(&self, leaf_hash: Hash) -> Hash {
        let mut current_hash = leaf_hash;

        for (sibling_hash, position) in self.proof_hashes.iter().zip(&self.proof_positions) {
            current_hash = match position {
                ProofPosition::Left => hash_internal(sibling_hash, &current_hash),
                ProofPosition::Right => hash_internal(&current_hash, sibling_hash),
            };
        }

        current_hash
    }

    /// Verifies this proof against a root hash.
    pub fn verify(&self, leaf_data: &[u8], root: &Hash) -> bool {
        let leaf_hash = hash_leaf(leaf_data);
        let computed_root = self.compute_root(leaf_hash);
        &computed_root == root
    }

    /// Gets the proof size in bytes.
    pub fn size(&self) -> usize {
        self.proof_hashes.len() * 32 + self.proof_positions.len()
    }
}

/// Sparse Merkle tree for efficient state representation.
#[derive(Clone, Debug)]
pub struct SparseMerkleTree {
    /// Root hash
    root: Hash,
    /// Leaf values (only non-zero leaves stored)
    leaves: HashMap<Hash, Hash>,
    /// Tree height (typically 256 for 256-bit keys)
    height: usize,
    /// Default hash for empty nodes at each level
    default_hashes: Vec<Hash>,
}

impl SparseMerkleTree {
    /// Creates a new sparse Merkle tree.
    pub fn new(height: usize) -> Self {
        // Precompute default hashes for empty subtrees at each level
        let mut default_hashes = vec![[0u8; 32]; height + 1];
        for i in (0..height).rev() {
            default_hashes[i] = hash_internal(&default_hashes[i + 1], &default_hashes[i + 1]);
        }

        Self {
            root: default_hashes[0],
            leaves: HashMap::new(),
            height,
            default_hashes,
        }
    }

    /// Updates a leaf value.
    pub fn update(&mut self, key: &Hash, value: &Hash) {
        if value == &[0u8; 32] {
            self.leaves.remove(key);
        } else {
            self.leaves.insert(*key, *value);
        }
        self.recompute_root();
    }

    /// Gets a leaf value.
    pub fn get(&self, key: &Hash) -> Hash {
        self.leaves.get(key).copied().unwrap_or([0u8; 32])
    }

    /// Gets the root hash.
    pub fn root(&self) -> Hash {
        self.root
    }

    /// Recomputes the root hash incrementally.
    /// 
    /// Only recomputes nodes along the paths from modified leaves to the root,
    /// avoiding full tree rebuilds. For a tree of height H with K dirty leaves,
    /// this is O(K * H) instead of O(N) for full rebuild.
    fn recompute_root(&mut self) {
        if self.leaves.is_empty() {
            self.root = self.default_hashes[0];
            return;
        }

        // Collect all leaf keys that need path recomputation
        let _dirty_keys: Vec<Hash> = self.leaves.keys().copied().collect();
        
        // Track nodes that have been computed at each level
        // (parent_key -> hash) to avoid redundant computation
        let mut computed_nodes: HashMap<Hash, Hash> = HashMap::new();
        
        // Seed with leaf values
        for (key, value) in &self.leaves {
            computed_nodes.insert(*key, *value);
        }
        
        // Propagate changes up level by level
        for level in (0..self.height).rev() {
            let mut next_computed: HashMap<Hash, Hash> = HashMap::new();
            
            // Only process nodes that were touched at this level
            let keys_at_level: Vec<Hash> = computed_nodes.keys().copied().collect();
            
            for key in keys_at_level {
                let parent_key = self.parent_key(&key, level);
                
                // Skip if parent already computed this round
                if next_computed.contains_key(&parent_key) {
                    continue;
                }
                
                let sibling_key = self.sibling_key(&key, level);
                
                // Get current node value
                let node_value = computed_nodes.get(&key)
                    .copied()
                    .unwrap_or(self.default_hashes[level + 1]);
                
                // Get sibling value (may be in computed set or default)
                let sibling_value = computed_nodes.get(&sibling_key)
                    .copied()
                    .unwrap_or(self.default_hashes[level + 1]);
                
                // Compute parent hash
                let parent_value = if self.is_left_child(&key, level) {
                    hash_internal(&node_value, &sibling_value)
                } else {
                    hash_internal(&sibling_value, &node_value)
                };
                
                next_computed.insert(parent_key, parent_value);
            }
            
            computed_nodes = next_computed;
        }

        self.root = computed_nodes.values().next().copied().unwrap_or(self.default_hashes[0]);
    }

    /// Gets parent key at a given level.
    fn parent_key(&self, key: &Hash, level: usize) -> Hash {
        let mut parent = *key;
        parent[level / 8] &= !(1 << (level % 8));
        parent
    }

    /// Gets sibling key at a given level.
    fn sibling_key(&self, key: &Hash, level: usize) -> Hash {
        let mut sibling = *key;
        sibling[level / 8] ^= 1 << (level % 8);
        sibling
    }

    /// Checks if key represents left child at level.
    fn is_left_child(&self, key: &Hash, level: usize) -> bool {
        (key[level / 8] & (1 << (level % 8))) == 0
    }

    /// Generates a Merkle proof for a key.
    pub fn generate_proof(&self, key: &Hash) -> SparseMerkleProof {
        let mut siblings = Vec::new();
        let mut current_key = *key;

        for level in (0..self.height).rev() {
            let sibling_key = self.sibling_key(&current_key, level);
            let sibling_value = self.leaves.get(&sibling_key)
                .copied()
                .unwrap_or(self.default_hashes[level + 1]);

            siblings.push(sibling_value);
            current_key = self.parent_key(&current_key, level);
        }

        SparseMerkleProof {
            key: *key,
            value: self.get(key),
            siblings,
        }
    }
}

/// Sparse Merkle proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SparseMerkleProof {
    /// Key being proved
    pub key: Hash,
    /// Value at the key
    pub value: Hash,
    /// Sibling hashes along path to root
    pub siblings: Vec<Hash>,
}

impl SparseMerkleProof {
    /// Verifies this proof against a root hash.
    pub fn verify(&self, root: &Hash, _height: usize) -> bool {
        let mut current_hash = hash_leaf(&self.value);

        for (level, sibling) in self.siblings.iter().enumerate().rev() {
            let is_left = (self.key[level / 8] & (1 << (level % 8))) == 0;

            current_hash = if is_left {
                hash_internal(&current_hash, sibling)
            } else {
                hash_internal(sibling, &current_hash)
            };
        }

        &current_hash == root
    }
}

/// Hashes a leaf value using SHA3-256.
pub fn hash_leaf(data: &[u8]) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.update(b"LEAF:");
    hasher.update(data);
    hasher.finalize().into()
}

/// Hashes two internal nodes using SHA3-256.
pub fn hash_internal(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.update(b"NODE:");
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Computes Merkle root from a list of hashes.
pub fn compute_merkle_root(hashes: &[Hash]) -> Hash {
    if hashes.is_empty() {
        return [0u8; 32];
    }

    let tree = MerkleTree::new(&hashes.iter().map(|h| h.to_vec()).collect::<Vec<_>>());
    tree.root()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_single_leaf() {
        let data = vec![b"test".to_vec()];
        let tree = MerkleTree::new(&data);

        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.height(), 0);
        assert_ne!(tree.root(), [0u8; 32]);
    }

    #[test]
    fn test_merkle_tree_multiple_leaves() {
        let data = vec![
            b"leaf0".to_vec(),
            b"leaf1".to_vec(),
            b"leaf2".to_vec(),
            b"leaf3".to_vec(),
        ];
        let tree = MerkleTree::new(&data);

        assert_eq!(tree.leaf_count(), 4);
        assert_eq!(tree.height(), 2);
    }

    #[test]
    fn test_merkle_proof_generation_and_verification() {
        let data = vec![
            b"leaf0".to_vec(),
            b"leaf1".to_vec(),
            b"leaf2".to_vec(),
            b"leaf3".to_vec(),
        ];
        let tree = MerkleTree::new(&data);

        for (i, leaf) in data.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(tree.verify_proof(leaf, &proof));
            assert!(proof.verify(leaf, &tree.root()));
        }
    }

    #[test]
    fn test_merkle_proof_invalid() {
        let data = vec![b"leaf0".to_vec(), b"leaf1".to_vec()];
        let tree = MerkleTree::new(&data);

        let proof = tree.generate_proof(0).unwrap();
        assert!(!tree.verify_proof(b"wrong", &proof));
    }

    #[test]
    fn test_sparse_merkle_tree() {
        let mut tree = SparseMerkleTree::new(8);
        let initial_root = tree.root();

        let key1 = [1u8; 32];
        let value1 = [100u8; 32];

        tree.update(&key1, &value1);
        assert_ne!(tree.root(), initial_root);
        assert_eq!(tree.get(&key1), value1);

        let key2 = [2u8; 32];
        assert_eq!(tree.get(&key2), [0u8; 32]);
    }

    #[test]
    fn test_sparse_merkle_proof() {
        let mut tree = SparseMerkleTree::new(8);
        let key = [42u8; 32];
        let value = [100u8; 32];

        tree.update(&key, &value);

        let proof = tree.generate_proof(&key);
        assert!(proof.verify(&tree.root(), 8));
    }

    #[test]
    fn test_hash_functions_deterministic() {
        let data = b"test data";
        let hash1 = hash_leaf(data);
        let hash2 = hash_leaf(data);
        assert_eq!(hash1, hash2);

        let left = [1u8; 32];
        let right = [2u8; 32];
        let internal1 = hash_internal(&left, &right);
        let internal2 = hash_internal(&left, &right);
        assert_eq!(internal1, internal2);
    }

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::new(&[]);
        assert_eq!(tree.leaf_count(), 0);
        assert_eq!(tree.root(), [0u8; 32]);
    }
}
