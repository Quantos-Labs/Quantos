use sha3::{Digest, Sha3_256, Shake256};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use crate::types::Hash;

pub fn sha3_256(data: &[u8]) -> Hash {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

pub fn shake256(data: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(data);
    let mut output = vec![0u8; output_len];
    hasher.finalize_xof().read(&mut output);
    output
}

pub fn blake3_hash(data: &[u8]) -> Hash {
    let hash = blake3::hash(data);
    *hash.as_bytes()
}

pub fn merkle_root(hashes: &[Hash]) -> Hash {
    if hashes.is_empty() {
        return [0u8; 32];
    }
    
    if hashes.len() == 1 {
        return hashes[0];
    }
    
    let mut current_level: Vec<Hash> = hashes.to_vec();
    
    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        
        for chunk in current_level.chunks(2) {
            let hash = if chunk.len() == 2 {
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(&chunk[0]);
                combined.extend_from_slice(&chunk[1]);
                sha3_256(&combined)
            } else {
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(&chunk[0]);
                combined.extend_from_slice(&chunk[0]);
                sha3_256(&combined)
            };
            next_level.push(hash);
        }
        
        current_level = next_level;
    }
    
    current_level[0]
}

pub fn compute_state_root(account_hashes: &[Hash]) -> Hash {
    merkle_root(account_hashes)
}

pub fn verify_merkle_proof(
    leaf: &Hash,
    proof: &[Hash],
    index: usize,
    root: &Hash,
) -> bool {
    let mut current = *leaf;
    let mut idx = index;
    
    for sibling in proof {
        let combined = if idx % 2 == 0 {
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(&current);
            data.extend_from_slice(sibling);
            data
        } else {
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(sibling);
            data.extend_from_slice(&current);
            data
        };
        
        current = sha3_256(&combined);
        idx /= 2;
    }
    
    current == *root
}

#[derive(Clone, Debug)]
pub struct MerkleProof {
    pub leaf: Hash,
    pub siblings: Vec<Hash>,
    pub index: usize,
}

impl MerkleProof {
    pub fn verify(&self, root: &Hash) -> bool {
        verify_merkle_proof(&self.leaf, &self.siblings, self.index, root)
    }
}

pub fn build_merkle_tree(leaves: &[Hash]) -> (Hash, Vec<Vec<Hash>>) {
    if leaves.is_empty() {
        return ([0u8; 32], Vec::new());
    }
    
    let mut levels: Vec<Vec<Hash>> = vec![leaves.to_vec()];
    
    while let Some(last_level) = levels.last() {
        if last_level.len() <= 1 {
            break;
        }
        
        let current = last_level;
        let mut next_level = Vec::new();
        
        for chunk in current.chunks(2) {
            let hash = if chunk.len() == 2 {
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(&chunk[0]);
                combined.extend_from_slice(&chunk[1]);
                sha3_256(&combined)
            } else {
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(&chunk[0]);
                combined.extend_from_slice(&chunk[0]);
                sha3_256(&combined)
            };
            next_level.push(hash);
        }
        
        levels.push(next_level);
    }
    
    let root = levels.last()
        .and_then(|level| level.first())
        .copied()
        .unwrap_or([0u8; 32]);
    (root, levels)
}

pub fn generate_merkle_proof(leaves: &[Hash], index: usize) -> Option<MerkleProof> {
    if index >= leaves.len() {
        return None;
    }
    
    let (_, levels) = build_merkle_tree(leaves);
    let mut siblings = Vec::new();
    let mut idx = index;
    
    for level in &levels[..levels.len() - 1] {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        let sibling = level.get(sibling_idx).copied().unwrap_or(level[idx]);
        siblings.push(sibling);
        idx /= 2;
    }
    
    Some(MerkleProof {
        leaf: leaves[index],
        siblings,
        index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256() {
        let data = b"Hello, Quantos!";
        let hash = sha3_256(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_merkle_root() {
        let leaves: Vec<Hash> = (0..8).map(|i| sha3_256(&[i])).collect();
        let root = merkle_root(&leaves);
        assert_eq!(root.len(), 32);
    }

    #[test]
    fn test_merkle_proof() {
        let leaves: Vec<Hash> = (0..8).map(|i| sha3_256(&[i])).collect();
        let (root, _) = build_merkle_tree(&leaves);
        
        let proof = generate_merkle_proof(&leaves, 3).unwrap();
        assert!(proof.verify(&root));
    }

    #[test]
    fn test_empty_merkle() {
        let root = merkle_root(&[]);
        assert_eq!(root, [0u8; 32]);
    }
}
