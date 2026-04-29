use crate::crypto::{CryptoResult, SphincsKeypair, verify_sphincs};
use crate::types::{Hash, hash_data};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};

#[derive(Clone)]
pub struct VRFKeypair {
    sphincs: SphincsKeypair,
}

impl VRFKeypair {
    pub fn generate() -> CryptoResult<Self> {
        Ok(Self {
            sphincs: SphincsKeypair::generate()?,
        })
    }

    pub fn from_sphincs(sphincs: SphincsKeypair) -> Self {
        Self { sphincs }
    }

    pub fn public_key(&self) -> &[u8] {
        &self.sphincs.public_key
    }

    pub fn prove(&self, seed: &[u8]) -> CryptoResult<VRFProof> {
        let signature = self.sphincs.sign(seed)?;
        
        let mut hasher = Shake256::default();
        hasher.update(&signature);
        let mut output = [0u8; 32];
        hasher.finalize_xof().read(&mut output);
        
        Ok(VRFProof {
            output,
            proof: signature,
        })
    }

    pub fn verify(&self, seed: &[u8], proof: &VRFProof) -> CryptoResult<bool> {
        let valid_sig = self.sphincs.verify(seed, &proof.proof)?;
        if !valid_sig {
            return Ok(false);
        }
        
        let mut hasher = Shake256::default();
        hasher.update(&proof.proof);
        let mut expected_output = [0u8; 32];
        hasher.finalize_xof().read(&mut expected_output);
        
        Ok(expected_output == proof.output)
    }
}

#[derive(Clone, Debug)]
pub struct VRFProof {
    pub output: Hash,
    pub proof: Vec<u8>,
}

impl VRFProof {
    pub fn to_u64(&self) -> u64 {
        let bytes: [u8; 8] = self.output[0..8].try_into().unwrap_or([0u8; 8]);
        u64::from_le_bytes(bytes)
    }

    pub fn to_committee_id(&self, num_committees: u16) -> u16 {
        (self.to_u64() % num_committees as u64) as u16
    }

    pub fn is_selected(&self, threshold: u64) -> bool {
        self.to_u64() < threshold
    }
}

pub fn verify_vrf_proof(
    public_key: &[u8],
    seed: &[u8],
    proof: &VRFProof,
) -> CryptoResult<bool> {
    let valid_sig = verify_sphincs(public_key, seed, &proof.proof)?;
    if !valid_sig {
        return Ok(false);
    }
    
    let mut hasher = Shake256::default();
    hasher.update(&proof.proof);
    let mut expected_output = [0u8; 32];
    hasher.finalize_xof().read(&mut expected_output);
    
    Ok(expected_output == proof.output)
}

// Committee seed and validator selection functions are in qr_vrf.rs (canonical PQ versions)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vrf_prove_verify() {
        let keypair = VRFKeypair::generate().unwrap();
        let seed = b"epoch_1_slot_100_randomness";
        
        let proof = keypair.prove(seed).unwrap();
        let valid = keypair.verify(seed, &proof).unwrap();
        assert!(valid);
        
        let wrong_seed = b"wrong_seed";
        let invalid = keypair.verify(wrong_seed, &proof).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_vrf_deterministic() {
        let keypair = VRFKeypair::generate().unwrap();
        let seed = b"deterministic_test";
        
        let proof1 = keypair.prove(seed).unwrap();
        let proof2 = keypair.prove(seed).unwrap();
        
        assert_eq!(proof1.output, proof2.output);
    }
}
