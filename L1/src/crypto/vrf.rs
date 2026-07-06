//! Simple VRF wrapper (SPHINCS+ + PRF).
//!
//! Same deterministic construction as `QrVrfKeypair` in `qr_vrf.rs`,
//! kept as a thin alias for code sites that use `VRFKeypair` directly.
//! See `qr_vrf.rs` for the full design rationale.

use crate::crypto::{
    CryptoResult, SphincsKeypair, verify_sphincs,
    DOMAIN_VRF_PRF, DOMAIN_VRF_OUTPUT, DOMAIN_VRF_PROVE,
};
use crate::types::{Hash, hash_data};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};

#[derive(Clone)]
pub struct VRFKeypair {
    sphincs: SphincsKeypair,
    prf_key: [u8; 32],
}

impl VRFKeypair {
    pub fn generate() -> CryptoResult<Self> {
        let sphincs = SphincsKeypair::generate()?;
        let prf_key = Self::derive_prf_key(&sphincs.secret_key);
        Ok(Self { sphincs, prf_key })
    }

    pub fn from_sphincs(sphincs: SphincsKeypair) -> Self {
        let prf_key = Self::derive_prf_key(&sphincs.secret_key);
        Self { sphincs, prf_key }
    }

    pub fn from_keys(public_key: Vec<u8>, secret_key: Vec<u8>) -> CryptoResult<Self> {
        let sphincs = SphincsKeypair::from_keys(public_key, secret_key)?;
        Ok(Self::from_sphincs(sphincs))
    }

    pub fn public_key(&self) -> &[u8] {
        &self.sphincs.public_key
    }

    pub fn secret_key(&self) -> &[u8] {
        &self.sphincs.secret_key
    }

    fn derive_prf_key(sk: &[u8]) -> [u8; 32] {
        let mut h = Shake256::default();
        h.update(DOMAIN_VRF_PRF);
        h.update(sk);
        let mut k = [0u8; 32];
        h.finalize_xof().read(&mut k);
        k
    }

    fn compute_output(prf_key: &[u8; 32], seed: &[u8]) -> [u8; 32] {
        let mut h = Shake256::default();
        h.update(DOMAIN_VRF_OUTPUT);
        h.update(prf_key);
        h.update(seed);
        let mut o = [0u8; 32];
        h.finalize_xof().read(&mut o);
        o
    }

    fn proof_msg(seed: &[u8], output: &[u8; 32]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(DOMAIN_VRF_PROVE.len() + seed.len() + 32);
        msg.extend_from_slice(DOMAIN_VRF_PROVE);
        msg.extend_from_slice(seed);
        msg.extend_from_slice(output);
        msg
    }

    /// Generates a deterministic VRF proof for `seed`.
    pub fn prove(&self, seed: &[u8]) -> CryptoResult<VRFProof> {
        let output = Self::compute_output(&self.prf_key, seed);
        let msg    = Self::proof_msg(seed, &output);
        let proof  = self.sphincs.sign(&msg)?;
        Ok(VRFProof { output, proof })
    }

    /// Verifies a VRF proof.
    pub fn verify(&self, seed: &[u8], proof: &VRFProof) -> CryptoResult<bool> {
        let msg = Self::proof_msg(seed, &proof.output);
        self.sphincs.verify(&msg, &proof.proof)
    }
}

#[derive(Clone, Debug)]
pub struct VRFProof {
    pub output: Hash,
    pub proof: Vec<u8>,
}

impl VRFProof {
    pub fn to_u64(&self) -> u64 {
        u64::from_le_bytes(self.output[0..8].try_into().unwrap_or([0u8; 8]))
    }

    pub fn to_committee_id(&self, num_committees: u16) -> u16 {
        if num_committees == 0 { return 0; }
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
    let mut msg = Vec::with_capacity(DOMAIN_VRF_PROVE.len() + seed.len() + 32);
    msg.extend_from_slice(DOMAIN_VRF_PROVE);
    msg.extend_from_slice(seed);
    msg.extend_from_slice(&proof.output);
    verify_sphincs(public_key, &msg, &proof.proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vrf_prove_verify() {
        let kp   = VRFKeypair::generate().unwrap();
        let seed = b"epoch_1_slot_100_randomness";
        let proof = kp.prove(seed).unwrap();
        assert!(kp.verify(seed, &proof).unwrap());
        assert!(!kp.verify(b"wrong_seed", &proof).unwrap());
    }

    #[test]
    fn test_vrf_deterministic() {
        let kp    = VRFKeypair::generate().unwrap();
        let seed  = b"deterministic_test";
        let p1    = kp.prove(seed).unwrap();
        let p2    = kp.prove(seed).unwrap();
        assert_eq!(p1.output, p2.output, "VRF output must be stable across calls");
    }
}
