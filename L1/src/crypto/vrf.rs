//! Hash-based VRF wrapper — delegates to `vrf_hashbased.rs`.
//!
//! This is the production VRF used by validators for committee selection.
//! The construction is purely hash-based (SHA3-256 PRF + STARK proof),
//! with no SPHINCS+ dependency. See `vrf_hashbased.rs` for the full
//! design rationale, circuit status, and `STARK_PROVES_UNIQUENESS`.

use crate::crypto::{CryptoResult, vrf_hashbased::{HashVrfKeypair, VrfStarkProof}};
use crate::types::Hash;

/// Production VRF keypair. Wraps [`HashVrfKeypair`] from `vrf_hashbased.rs`.
#[derive(Clone, Debug)]
pub struct VRFKeypair {
    inner: HashVrfKeypair,
}

impl VRFKeypair {
    pub fn generate() -> CryptoResult<Self> {
        Ok(Self { inner: HashVrfKeypair::generate()? })
    }

    /// Reconstruct from stored hex-encoded keys.
    /// `public_key` is ignored — it is recomputed as SHA3-256(secret_key).
    pub fn from_keys(_public_key: Vec<u8>, secret_key: Vec<u8>) -> CryptoResult<Self> {
        let mut sk = [0u8; 32];
        if secret_key.len() >= 32 {
            sk.copy_from_slice(&secret_key[..32]);
        }
        let pk = HashVrfKeypair::hash_sk(&sk);
        Ok(Self { inner: HashVrfKeypair { secret_key: sk, public_key: pk } })
    }

    pub fn public_key(&self) -> &[u8] {
        &self.inner.public_key
    }

    pub fn secret_key(&self) -> &[u8] {
        &self.inner.secret_key
    }

    /// Generates a deterministic VRF proof (STARK) for `seed`.
    pub fn prove(&self, seed: &[u8]) -> CryptoResult<VRFProof> {
        let stark = self.inner.prove(seed)?;
        Ok(VRFProof { output: stark.beta, proof: stark.stark_bytes })
    }

    /// Verifies a VRF proof.
    pub fn verify(&self, seed: &[u8], proof: &VRFProof) -> CryptoResult<bool> {
        let stark = VrfStarkProof { beta: proof.output, stark_bytes: proof.proof.clone() };
        self.inner.verify(seed, &stark)
    }
}

/// VRF proof — wraps the STARK proof bytes and the deterministic output.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
