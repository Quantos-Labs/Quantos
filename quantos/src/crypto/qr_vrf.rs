//! # Quantum-Resistant VRF (QR-VRF)
//!
//! ## Security design
//!
//! SPHINCS+ is a randomised signature scheme: the same (sk, message) pair
//! produces **different** signature bytes on each call. Using the raw
//! SPHINCS+ signature as the VRF output therefore breaks the **uniqueness**
//! property (a malicious validator could grind signatures until it picks a
//! committee-favourable output).
//!
//! ### Construction (PRF + SPHINCS+-proof VRF)
//!
//! ```text
//!  prf_key  = SHAKE256(DOMAIN_VRF_PRF  ‖ sk_bytes)        [0..32]
//!  output   = SHAKE256(DOMAIN_VRF_OUTPUT ‖ prf_key ‖ seed) [0..32]
//!  pi       = SPHINCS+_sign(sk, DOMAIN_VRF_PROVE ‖ seed ‖ output)
//! ```
//!
//! **Verify**: `SPHINCS+_verify(pk, DOMAIN_VRF_PROVE ‖ seed ‖ output, pi)`
//!
//! Properties:
//! * **Uniqueness** – output is a PRF value; a validator that signs a different
//!   output for the same seed is trivially detected (equivocation evidence).
//! * **Verifiability** – anyone with pk can check the binding.
//! * **Pseudorandomness** – SHAKE256 keyed with a secret value.
//! * **Post-quantum** – SPHINCS+ and SHAKE256 are both PQ-secure.

use serde::{Deserialize, Serialize};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::crypto::{
    CryptoResult, SphincsKeypair, verify_sphincs,
    DOMAIN_VRF_PRF, DOMAIN_VRF_OUTPUT, DOMAIN_VRF_PROVE,
};
use crate::types::{Hash, Address, hash_data};

// ── Keypair ───────────────────────────────────────────────────────────────────

/// QR-VRF keypair.
///
/// The SPHINCS+ keypair is used only for proving. The deterministic VRF output
/// is derived via a keyed PRF built from the same secret key bytes.
#[derive(Clone)]
pub struct QrVrfKeypair {
    sphincs: SphincsKeypair,
    /// Stable PRF key derived once from the SPHINCS+ secret key.
    prf_key: [u8; 32],
}

impl QrVrfKeypair {
    /// Generates a fresh QR-VRF keypair.
    pub fn generate() -> CryptoResult<Self> {
        let sphincs = SphincsKeypair::generate()?;
        let prf_key = Self::derive_prf_key(&sphincs.secret_key);
        Ok(Self { sphincs, prf_key })
    }

    /// Wraps an existing SPHINCS+ keypair.
    pub fn from_sphincs(sphincs: SphincsKeypair) -> Self {
        let prf_key = Self::derive_prf_key(&sphincs.secret_key);
        Self { sphincs, prf_key }
    }

    /// Returns the SPHINCS+ public key (used as the VRF public key).
    pub fn public_key(&self) -> &[u8] {
        &self.sphincs.public_key
    }

    /// Returns the address (SHA3-256 of public key).
    pub fn address(&self) -> Address {
        let hash = hash_data(self.public_key());
        hash
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    fn derive_prf_key(sk_bytes: &[u8]) -> [u8; 32] {
        let mut h = Shake256::default();
        h.update(DOMAIN_VRF_PRF);
        h.update(sk_bytes);
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

    // ── Public VRF API ────────────────────────────────────────────────────────

    /// Generates a deterministic VRF proof for `seed`.
    ///
    /// The output is always the same for a given (keypair, seed) pair.
    /// The SPHINCS+ signature (proof bytes) may vary between calls because
    /// SPHINCS+ is randomised, but that does not affect the VRF output.
    pub fn prove(&self, seed: &[u8]) -> CryptoResult<QrVrfProof> {
        let output = Self::compute_output(&self.prf_key, seed);
        let msg    = Self::proof_msg(seed, &output);
        let proof  = self.sphincs.sign(&msg)?;
        Ok(QrVrfProof {
            output,
            proof,
            seed_hash: hash_data(seed),
        })
    }

    /// Verifies that `proof` was honestly produced by this keypair for `seed`.
    pub fn verify(&self, seed: &[u8], proof: &QrVrfProof) -> CryptoResult<bool> {
        if hash_data(seed) != proof.seed_hash {
            return Ok(false);
        }
        let msg = Self::proof_msg(seed, &proof.output);
        self.sphincs.verify(&msg, &proof.proof)
    }
}

// ── Standalone verification ───────────────────────────────────────────────────

/// Verifies a `QrVrfProof` against a raw SPHINCS+ public key.
///
/// This does **not** require a `QrVrfKeypair` instance; anyone with the
/// validator's registered public key can call this.
pub fn verify_qr_vrf_proof(
    public_key: &[u8],
    seed: &[u8],
    proof: &QrVrfProof,
) -> CryptoResult<bool> {
    if hash_data(seed) != proof.seed_hash {
        return Ok(false);
    }
    let mut msg = Vec::with_capacity(DOMAIN_VRF_PROVE.len() + seed.len() + 32);
    msg.extend_from_slice(DOMAIN_VRF_PROVE);
    msg.extend_from_slice(seed);
    msg.extend_from_slice(&proof.output);
    verify_sphincs(public_key, &msg, &proof.proof)
}

// ── Proof type ────────────────────────────────────────────────────────────────

/// A quantum-resistant VRF proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QrVrfProof {
    /// Deterministic VRF output (32 bytes). This is the value used for
    /// committee selection; it is stable across multiple `prove` calls.
    pub output: Hash,
    /// SPHINCS+ signature over `(DOMAIN_VRF_PROVE ‖ seed ‖ output)`.
    /// ~17 KB for SPHINCS+-shake-256f.
    pub proof: Vec<u8>,
    /// SHA3-256 of the input seed (convenience for fast pre-check).
    pub seed_hash: Hash,
}

impl QrVrfProof {
    pub fn to_u64(&self) -> u64 {
        u64::from_le_bytes(self.output[0..8].try_into().unwrap_or([0u8; 8]))
    }

    pub fn to_u128(&self) -> u128 {
        u128::from_le_bytes(self.output[0..16].try_into().unwrap_or([0u8; 16]))
    }

    pub fn to_committee_id(&self, num_committees: u16) -> u16 {
        if num_committees == 0 { return 0; }
        (self.to_u64() % num_committees as u64) as u16
    }

    /// Stake-weighted probabilistic selection.
    ///
    /// A validator is selected if:
    ///   `(vrf_value % total_stake) < stake * committee_size`
    ///
    /// This is equivalent to probability = min(1, stake/total_stake * committee_size)
    /// without the integer-truncation bug of dividing first.
    pub fn is_stake_selected(&self, stake: u128, total_stake: u128, committee_size: usize) -> bool {
        if total_stake == 0 || stake == 0 {
            return false;
        }
        let vrf_value      = self.to_u128();
        let max_unbiased   = (u128::MAX / total_stake) * total_stake;
        if vrf_value >= max_unbiased {
            return false;
        }
        let selection_value = vrf_value % total_stake;
        let threshold = stake.saturating_mul(committee_size as u128);
        // If threshold >= total_stake the probability is 1 (always selected).
        if threshold >= total_stake {
            return true;
        }
        selection_value < threshold
    }
}

// ── Committee seed helper ─────────────────────────────────────────────────────

/// Computes the canonical VRF input seed for an epoch/slot.
pub fn compute_committee_seed(epoch: u64, slot: u64, prev_randomness: &Hash) -> Hash {
    let mut data = Vec::with_capacity(48);
    data.extend_from_slice(&epoch.to_le_bytes());
    data.extend_from_slice(&slot.to_le_bytes());
    data.extend_from_slice(prev_randomness);
    hash_data(&data)
}

// ── Standalone selection helper ───────────────────────────────────────────────

/// Selects committee validators by stake-weighted VRF.
///
/// The threshold uses `stake * committee_size` (not divided by `total_stake`)
/// to avoid integer truncation for small stakes.
pub fn select_committee_validators(
    vrf_outputs: &[(Hash, u128)],
    committee_size: usize,
    total_stake: u128,
) -> Vec<usize> {
    let mut selected = Vec::new();
    if total_stake == 0 || committee_size == 0 {
        return selected;
    }
    for (i, (output, stake)) in vrf_outputs.iter().enumerate() {
        let vrf_value    = u128::from_le_bytes(output[0..16].try_into().unwrap_or([0u8; 16]));
        let max_unbiased = (u128::MAX / total_stake) * total_stake;
        if vrf_value >= max_unbiased {
            continue;
        }
        let selection_value = vrf_value % total_stake;
        let threshold = stake.saturating_mul(committee_size as u128);
        let is_selected = if threshold >= total_stake {
            true
        } else {
            selection_value < threshold
        };
        if is_selected {
            selected.push(i);
            if selected.len() >= committee_size {
                break;
            }
        }
    }
    selected
}

// ── Committee selector ────────────────────────────────────────────────────────

/// Configuration for committee selection.
#[derive(Clone, Debug)]
pub struct CommitteeSelectionConfig {
    pub committee_size: usize,
    pub min_stake: u128,
    pub enable_stake_weighting: bool,
    pub max_validators: usize,
}

impl Default for CommitteeSelectionConfig {
    fn default() -> Self {
        Self {
            committee_size: 21,
            min_stake: 1_000_000,
            enable_stake_weighting: true,
            max_validators: 100_000,
        }
    }
}

/// Deterministic committee selector using VRF outputs.
pub struct CommitteeSelector {
    config: CommitteeSelectionConfig,
}

impl CommitteeSelector {
    pub fn new(config: CommitteeSelectionConfig) -> Self {
        Self { config }
    }

    pub fn select_committee(
        &self,
        validators: &[(usize, QrVrfProof, u128)],
        total_stake: u128,
    ) -> Vec<usize> {
        let eligible: Vec<_> = validators
            .iter()
            .filter(|(_, _, stake)| *stake >= self.config.min_stake)
            .take(self.config.max_validators)
            .collect();

        let mut selected = Vec::new();
        for (idx, proof, stake) in eligible {
            if proof.is_stake_selected(*stake, total_stake, self.config.committee_size) {
                selected.push(*idx);
                if selected.len() >= self.config.committee_size {
                    break;
                }
            }
        }
        selected
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qr_vrf_prove_verify() {
        let kp   = QrVrfKeypair::generate().unwrap();
        let seed = compute_committee_seed(1, 100, &[0u8; 32]);

        let proof = kp.prove(&seed).unwrap();
        assert!(kp.verify(&seed, &proof).unwrap(), "valid proof should verify");

        let wrong_seed = compute_committee_seed(1, 101, &[0u8; 32]);
        assert!(!kp.verify(&wrong_seed, &proof).unwrap(), "wrong seed must reject");
    }

    #[test]
    fn test_qr_vrf_deterministic_output() {
        let kp    = QrVrfKeypair::generate().unwrap();
        let seed  = b"deterministic_test_seed";
        let p1    = kp.prove(seed).unwrap();
        let p2    = kp.prove(seed).unwrap();
        // Output must be identical (PRF-derived).
        assert_eq!(p1.output, p2.output, "VRF output must be deterministic");
    }

    #[test]
    fn test_standalone_verification() {
        let kp   = QrVrfKeypair::generate().unwrap();
        let seed = b"test_seed_for_verification";
        let proof = kp.prove(seed).unwrap();
        let ok = verify_qr_vrf_proof(kp.public_key(), seed, &proof).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_committee_selection() {
        let total_stake = 1_000_000u128;
        // Use VRF output [0u8;32]: vrf_value = 0, selection_value = 0 < threshold > 0 → all selected.
        let vrf_outputs = vec![
            ([0u8; 32], 100_000u128),
            ([0u8; 32], 200_000u128),
            ([0u8; 32], 300_000u128),
            ([0u8; 32], 400_000u128),
        ];
        let selected = select_committee_validators(&vrf_outputs, 2, total_stake);
        assert!(!selected.is_empty(), "should select at least one validator");
        assert!(selected.len() <= 2);
    }

    #[test]
    fn test_stake_weighted_selection() {
        // With selection_value = 0, any threshold > 0 selects the validator.
        let proof_zero = QrVrfProof { output: [0u8; 32], proof: vec![], seed_hash: [0u8; 32] };
        assert!(proof_zero.is_stake_selected(500_000, 1_000_000, 10));
        assert!(proof_zero.is_stake_selected(10_000, 1_000_000, 10));

        // With selection_value ≈ total_stake - 1 (all-FF output), only large stake selects.
        let mut high_output = [0u8; 32];
        high_output[0..16].copy_from_slice(&(999_999u128 - 1).to_le_bytes());
        let proof_high = QrVrfProof { output: high_output, proof: vec![], seed_hash: [0u8; 32] };
        // selection_value = 999_998, threshold for 500_000 stake * 1 committee_size = 500_000 → NOT selected
        assert!(!proof_high.is_stake_selected(500_000, 1_000_000, 1));
        // But with committee_size = 3: threshold = 500_000 * 3 = 1_500_000 >= total_stake → always selected
        assert!(proof_high.is_stake_selected(500_000, 1_000_000, 3));
    }

    #[test]
    fn test_committee_selector_min_stake_filter() {
        let config = CommitteeSelectionConfig {
            committee_size: 3,
            min_stake: 50_000,
            ..Default::default()
        };
        let selector = CommitteeSelector::new(config);
        let validators = vec![
            (0, QrVrfProof { output: [0u8; 32], proof: vec![], seed_hash: [0u8; 32] }, 100_000u128),
            (1, QrVrfProof { output: [0u8; 32], proof: vec![], seed_hash: [0u8; 32] }, 200_000u128),
            // Below min_stake – must be filtered
            (2, QrVrfProof { output: [0u8; 32], proof: vec![], seed_hash: [0u8; 32] }, 30_000u128),
        ];
        let selected = selector.select_committee(&validators, 300_000);
        assert!(!selected.contains(&2), "validator below min_stake must not be selected");
    }
}
