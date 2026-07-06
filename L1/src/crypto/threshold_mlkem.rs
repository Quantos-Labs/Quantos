//! Threshold ML-KEM-768 Decryption
//!
//! **Experimental / research only.** Not compiled unless the
//! `experimental-threshold-mlkem` Cargo feature is enabled. Mainnet uses
//! accountable-leader front-running protection instead.
//!
//! The secret vector `s` is split coefficient-wise via Shamir over Z_q.
//! Each participant holds a share of every scalar coefficient. During
//! threshold decapsulation each participant computes `partial_i = s_i^T · u`
//! in the NTT domain; `t` partials are combined via Lagrange interpolation
//! to recover `s^T·u`, from which the shared secret is derived.

use crate::crypto::mlkem_core::{
    Poly256, PolyVec, N, K,
    ntt, inv_ntt, vec_inner_ntt,
    poly_add, poly_mul_ntt, decompress, compress, DU, DV,
    Mlkem768Keypair, Mlkem768Ciphertext,
    polyvec_to_bytes, bytes_to_polyvec, poly_decompress,
};
use crate::crypto::shamir_zq::{split_scalar, recombine_scalar, ScalarShare};
use crate::crypto::lattice_nizk::{prove as nizk_prove, verify as nizk_verify};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Key share type ────────────────────────────────────────────────────────────

/// A participant's share of the ML-KEM secret vector.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Mlkem768KeyShare {
    pub participant_id: u32,
    /// Flat array of K×N scalar shares (one per coefficient of s).
    pub coefficient_shares: Vec<i16>,
    /// Public verification key for DLEQ proofs.
    pub verification_key: Vec<u8>,
}

// ── DKG / Share splitting ───────────────────────────────────────────────────

/// Split the secret vector `s` into `n` participant shares with threshold `t`.
/// Each polynomial coefficient gets its own independent Shamir polynomial.
pub fn split_secret_vector(
    s_ntt: &PolyVec,
    t: usize,
    n: usize,
) -> Vec<Mlkem768KeyShare> {
    let num_coeffs = K * N;
    // First, generate all shares per-coefficient
    let mut all_per_coeff: Vec<Vec<ScalarShare>> = Vec::with_capacity(num_coeffs);
    for poly in s_ntt.iter() {
        for &coeff in poly.coeffs.iter() {
            all_per_coeff.push(split_scalar(coeff, t, n));
        }
    }

    // Assemble per-participant flat vectors
    let mut participants = Vec::with_capacity(n);
    for pid in 1..=n {
        let mut shares = Vec::with_capacity(num_coeffs);
        for coeff_shares in &all_per_coeff {
            shares.push(coeff_shares[pid - 1].value);
        }
        participants.push(Mlkem768KeyShare {
            participant_id: pid as u32,
            coefficient_shares: shares,
            verification_key: vec![], // derived from coefficient shares during key distribution
        });
    }
    participants
}

/// Reconstruct the full secret vector from `t` shares.
pub fn reconstruct_secret_vector(shares: &[Mlkem768KeyShare]) -> PolyVec {
    let num_coeffs = K * N;
    assert!(!shares.is_empty());
    assert_eq!(shares[0].coefficient_shares.len(), num_coeffs);

    let mut s = [Poly256::default(); K];
    for coeff_idx in 0..num_coeffs {
        let scalar_shares: Vec<ScalarShare> = shares.iter()
            .map(|sh| ScalarShare { id: sh.participant_id, value: sh.coefficient_shares[coeff_idx] })
            .collect();
        let recovered = recombine_scalar(&scalar_shares);
        let poly_idx = coeff_idx / N;
        let c_idx = coeff_idx % N;
        s[poly_idx].coeffs[c_idx] = recovered;
    }
    s
}

// ── Threshold decapsulation ─────────────────────────────────────────────────

/// A partial inner-product computed by one participant.
#[derive(Clone, Debug)]
pub struct PartialDecaps {
    pub participant_id: u32,
    pub poly: Poly256,
}

/// Participant computes `partial = s_i^T · u` where `u` is the decompressed
/// ciphertext vector (must already be in NTT domain).
pub fn partial_decapsulate(share: &Mlkem768KeyShare, u_ntt: &PolyVec) -> PartialDecaps {
    // Rebuild s_i from flat coefficient_shares
    let mut s_i = [Poly256::default(); K];
    let mut idx = 0usize;
    for poly_i in 0..K {
        for c_j in 0..N {
            s_i[poly_i].coeffs[c_j] = share.coefficient_shares[idx];
            idx += 1;
        }
    }
    let partial = vec_inner_ntt(&s_i, u_ntt);
    PartialDecaps {
        participant_id: share.participant_id,
        poly: partial,
    }
}

/// Combine `t` partial inner-products via Lagrange interpolation to recover
/// `s^T · u`.
pub fn combine_partials(partials: &[PartialDecaps]) -> Poly256 {
    let mut result = Poly256::default();
    for (i, partial) in partials.iter().enumerate() {
        let pid = partial.participant_id;
        let mut num = 1i16;
        let mut den = 1i16;
        for (j, other) in partials.iter().enumerate() {
            if i == j { continue; }
            let other_pid = other.participant_id;
            num = crate::crypto::mlkem_core::mul_mod(num,
                crate::crypto::mlkem_core::sub_mod(0, other_pid as i16));
            den = crate::crypto::mlkem_core::mul_mod(den,
                crate::crypto::mlkem_core::sub_mod(pid as i16, other_pid as i16));
        }
        let lambda = crate::crypto::mlkem_core::mul_mod(num,
            crate::crypto::mlkem_core::mod_inverse(den));
        for coeff in 0..N {
            result.coeffs[coeff] = crate::crypto::mlkem_core::add_mod(
                result.coeffs[coeff],
                crate::crypto::mlkem_core::mul_mod(partial.poly.coeffs[coeff], lambda)
            );
        }
    }
    result
}

/// Threshold decapsulation: given a ciphertext and `t` shares, recover
/// the 32-byte shared secret.
pub fn threshold_decapsulate(
    ct: &Mlkem768Ciphertext,
    partials: &[PartialDecaps],
) -> [u8; 32] {
    let su_ntt = combine_partials(partials);
    let mut su = su_ntt;
    inv_ntt(&mut su);

    let v = poly_decompress(DV, &ct.v_compressed);
    let mut m_poly = crate::crypto::mlkem_core::poly_sub(&v, &su);

    let mut m = [0u8; 32];
    for byte_idx in 0..32 {
        let mut byte = 0u8;
        for bit in 0..8 {
            let coeff = m_poly.coeffs[byte_idx * 8 + bit];
            let rounded = if coeff < 0 { coeff + 3329 } else { coeff };
            if rounded > (3329 / 2) {
                byte |= 1 << bit;
            }
        }
        m[byte_idx] = byte;
    }

    use sha3::{Sha3_256, Digest};
    let mut hasher = Sha3_256::new();
    hasher.update(&m);
    let mut ss = [0u8; 32];
    ss.copy_from_slice(&hasher.finalize());
    ss
}

// ── NIZK proofs (production lattice Fiat-Shamir) ────────────────────────────

pub use crate::crypto::lattice_nizk::LatticeNizkProof;

/// Prove knowledge of the share used to compute `partial = s_i^T · u`.
pub fn prove_partial_decaps(
    share: &Mlkem768KeyShare,
    u_ntt: &PolyVec,
) -> (PartialDecaps, LatticeNizkProof) {
    // Rebuild s_i from flat coefficient_shares
    let mut s_i = [Poly256::default(); K];
    let mut idx = 0usize;
    for poly_i in 0..K {
        for c_j in 0..N {
            s_i[poly_i].coeffs[c_j] = share.coefficient_shares[idx];
            idx += 1;
        }
    }
    let partial = vec_inner_ntt(&s_i, u_ntt);
    let proof = nizk_prove(&s_i, u_ntt, &partial, &share.verification_key);
    (
        PartialDecaps {
            participant_id: share.participant_id,
            poly: partial,
        },
        proof,
    )
}

/// Verify a lattice NIZK proof for a partial decapsulation.
pub fn verify_dleq(
    vk: &[u8],
    u_ntt: &PolyVec,
    partial: &PartialDecaps,
    proof: &LatticeNizkProof,
) -> bool {
    nizk_verify(u_ntt, &partial.poly, vk, proof)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::mlkem_core::{keypair, encapsulate, decapsulate, ntt};

    #[test]
    fn test_threshold_roundtrip() {
        // 1. Generate keypair
        let kp = keypair();

        // 2. Encapsulate
        let (ct, ss_enc) = encapsulate(&kp.public_key_bytes);

        // 3. Split secret into 5 shares, threshold 3
        let shares = split_secret_vector(&kp.secret_vec_ntt, 3, 5);

        // 4. Reconstruct from 3 shares and verify it matches the original
        let reconstructed = reconstruct_secret_vector(&shares[0..3]);
        assert_eq!(reconstructed, kp.secret_vec_ntt);

        // 5. Build u_ntt from ciphertext (simplified: decompress and NTT)
        let u_decomp = poly_decompress(DU, &ct.u_compressed);
        let mut u_ntt = [u_decomp.clone(), u_decomp.clone(), u_decomp.clone()];
        for i in 0..K { ntt(&mut u_ntt[i]); }

        // 6. Each of 3 participants computes a partial
        let mut partials = Vec::new();
        for share in &shares[0..3] {
            partials.push(partial_decapsulate(share, &u_ntt));
        }

        // 7. Combine partials → shared secret
        let ss_thr = threshold_decapsulate(&ct, &partials);

        // 8. Verify against single-party decapsulation
        let ss_single = decapsulate(&kp, &ct);
        assert_eq!(ss_thr, ss_single, "threshold decaps must match single-party");
        assert_eq!(ss_thr, ss_enc, "threshold decaps must match encaps secret");
    }
}
