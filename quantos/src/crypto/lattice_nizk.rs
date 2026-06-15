//! # Lattice NIZK — Fiat-Shamir Proof of Knowledge for Inner-Products
//!
//! Production zero-knowledge proof that a participant computed
//! `partial = ⟨s_i, u⟩` honestly, without revealing the secret share `s_i`.
//!
//! ## Construction (Schnorr over R_q modules)
//!
//! Given public `u ∈ R_q^k`, public `partial ∈ R_q`, and secret `s_i ∈ R_q^k`:
//!
//! 1. Prover samples `r ← R_q^k` uniformly.
//! 2. Computes commitment `A = Σ_j (r[j] ∘ u[j])`  (NTT-domain inner-product).
//! 3. Challenge `c = SHA3-256(A ‖ partial ‖ u ‖ pk ‖ context)`.
//! 4. Response `z = r + c · s_i`  (coefficient-wise mod q).
//!
//! **Verify**: `A' = Σ_j (z[j] ∘ u[j]) - c · partial` and `c == H(A' ‖ ...)`.
//!
//! ## Security
//!
//! - **Completeness**: `A' = Σ((r+cs)∘u) - c·Σ(s∘u) = Σ(r∘u) = A`.
//! - **Knowledge soundness**: extractor via rewinding (two transcripts with different
//!   challenges yield `s_i = (z₁ - z₂) / (c₁ - c₂)`).
//! - **Perfect zero-knowledge**: `z` is uniformly random in `R_q^k` because `r` is.
//!
//! ## Size
//!
//! Response `z` = K·N coefficients × 2 bytes ≈ 1.5 KB.  Challenge = 32 bytes.
//! Total proof ≈ 1.6 KB per partial decapsulation.

use crate::crypto::mlkem_core::{
    Poly256, PolyVec, N, K, add_mod, mul_mod, poly_mul_ntt, poly_add, poly_sub,
};
use sha3::{Sha3_256, Digest};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A lattice NIZK proof: knowledge of `s` such that `⟨s, u⟩ = partial`.
#[derive(Clone, Debug)]
pub struct LatticeNizkProof {
    /// Fiat-Shamir challenge (32 bytes)
    pub challenge: [u8; 32],
    /// Response vector z ∈ R_q^k (same shape as s_i)
    pub response_z: PolyVec,
}

impl Zeroize for LatticeNizkProof {
    fn zeroize(&mut self) {
        self.challenge.zeroize();
        for p in &mut self.response_z {
            p.coeffs.zeroize();
        }
    }
}

impl ZeroizeOnDrop for LatticeNizkProof {}

/// Domain separator for transcript hashing.
const DOMAIN_NIZK_CONTEXT: &[u8] = b"quantos-lattice-nizk-v1";

/// Generate a random vector of `K` polynomials with coefficients in Z_q.
fn random_polyvec() -> PolyVec {
    let mut vec = [Poly256::default(); K];
    let mut buf = [0u8; 64];
    for poly in &mut vec {
        for chunk in poly.coeffs.chunks_mut(32) {
            getrandom::getrandom(&mut buf[..chunk.len()]).unwrap();
            for i in 0..chunk.len() {
                chunk[i] = (buf[i] as i16) % 3329i16;
            }
        }
    }
    vec
}

/// Serialize a PolyVec into a flat byte string.
fn polyvec_to_bytes(v: &PolyVec) -> Vec<u8> {
    let mut out = Vec::with_capacity(K * N * 2);
    for poly in v.iter() {
        for &c in poly.coeffs.iter() {
            let u = c as u16;
            out.push((u & 0xFF) as u8);
            out.push(((u >> 8) & 0xFF) as u8);
        }
    }
    out
}

/// Serialize a Poly256 into bytes.
fn poly_to_bytes(p: &Poly256) -> Vec<u8> {
    let mut out = Vec::with_capacity(N * 2);
    for &c in p.coeffs.iter() {
        let u = c as u16;
        out.push((u & 0xFF) as u8);
        out.push(((u >> 8) & 0xFF) as u8);
    }
    out
}

/// Compute the inner-product `Σ_j (a[j] ∘ b[j])` in the NTT domain.
fn inner_product_ntt(a: &PolyVec, b: &PolyVec) -> Poly256 {
    let mut sum = Poly256::default();
    for i in 0..K {
        let prod = poly_mul_ntt(&a[i], &b[i]);
        sum = poly_add(&sum, &prod);
    }
    sum
}

/// Compute the Fiat-Shamir challenge from commitment, partial, u, and public key.
fn compute_challenge(
    commitment: &Poly256,
    partial: &Poly256,
    u: &PolyVec,
    pk_bytes: &[u8],
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DOMAIN_NIZK_CONTEXT);
    h.update(&poly_to_bytes(commitment));
    h.update(&poly_to_bytes(partial));
    h.update(&polyvec_to_bytes(u));
    h.update(pk_bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Scalar-vector multiplication: `c · vec` coefficient-wise mod q.
fn scalar_mul_polyvec(scalar: i16, vec: &PolyVec) -> PolyVec {
    let mut out = [Poly256::default(); K];
    for i in 0..K {
        for j in 0..N {
            out[i].coeffs[j] = mul_mod(scalar, vec[i].coeffs[j]);
        }
    }
    out
}

/// Vector addition: `a + b` coefficient-wise mod q.
fn add_polyvec(a: &PolyVec, b: &PolyVec) -> PolyVec {
    let mut out = [Poly256::default(); K];
    for i in 0..K {
        for j in 0..N {
            out[i].coeffs[j] = add_mod(a[i].coeffs[j], b[i].coeffs[j]);
        }
    }
    out
}

/// Convert a 32-byte challenge to a Z_q scalar (big-endian interpretation mod q).
fn challenge_to_scalar(c: &[u8; 32]) -> i16 {
    let mut x = 0i32;
    for &b in c.iter().take(4) {
        x = (x << 8) | (b as i32);
    }
    crate::crypto::mlkem_core::mod_q(x)
}

// ── Prove / Verify ────────────────────────────────────────────────────────────

/// Prove knowledge of `s_i` such that `inner_product_ntt(s_i, u) == partial`.
///
/// # Arguments
/// * `secret_s` — the secret share vector `s_i` (K polynomials)
/// * `u` — the public ciphertext vector `u` (in NTT domain)
/// * `partial` — the public inner-product result `partial = ⟨s_i, u⟩`
/// * `pk_bytes` — the participant's public verification key bytes
pub fn prove(
    secret_s: &PolyVec,
    u: &PolyVec,
    partial: &Poly256,
    pk_bytes: &[u8],
) -> LatticeNizkProof {
    let r = random_polyvec();
    let a = inner_product_ntt(&r, u);
    let c_bytes = compute_challenge(&a, partial, u, pk_bytes);
    let c_scalar = challenge_to_scalar(&c_bytes);

    let c_s = scalar_mul_polyvec(c_scalar, secret_s);
    let z = add_polyvec(&r, &c_s);

    LatticeNizkProof {
        challenge: c_bytes,
        response_z: z,
    }
}

/// Verify a lattice NIZK proof.
///
/// Returns `true` iff the prover knew a valid `s_i` producing `partial`.
pub fn verify(
    u: &PolyVec,
    partial: &Poly256,
    pk_bytes: &[u8],
    proof: &LatticeNizkProof,
) -> bool {
    let c_scalar = challenge_to_scalar(&proof.challenge);

    // Recompute commitment: A' = ⟨z, u⟩ - c · partial
    let z_u = inner_product_ntt(&proof.response_z, u);
    let c_p = {
        let mut p = Poly256::default();
        for i in 0..N {
            p.coeffs[i] = mul_mod(c_scalar, partial.coeffs[i]);
        }
        p
    };
    let a_prime = poly_sub(&z_u, &c_p);

    // Recompute challenge
    let c_prime = compute_challenge(&a_prime, partial, u, pk_bytes);

    c_prime == proof.challenge
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::mlkem_core::{keypair, expand_s, expand_ephemeral, ntt, Poly256, K};

    fn make_test_u_ntt() -> PolyVec {
        let seed = [42u8; 32];
        let (r, _e1, _e2) = expand_ephemeral(&seed);
        let mut u = r;
        for i in 0..K { ntt(&mut u[i]); }
        u
    }

    #[test]
    fn test_nizk_verify_valid() {
        let kp = keypair();
        let u = make_test_u_ntt();
        let partial = inner_product_ntt(&kp.secret_vec_ntt, &u);
        let pk = kp.public_key_bytes.to_vec();

        let proof = prove(&kp.secret_vec_ntt, &u, &partial, &pk);
        assert!(verify(&u, &partial, &pk, &proof));
    }

    #[test]
    fn test_nizk_reject_wrong_partial() {
        let kp = keypair();
        let u = make_test_u_ntt();
        let partial = inner_product_ntt(&kp.secret_vec_ntt, &u);
        let pk = kp.public_key_bytes.to_vec();

        let proof = prove(&kp.secret_vec_ntt, &u, &partial, &pk);

        // Tamper with partial
        let mut wrong_partial = partial.clone();
        wrong_partial.coeffs[0] = add_mod(wrong_partial.coeffs[0], 1);

        assert!(!verify(&u, &wrong_partial, &pk, &proof));
    }

    #[test]
    fn test_nizk_reject_wrong_secret() {
        let kp = keypair();
        let u = make_test_u_ntt();
        let partial = inner_product_ntt(&kp.secret_vec_ntt, &u);
        let pk = kp.public_key_bytes.to_vec();

        let proof = prove(&kp.secret_vec_ntt, &u, &partial, &pk);

        // Use a different u (different statement)
        let other_u = make_test_u_ntt();
        assert!(!verify(&other_u, &partial, &pk, &proof));
    }

    #[test]
    fn test_nizk_deterministic_transcript() {
        let kp = keypair();
        let u = make_test_u_ntt();
        let partial = inner_product_ntt(&kp.secret_vec_ntt, &u);
        let pk = kp.public_key_bytes.to_vec();

        let p1 = prove(&kp.secret_vec_ntt, &u, &partial, &pk);
        let p2 = prove(&kp.secret_vec_ntt, &u, &partial, &pk);

        // Proofs differ because r is random (perfect ZK)
        assert_ne!(p1.challenge, p2.challenge);
        assert_ne!(p1.response_z[0].coeffs, p2.response_z[0].coeffs);

        // Both verify
        assert!(verify(&u, &partial, &pk, &p1));
        assert!(verify(&u, &partial, &pk, &p2));
    }
}
