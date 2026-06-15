//! Shamir Secret Sharing over Z_q (q = 3329)
//!
//! Every scalar secret is split into `n` shares with threshold `t`.
//! Reconstruction requires any `t` shares via Lagrange interpolation.

use crate::crypto::mlkem_core::{mod_q, mul_mod, add_mod, sub_mod, mod_inverse, Q};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A single scalar share: (participant_id, value).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScalarShare {
    pub id: u32,
    pub value: i16,
}

/// Split a scalar secret into `n` shares with threshold `t`.
pub fn split_scalar(secret: i16, t: usize, n: usize) -> Vec<ScalarShare> {
    let mut coeffs = vec![secret];
    let mut buf = [0u8; 64];
    for _ in 1..t {
        getrandom::getrandom(&mut buf).unwrap();
        coeffs.push((buf[0] as i16) % (Q as i16));
    }
    let mut shares = Vec::with_capacity(n);
    for i in 1..=n {
        let x = i as i16;
        let mut y = 0i16;
        for c in coeffs.iter().rev() {
            y = add_mod(mul_mod(y, x), *c);
        }
        shares.push(ScalarShare { id: i as u32, value: y });
    }
    shares
}

/// Lagrange interpolation at x=0 to recover the secret.
pub fn recombine_scalar(shares: &[ScalarShare]) -> i16 {
    let mut secret = 0i16;
    for (i, &ScalarShare { id: x_i, value: y_i }) in shares.iter().enumerate() {
        let mut num = 1i16;
        let mut den = 1i16;
        for (j, &ScalarShare { id: x_j, .. }) in shares.iter().enumerate() {
            if i == j { continue; }
            num = mul_mod(num, sub_mod(0, x_j as i16));
            den = mul_mod(den, sub_mod(x_i as i16, x_j as i16));
        }
        let lambda = mul_mod(num, mod_inverse(den));
        secret = add_mod(secret, mul_mod(y_i, lambda));
    }
    secret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_roundtrip() {
        let secret = 1234i16;
        let shares = split_scalar(secret, 3, 5);
        for subset in shares.windows(3) {
            let rec = recombine_scalar(subset);
            assert_eq!(rec, secret, "3-of-5 reconstruction failed");
        }
    }

    #[test]
    fn test_shamir_too_few_fails() {
        let secret = 1234i16;
        let shares = split_scalar(secret, 3, 5);
        let rec = recombine_scalar(&shares[0..2]);
        // With 2 shares and degree-2 polynomial, result is random
        assert_ne!(rec, secret);
    }
}
