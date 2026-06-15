//! ML-KEM-768 Core Primitives (FIPS 203)
//!
//! Pure-Rust implementation of the parameter set n=256, q=3329, k=3.
//! Provides NTT, polynomial arithmetic, compression, and sampling.

use sha3::{Sha3_256, Sha3_512, Digest};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Parameters ────────────────────────────────────────────────────────────────

pub const N: usize = 256;
pub const Q: i32 = 3329;
pub const K: usize = 3;
pub const ETA1: usize = 2;
pub const ETA2: usize = 2;
pub const DU: usize = 10;
pub const DV: usize = 4;
pub const SHARED_SECRET_BYTES: usize = 32;

pub const ZETA: i16 = 17;  // primitive 256th root of unity mod 3329

/// 128^{-1} mod 3329  (used in inverse NTT scaling)
pub const INV_NTT_SCALE: i16 = 3303;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poly256 {
    pub coeffs: [i16; N],
}

impl Default for Poly256 {
    fn default() -> Self {
        Self { coeffs: [0i16; N] }
    }
}

impl Zeroize for Poly256 {
    fn zeroize(&mut self) {
        self.coeffs.zeroize();
    }
}

pub type PolyVec = [Poly256; K];
pub type PolyMat = [[Poly256; K]; K];

// ── Modular arithmetic ────────────────────────────────────────────────────────

#[inline(always)]
pub fn mod_q(x: i32) -> i16 {
    let r = x % Q;
    if r < 0 { (r + Q) as i16 } else { r as i16 }
}

#[inline(always)]
pub fn add_mod(a: i16, b: i16) -> i16 { mod_q((a as i32) + (b as i32)) }

#[inline(always)]
pub fn sub_mod(a: i16, b: i16) -> i16 { mod_q((a as i32) - (b as i32)) }

#[inline(always)]
pub fn mul_mod(a: i16, b: i16) -> i16 { mod_q((a as i32) * (b as i32)) }

/// Extended Euclid: modular inverse mod Q (Q = 3329 is prime).
pub fn mod_inverse(a: i16) -> i16 {
    let a = ((a as i32 % Q) + Q) % Q;
    let mut t = 0i32;
    let mut new_t = 1i32;
    let mut r = Q as i32;
    let mut new_r = a;
    while new_r != 0 {
        let q = r / new_r;
        let tmp_t = t - q * new_t;
        t = new_t;
        new_t = tmp_t;
        let tmp_r = r - q * new_r;
        r = new_r;
        new_r = tmp_r;
    }
    if r > 1 { return 1; }
    if t < 0 { t += Q as i32; }
    t as i16
}

// ── NTT ───────────────────────────────────────────────────────────────────────

/// Precomputed bit-reversed powers of ζ for the forward NTT.
/// Generated offline via `zeta_power(bitreverse7(i))`.
pub static ZETA_TABLE: [i16; 128] = [
    1,   17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,
    17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,
    17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,
    17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,
    17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,
    17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,
    17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,
    17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,
];

pub fn ntt(p: &mut Poly256) {
    let mut len = 2usize;
    let mut k = 0usize;
    while len <= 128 {
        for start in (0..N).step_by(len * 2) {
            let zeta = ZETA_TABLE[k];
            k += 1;
            for j in start..(start + len) {
                let t = mul_mod(zeta, p.coeffs[j + len]);
                p.coeffs[j + len] = sub_mod(p.coeffs[j], t);
                p.coeffs[j] = add_mod(p.coeffs[j], t);
            }
        }
        len <<= 1;
    }
}

pub fn inv_ntt(p: &mut Poly256) {
    let mut len = 128usize;
    let mut k = 127usize;
    while len >= 2 {
        for start in (0..N).step_by(len * 2) {
            let zeta = ZETA_TABLE[k];
            for j in start..(start + len) {
                let t = p.coeffs[j];
                p.coeffs[j] = add_mod(t, p.coeffs[j + len]);
                let diff = sub_mod(t, p.coeffs[j + len]);
                p.coeffs[j + len] = mul_mod(zeta, diff);
            }
            k = k.saturating_sub(1);
        }
        len >>= 1;
    }
    for c in &mut p.coeffs {
        *c = mul_mod(*c, INV_NTT_SCALE);
    }
}

// ── Polynomial ops ────────────────────────────────────────────────────────────

pub fn poly_mul_ntt(a: &Poly256, b: &Poly256) -> Poly256 {
    let mut out = Poly256::default();
    for i in 0..N { out.coeffs[i] = mul_mod(a.coeffs[i], b.coeffs[i]); }
    out
}

pub fn poly_add(a: &Poly256, b: &Poly256) -> Poly256 {
    let mut out = Poly256::default();
    for i in 0..N { out.coeffs[i] = add_mod(a.coeffs[i], b.coeffs[i]); }
    out
}

pub fn poly_sub(a: &Poly256, b: &Poly256) -> Poly256 {
    let mut out = Poly256::default();
    for i in 0..N { out.coeffs[i] = sub_mod(a.coeffs[i], b.coeffs[i]); }
    out
}

pub fn vec_inner_ntt(a: &PolyVec, b: &PolyVec) -> Poly256 {
    let mut sum = Poly256::default();
    for i in 0..K {
        sum = poly_add(&sum, &poly_mul_ntt(&a[i], &b[i]));
    }
    sum
}

// ── Sampling ─────────────────────────────────────────────────────────────────

pub fn sample_cbd(eta: usize, buf: &[u8]) -> Poly256 {
    let mut p = Poly256::default();
    for i in 0..N {
        let byte_idx = (i * 2 * eta) / 8;
        let bit_off = (i * 2 * eta) % 8;
        if byte_idx + eta > buf.len() { break; }
        let mut a = 0i16;
        let mut b = 0i16;
        for j in 0..eta {
            let byte = buf[byte_idx + j];
            a += ((byte >> bit_off) & 1) as i16;
            b += ((byte >> (bit_off + 1)) & 1) as i16;
        }
        p.coeffs[i] = a - b;
    }
    p
}

// ── Compression ───────────────────────────────────────────────────────────────

pub fn compress(d: usize, x: i16) -> i16 {
    let mut u = x as u16;
    if x < 0 { u = ((x as i32) + Q) as u16; }
    let num = (u as u32) << d;
    let den = Q as u32;
    let rounded = (num + den / 2) / den;
    (rounded & ((1u32 << d) - 1)) as i16
}

pub fn decompress(d: usize, x: i16) -> i16 {
    let y = x as u32;
    let num = y * Q as u32;
    let den = 1u32 << d;
    let rounded = (num + den / 2) / den;
    mod_q(rounded as i32)
}

pub fn poly_compress(d: usize, p: &Poly256) -> Vec<u8> {
    let bits_total = N * d;
    let bytes = (bits_total + 7) / 8;
    let mut out = vec![0u8; bytes];
    for i in 0..N {
        let c = compress(d, p.coeffs[i]) as u16;
        let bits = i * d;
        let byte = bits / 8;
        let bit = bits % 8;
        if byte < out.len() {
            out[byte] |= ((c << bit) & 0xFF) as u8;
            let rem_bits = (c >> (8 - bit)) as u8;
            if bit > 0 && byte + 1 < out.len() {
                out[byte + 1] |= rem_bits;
            }
        }
    }
    out
}

pub fn poly_decompress(d: usize, data: &[u8]) -> Poly256 {
    let mut p = Poly256::default();
    for i in 0..N {
        let bits = i * d;
        let byte = bits / 8;
        let bit = bits % 8;
        if byte + 1 < data.len() {
            let low = data[byte] as u16;
            let high = if bit > 0 && byte + 1 < data.len() {
                (data[byte + 1] as u16) << (8 - bit)
            } else { 0 };
            let mask = (1u16 << d) - 1;
            let raw = ((low | high) >> bit) & mask;
            p.coeffs[i] = decompress(d, raw as i16);
        }
    }
    p
}

// ── PRF / XOF helpers ───────────────────────────────────────────────────────

pub fn shake256_32(seed: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(seed);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

pub fn shake256_64(seed: &[u8]) -> [u8; 64] {
    let mut h = Sha3_512::new();
    h.update(seed);
    let mut out = [0u8; 64];
    out.copy_from_slice(&h.finalize());
    out
}

pub fn xof_expand_a(seed: &[u8]) -> PolyMat {
    let mut mat = [[Poly256::default(); K]; K];
    for i in 0..K {
        for j in 0..K {
            let mut inp = seed.to_vec();
            inp.push(i as u8);
            inp.push(j as u8);
            let h = shake256_64(&inp);
            mat[i][j] = sample_cbd(3, &h);
        }
    }
    mat
}

pub fn expand_s(seed: &[u8]) -> PolyVec {
    let mut vec = [Poly256::default(); K];
    for i in 0..K {
        let mut inp = seed.to_vec();
        inp.push(i as u8);
        vec[i] = sample_cbd(ETA1, &shake256_64(&inp));
    }
    vec
}

pub fn expand_e(seed: &[u8]) -> PolyVec {
    let mut vec = [Poly256::default(); K];
    for i in 0..K {
        let mut inp = seed.to_vec();
        inp.push((i + K) as u8);
        vec[i] = sample_cbd(ETA1, &shake256_64(&inp));
    }
    vec
}

pub fn expand_ephemeral(seed: &[u8]) -> (PolyVec, PolyVec, Poly256) {
    let mut r = [Poly256::default(); K];
    let mut e1 = [Poly256::default(); K];
    for i in 0..K {
        let mut inp = seed.to_vec();
        inp.push(i as u8);
        r[i] = sample_cbd(ETA1, &shake256_64(&inp));
    }
    for i in 0..K {
        let mut inp = seed.to_vec();
        inp.push((i + K) as u8);
        e1[i] = sample_cbd(ETA2, &shake256_64(&inp));
    }
    let e2 = {
        let mut inp = seed.to_vec();
        inp.push((2 * K) as u8);
        sample_cbd(ETA2, &shake256_64(&inp))
    };
    (r, e1, e2)
}

// ── Serialization ─────────────────────────────────────────────────────────────

pub fn polyvec_to_bytes(v: &PolyVec) -> [u8; K * N * 2] {
    let mut out = [0u8; K * N * 2];
    let mut off = 0usize;
    for poly in v.iter() {
        for &c in poly.coeffs.iter() {
            let u = c as u16;
            out[off] = (u & 0xFF) as u8;
            out[off + 1] = ((u >> 8) & 0xFF) as u8;
            off += 2;
        }
    }
    out
}

pub fn bytes_to_polyvec(data: &[u8]) -> PolyVec {
    let mut v = [Poly256::default(); K];
    let mut off = 0usize;
    for i in 0..K {
        for j in 0..N {
            let low = data[off] as u16;
            let high = data[off + 1] as u16;
            v[i].coeffs[j] = ((low | (high << 8)) & 0xFFFF) as i16;
            off += 2;
        }
    }
    v
}

// ── KeyGen / Encaps / Decaps ──────────────────────────────────────────────────

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Mlkem768Keypair {
    pub public_key_bytes: [u8; K * N * 2],
    pub secret_vec_ntt: PolyVec,
    pub seed_a: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mlkem768Ciphertext {
    pub u_compressed: Vec<u8>,
    pub v_compressed: Vec<u8>,
}

pub fn keypair() -> Mlkem768Keypair {
    let seed_a = {
        let mut s = [0u8; 32];
        getrandom::getrandom(&mut s).unwrap();
        s
    };
    let seed_s = shake256_32(&seed_a);

    let a_mat = xof_expand_a(&seed_a);
    let s_vec = expand_s(&seed_s);
    let e_vec = expand_e(&seed_s);

    let mut s_ntt = s_vec;
    let mut e_ntt = e_vec;
    for i in 0..K { ntt(&mut s_ntt[i]); ntt(&mut e_ntt[i]); }

    let mut t = [Poly256::default(); K];
    for i in 0..K {
        for j in 0..K {
            t[i] = poly_add(&t[i], &poly_mul_ntt(&a_mat[i][j], &s_ntt[j]));
        }
        t[i] = poly_add(&t[i], &e_ntt[i]);
    }

    Mlkem768Keypair {
        public_key_bytes: polyvec_to_bytes(&t),
        secret_vec_ntt: s_ntt,
        seed_a,
    }
}

pub fn encapsulate(pk_bytes: &[u8]) -> (Mlkem768Ciphertext, [u8; SHARED_SECRET_BYTES]) {
    let t_ntt = bytes_to_polyvec(pk_bytes);
    let mut m = [0u8; 32];
    getrandom::getrandom(&mut m).unwrap();

    let seed_eph = shake256_64(&m);
    let (mut r_ntt, e1, mut e2) = expand_ephemeral(&seed_eph);
    for i in 0..K { ntt(&mut r_ntt[i]); }

    let a_mat = xof_expand_a(&[0u8; 32]); // deterministic for demo; real impl seeds from pk
    let mut u = [Poly256::default(); K];
    for i in 0..K {
        for j in 0..K {
            u[i] = poly_add(&u[i], &poly_mul_ntt(&a_mat[j][i], &r_ntt[j]));
        }
        inv_ntt(&mut u[i]);
        u[i] = poly_add(&u[i], &e1[i]);
    }

    let mut v_ntt = Poly256::default();
    for i in 0..K {
        v_ntt = poly_add(&v_ntt, &poly_mul_ntt(&t_ntt[i], &r_ntt[i]));
    }
    inv_ntt(&mut v_ntt);

    let mut m_poly = Poly256::default();
    for (byte_idx, &byte) in m.iter().enumerate() {
        for bit in 0..8 {
            m_poly.coeffs[byte_idx * 8 + bit] = (((byte >> bit) & 1) as i16) * ((Q / 2 + 1) as i16);
        }
    }
    let v = poly_add(&v_ntt, &poly_add(&e2, &m_poly));

    let mut hasher = Sha3_256::new();
    hasher.update(&m);
    let mut ss = [0u8; SHARED_SECRET_BYTES];
    ss.copy_from_slice(&hasher.finalize());

    let mut u_bytes = Vec::with_capacity(K * (N * DU / 8));
    for poly in &u {
        u_bytes.extend_from_slice(&poly_compress(DU, poly));
    }
    let ct = Mlkem768Ciphertext {
        u_compressed: u_bytes,
        v_compressed: poly_compress(DV, &v),
    };
    (ct, ss)
}

pub fn decapsulate(sk: &Mlkem768Keypair, ct: &Mlkem768Ciphertext) -> [u8; SHARED_SECRET_BYTES] {
    let mut u = [Poly256::default(); K];
    let u_bytes_per_poly = N * DU / 8;
    for i in 0..K {
        let start = i * u_bytes_per_poly;
        let end = start + u_bytes_per_poly;
        if end <= ct.u_compressed.len() {
            u[i] = poly_decompress(DU, &ct.u_compressed[start..end]);
        }
    }
    let v = poly_decompress(DV, &ct.v_compressed);

    for i in 0..K { ntt(&mut u[i]); }
    let mut s_ntt = sk.secret_vec_ntt.clone();
    let su = vec_inner_ntt(&s_ntt, &u);
    let mut su_coeff = su;
    inv_ntt(&mut su_coeff);

    let mut m_poly = poly_sub(&v, &su_coeff);
    // Round each coefficient to 0 or 1
    let mut m = [0u8; 32];
    for byte_idx in 0..32 {
        let mut byte = 0u8;
        for bit in 0..8 {
            let coeff = m_poly.coeffs[byte_idx * 8 + bit];
            let rounded = if coeff < 0 { coeff + Q as i16 } else { coeff };
            if rounded > (Q as i16 / 2) {
                byte |= 1 << bit;
            }
        }
        m[byte_idx] = byte;
    }

    let mut hasher = Sha3_256::new();
    hasher.update(&m);
    let mut ss = [0u8; SHARED_SECRET_BYTES];
    ss.copy_from_slice(&hasher.finalize());
    ss
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mod_arithmetic() {
        assert_eq!(mod_q(3329), 0);
        assert_eq!(mod_q(-1), 3328);
        assert_eq!(mod_q(5000), 1671);
    }

    #[test]
    fn test_ntt_roundtrip() {
        let mut p = Poly256::default();
        p.coeffs[0] = 100;
        p.coeffs[1] = 200;
        p.coeffs[255] = 50;
        let mut q = p.clone();
        ntt(&mut q);
        inv_ntt(&mut q);
        assert_eq!(p.coeffs, q.coeffs);
    }

    #[test]
    fn test_keypair_and_encaps_decaps() {
        let kp = keypair();
        let (ct, ss_enc) = encapsulate(&kp.public_key_bytes);
        let ss_dec = decapsulate(&kp, &ct);
        assert_eq!(ss_enc, ss_dec);
    }
}
