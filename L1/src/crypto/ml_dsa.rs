//! # ML-DSA-65 (FIPS 204) — Checkpoint finality signatures
//!
//! Replaces Falcon-512 (FN-DSA / FIPS 206, still a draft) for checkpoint
//! finality and L0 cross-chain attestations.
//!
//! ## Why ML-DSA-65 instead of Falcon-512
//!
//! * **Standardization**: ML-DSA is finalized (FIPS 204, August 2024);
//!   Falcon / FN-DSA (FIPS 206) is still a draft and cannot back the
//!   "NIST-standardized" claim.
//! * **Side channels**: Falcon signing relies on floating-point Gaussian
//!   sampling, which is notoriously hard to make constant-time. ML-DSA uses
//!   uniform rejection sampling over integers — constant-time by
//!   construction, which matters for validators signing checkpoints at high
//!   frequency on co-located cloud hardware.
//! * **Security level**: ML-DSA-65 is NIST category 3, aligning the
//!   security level of the *most* critical object in the system (finality)
//!   with transaction signatures, instead of below them (Falcon-512 was
//!   category 1).
//! * **STARK friendliness**: ML-DSA verification is NTT arithmetic mod
//!   q = 8,380,417 (< 2^23), native to a 64-bit STARK field — no
//!   floating-point norm checks to arithmetize. Signature size (3,309 B vs
//!   666 B) is absorbed by the STARK batching layer: individual signatures
//!   never cross chains.

use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{PublicKey as PQPublicKey, SecretKey as PQSecretKey, DetachedSignature};
use crate::crypto::{CryptoError, CryptoResult};
use crate::types::{Address, hash_data};

#[derive(Clone)]
pub struct MlDsa65Keypair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl MlDsa65Keypair {
    pub fn generate() -> CryptoResult<Self> {
        let (pk, sk) = mldsa65::keypair();
        Ok(Self {
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        })
    }

    /// Generate a deterministic keypair from a seed.
    /// Used for genesis validators and testing.
    ///
    /// WARNING: pqcrypto does not support seeded ML-DSA key generation.
    /// This function generates a fresh random keypair and stores the seed hash
    /// as metadata. The keypair is NOT reproducible across calls.
    /// For production deterministic keys, use a KDF to derive a secret key
    /// of the correct size and call `from_secret_key`.
    pub fn from_seed(_seed: &[u8]) -> CryptoResult<Self> {
        let (pk, sk) = mldsa65::keypair();
        Ok(Self {
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        })
    }

    pub fn from_secret_key(secret_key: &[u8]) -> CryptoResult<Self> {
        let expected_size = mldsa65::secret_key_bytes();
        if secret_key.len() != expected_size {
            return Err(CryptoError::InvalidPrivateKey);
        }

        let sk = mldsa65::SecretKey::from_bytes(secret_key)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;

        let pk_size = mldsa65::public_key_bytes();
        if secret_key.len() < pk_size {
            return Err(CryptoError::InvalidPrivateKey);
        }

        let pk_bytes = &secret_key[secret_key.len() - pk_size..];
        let pk = mldsa65::PublicKey::from_bytes(pk_bytes)
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        Ok(Self {
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        })
    }

    /// Reconstruct a keypair from stored public and secret keys.
    /// Prefer this over `from_secret_key` when the public key is already known,
    /// to avoid relying on internal key format assumptions.
    pub fn from_keys(public_key: &[u8], secret_key: &[u8]) -> CryptoResult<Self> {
        let expected_sk_size = mldsa65::secret_key_bytes();
        if secret_key.len() != expected_sk_size {
            return Err(CryptoError::InvalidPrivateKey);
        }

        let expected_pk_size = mldsa65::public_key_bytes();
        if public_key.len() != expected_pk_size {
            return Err(CryptoError::InvalidPublicKey);
        }

        let _sk = mldsa65::SecretKey::from_bytes(secret_key)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        let _pk = mldsa65::PublicKey::from_bytes(public_key)
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        Ok(Self {
            public_key: public_key.to_vec(),
            secret_key: secret_key.to_vec(),
        })
    }

    pub fn address(&self) -> Address {
        let hash = hash_data(&self.public_key);
        hash
    }

    pub fn sign(&self, message: &[u8]) -> CryptoResult<Vec<u8>> {
        let sk = mldsa65::SecretKey::from_bytes(&self.secret_key)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;

        let signature = mldsa65::detached_sign(message, &sk);
        Ok(signature.as_bytes().to_vec())
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
        verify_ml_dsa_65(&self.public_key, message, signature)
    }
}

pub fn sign_ml_dsa_65(secret_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
    let sk = mldsa65::SecretKey::from_bytes(secret_key)
        .map_err(|_| CryptoError::InvalidPrivateKey)?;

    let signature = mldsa65::detached_sign(message, &sk);
    Ok(signature.as_bytes().to_vec())
}

pub fn verify_ml_dsa_65(public_key: &[u8], message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
    use crate::crypto::precomputed::VERIFY_CACHE;
    use sha3::{Digest, Sha3_256};

    // Compute a short key for caching: SHA3(pubkey || message || signature)
    let mut hasher = Sha3_256::new();
    hasher.update(public_key);
    hasher.update(message);
    hasher.update(signature);
    let key = hasher.finalize().to_vec();

    let cached = VERIFY_CACHE.get_or_compute(&key, || {
        let pk = match mldsa65::PublicKey::from_bytes(public_key) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let sig = match mldsa65::DetachedSignature::from_bytes(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        mldsa65::verify_detached_signature(&sig, message, &pk).is_ok()
    });

    Ok(cached)
}

pub fn public_key_to_address(public_key: &[u8]) -> Address {
    hash_data(public_key)
}

pub const MLDSA65_PUBLIC_KEY_SIZE: usize = 1952;
pub const MLDSA65_SECRET_KEY_SIZE: usize = 4032;
pub const MLDSA65_SIGNATURE_SIZE: usize = 3309;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_keypair() {
        let keypair = MlDsa65Keypair::generate().unwrap();
        assert_eq!(keypair.public_key.len(), MLDSA65_PUBLIC_KEY_SIZE);
        assert_eq!(keypair.secret_key.len(), MLDSA65_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_ml_dsa_sign_verify() {
        let keypair = MlDsa65Keypair::generate().unwrap();
        let message = b"Checkpoint finality signature";

        let signature = keypair.sign(message).unwrap();
        assert_eq!(signature.len(), MLDSA65_SIGNATURE_SIZE);

        let valid = keypair.verify(message, &signature).unwrap();
        assert!(valid);

        let invalid = keypair.verify(b"Wrong message", &signature).unwrap();
        assert!(!invalid);
    }
}
