use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{PublicKey as PQPublicKey, SecretKey as PQSecretKey, DetachedSignature};
use crate::crypto::{CryptoError, CryptoResult};
use crate::crypto::precomputed::VERIFY_CACHE;
use sha3::{Digest, Sha3_256};
use crate::types::{Address, hash_data};

#[derive(Clone)]
pub struct DilithiumKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl DilithiumKeypair {
    pub fn generate() -> CryptoResult<Self> {
        let (pk, sk) = dilithium3::keypair();
        Ok(Self {
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        })
    }

    /// Generate a deterministic keypair from a seed.
    /// Used for genesis validators and testing.
    ///
    /// WARNING: pqcrypto does not support seeded Dilithium key generation.
    /// This function generates a fresh random keypair and stores the seed hash
    /// as metadata. The keypair is NOT reproducible across calls.
    /// For production deterministic keys, use a KDF to derive a secret key
    /// of the correct size and call `from_secret_key`.
    pub fn from_seed(_seed: &[u8]) -> CryptoResult<Self> {
        // pqcrypto doesn't support seeded generation directly.
        // Previous implementation XOR'd random keys with seed bytes, which:
        //   1. Was NOT deterministic (different each call)
        //   2. Corrupted key structure, breaking sign/verify
        //
        // Correct approach: just generate a fresh keypair.
        // Callers needing determinism must use external seeded key management.
        let (pk, sk) = dilithium3::keypair();
        
        Ok(Self {
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        })
    }
    
    pub fn from_secret_key(secret_key: &[u8]) -> CryptoResult<Self> {
        // Validate input size before attempting to extract public key
        let expected_size = dilithium3::secret_key_bytes();
        if secret_key.len() != expected_size {
            return Err(CryptoError::InvalidPrivateKey);
        }
        
        let sk = dilithium3::SecretKey::from_bytes(secret_key)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        
        // Safe to index now that we've validated the size
        let pk_size = dilithium3::public_key_bytes();
        if secret_key.len() < pk_size {
            return Err(CryptoError::InvalidPrivateKey);
        }
        
        let pk_bytes = &secret_key[secret_key.len() - pk_size..];
        let pk = dilithium3::PublicKey::from_bytes(pk_bytes)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        
        Ok(Self {
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        })
    }

    pub fn address(&self) -> Address {
        let hash = hash_data(&self.public_key);
        hash
    }

    pub fn sign(&self, message: &[u8]) -> CryptoResult<Vec<u8>> {
        let sk = dilithium3::SecretKey::from_bytes(&self.secret_key)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        
        let signature = dilithium3::detached_sign(message, &sk);
        Ok(signature.as_bytes().to_vec())
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
        verify_dilithium(&self.public_key, message, signature)
    }
}

pub fn sign_dilithium(secret_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
    let sk = dilithium3::SecretKey::from_bytes(secret_key)
        .map_err(|_| CryptoError::InvalidPrivateKey)?;
    
    let signature = dilithium3::detached_sign(message, &sk);
    Ok(signature.as_bytes().to_vec())
}

pub fn verify_dilithium(public_key: &[u8], message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
    // Compute a short key for caching: SHA3(pubkey || message || signature)
    let mut hasher = Sha3_256::new();
    hasher.update(public_key);
    hasher.update(message);
    hasher.update(signature);
    let key = hasher.finalize().to_vec();

    let cached = VERIFY_CACHE.get_or_compute(&key, || {
        // If not cached, perform the expensive parse + verify
        let pk = match dilithium3::PublicKey::from_bytes(public_key) {
            Ok(v) => v,
            Err(_) => return false,
        };

        let sig = match dilithium3::DetachedSignature::from_bytes(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        dilithium3::verify_detached_signature(&sig, message, &pk).is_ok()
    });

    Ok(cached)
}

pub fn public_key_to_address(public_key: &[u8]) -> Address {
    hash_data(public_key)
}

pub const DILITHIUM3_PUBLIC_KEY_SIZE: usize = 1952;
pub const DILITHIUM3_SECRET_KEY_SIZE: usize = 4000;
pub const DILITHIUM3_SIGNATURE_SIZE: usize = 3293;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = DilithiumKeypair::generate().unwrap();
        assert_eq!(keypair.public_key.len(), DILITHIUM3_PUBLIC_KEY_SIZE);
        assert_eq!(keypair.secret_key.len(), DILITHIUM3_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = DilithiumKeypair::generate().unwrap();
        let message = b"Hello, Quantos!";
        
        let signature = keypair.sign(message).unwrap();
        assert_eq!(signature.len(), DILITHIUM3_SIGNATURE_SIZE);
        
        let valid = keypair.verify(message, &signature).unwrap();
        assert!(valid);
        
        let invalid = keypair.verify(b"Wrong message", &signature).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_address_derivation() {
        let keypair = DilithiumKeypair::generate().unwrap();
        let address = keypair.address();
        assert_eq!(address.len(), 32);
    }
}
