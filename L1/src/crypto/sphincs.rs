use pqcrypto_sphincsplus::sphincsshake128fsimple as sphincs;
use pqcrypto_traits::sign::{PublicKey as PQPublicKey, SecretKey as PQSecretKey, DetachedSignature};
use crate::crypto::{CryptoError, CryptoResult};

#[derive(Clone)]
pub struct SphincsKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl SphincsKeypair {
    pub fn generate() -> CryptoResult<Self> {
        let (pk, sk) = sphincs::keypair();
        Ok(Self {
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        })
    }

    pub fn from_keys(public_key: Vec<u8>, secret_key: Vec<u8>) -> CryptoResult<Self> {
        if public_key.len() != sphincs::public_key_bytes() {
            return Err(CryptoError::InvalidPublicKey);
        }
        if secret_key.len() != sphincs::secret_key_bytes() {
            return Err(CryptoError::InvalidPrivateKey);
        }
        // Validate that both keys parse correctly.
        let _ = sphincs::PublicKey::from_bytes(&public_key)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        let _ = sphincs::SecretKey::from_bytes(&secret_key)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        Ok(Self { public_key, secret_key })
    }

    pub fn sign(&self, message: &[u8]) -> CryptoResult<Vec<u8>> {
        let sk = sphincs::SecretKey::from_bytes(&self.secret_key)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        
        let signature = sphincs::detached_sign(message, &sk);
        Ok(signature.as_bytes().to_vec())
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
        verify_sphincs(&self.public_key, message, signature)
    }
}

pub fn sign_sphincs(secret_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
    let sk = sphincs::SecretKey::from_bytes(secret_key)
        .map_err(|_| CryptoError::InvalidPrivateKey)?;
    
    let signature = sphincs::detached_sign(message, &sk);
    Ok(signature.as_bytes().to_vec())
}

pub fn verify_sphincs(public_key: &[u8], message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
    let pk = sphincs::PublicKey::from_bytes(public_key)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    
    let sig = sphincs::DetachedSignature::from_bytes(signature)
        .map_err(|_| CryptoError::InvalidSignature)?;
    
    match sphincs::verify_detached_signature(&sig, message, &pk) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub const SPHINCS_PUBLIC_KEY_SIZE: usize = 32;
pub const SPHINCS_SECRET_KEY_SIZE: usize = 64;
pub const SPHINCS_SIGNATURE_SIZE: usize = 17088;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sphincs_keypair() {
        let keypair = SphincsKeypair::generate().unwrap();
        assert!(!keypair.public_key.is_empty());
        assert!(!keypair.secret_key.is_empty());
    }

    #[test]
    fn test_sphincs_sign_verify() {
        let keypair = SphincsKeypair::generate().unwrap();
        let message = b"VRF seed for committee selection";
        
        let signature = keypair.sign(message).unwrap();
        let valid = keypair.verify(message, &signature).unwrap();
        assert!(valid);
    }
}
