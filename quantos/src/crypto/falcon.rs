use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{PublicKey as PQPublicKey, SecretKey as PQSecretKey, DetachedSignature};
use crate::crypto::{CryptoError, CryptoResult};

#[derive(Clone)]
pub struct FalconKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl FalconKeypair {
    pub fn generate() -> CryptoResult<Self> {
        let (pk, sk) = falcon512::keypair();
        Ok(Self {
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        })
    }

    pub fn sign(&self, message: &[u8]) -> CryptoResult<Vec<u8>> {
        let sk = falcon512::SecretKey::from_bytes(&self.secret_key)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        
        let signature = falcon512::detached_sign(message, &sk);
        Ok(signature.as_bytes().to_vec())
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
        verify_falcon(&self.public_key, message, signature)
    }
}

pub fn sign_falcon(secret_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
    let sk = falcon512::SecretKey::from_bytes(secret_key)
        .map_err(|_| CryptoError::InvalidPrivateKey)?;
    
    let signature = falcon512::detached_sign(message, &sk);
    Ok(signature.as_bytes().to_vec())
}

pub fn verify_falcon(public_key: &[u8], message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
    let pk = falcon512::PublicKey::from_bytes(public_key)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    
    let sig = falcon512::DetachedSignature::from_bytes(signature)
        .map_err(|_| CryptoError::InvalidSignature)?;
    
    match falcon512::verify_detached_signature(&sig, message, &pk) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub const FALCON512_PUBLIC_KEY_SIZE: usize = 897;
pub const FALCON512_SECRET_KEY_SIZE: usize = 1281;
pub const FALCON512_SIGNATURE_SIZE: usize = 666;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_falcon_keypair() {
        let keypair = FalconKeypair::generate().unwrap();
        assert_eq!(keypair.public_key.len(), FALCON512_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_falcon_sign_verify() {
        let keypair = FalconKeypair::generate().unwrap();
        let message = b"Checkpoint finality signature";
        
        let signature = keypair.sign(message).unwrap();
        assert!(signature.len() <= FALCON512_SIGNATURE_SIZE + 100);
        
        let valid = keypair.verify(message, &signature).unwrap();
        assert!(valid);
    }
}
