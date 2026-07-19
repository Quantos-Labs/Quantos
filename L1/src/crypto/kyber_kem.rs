//! Kyber768 ML-KEM for Quantos P2P session keys (NIST-aligned PQ-KEM via PQClean).
//!
//! Pair with ML-DSA-65 signatures over [`crate::crypto::DOMAIN_PQ_KEM_HANDSHAKE`] transcripts.

use hkdf::Hkdf;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
    SharedSecret as KemSharedSecret,
};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::{domains::DOMAIN_PQ_KEM_HANDSHAKE, with_domain, CryptoError, CryptoResult};

/// Kyber768 keypair for encapsulating shared secrets toward peers.
#[derive(Clone)]
pub struct KemKeypair {
    pub public_key: Vec<u8>,
    secret_key: Zeroizing<Vec<u8>>,
}

impl KemKeypair {
    pub fn generate() -> CryptoResult<Self> {
        let (pk, sk) = kyber768::keypair();
        Ok(Self {
            public_key: pk.as_bytes().to_vec(),
            secret_key: Zeroizing::new(sk.as_bytes().to_vec()),
        })
    }

    /// Restore Kyber768 keys from persisted material (public + secret).
    pub fn from_storage(public_key: Vec<u8>, secret_key: Vec<u8>) -> CryptoResult<Self> {
        if public_key.len() != kyber768::public_key_bytes()
            || secret_key.len() != kyber768::secret_key_bytes()
        {
            return Err(CryptoError::InvalidPrivateKey);
        }
        let _ = kyber768::PublicKey::from_bytes(&public_key).map_err(|_| CryptoError::InvalidPublicKey)?;
        let _ = kyber768::SecretKey::from_bytes(&secret_key).map_err(|_| CryptoError::InvalidPrivateKey)?;
        Ok(Self {
            public_key,
            secret_key: Zeroizing::new(secret_key),
        })
    }

    pub fn public_key_slice(&self) -> &[u8] {
        &self.public_key
    }

    pub fn secret_key_slice(&self) -> &[u8] {
        self.secret_key.as_slice()
    }

    /// Encapsulate to a peer's Kyber768 public key: returns `(shared_secret, ciphertext)`.
    pub fn encapsulate(peer_kem_pk: &[u8]) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        let pk =
            kyber768::PublicKey::from_bytes(peer_kem_pk).map_err(|_| CryptoError::InvalidPublicKey)?;
        let (ss, ct) = kyber768::encapsulate(&pk);
        Ok((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()))
    }

    /// Decapsulate a ciphertext sent to this node.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        let sk = kyber768::SecretKey::from_bytes(self.secret_key.as_slice())
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        let ct =
            kyber768::Ciphertext::from_bytes(ciphertext).map_err(|_| CryptoError::InvalidKemCiphertext)?;
        let ss = kyber768::decapsulate(&ct, &sk);
        Ok(ss.as_bytes().to_vec())
    }
}

/// Canonical handshake transcript bound into ML-DSA-65 signatures.
///
/// `role`: `0` = initiator, `1` = responder (explicit ordering prevents symmetric ambiguity).
pub fn kem_handshake_transcript(
    role: u8,
    initiator_mldsa_pk: &[u8],
    responder_mldsa_pk: &[u8],
    initiator_kem_pk: &[u8],
    responder_kem_pk: &[u8],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        1 + initiator_mldsa_pk.len()
            + responder_mldsa_pk.len()
            + initiator_kem_pk.len()
            + responder_kem_pk.len()
            + ciphertext.len(),
    );
    msg.push(role);
    msg.extend_from_slice(initiator_mldsa_pk);
    msg.extend_from_slice(responder_mldsa_pk);
    msg.extend_from_slice(initiator_kem_pk);
    msg.extend_from_slice(responder_kem_pk);
    msg.extend_from_slice(ciphertext);
    with_domain(DOMAIN_PQ_KEM_HANDSHAKE, &msg)
}

/// Derive a 256-bit symmetric key from a Kyber shared secret for AEAD (AES-GCM, etc.).
pub fn derive_channel_key(shared_secret: &[u8], transcript: &[u8]) -> CryptoResult<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(DOMAIN_PQ_KEM_HANDSHAKE), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(transcript, &mut okm)
        .map_err(|_| CryptoError::HashError("HKDF expand failed".into()))?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kyber768_roundtrip() {
        let bob = KemKeypair::generate().unwrap();
        let (ss_a, ct) = KemKeypair::encapsulate(&bob.public_key).unwrap();
        let ss_b = bob.decapsulate(&ct).unwrap();
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn derive_channel_key_deterministic() {
        let bob = KemKeypair::generate().unwrap();
        let (ss, ct) = KemKeypair::encapsulate(&bob.public_key).unwrap();
        let t = kem_handshake_transcript(0, b"pk_i", b"pk_r", b"kem_i", b"kem_r", &ct);
        let k1 = derive_channel_key(&ss, &t).unwrap();
        let k2 = derive_channel_key(&ss, &t).unwrap();
        assert_eq!(k1, k2);
    }
}
