// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Confidential L0 Cross-Chain Payload
//!
//! The L0 Finality Hub attests that a state was finalized on a chain. By
//! default the attested message (amount, parties, memo) travels in clear inside
//! the proof body. This module lets the **message content** be confidential
//! while keeping the **finality proof publicly verifiable**:
//!
//! - The payload (amount, sender, recipient, memo) is encrypted toward the
//!   destination-chain recipient with **ML-KEM-768** + AES-256-GCM.
//! - Only a 32-byte `payload_commitment = H(DOMAIN ‖ payload ‖ blinding)` is
//!   bound into the L0 proof's `state_root`. Any verifier confirms the
//!   commitment was finalized (via the existing PQC/STARK finality machinery)
//!   without learning what was transferred.
//! - The destination recipient decrypts the payload off-chain and checks it
//!   opens to the finalized commitment.
//!
//! This changes *what* is attested, not *how* finality is proven: the L0 hub's
//! signature/STARK aggregation and the directional-finality trust model are
//! untouched.

use serde::{Deserialize, Serialize};

use crate::crypto::{derive_channel_key, KemKeypair};
use crate::types::{hash_data, Hash};

use super::{aead_open, aead_seal, PrivacyError, DOMAIN_CONF_L0};

/// A sealed cross-chain payload plus the public commitment that the L0 proof
/// finalizes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfidentialL0Payload {
    /// Public commitment finalized inside the L0 proof's `state_root`.
    pub payload_commitment: Hash,
    /// ML-KEM-768 ciphertext encapsulating the payload-encryption secret.
    pub ephemeral_ciphertext: Vec<u8>,
    /// AES-256-GCM ciphertext of the cross-chain message content.
    pub encrypted_payload: Vec<u8>,
}

/// Commits to a payload: `H(DOMAIN_CONF_L0 ‖ payload ‖ blinding)`.
pub fn commit_payload(payload: &[u8], blinding: &Hash) -> Hash {
    let mut data = Vec::with_capacity(DOMAIN_CONF_L0.len() + payload.len() + 32);
    data.extend_from_slice(DOMAIN_CONF_L0);
    data.extend_from_slice(payload);
    data.extend_from_slice(blinding);
    hash_data(&data)
}

impl ConfidentialL0Payload {
    /// Seals a cross-chain `payload` toward `recipient_kem_pk` (the recipient's
    /// ML-KEM public key on the destination chain). Returns the sealed payload
    /// and the blinding factor (kept by the sender to prove the opening).
    pub fn seal(
        recipient_kem_pk: &[u8],
        payload: &[u8],
        blinding: Hash,
    ) -> Result<Self, PrivacyError> {
        let (shared_secret, ephemeral_ciphertext) =
            KemKeypair::encapsulate(recipient_kem_pk).map_err(|e| PrivacyError::Crypto(e.to_string()))?;
        let key = derive_channel_key(&shared_secret, DOMAIN_CONF_L0)
            .map_err(|e| PrivacyError::Crypto(e.to_string()))?;
        let encrypted_payload = aead_seal(&key, payload)?;
        let payload_commitment = commit_payload(payload, &blinding);

        Ok(Self {
            payload_commitment,
            ephemeral_ciphertext,
            encrypted_payload,
        })
    }

    /// Recipient-side: decrypts the payload using the recipient's ML-KEM
    /// keypair, then verifies it opens to `payload_commitment` under `blinding`.
    pub fn open(
        &self,
        recipient: &KemKeypair,
        blinding: &Hash,
    ) -> Result<Vec<u8>, PrivacyError> {
        let shared_secret = recipient
            .decapsulate(&self.ephemeral_ciphertext)
            .map_err(|e| PrivacyError::Crypto(e.to_string()))?;
        let key = derive_channel_key(&shared_secret, DOMAIN_CONF_L0)
            .map_err(|e| PrivacyError::Crypto(e.to_string()))?;
        let payload = aead_open(&key, &self.encrypted_payload)?;

        if commit_payload(&payload, blinding) != self.payload_commitment {
            return Err(PrivacyError::InvalidCommitment);
        }
        Ok(payload)
    }

    /// Verifies that this payload's commitment is the one finalized by an L0
    /// proof, given the proof's `state_root` and the Merkle path of the
    /// commitment within that root. Finality itself is checked separately by
    /// the L0 verifier; this only binds *content* to the finalized root.
    pub fn verify_finalized(&self, state_root: &Hash, merkle_path: &[Hash]) -> bool {
        let mut acc = self.payload_commitment;
        for sibling in merkle_path {
            let mut buf = Vec::with_capacity(64);
            // Canonical ordering: lexicographically smaller node first.
            if acc <= *sibling {
                buf.extend_from_slice(&acc);
                buf.extend_from_slice(sibling);
            } else {
                buf.extend_from_slice(sibling);
                buf.extend_from_slice(&acc);
            }
            acc = hash_data(&buf);
        }
        &acc == state_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_seal_open_roundtrip() {
        let recipient = KemKeypair::generate().unwrap();
        let payload = b"transfer:1000:from=A:to=B";
        let blinding = [5u8; 32];

        let sealed =
            ConfidentialL0Payload::seal(&recipient.public_key, payload, blinding).unwrap();
        let opened = sealed.open(&recipient, &blinding).unwrap();
        assert_eq!(opened, payload);
    }

    #[test]
    fn wrong_blinding_rejected() {
        let recipient = KemKeypair::generate().unwrap();
        let sealed =
            ConfidentialL0Payload::seal(&recipient.public_key, b"x", [1u8; 32]).unwrap();
        assert!(sealed.open(&recipient, &[2u8; 32]).is_err());
    }

    #[test]
    fn commitment_finalized_against_root() {
        let recipient = KemKeypair::generate().unwrap();
        let sealed =
            ConfidentialL0Payload::seal(&recipient.public_key, b"msg", [9u8; 32]).unwrap();
        // Single-leaf tree: the commitment is itself the root.
        assert!(sealed.verify_finalized(&sealed.payload_commitment, &[]));
        assert!(!sealed.verify_finalized(&[0u8; 32], &[]));
    }
}
