// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use crate::crypto::{
    CryptoResult, MlDsa65Keypair, VRFKeypair,
};
use crate::types::Address;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct ValidatorKeys {
    pub signing_key: MlDsa65Keypair,
    pub vrf_key: VRFKeypair,
    pub finality_key: MlDsa65Keypair,
}

impl ValidatorKeys {
    pub fn generate() -> CryptoResult<Self> {
        Ok(Self {
            signing_key: MlDsa65Keypair::generate()?,
            vrf_key: VRFKeypair::generate()?,
            finality_key: MlDsa65Keypair::generate()?,
        })
    }

    pub fn address(&self) -> Address {
        self.signing_key.address()
    }

    pub fn public_keys(&self) -> ValidatorPublicKeys {
        ValidatorPublicKeys {
            signing_public_key: self.signing_key.public_key.clone(),
            vrf_public_key: self.vrf_key.public_key().to_vec(),
            finality_public_key: self.finality_key.public_key.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorPublicKeys {
    pub signing_public_key: Vec<u8>,
    pub vrf_public_key: Vec<u8>,
    pub finality_public_key: Vec<u8>,
}

pub struct AccountKeypair {
    pub mldsa: MlDsa65Keypair,
}

impl AccountKeypair {
    pub fn generate() -> CryptoResult<Self> {
        Ok(Self {
            mldsa: MlDsa65Keypair::generate()?,
        })
    }

    pub fn address(&self) -> Address {
        self.mldsa.address()
    }

    pub fn public_key(&self) -> &[u8] {
        &self.mldsa.public_key
    }

    pub fn sign(&self, message: &[u8]) -> CryptoResult<Vec<u8>> {
        self.mldsa.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
        self.mldsa.verify(message, signature)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl From<&MlDsa65Keypair> for SerializableKeypair {
    fn from(keypair: &MlDsa65Keypair) -> Self {
        Self {
            public_key: keypair.public_key.clone(),
            secret_key: keypair.secret_key.clone(),
        }
    }
}

impl TryFrom<SerializableKeypair> for MlDsa65Keypair {
    type Error = crate::crypto::CryptoError;

    fn try_from(value: SerializableKeypair) -> Result<Self, Self::Error> {
        Ok(Self {
            public_key: value.public_key,
            secret_key: value.secret_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_keys() {
        let keys = ValidatorKeys::generate().unwrap();
        let address = keys.address();
        assert_eq!(address.len(), 32);
        
        let pub_keys = keys.public_keys();
        assert!(!pub_keys.signing_public_key.is_empty());
        assert!(!pub_keys.vrf_public_key.is_empty());
        assert!(!pub_keys.finality_public_key.is_empty());
    }

    #[test]
    fn test_account_keypair() {
        let keypair = AccountKeypair::generate().unwrap();
        let message = b"Test transaction";
        
        let signature = keypair.sign(message).unwrap();
        let valid = keypair.verify(message, &signature).unwrap();
        assert!(valid);
    }
}
