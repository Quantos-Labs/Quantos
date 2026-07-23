// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! AEAD transport using AES-256-GCM.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::crypto::{CryptoError, CryptoResult};

/// Plaintext cap per frame (after decryption).
pub const MAX_FRAME_PLAINTEXT: usize = 12 * 1024 * 1024;

pub struct SessionEncrypt {
    cipher: Aes256Gcm,
    counter: u64,
    nonce_tag: u8,
}

pub struct SessionDecrypt {
    cipher: Aes256Gcm,
}

impl SessionEncrypt {
    pub fn new(key: &[u8; 32], nonce_tag: u8) -> CryptoResult<Self> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidPrivateKey)?;
        Ok(Self {
            cipher,
            counter: 0,
            nonce_tag,
        })
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        if plaintext.len() > MAX_FRAME_PLAINTEXT {
            return Err(CryptoError::HashError("frame too large".into()));
        }
        let c = self.counter;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| CryptoError::HashError("encrypt nonce exhausted".into()))?;
        let mut raw = [0u8; 12];
        raw[0] = self.nonce_tag;
        raw[4..12].copy_from_slice(&c.to_le_bytes());
        let nonce = Nonce::from_slice(&raw);
        let ct = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::HashError("AEAD encrypt failed".into()))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&raw);
        out.extend_from_slice(&ct);
        Ok(out)
    }
}

impl SessionDecrypt {
    pub fn new(key: &[u8; 32]) -> CryptoResult<Self> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidPrivateKey)?;
        Ok(Self { cipher })
    }

    pub fn open(&self, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        if ciphertext.len() < 12 + 16 {
            return Err(CryptoError::HashError("truncated AEAD frame".into()));
        }
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        self.cipher
            .decrypt(nonce, ciphertext[12..].as_ref())
            .map_err(|_| CryptoError::HashError("AEAD decrypt failed".into()))
    }
}
