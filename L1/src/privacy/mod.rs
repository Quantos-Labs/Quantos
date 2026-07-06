//! # Quantos Confidential Mode — Optional Privacy Layer
//!
//! This module adds an **opt-in** privacy layer on top of the transparent
//! Quantos L1. It is disabled by default: existing transparent accounts,
//! balances and transactions keep working exactly as before. When a user (or a
//! dApp) opts in, the following data can be made confidential while remaining
//! publicly *verifiable* via post-quantum zk-STARK proofs:
//!
//! | Confidential surface            | Mechanism                                   | Submodule            |
//! |---------------------------------|---------------------------------------------|----------------------|
//! | Transaction amounts             | Pedersen-style commitments + range proof    | [`shielded_pool`]    |
//! | Account balances                | Note (UTXO) commitments, no plaintext map   | [`shielded_pool`]    |
//! | Sender → recipient graph        | ML-KEM-768 stealth one-time addresses       | [`stealth`]          |
//! | Smart-contract internal state   | Encrypted storage slots + slot commitments  | [`confidential_state`]|
//! | QN token holder registry        | Per-token shielded note set                 | [`confidential_token`]|
//! | L0 cross-chain message content  | Committed/encrypted payload, public finality| [`confidential_l0`]  |
//!
//! The encrypted mempool (front-running protection before ordering) is already
//! provided by the consensus/mempool layer and is therefore *not* re-implemented
//! here; this module composes with it.
//!
//! ## Cryptographic basis
//!
//! - **Post-quantum confidentiality**: note encryption and stealth-address key
//!   agreement use **ML-KEM-768** ([`crate::crypto::KemKeypair`]) with an
//!   HKDF-derived AES-256-GCM channel key. No classical (ECDH) assumption is
//!   used, so the privacy layer is harvest-now-decrypt-later resistant.
//! - **Publicly verifiable correctness**: value conservation, range bounds and
//!   note membership are proven with the existing Winterfell zk-STARK prover
//!   ([`crate::zk::StarkProver`]). STARKs are transparent (no trusted setup) and
//!   plausibly post-quantum, matching the rest of the protocol.
//!
//! ## Honesty note (audit scope)
//!
//! Confidentiality of the *payload* (amounts, balances, parties, slots) is
//! enforced today by commitments + ML-KEM encryption + nullifiers. The
//! zero-knowledge *correctness* circuits reuse the commitment-based STARK
//! aggregation already documented for the L0 hub: balance/range/membership are
//! bound through public commitments verified off-chain. Full in-circuit Keccak
//! AIR binding of the private witness is shared with, and gated by, the same
//! `STARK_PROVES_UNIQUENESS` track as the VRF, and is pending independent audit
//! before the confidential path is placed on the mainnet critical path.

pub mod stealth;
pub mod shielded_pool;
pub mod confidential_state;
pub mod confidential_token;
pub mod confidential_l0;

pub use stealth::*;
pub use shielded_pool::*;
pub use confidential_state::*;
pub use confidential_token::*;
pub use confidential_l0::*;

use serde::{Deserialize, Serialize};

use crate::types::{Hash, hash_data};

// ── Domain separators ───────────────────────────────────────────────────────

/// Domain tag for stealth one-time address derivation.
pub const DOMAIN_STEALTH: &[u8] = b"QUANTOS_PRIVACY_STEALTH_V1";
/// Domain tag for note value encryption key derivation.
pub const DOMAIN_NOTE_ENC: &[u8] = b"QUANTOS_PRIVACY_NOTE_ENC_V1";
/// Domain tag for confidential contract-state slot commitments.
pub const DOMAIN_CONF_STATE: &[u8] = b"QUANTOS_PRIVACY_CONF_STATE_V1";
/// Domain tag for confidential token registry commitments.
pub const DOMAIN_CONF_TOKEN: &[u8] = b"QUANTOS_PRIVACY_CONF_TOKEN_V1";
/// Domain tag for confidential L0 cross-chain payload commitments.
pub const DOMAIN_CONF_L0: &[u8] = b"QUANTOS_PRIVACY_CONF_L0_V1";

// ── Configuration ───────────────────────────────────────────────────────────

/// Per-account / per-transaction privacy selector.
///
/// `Transparent` preserves the classic public Quantos semantics; `Confidential`
/// routes the operation through the shielded pool and commitment machinery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivacyMode {
    /// Public amounts/balances/addresses (default, backwards-compatible).
    Transparent,
    /// Shielded amounts/balances and stealth addressing.
    Confidential,
}

impl Default for PrivacyMode {
    fn default() -> Self {
        PrivacyMode::Transparent
    }
}

/// Node-level configuration for the optional confidential mode.
///
/// All flags default to `false` so that a node that does not opt in behaves
/// identically to a pre-privacy build. Operators enable confidential mode
/// explicitly in production.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// Master switch. When `false`, every privacy entrypoint returns
    /// [`PrivacyError::Disabled`] and the node is fully transparent.
    pub enabled: bool,
    /// Default mode applied to transactions that do not specify one.
    pub default_mode: PrivacyMode,
    /// Hide transfer amounts behind value commitments.
    pub shield_amounts: bool,
    /// Hide balances by representing funds as shielded notes (no plaintext map).
    pub shield_balances: bool,
    /// Hide the sender→recipient graph using ML-KEM stealth one-time addresses.
    pub stealth_addresses: bool,
    /// Allow contracts to keep confidential (encrypted + committed) storage slots.
    pub confidential_contract_state: bool,
    /// Allow QN tokens to keep a shielded holder registry.
    pub confidential_token_registry: bool,
    /// Allow L0 cross-chain messages to carry a confidential payload while the
    /// finality proof stays publicly verifiable.
    pub confidential_l0_payload: bool,
    /// Depth of the note-commitment Merkle tree (number of leaves = 2^depth).
    pub note_tree_depth: u8,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_mode: PrivacyMode::Transparent,
            shield_amounts: false,
            shield_balances: false,
            stealth_addresses: false,
            confidential_contract_state: false,
            confidential_token_registry: false,
            confidential_l0_payload: false,
            note_tree_depth: 32,
        }
    }
}

impl PrivacyConfig {
    /// A configuration with every confidential surface enabled. Useful for
    /// testnets and for opt-in production deployments that want full privacy.
    pub fn all_enabled() -> Self {
        Self {
            enabled: true,
            default_mode: PrivacyMode::Confidential,
            shield_amounts: true,
            shield_balances: true,
            stealth_addresses: true,
            confidential_contract_state: true,
            confidential_token_registry: true,
            confidential_l0_payload: true,
            note_tree_depth: 32,
        }
    }

    /// Returns `Ok(())` if confidential mode is enabled, otherwise
    /// [`PrivacyError::Disabled`].
    pub fn ensure_enabled(&self) -> Result<(), PrivacyError> {
        if self.enabled {
            Ok(())
        } else {
            Err(PrivacyError::Disabled)
        }
    }
}

// ── Errors ──────────────────────────────────────────────────────────────────

/// Errors produced by the confidential-mode subsystem.
#[derive(Debug, thiserror::Error)]
pub enum PrivacyError {
    /// Confidential mode is not enabled in the node configuration.
    #[error("confidential mode is disabled")]
    Disabled,
    /// Underlying post-quantum crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// Underlying zk-STARK operation failed.
    #[error("zk error: {0}")]
    Zk(String),
    /// A nullifier was already present in the spent set (double-spend attempt).
    #[error("nullifier already spent (double-spend)")]
    DoubleSpend,
    /// A referenced note does not exist in the pool.
    #[error("note not found")]
    NoteNotFound,
    /// sum(inputs) != sum(outputs) + fee.
    #[error("value conservation violated")]
    BalanceViolation,
    /// The note-commitment tree is full.
    #[error("note commitment tree is full")]
    TreeFull,
    /// AEAD decryption / authentication failed.
    #[error("decryption failed")]
    DecryptionFailed,
    /// A commitment did not open to the claimed value/blinding.
    #[error("invalid commitment opening")]
    InvalidCommitment,
}

// ── Shared helpers (crate-internal) ──────────────────────────────────────────

/// Computes a binary Merkle root over a list of 32-byte leaves using SHA3-256
/// (the protocol's canonical hash). An odd node is duplicated. Empty input
/// yields the zero hash.
pub(crate) fn merkle_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut buf = Vec::with_capacity(64);
        for chunk in level.chunks(2) {
            buf.clear();
            buf.extend_from_slice(&chunk[0]);
            let right = if chunk.len() > 1 { &chunk[1] } else { &chunk[0] };
            buf.extend_from_slice(right);
            next.push(hash_data(&buf));
        }
        level = next;
    }
    level[0]
}

/// Authenticated encryption (AES-256-GCM) of `plaintext` under `key`.
/// A fresh 12-byte random nonce is prepended to the returned blob.
pub(crate) fn aead_seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, PrivacyError> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use rand::RngCore;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| PrivacyError::Crypto("AEAD seal failed".into()))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Inverse of [`aead_seal`]. Expects a 12-byte nonce prefix.
pub(crate) fn aead_open(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, PrivacyError> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    if data.len() < 12 {
        return Err(PrivacyError::DecryptionFailed);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&data[..12]);
    cipher
        .decrypt(nonce, &data[12..])
        .map_err(|_| PrivacyError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default_is_transparent_and_disabled() {
        let c = PrivacyConfig::default();
        assert!(!c.enabled);
        assert_eq!(c.default_mode, PrivacyMode::Transparent);
        assert!(c.ensure_enabled().is_err());
    }

    #[test]
    fn config_all_enabled_opts_in() {
        let c = PrivacyConfig::all_enabled();
        assert!(c.enabled);
        assert_eq!(c.default_mode, PrivacyMode::Confidential);
        assert!(c.ensure_enabled().is_ok());
    }

    #[test]
    fn aead_roundtrip() {
        let key = [7u8; 32];
        let msg = b"confidential-quantos-note";
        let sealed = aead_seal(&key, msg).unwrap();
        let opened = aead_open(&key, &sealed).unwrap();
        assert_eq!(opened, msg);
    }

    #[test]
    fn aead_wrong_key_fails() {
        let sealed = aead_seal(&[1u8; 32], b"secret").unwrap();
        assert!(aead_open(&[2u8; 32], &sealed).is_err());
    }

    #[test]
    fn merkle_root_stable() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let r1 = merkle_root(&leaves);
        let r2 = merkle_root(&leaves);
        assert_eq!(r1, r2);
        assert_ne!(r1, [0u8; 32]);
        assert_eq!(merkle_root(&[]), [0u8; 32]);
    }
}
