//! # PQC Stealth Addresses
//!
//! Breaks the on-chain **sender → recipient graph**. A recipient publishes a
//! long-lived *meta-address* once. Every payment to that recipient lands on a
//! fresh, unlinkable **one-time address** that only the recipient can recognise
//! and spend.
//!
//! Unlike Monero/Ethereum stealth schemes that rely on elliptic-curve
//! Diffie–Hellman (broken by Shor), Quantos derives the shared secret with
//! **ML-KEM-768** ([`crate::crypto::KemKeypair`]) — a NIST-finalized,
//! post-quantum KEM. The construction is therefore safe against
//! harvest-now-decrypt-later linkage attacks.
//!
//! ## Protocol
//!
//! Setup (recipient, once):
//! - generate an ML-KEM *scan* keypair `(scan_pk, scan_sk)`
//! - bind a *spend* authority commitment `spend_pubkey_hash`
//! - publish `meta = { scan_pk, spend_pubkey_hash }`
//!
//! Send (payer, per payment):
//! - `(ss, ct) = MLKEM.Encapsulate(scan_pk)`
//! - `one_time_address = H(DOMAIN_STEALTH ‖ ss ‖ spend_pubkey_hash)`
//! - `view_tag = H(DOMAIN_STEALTH ‖ "VIEWTAG" ‖ ss)[0]`
//! - publish `{ one_time_address, ct, view_tag }`
//!
//! Scan (recipient):
//! - `ss' = MLKEM.Decapsulate(scan_sk, ct)`
//! - fast-reject if `view_tag != H(.. ‖ ss')[0]`
//! - accept iff `one_time_address == H(DOMAIN_STEALTH ‖ ss' ‖ spend_pubkey_hash)`
//!
//! No third party can link two one-time addresses to the same meta-address, and
//! no party other than the recipient learns the shared secret.

use serde::{Deserialize, Serialize};

use crate::crypto::KemKeypair;
use crate::types::{hash_data, Address, Hash};

use super::{PrivacyError, DOMAIN_STEALTH};

/// A recipient's published stealth meta-address.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StealthMetaAddress {
    /// ML-KEM-768 public key used to derive per-payment shared secrets.
    pub scan_public_key: Vec<u8>,
    /// Commitment to the recipient's spend authority (e.g. hash of the
    /// account's ML-DSA spend public key). Bound into every one-time address.
    pub spend_pubkey_hash: Hash,
}

/// The recipient-side secret material for a stealth meta-address.
///
/// Holds the ML-KEM *scan* secret key (used to detect incoming payments). It is
/// intentionally **not** serialisable.
pub struct StealthKeys {
    scan: KemKeypair,
    spend_pubkey_hash: Hash,
}

/// A single stealth payment as broadcast on-chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StealthPayment {
    /// The fresh one-time address the funds are sent to.
    pub one_time_address: Address,
    /// ML-KEM-768 ciphertext encapsulating the per-payment shared secret.
    pub ephemeral_ciphertext: Vec<u8>,
    /// 1-byte view tag enabling fast wallet scanning (rejects ~255/256 of
    /// non-matching payments without a full address recomputation).
    pub view_tag: u8,
}

impl StealthKeys {
    /// Generates fresh scan keys bound to the given spend-authority commitment.
    pub fn generate(spend_pubkey_hash: Hash) -> Result<Self, PrivacyError> {
        let scan = KemKeypair::generate().map_err(|e| PrivacyError::Crypto(e.to_string()))?;
        Ok(Self {
            scan,
            spend_pubkey_hash,
        })
    }

    /// Restores scan keys from persisted ML-KEM material.
    pub fn from_storage(
        scan_public_key: Vec<u8>,
        scan_secret_key: Vec<u8>,
        spend_pubkey_hash: Hash,
    ) -> Result<Self, PrivacyError> {
        let scan = KemKeypair::from_storage(scan_public_key, scan_secret_key)
            .map_err(|e| PrivacyError::Crypto(e.to_string()))?;
        Ok(Self {
            scan,
            spend_pubkey_hash,
        })
    }

    /// The public meta-address to advertise to payers.
    pub fn meta_address(&self) -> StealthMetaAddress {
        StealthMetaAddress {
            scan_public_key: self.scan.public_key.clone(),
            spend_pubkey_hash: self.spend_pubkey_hash,
        }
    }

    /// Scans an on-chain payment. Returns `Some(one_time_address)` when the
    /// payment is destined to this recipient, `None` otherwise.
    pub fn scan_payment(
        &self,
        payment: &StealthPayment,
    ) -> Result<Option<Address>, PrivacyError> {
        let ss = self
            .scan
            .decapsulate(&payment.ephemeral_ciphertext)
            .map_err(|e| PrivacyError::Crypto(e.to_string()))?;

        // Fast path: reject on view-tag mismatch before recomputing the address.
        if view_tag_from_secret(&ss) != payment.view_tag {
            return Ok(None);
        }

        let meta = self.meta_address();
        let derived = derive_one_time_address(&ss, &meta);
        if derived == payment.one_time_address {
            Ok(Some(derived))
        } else {
            Ok(None)
        }
    }

    /// Recovers the shared secret for a payment that was confirmed to belong to
    /// this recipient. Used to derive the note-decryption key.
    pub fn recover_shared_secret(
        &self,
        payment: &StealthPayment,
    ) -> Result<Vec<u8>, PrivacyError> {
        self.scan
            .decapsulate(&payment.ephemeral_ciphertext)
            .map_err(|e| PrivacyError::Crypto(e.to_string()))
    }
}

/// Derives the one-time address from a shared secret and a meta-address.
pub fn derive_one_time_address(shared_secret: &[u8], meta: &StealthMetaAddress) -> Address {
    let mut data = Vec::with_capacity(DOMAIN_STEALTH.len() + shared_secret.len() + 32);
    data.extend_from_slice(DOMAIN_STEALTH);
    data.extend_from_slice(shared_secret);
    data.extend_from_slice(&meta.spend_pubkey_hash);
    hash_data(&data)
}

/// 1-byte view tag derived from a shared secret.
fn view_tag_from_secret(shared_secret: &[u8]) -> u8 {
    let mut data = Vec::with_capacity(DOMAIN_STEALTH.len() + 7 + shared_secret.len());
    data.extend_from_slice(DOMAIN_STEALTH);
    data.extend_from_slice(b"VIEWTAG");
    data.extend_from_slice(shared_secret);
    hash_data(&data)[0]
}

/// Payer-side: creates a stealth payment toward `meta`. Also returns the shared
/// secret so the payer can derive the matching note-encryption key.
pub fn create_stealth_payment(
    meta: &StealthMetaAddress,
) -> Result<(StealthPayment, Vec<u8>), PrivacyError> {
    let (shared_secret, ciphertext) =
        KemKeypair::encapsulate(&meta.scan_public_key).map_err(|e| PrivacyError::Crypto(e.to_string()))?;
    let one_time_address = derive_one_time_address(&shared_secret, meta);
    let view_tag = view_tag_from_secret(&shared_secret);
    Ok((
        StealthPayment {
            one_time_address,
            ephemeral_ciphertext: ciphertext,
            view_tag,
        },
        shared_secret,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_detects_own_payment() {
        let keys = StealthKeys::generate([9u8; 32]).unwrap();
        let meta = keys.meta_address();

        let (payment, payer_ss) = create_stealth_payment(&meta).unwrap();
        let detected = keys.scan_payment(&payment).unwrap();

        assert_eq!(detected, Some(payment.one_time_address));
        // Payer and recipient agree on the shared secret.
        let recipient_ss = keys.recover_shared_secret(&payment).unwrap();
        assert_eq!(payer_ss, recipient_ss);
    }

    #[test]
    fn other_recipient_does_not_detect() {
        let alice = StealthKeys::generate([1u8; 32]).unwrap();
        let bob = StealthKeys::generate([2u8; 32]).unwrap();

        let (payment, _) = create_stealth_payment(&alice.meta_address()).unwrap();
        // Bob scanning Alice's payment must not match.
        assert_eq!(bob.scan_payment(&payment).unwrap(), None);
    }

    #[test]
    fn payments_are_unlinkable() {
        let keys = StealthKeys::generate([5u8; 32]).unwrap();
        let meta = keys.meta_address();
        let (p1, _) = create_stealth_payment(&meta).unwrap();
        let (p2, _) = create_stealth_payment(&meta).unwrap();
        // Two payments to the same recipient yield different one-time addresses.
        assert_ne!(p1.one_time_address, p2.one_time_address);
        assert!(keys.scan_payment(&p1).unwrap().is_some());
        assert!(keys.scan_payment(&p2).unwrap().is_some());
    }
}
