//! External verifier for [`L0FinalityProof`].
//!
//! The verifier is **stateless and self-contained**: given a proof and
//! the validator set snapshot referenced by its header, it returns a
//! [`VerificationReport`] without consulting any external state. This
//! makes the same code reusable inside Quantos, in an off-chain audit
//! tool, or behind a smart-contract / native program on the target chain.

use crate::crypto::{verify_dilithium_batch, verify_falcon};
use crate::l0::error::{L0Error, L0Result};
use crate::l0::hub::ValidatorSetSnapshot;
use crate::l0::proof::{L0FinalityProof, L0_PROOF_VERSION, PqcSignatureAlgo};

/// Outcome of [`ExternalVerifier::verify`].
#[derive(Clone, Debug)]
pub struct VerificationReport {
    /// Stake actually backed by valid signatures.
    pub signed_stake: u128,
    /// Threshold the proof claims to satisfy.
    pub stake_threshold: u128,
    /// Number of signatures whose verification succeeded.
    pub valid_signatures: usize,
    /// Number of signatures whose verification failed.
    pub invalid_signatures: usize,
}

impl VerificationReport {
    /// Returns true when the proof is fully valid and the threshold
    /// has been reached.
    pub fn is_final(&self) -> bool {
        self.invalid_signatures == 0 && self.signed_stake >= self.stake_threshold
    }
}

/// Stateless PQC verifier.
#[derive(Clone, Debug, Default)]
pub struct ExternalVerifier;

impl ExternalVerifier {
    /// Constructs a new verifier. No internal state.
    pub fn new() -> Self {
        Self
    }

    /// Verifies the proof against the validator set snapshot it
    /// references.
    pub fn verify(
        &self,
        proof: &L0FinalityProof,
        snapshot: &ValidatorSetSnapshot,
    ) -> L0Result<VerificationReport> {
        if proof.header.version != L0_PROOF_VERSION {
            return Err(L0Error::UnsupportedVersion(proof.header.version));
        }
        if proof.header.validator_set_root != snapshot.root {
            return Err(L0Error::UnknownValidatorSet(format!(
                "expected {} got {}",
                hex::encode(proof.header.validator_set_root),
                hex::encode(snapshot.root)
            )));
        }
        if proof.validators.len() != snapshot.validators.len() {
            return Err(L0Error::UnknownValidatorSet(
                "validator set length mismatch".into(),
            ));
        }

        // Cheap sanity: total stake recorded must match.
        if proof.header.total_stake != snapshot.total_stake() {
            return Err(L0Error::InvalidCheckpoint(
                "total_stake mismatch with snapshot".into(),
            ));
        }

        let digest = proof.signing_digest();

        let mut signed_stake: u128 = 0;
        let mut valid_signatures = 0usize;
        let mut invalid_signatures = 0usize;

        for sig in &proof.signatures {
            let Some(validator) = proof.validators.get(sig.validator_index as usize) else {
                invalid_signatures += 1;
                continue;
            };

            let ok = match sig.algo {
                PqcSignatureAlgo::Falcon512 => verify_falcon(
                    &validator.public_key,
                    &digest,
                    &sig.signature,
                )
                .unwrap_or(false),
                PqcSignatureAlgo::Dilithium3 => verify_dilithium_batch(
                    validator.public_key.clone(),
                    digest.to_vec(),
                    sig.signature.clone(),
                ),
            };

            if ok {
                valid_signatures += 1;
                signed_stake = signed_stake.saturating_add(validator.stake);
            } else {
                invalid_signatures += 1;
            }
        }

        Ok(VerificationReport {
            signed_stake,
            stake_threshold: proof.header.stake_threshold,
            valid_signatures,
            invalid_signatures,
        })
    }
}
