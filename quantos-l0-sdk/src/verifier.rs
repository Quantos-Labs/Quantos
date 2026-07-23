// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

use crate::error::{L0Error, L0Result, VerificationReport, ValidatorSetSnapshot};
use crate::types::{L0FinalityProof, L0_PROOF_VERSION, PqcSignatureAlgo};

pub fn verify_ml_dsa_65(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, L0Error> {
    let pk = mldsa65::PublicKey::from_bytes(public_key)
        .map_err(|e| L0Error::Encoding(format!("invalid ML-DSA-65 public key: {e}")))?;
    let sig = mldsa65::DetachedSignature::from_bytes(signature)
        .map_err(|e| L0Error::Encoding(format!("invalid ML-DSA-65 signature: {e}")))?;
    Ok(mldsa65::verify_detached_signature(&sig, message, &pk).is_ok())
}

pub fn verify_proof(
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
    if proof.header.total_stake != snapshot.total_stake() {
        return Err(L0Error::InvalidCheckpoint(
            "total_stake mismatch with snapshot".into(),
        ));
    }

    let message = proof.signed_message();

    let mut signed_stake: u128 = 0;
    let mut valid_signatures = 0usize;
    let mut invalid_signatures = 0usize;

    for sig in &proof.signatures {
        let Some(validator) = proof.validators.get(sig.validator_index as usize) else {
            invalid_signatures += 1;
            continue;
        };

        let ok = match sig.algo {
            PqcSignatureAlgo::MlDsa65 => {
                verify_ml_dsa_65(&validator.public_key, &message, &sig.signature).unwrap_or(false)
            }
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
