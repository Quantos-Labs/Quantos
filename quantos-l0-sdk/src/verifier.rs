use pqcrypto_falcon::falcon512;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

use crate::error::{L0Error, L0Result, VerificationReport, ValidatorSetSnapshot};
use crate::types::{L0FinalityProof, L0_PROOF_VERSION, PqcSignatureAlgo};

pub fn verify_falcon(public_key: &[u8], digest: &[u8], signature: &[u8]) -> Result<bool, L0Error> {
    let pk = falcon512::PublicKey::from_bytes(public_key)
        .map_err(|e| L0Error::Encoding(format!("invalid falcon public key: {e}")))?;
    let sig = falcon512::DetachedSignature::from_bytes(signature)
        .map_err(|e| L0Error::Encoding(format!("invalid falcon signature: {e}")))?;
    Ok(pqcrypto_falcon::falcon512::detached_verify(&sig, digest, &pk).is_ok())
}

pub fn verify_dilithium(public_key: Vec<u8>, digest: Vec<u8>, signature: Vec<u8>) -> bool {
    let Ok(pk) = dilithium3::PublicKey::from_bytes(&public_key) else {
        return false;
    };
    let Ok(sig) = dilithium3::DetachedSignature::from_bytes(&signature) else {
        return false;
    };
    pqcrypto_dilithium::dilithium3::detached_verify(&sig, &digest, &pk).is_ok()
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
            PqcSignatureAlgo::Falcon512 => {
                verify_falcon(&validator.public_key, &digest, &sig.signature).unwrap_or(false)
            }
            PqcSignatureAlgo::Dilithium3 => verify_dilithium(
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
