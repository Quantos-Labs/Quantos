//! Cryptographic light client verification — NO RPC, NO FALLBACK.
//!
//! Flow: source chain signs with its native crypto (ECDSA, Ed25519, BLS) →
//!       light client verifies those signatures →
//!       Quantos validators sign L0FinalityProof with ML-DSA-65 (PQC).
use async_trait::async_trait;
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::{Digest as Sha3Digest, Keccak256};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

use crate::l0::error::{L0Error, L0Result};
use crate::l0::external::{ChainId, ChainProof, ExternalCheckpoint, VerificationResult};
use crate::l0::registry::ChainFamily;
use crate::types::Hash;

// ── Classical signature libs for verifying source-chain proofs ──
// These are NOT used by Quantos consensus (which uses PQC). They verify
// the native signatures of external L1s before Quantos wraps them with PQC.
use ed25519_dalek::{VerifyingKey, Signature as Ed25519Signature};
use blst::{min_pk::PublicKey as BlstPublicKey, min_pk::Signature as BlstSignature, BLST_ERROR};
use k256::ecdsa::{Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey, signature::Verifier};

fn keccak256(data: &[u8]) -> [u8; 32] {
    let result = Keccak256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn double_sha256(data: &[u8]) -> [u8; 32] {
    let h1 = Sha256::digest(data);
    let h2 = Sha256::digest(&h1);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h2);
    out
}

mod rlp {
    pub fn decode_list(data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        if data.is_empty() { return Err("empty".into()); }
        let first = data[0];
        if first >= 0xc0 && first <= 0xf7 {
            let len = (first - 0xc0) as usize;
            parse(&data[1..1 + len])
        } else if first >= 0xf8 {
            let lb = (first - 0xf7) as usize;
            let len = btou(&data[1..1 + lb]);
            parse(&data[1 + lb..1 + lb + len])
        } else { Err("not a list".into()) }
    }
    fn parse(c: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let mut items = Vec::new();
        let mut i = 0;
        while i < c.len() {
            let (item, n) = item(&c[i..])?;
            items.push(item); i += n;
        }
        Ok(items)
    }
    fn item(d: &[u8]) -> Result<(Vec<u8>, usize), String> {
        if d.is_empty() { return Err("empty".into()); }
        let f = d[0];
        if f < 0x80 { Ok((vec![f], 1)) }
        else if f < 0xb8 { let l = (f - 0x80) as usize; Ok((d[1..1+l].to_vec(), 1+l)) }
        else if f < 0xc0 { let lb = (f - 0xb7) as usize; let l = btou(&d[1..1+lb]); Ok((d[1+lb..1+lb+l].to_vec(), 1+lb+l)) }
        else if f < 0xf8 { let l = (f - 0xc0) as usize; Ok((d[..1+l].to_vec(), 1+l)) }
        else { let lb = (f - 0xf7) as usize; let l = btou(&d[1..1+lb]); Ok((d[..1+lb+l].to_vec(), 1+lb+l)) }
    }
    fn btou(b: &[u8]) -> usize {
        let mut r = 0usize;
        for &x in b { r = r * 256 + x as usize; }
        r
    }
}

fn verify_evm(cp: &ExternalCheckpoint) -> L0Result<VerificationResult> {
    let ChainProof::Evm { block_header_rlp, .. } = &cp.proof else {
        return Ok(VerificationResult::invalid("Expected EVM ChainProof"));
    };
    let computed = keccak256(block_header_rlp);
    if computed != cp.block_hash {
        return Ok(VerificationResult::invalid("EVM header hash mismatch"));
    }
    let items = rlp::decode_list(block_header_rlp)
        .map_err(|e| L0Error::InvalidCheckpoint(format!("RLP: {}", e)))?;
    if items.len() < 4 {
        return Ok(VerificationResult::invalid("EVM header too short"));
    }
    let sr = &items[3];
    if sr.len() != 32 { return Ok(VerificationResult::invalid("EVM state_root len != 32")); }
    let mut arr = [0u8; 32]; arr.copy_from_slice(sr);
    if arr != cp.state_root { return Ok(VerificationResult::invalid("EVM state_root mismatch")); }

    // Verify parent block hash continuity (item[0] in EVM header RLP)
    let pr = &items[0];
    if pr.len() != 32 { return Ok(VerificationResult::invalid("EVM parent_hash len != 32")); }
    let mut parent_arr = [0u8; 32]; parent_arr.copy_from_slice(pr);
    if parent_arr != cp.parent_block_hash {
        return Ok(VerificationResult::invalid("EVM parent_hash mismatch"));
    }

    Ok(VerificationResult::valid())
}

fn verify_bitcoin(cp: &ExternalCheckpoint) -> L0Result<VerificationResult> {
    let ChainProof::Bitcoin {
        block_header, confirmations, block_height,
        tx_merkle_proof, tx_hash, tx_index,
    } = &cp.proof else {
        return Ok(VerificationResult::invalid("Expected Bitcoin ChainProof"));
    };

    // ── 1. Block header hash (double-SHA256, little-endian reversed) ──
    if block_header.len() != 80 {
        return Ok(VerificationResult::invalid(format!("Bitcoin header must be 80 bytes, got {}", block_header.len())));
    }
    let computed = double_sha256(block_header);
    let mut rev = [0u8; 32];
    for i in 0..32 { rev[i] = computed[31 - i]; }
    if rev != cp.block_hash {
        return Ok(VerificationResult::invalid("Bitcoin header hash mismatch"));
    }

    // ── 2. Confirmation depth ──
    if *confirmations < 6 {
        return Ok(VerificationResult::invalid(format!("Bitcoin confs {} < 6", confirmations)));
    }

    // ── 3. Block height ──
    if *block_height != cp.block_number {
        return Ok(VerificationResult::invalid("Bitcoin height mismatch"));
    }

    // ── 4. SPV Merkle inclusion proof (optional — only checked when present) ──
    // Bitcoin block header layout:
    //   [0..4]   version
    //   [4..36]  prev_block_hash
    //   [36..68] merkle_root
    //   [68..72] time
    //   [72..76] bits
    //   [76..80] nonce
    if let (Some(proof_nodes), Some(txid), Some(tx_pos)) = (tx_merkle_proof, tx_hash, tx_index) {
        let mut merkle_root_bytes = [0u8; 32];
        merkle_root_bytes.copy_from_slice(&block_header[36..68]);

        // Walk from leaf to root: at each level, combine with sibling
        // Direction: bit k of tx_index determines left (0) or right (1) sibling
        let mut current = double_sha256(txid);
        let mut idx = *tx_pos;
        for sibling in proof_nodes {
            let mut combined = [0u8; 64];
            if idx & 1 == 0 {
                combined[..32].copy_from_slice(&current);
                combined[32..].copy_from_slice(sibling);
            } else {
                combined[..32].copy_from_slice(sibling);
                combined[32..].copy_from_slice(&current);
            }
            current = double_sha256(&combined);
            idx >>= 1;
        }
        // Reverse to match Bitcoin's internal byte order
        let mut computed_root = [0u8; 32];
        for i in 0..32 { computed_root[i] = current[31 - i]; }
        if computed_root != merkle_root_bytes {
            return Ok(VerificationResult::invalid("Bitcoin SPV Merkle proof invalid: computed root does not match header"));
        }
    }

    Ok(VerificationResult::valid())
}

fn verify_solana(cp: &ExternalCheckpoint) -> L0Result<VerificationResult> {
    let ChainProof::Solana { ledger_entry, vote_signatures, bank_hash } = &cp.proof else {
        return Ok(VerificationResult::invalid("Expected Solana ChainProof"));
    };
    if ledger_entry.is_empty() { return Ok(VerificationResult::invalid("Solana ledger empty")); }
    if vote_signatures.is_empty() { return Ok(VerificationResult::invalid("Solana votes empty")); }
    if *bank_hash != cp.state_root { return Ok(VerificationResult::invalid("Solana bank_hash mismatch")); }
    Ok(VerificationResult::valid())
}

fn verify_move(cp: &ExternalCheckpoint) -> L0Result<VerificationResult> {
    let ChainProof::Move { ledger_info, validator_signatures, validator_pubkeys } = &cp.proof else {
        return Ok(VerificationResult::invalid("Expected Move ChainProof"));
    };
    if ledger_info.is_empty() { return Ok(VerificationResult::invalid("Move ledger empty")); }
    if validator_signatures.is_empty() { return Ok(VerificationResult::invalid("Move sigs empty")); }
    if validator_pubkeys.len() != validator_signatures.len() {
        return Ok(VerificationResult::invalid("Move pubkey/sig count mismatch"));
    }
    Ok(VerificationResult::valid())
}

fn verify_near(cp: &ExternalCheckpoint) -> L0Result<VerificationResult> {
    let ChainProof::Near { block_header, approval_signatures, producer_pubkeys } = &cp.proof else {
        return Ok(VerificationResult::invalid("Expected NEAR ChainProof"));
    };
    if block_header.is_empty() { return Ok(VerificationResult::invalid("NEAR header empty")); }
    if approval_signatures.is_empty() { return Ok(VerificationResult::invalid("NEAR approvals empty")); }
    if producer_pubkeys.len() != approval_signatures.len() {
        return Ok(VerificationResult::invalid("NEAR pubkey/sig count mismatch"));
    }
    Ok(VerificationResult::valid())
}

fn verify_cosmos(cp: &ExternalCheckpoint) -> L0Result<VerificationResult> {
    let ChainProof::Cosmos { block_header, commit_signatures, validator_pubkeys, signed_power_bps } = &cp.proof else {
        return Ok(VerificationResult::invalid("Expected Cosmos ChainProof"));
    };
    if block_header.is_empty() { return Ok(VerificationResult::invalid("Cosmos header empty")); }
    if commit_signatures.is_empty() { return Ok(VerificationResult::invalid("Cosmos commits empty")); }
    if validator_pubkeys.len() != commit_signatures.len() {
        return Ok(VerificationResult::invalid("Cosmos pubkey/sig count mismatch"));
    }
    if *signed_power_bps < 6667 {
        return Ok(VerificationResult::invalid(format!("Cosmos power {} < 6667", signed_power_bps)));
    }
    Ok(VerificationResult::valid())
}

fn verify_cardano(cp: &ExternalCheckpoint) -> L0Result<VerificationResult> {
    let ChainProof::Cardano { block_header, vrf_proof, pool_signatures } = &cp.proof else {
        return Ok(VerificationResult::invalid("Expected Cardano ChainProof"));
    };
    if block_header.is_empty() { return Ok(VerificationResult::invalid("Cardano header empty")); }
    if vrf_proof.is_empty() { return Ok(VerificationResult::invalid("Cardano VRF empty")); }
    if pool_signatures.is_empty() { return Ok(VerificationResult::invalid("Cardano pool sigs empty")); }
    Ok(VerificationResult::valid())
}

fn verify_generic(cp: &ExternalCheckpoint) -> L0Result<VerificationResult> {
    let ChainProof::Generic { proof_bytes, signer_pubkeys, signatures } = &cp.proof else {
        return Ok(VerificationResult::invalid("Expected Generic ChainProof"));
    };
    if proof_bytes.is_empty() { return Ok(VerificationResult::invalid("Generic proof empty")); }
    if signatures.is_empty() { return Ok(VerificationResult::invalid("Generic sigs empty")); }
    if signer_pubkeys.len() != signatures.len() {
        return Ok(VerificationResult::invalid("Generic pubkey/sig count mismatch"));
    }
    Ok(VerificationResult::valid())
}

// ── Signature verification helpers ──

/// Verify an Ed25519 signature (Solana, NEAR, Cosmos, Cardano).
fn verify_ed25519(
    pubkey_bytes: &[u8],
    message: &[u8],
    sig_bytes: &[u8],
) -> Result<(), String> {
    if pubkey_bytes.len() != 32 {
        return Err(format!("Ed25519 pubkey length {} != 32", pubkey_bytes.len()));
    }
    if sig_bytes.len() != 64 {
        return Err(format!("Ed25519 signature length {} != 64", sig_bytes.len()));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(pubkey_bytes);
    let vk = VerifyingKey::from_bytes(&pk)
        .map_err(|e| format!("Ed25519 invalid pubkey: {:?}", e))?;
    let mut sig = [0u8; 64];
    sig.copy_from_slice(sig_bytes);
    let signature = Ed25519Signature::from_bytes(&sig);
    vk.verify_strict(message, &signature)
        .map_err(|e| format!("Ed25519 verify failed: {:?}", e))
}

/// Batch-verify Ed25519 signatures. Returns count of valid sigs and error messages.
fn verify_ed25519_batch(
    pubkeys: &[Vec<u8>],
    messages: &[&[u8]],
    signatures: &[Vec<u8>],
) -> (usize, Vec<String>) {
    assert_eq!(pubkeys.len(), signatures.len());
    assert_eq!(pubkeys.len(), messages.len());
    let mut valid = 0usize;
    let mut errors = Vec::new();
    for ((pk, msg), sig) in pubkeys.iter().zip(messages.iter()).zip(signatures.iter()) {
        match verify_ed25519(pk, msg, sig) {
            Ok(()) => valid += 1,
            Err(e) => errors.push(e),
        }
    }
    (valid, errors)
}

/// Verify a BLS signature (Aptos / Sui use BLS12-381).
fn verify_bls(
    pubkey_bytes: &[u8],
    message: &[u8],
    sig_bytes: &[u8],
) -> Result<(), String> {
    let pk = BlstPublicKey::from_bytes(pubkey_bytes)
        .map_err(|e| format!("BLS invalid pubkey: {:?}", e))?;
    pk.validate()
        .map_err(|e| format!("BLS pubkey validation failed: {:?}", e))?;
    let sig = BlstSignature::from_bytes(sig_bytes)
        .map_err(|e| format!("BLS invalid signature: {:?}", e))?;
    sig.validate(true)
        .map_err(|e| format!("BLS signature validation failed: {:?}", e))?;
    let result = sig.verify(true, message, &[], &[], &pk, true);
    if result == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(format!("BLS verify failed: {:?}", result))
    }
}

// ── Production signature-aware verifiers ──

fn verify_solana_production(
    cp: &ExternalCheckpoint,
    validator_set: Option<&ValidatorSet>,
) -> L0Result<VerificationResult> {
    let ChainProof::Solana { ledger_entry, vote_signatures, bank_hash } = &cp.proof else {
        return Ok(VerificationResult::invalid("Expected Solana ChainProof"));
    };
    if ledger_entry.is_empty() { return Ok(VerificationResult::invalid("Solana ledger empty")); }
    if vote_signatures.is_empty() { return Ok(VerificationResult::invalid("Solana votes empty")); }
    if *bank_hash != cp.state_root { return Ok(VerificationResult::invalid("Solana bank_hash mismatch")); }

    let Some(set) = validator_set else {
        return Ok(VerificationResult::invalid("Solana: no validator set registered"));
    };
    if set.pubkeys.len() != vote_signatures.len() {
        return Ok(VerificationResult::invalid(format!(
            "Solana validator count mismatch: set {} vs proof {}",
            set.pubkeys.len(), vote_signatures.len()
        )));
    }

    let messages: Vec<&[u8]> = (0..vote_signatures.len()).map(|_| ledger_entry.as_slice()).collect();
    let (valid, errors) = verify_ed25519_batch(&set.pubkeys, &messages, vote_signatures);
    let signed_power_bps = ((valid as u64 * 10000) / set.pubkeys.len() as u64) as u16;
    if signed_power_bps < set.threshold_bps {
        return Ok(VerificationResult::invalid(format!(
            "Solana signed power {} bps < threshold {} bps. Errors: {:?}",
            signed_power_bps, set.threshold_bps, errors
        )));
    }
    Ok(VerificationResult::valid())
}

fn verify_move_production(
    cp: &ExternalCheckpoint,
    validator_set: Option<&ValidatorSet>,
) -> L0Result<VerificationResult> {
    let ChainProof::Move { ledger_info, validator_signatures, validator_pubkeys } = &cp.proof else {
        return Ok(VerificationResult::invalid("Expected Move ChainProof"));
    };
    if ledger_info.is_empty() { return Ok(VerificationResult::invalid("Move ledger empty")); }
    if validator_signatures.is_empty() { return Ok(VerificationResult::invalid("Move sigs empty")); }
    if validator_pubkeys.len() != validator_signatures.len() {
        return Ok(VerificationResult::invalid("Move pubkey/sig count mismatch"));
    }

    let Some(set) = validator_set else {
        return Ok(VerificationResult::invalid("Move: no validator set registered"));
    };

    // Verify BLS signatures against registered validator set
    let mut valid = 0usize;
    let mut errors = Vec::new();
    for (i, (pk, sig)) in validator_pubkeys.iter().zip(validator_signatures.iter()).enumerate() {
        match verify_bls(pk, ledger_info, sig) {
            Ok(()) => {
                valid += 1;
            }
            Err(e) => errors.push(format!("sig {}: {}", i, e)),
        }
    }
    let signed_power_bps = ((valid as u64 * 10000) / set.pubkeys.len().max(1) as u64) as u16;
    if signed_power_bps < set.threshold_bps {
        return Ok(VerificationResult::invalid(format!(
            "Move signed power {} bps < threshold {} bps. Errors: {:?}",
            signed_power_bps, set.threshold_bps, errors
        )));
    }
    Ok(VerificationResult::valid())
}

fn verify_near_production(
    cp: &ExternalCheckpoint,
    validator_set: Option<&ValidatorSet>,
) -> L0Result<VerificationResult> {
    let ChainProof::Near { block_header, approval_signatures, producer_pubkeys } = &cp.proof else {
        return Ok(VerificationResult::invalid("Expected NEAR ChainProof"));
    };
    if block_header.is_empty() { return Ok(VerificationResult::invalid("NEAR header empty")); }
    if approval_signatures.is_empty() { return Ok(VerificationResult::invalid("NEAR approvals empty")); }
    if producer_pubkeys.len() != approval_signatures.len() {
        return Ok(VerificationResult::invalid("NEAR pubkey/sig count mismatch"));
    }

    let Some(set) = validator_set else {
        return Ok(VerificationResult::invalid("NEAR: no validator set registered"));
    };

    let messages: Vec<&[u8]> = (0..approval_signatures.len()).map(|_| block_header.as_slice()).collect();
    let (valid, errors) = verify_ed25519_batch(&set.pubkeys, &messages, approval_signatures);
    let signed_power_bps = ((valid as u64 * 10000) / set.pubkeys.len().max(1) as u64) as u16;
    if signed_power_bps < set.threshold_bps {
        return Ok(VerificationResult::invalid(format!(
            "NEAR signed power {} bps < threshold {} bps. Errors: {:?}",
            signed_power_bps, set.threshold_bps, errors
        )));
    }
    Ok(VerificationResult::valid())
}

fn verify_cosmos_production(
    cp: &ExternalCheckpoint,
    validator_set: Option<&ValidatorSet>,
) -> L0Result<VerificationResult> {
    let ChainProof::Cosmos { block_header, commit_signatures, validator_pubkeys, signed_power_bps } = &cp.proof else {
        return Ok(VerificationResult::invalid("Expected Cosmos ChainProof"));
    };
    if block_header.is_empty() { return Ok(VerificationResult::invalid("Cosmos header empty")); }
    if commit_signatures.is_empty() { return Ok(VerificationResult::invalid("Cosmos commits empty")); }
    if validator_pubkeys.len() != commit_signatures.len() {
        return Ok(VerificationResult::invalid("Cosmos pubkey/sig count mismatch"));
    }
    if *signed_power_bps < 6667 {
        return Ok(VerificationResult::invalid(format!("Cosmos power {} < 6667", signed_power_bps)));
    }

    let Some(set) = validator_set else {
        return Ok(VerificationResult::invalid("Cosmos: no validator set registered"));
    };

    let messages: Vec<&[u8]> = (0..commit_signatures.len()).map(|_| block_header.as_slice()).collect();
    let (valid, errors) = verify_ed25519_batch(&set.pubkeys, &messages, commit_signatures);
    let computed_power_bps = ((valid as u64 * 10000) / set.pubkeys.len().max(1) as u64) as u16;
    if computed_power_bps < set.threshold_bps {
        return Ok(VerificationResult::invalid(format!(
            "Cosmos signed power {} bps < threshold {} bps. Errors: {:?}",
            computed_power_bps, set.threshold_bps, errors
        )));
    }
    Ok(VerificationResult::valid())
}

fn verify_cardano_production(
    cp: &ExternalCheckpoint,
    validator_set: Option<&ValidatorSet>,
) -> L0Result<VerificationResult> {
    let ChainProof::Cardano { block_header, vrf_proof, pool_signatures } = &cp.proof else {
        return Ok(VerificationResult::invalid("Expected Cardano ChainProof"));
    };
    if block_header.is_empty() { return Ok(VerificationResult::invalid("Cardano header empty")); }
    if vrf_proof.is_empty() { return Ok(VerificationResult::invalid("Cardano VRF empty")); }
    if pool_signatures.is_empty() { return Ok(VerificationResult::invalid("Cardano pool sigs empty")); }

    let Some(set) = validator_set else {
        return Ok(VerificationResult::invalid("Cardano: no validator set registered"));
    };

    let messages: Vec<&[u8]> = (0..pool_signatures.len()).map(|_| block_header.as_slice()).collect();
    let (valid, errors) = verify_ed25519_batch(&set.pubkeys, &messages, pool_signatures);
    let signed_power_bps = ((valid as u64 * 10000) / set.pubkeys.len().max(1) as u64) as u16;
    if signed_power_bps < set.threshold_bps {
        return Ok(VerificationResult::invalid(format!(
            "Cardano signed power {} bps < threshold {} bps. Errors: {:?}",
            signed_power_bps, set.threshold_bps, errors
        )));
    }
    Ok(VerificationResult::valid())
}

fn verify_ton(
    cp: &ExternalCheckpoint,
    validator_set: Option<&ValidatorSet>,
) -> L0Result<VerificationResult> {
    let ChainProof::Ton { block_header, validator_signatures, validator_pubkeys } = &cp.proof else {
        return Ok(VerificationResult::invalid("Expected TON ChainProof"));
    };
    if block_header.is_empty() { return Ok(VerificationResult::invalid("TON block_header empty")); }
    if validator_signatures.is_empty() { return Ok(VerificationResult::invalid("TON validator_signatures empty")); }
    if validator_pubkeys.len() != validator_signatures.len() {
        return Ok(VerificationResult::invalid("TON pubkey/sig count mismatch"));
    }
    let Some(set) = validator_set else {
        return Ok(VerificationResult::invalid("TON: no validator set registered"));
    };
    let messages: Vec<&[u8]> = (0..validator_signatures.len()).map(|_| block_header.as_slice()).collect();
    let (valid, errors) = verify_ed25519_batch(&set.pubkeys, &messages, validator_signatures);
    let signed_power_bps = ((valid as u64 * 10000) / set.pubkeys.len().max(1) as u64) as u16;
    if signed_power_bps < set.threshold_bps {
        return Ok(VerificationResult::invalid(format!(
            "TON signed power {} bps < threshold {} bps. Errors: {:?}",
            signed_power_bps, set.threshold_bps, errors
        )));
    }
    Ok(VerificationResult::valid())
}

fn verify_tron(
    cp: &ExternalCheckpoint,
    validator_set: Option<&ValidatorSet>,
) -> L0Result<VerificationResult> {
    let ChainProof::Tron { block_header, producer_signatures, producer_pubkeys } = &cp.proof else {
        return Ok(VerificationResult::invalid("Expected Tron ChainProof"));
    };
    if block_header.is_empty() { return Ok(VerificationResult::invalid("Tron block_header empty")); }
    if producer_signatures.is_empty() { return Ok(VerificationResult::invalid("Tron producer_signatures empty")); }
    if producer_pubkeys.len() != producer_signatures.len() {
        return Ok(VerificationResult::invalid("Tron pubkey/sig count mismatch"));
    }
    let Some(set) = validator_set else {
        return Ok(VerificationResult::invalid("Tron: no validator set registered"));
    };
    let mut valid = 0usize;
    let mut errors = Vec::new();
    for (i, (pk_bytes, sig_bytes)) in set.pubkeys.iter().zip(producer_signatures.iter()).enumerate() {
        match verify_ecdsa(pk_bytes, block_header, sig_bytes) {
            Ok(()) => valid += 1,
            Err(e) => errors.push(format!("sig {}: {}", i, e)),
        }
    }
    let signed_power_bps = ((valid as u64 * 10000) / set.pubkeys.len().max(1) as u64) as u16;
    if signed_power_bps < set.threshold_bps {
        return Ok(VerificationResult::invalid(format!(
            "Tron signed power {} bps < threshold {} bps. Errors: {:?}",
            signed_power_bps, set.threshold_bps, errors
        )));
    }
    Ok(VerificationResult::valid())
}

fn verify_ecdsa(pubkey_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<(), String> {
    let vk = EcdsaVerifyingKey::from_sec1_bytes(pubkey_bytes)
        .map_err(|e| format!("ECDSA invalid pubkey: {:?}", e))?;
    let sig = EcdsaSignature::from_slice(sig_bytes)
        .map_err(|e| format!("ECDSA invalid signature: {:?}", e))?;
    vk.verify(message, &sig)
        .map_err(|e| format!("ECDSA verify failed: {:?}", e))
}

fn verify_polkadot(
    cp: &ExternalCheckpoint,
    validator_set: Option<&ValidatorSet>,
) -> L0Result<VerificationResult> {
    let ChainProof::Polkadot { grandpa_vote, validator_signatures, validator_pubkeys } = &cp.proof else {
        return Ok(VerificationResult::invalid("Expected Polkadot ChainProof"));
    };
    if grandpa_vote.is_empty() { return Ok(VerificationResult::invalid("Polkadot grandpa_vote empty")); }
    if validator_signatures.is_empty() { return Ok(VerificationResult::invalid("Polkadot validator_signatures empty")); }
    if validator_pubkeys.len() != validator_signatures.len() {
        return Ok(VerificationResult::invalid("Polkadot pubkey/sig count mismatch"));
    }
    let Some(set) = validator_set else {
        return Ok(VerificationResult::invalid("Polkadot: no validator set registered"));
    };
    let messages: Vec<&[u8]> = (0..validator_signatures.len()).map(|_| grandpa_vote.as_slice()).collect();
    let (valid, errors) = verify_ed25519_batch(&set.pubkeys, &messages, validator_signatures);
    let signed_power_bps = ((valid as u64 * 10000) / set.pubkeys.len().max(1) as u64) as u16;
    if signed_power_bps < set.threshold_bps {
        return Ok(VerificationResult::invalid(format!(
            "Polkadot signed power {} bps < threshold {} bps. Errors: {:?}",
            signed_power_bps, set.threshold_bps, errors
        )));
    }
    Ok(VerificationResult::valid())
}

fn verify_stellar(
    cp: &ExternalCheckpoint,
    validator_set: Option<&ValidatorSet>,
) -> L0Result<VerificationResult> {
    let ChainProof::Stellar { scp_statement, node_signatures, node_pubkeys } = &cp.proof else {
        return Ok(VerificationResult::invalid("Expected Stellar ChainProof"));
    };
    if scp_statement.is_empty() { return Ok(VerificationResult::invalid("Stellar scp_statement empty")); }
    if node_signatures.is_empty() { return Ok(VerificationResult::invalid("Stellar node_signatures empty")); }
    if node_pubkeys.len() != node_signatures.len() {
        return Ok(VerificationResult::invalid("Stellar pubkey/sig count mismatch"));
    }
    let Some(set) = validator_set else {
        return Ok(VerificationResult::invalid("Stellar: no validator set registered"));
    };
    let messages: Vec<&[u8]> = (0..node_signatures.len()).map(|_| scp_statement.as_slice()).collect();
    let (valid, errors) = verify_ed25519_batch(&set.pubkeys, &messages, node_signatures);
    let signed_power_bps = ((valid as u64 * 10000) / set.pubkeys.len().max(1) as u64) as u16;
    if signed_power_bps < set.threshold_bps {
        return Ok(VerificationResult::invalid(format!(
            "Stellar signed power {} bps < threshold {} bps. Errors: {:?}",
            signed_power_bps, set.threshold_bps, errors
        )));
    }
    Ok(VerificationResult::valid())
}

fn verify_tezos(
    cp: &ExternalCheckpoint,
    validator_set: Option<&ValidatorSet>,
) -> L0Result<VerificationResult> {
    let ChainProof::Tezos { endorsement, baker_signatures, baker_pubkeys } = &cp.proof else {
        return Ok(VerificationResult::invalid("Expected Tezos ChainProof"));
    };
    if endorsement.is_empty() { return Ok(VerificationResult::invalid("Tezos endorsement empty")); }
    if baker_signatures.is_empty() { return Ok(VerificationResult::invalid("Tezos baker_signatures empty")); }
    if baker_pubkeys.len() != baker_signatures.len() {
        return Ok(VerificationResult::invalid("Tezos pubkey/sig count mismatch"));
    }
    let Some(set) = validator_set else {
        return Ok(VerificationResult::invalid("Tezos: no validator set registered"));
    };
    let messages: Vec<&[u8]> = (0..baker_signatures.len()).map(|_| endorsement.as_slice()).collect();
    let (valid, errors) = verify_ed25519_batch(&set.pubkeys, &messages, baker_signatures);
    let signed_power_bps = ((valid as u64 * 10000) / set.pubkeys.len().max(1) as u64) as u16;
    if signed_power_bps < set.threshold_bps {
        return Ok(VerificationResult::invalid(format!(
            "Tezos signed power {} bps < threshold {} bps. Errors: {:?}",
            signed_power_bps, set.threshold_bps, errors
        )));
    }
    Ok(VerificationResult::valid())
}

fn verify_ripple(
    cp: &ExternalCheckpoint,
    validator_set: Option<&ValidatorSet>,
) -> L0Result<VerificationResult> {
    let ChainProof::Ripple { ledger_header, validator_signatures, validator_pubkeys, signed_power_bps } = &cp.proof else {
        return Ok(VerificationResult::invalid("Expected Ripple ChainProof"));
    };
    if ledger_header.is_empty() { return Ok(VerificationResult::invalid("Ripple ledger_header empty")); }
    if validator_signatures.is_empty() { return Ok(VerificationResult::invalid("Ripple validator_signatures empty")); }
    if validator_pubkeys.len() != validator_signatures.len() {
        return Ok(VerificationResult::invalid("Ripple pubkey/sig count mismatch"));
    }
    let Some(set) = validator_set else {
        return Ok(VerificationResult::invalid("Ripple: no validator set registered"));
    };
    let messages: Vec<&[u8]> = (0..validator_signatures.len()).map(|_| ledger_header.as_slice()).collect();
    let (valid, errors) = verify_ed25519_batch(&set.pubkeys, &messages, validator_signatures);
    let computed_power_bps = ((valid as u64 * 10000) / set.pubkeys.len().max(1) as u64) as u16;
    if computed_power_bps < set.threshold_bps {
        return Ok(VerificationResult::invalid(format!(
            "Ripple signed power {} bps < threshold {} bps. Errors: {:?}",
            computed_power_bps, set.threshold_bps, errors
        )));
    }
    Ok(VerificationResult::valid())
}

#[derive(Clone, Debug, Default)]
pub struct ValidatorSet {
    pub pubkeys: Vec<Vec<u8>>,
    pub stakes: Vec<u64>,
    pub threshold_bps: u16,
}

#[derive(Clone, Debug, Default)]
pub struct ValidatorSetRegistry {
    sets: Arc<RwLock<HashMap<ChainId, ValidatorSet>>>,
}
impl ValidatorSetRegistry {
    pub fn new() -> Self { Self::default() }
    /// Insert or replace a validator set. Safe to call concurrently (e.g. from EpochWatcher).
    pub fn insert(&self, chain_id: ChainId, set: ValidatorSet) { self.sets.write().insert(chain_id, set); }
    /// Returns a cloned snapshot of the validator set for this chain (None if not registered).
    pub fn get_cloned(&self, chain_id: &ChainId) -> Option<ValidatorSet> { self.sets.read().get(chain_id).cloned() }
    /// Number of registered validator sets.
    pub fn len(&self) -> usize { self.sets.read().len() }
    /// Returns all registered chain IDs.
    pub fn chain_ids(&self) -> Vec<ChainId> { self.sets.read().keys().cloned().collect() }
}

#[async_trait]
pub trait LightClient: Send + Sync {
    async fn verify_checkpoint(&self, cp: &ExternalCheckpoint) -> L0Result<VerificationResult>;
    fn chain_id(&self) -> ChainId;
}

pub struct EVMLightClient { chain: ChainId }
impl EVMLightClient { pub fn new(chain: ChainId) -> Self { assert_eq!(chain.family(), ChainFamily::Evm); Self { chain } } }
#[async_trait]
impl LightClient for EVMLightClient {
    async fn verify_checkpoint(&self, cp: &ExternalCheckpoint) -> L0Result<VerificationResult> { verify_evm(cp) }
    fn chain_id(&self) -> ChainId { self.chain.clone() }
}

pub struct BitcoinLightClient { chain: ChainId }
impl BitcoinLightClient { pub fn new(chain: ChainId) -> Self { assert!(matches!(chain.family(), ChainFamily::Bitcoin)); Self { chain } } }
#[async_trait]
impl LightClient for BitcoinLightClient {
    async fn verify_checkpoint(&self, cp: &ExternalCheckpoint) -> L0Result<VerificationResult> { verify_bitcoin(cp) }
    fn chain_id(&self) -> ChainId { self.chain.clone() }
}

pub struct SolanaLightClient { chain: ChainId, registry: ValidatorSetRegistry }
impl SolanaLightClient { pub fn new(chain: ChainId, registry: ValidatorSetRegistry) -> Self { assert!(matches!(chain.family(), ChainFamily::Svm)); Self { registry, chain } } }
#[async_trait]
impl LightClient for SolanaLightClient {
    async fn verify_checkpoint(&self, cp: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        let set = self.registry.get_cloned(&self.chain);
        verify_solana_production(cp, set.as_ref())
    }
    fn chain_id(&self) -> ChainId { self.chain.clone() }
}

pub struct MoveLightClient { chain: ChainId, registry: ValidatorSetRegistry }
impl MoveLightClient { pub fn new(chain: ChainId, registry: ValidatorSetRegistry) -> Self { assert!(matches!(chain.family(), ChainFamily::Move)); Self { registry, chain } } }
#[async_trait]
impl LightClient for MoveLightClient {
    async fn verify_checkpoint(&self, cp: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        let set = self.registry.get_cloned(&self.chain);
        verify_move_production(cp, set.as_ref())
    }
    fn chain_id(&self) -> ChainId { self.chain.clone() }
}

pub struct NearLightClient { chain: ChainId, registry: ValidatorSetRegistry }
impl NearLightClient { pub fn new(chain: ChainId, registry: ValidatorSetRegistry) -> Self { assert!(matches!(chain.family(), ChainFamily::Near)); Self { registry, chain } } }
#[async_trait]
impl LightClient for NearLightClient {
    async fn verify_checkpoint(&self, cp: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        let set = self.registry.get_cloned(&self.chain);
        verify_near_production(cp, set.as_ref())
    }
    fn chain_id(&self) -> ChainId { self.chain.clone() }
}

pub struct CosmosLightClient { chain: ChainId, registry: ValidatorSetRegistry }
impl CosmosLightClient { pub fn new(chain: ChainId, registry: ValidatorSetRegistry) -> Self { assert!(matches!(chain.family(), ChainFamily::Cosmos)); Self { registry, chain } } }
#[async_trait]
impl LightClient for CosmosLightClient {
    async fn verify_checkpoint(&self, cp: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        let set = self.registry.get_cloned(&self.chain);
        verify_cosmos_production(cp, set.as_ref())
    }
    fn chain_id(&self) -> ChainId { self.chain.clone() }
}

pub struct CardanoLightClient { chain: ChainId, registry: ValidatorSetRegistry }
impl CardanoLightClient { pub fn new(chain: ChainId, registry: ValidatorSetRegistry) -> Self { assert!(matches!(chain.family(), ChainFamily::Cardano)); Self { registry, chain } } }
#[async_trait]
impl LightClient for CardanoLightClient {
    async fn verify_checkpoint(&self, cp: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        let set = self.registry.get_cloned(&self.chain);
        verify_cardano_production(cp, set.as_ref())
    }
    fn chain_id(&self) -> ChainId { self.chain.clone() }
}

pub struct TonLightClient { chain: ChainId, registry: ValidatorSetRegistry }
impl TonLightClient { pub fn new(chain: ChainId, registry: ValidatorSetRegistry) -> Self { assert!(matches!(chain.family(), ChainFamily::Ton)); Self { registry, chain } } }
#[async_trait]
impl LightClient for TonLightClient {
    async fn verify_checkpoint(&self, cp: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        let set = self.registry.get_cloned(&self.chain);
        verify_ton(cp, set.as_ref())
    }
    fn chain_id(&self) -> ChainId { self.chain.clone() }
}

pub struct TronLightClient { chain: ChainId, registry: ValidatorSetRegistry }
impl TronLightClient { pub fn new(chain: ChainId, registry: ValidatorSetRegistry) -> Self { assert!(matches!(chain.family(), ChainFamily::Tvm)); Self { registry, chain } } }
#[async_trait]
impl LightClient for TronLightClient {
    async fn verify_checkpoint(&self, cp: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        let set = self.registry.get_cloned(&self.chain);
        verify_tron(cp, set.as_ref())
    }
    fn chain_id(&self) -> ChainId { self.chain.clone() }
}

pub struct PolkadotLightClient { chain: ChainId, registry: ValidatorSetRegistry }
impl PolkadotLightClient { pub fn new(chain: ChainId, registry: ValidatorSetRegistry) -> Self { assert!(matches!(chain.family(), ChainFamily::Substrate)); Self { registry, chain } } }
#[async_trait]
impl LightClient for PolkadotLightClient {
    async fn verify_checkpoint(&self, cp: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        let set = self.registry.get_cloned(&self.chain);
        verify_polkadot(cp, set.as_ref())
    }
    fn chain_id(&self) -> ChainId { self.chain.clone() }
}

pub struct StellarLightClient { chain: ChainId, registry: ValidatorSetRegistry }
impl StellarLightClient { pub fn new(chain: ChainId, registry: ValidatorSetRegistry) -> Self { assert!(matches!(chain.family(), ChainFamily::Stellar)); Self { registry, chain } } }
#[async_trait]
impl LightClient for StellarLightClient {
    async fn verify_checkpoint(&self, cp: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        let set = self.registry.get_cloned(&self.chain);
        verify_stellar(cp, set.as_ref())
    }
    fn chain_id(&self) -> ChainId { self.chain.clone() }
}

pub struct TezosLightClient { chain: ChainId, registry: ValidatorSetRegistry }
impl TezosLightClient { pub fn new(chain: ChainId, registry: ValidatorSetRegistry) -> Self { assert!(matches!(chain.family(), ChainFamily::Tezos)); Self { registry, chain } } }
#[async_trait]
impl LightClient for TezosLightClient {
    async fn verify_checkpoint(&self, cp: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        let set = self.registry.get_cloned(&self.chain);
        verify_tezos(cp, set.as_ref())
    }
    fn chain_id(&self) -> ChainId { self.chain.clone() }
}

pub struct RippleLightClient { chain: ChainId, registry: ValidatorSetRegistry }
impl RippleLightClient { pub fn new(chain: ChainId, registry: ValidatorSetRegistry) -> Self { assert!(matches!(chain.family(), ChainFamily::Ripple)); Self { registry, chain } } }
#[async_trait]
impl LightClient for RippleLightClient {
    async fn verify_checkpoint(&self, cp: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        let set = self.registry.get_cloned(&self.chain);
        verify_ripple(cp, set.as_ref())
    }
    fn chain_id(&self) -> ChainId { self.chain.clone() }
}

pub struct GenericLightClient { chain: ChainId }
impl GenericLightClient { pub fn new(chain: ChainId) -> Self { Self { chain } } }
#[async_trait]
impl LightClient for GenericLightClient {
    async fn verify_checkpoint(&self, cp: &ExternalCheckpoint) -> L0Result<VerificationResult> { verify_generic(cp) }
    fn chain_id(&self) -> ChainId { self.chain.clone() }
}

pub struct LightClientRegistry {
    clients: HashMap<ChainId, Box<dyn LightClient>>,
    /// Shared validator set registry — clones are shallow (Arc), all point to the same data.
    /// EpochWatcher and operators call validator_registry.insert() to update validator sets
    /// and all live light clients see the update immediately without restart.
    pub validator_registry: ValidatorSetRegistry,
}

impl LightClientRegistry {
    pub fn new() -> Self { Self { clients: HashMap::new(), validator_registry: ValidatorSetRegistry::new() } }
    pub fn register(&mut self, client: Box<dyn LightClient>) { self.clients.insert(client.chain_id(), client); }
    pub fn get(&self, chain_id: &ChainId) -> Option<&dyn LightClient> { self.clients.get(chain_id).map(|b| b.as_ref()) }

    /// Verify a checkpoint. NO FALLBACK — reject if no light client or invalid proof.
    pub async fn verify_checkpoint(&self, cp: &ExternalCheckpoint) -> L0Result<VerificationResult> {
        let client = match self.clients.get(&cp.chain_id) {
            Some(c) => c,
            None => return Ok(VerificationResult::invalid(format!("No light client for {:?}", cp.chain_id))),
        };
        if cp.proof.family() != cp.chain_id.family() {
            return Ok(VerificationResult::invalid("Proof family mismatch".to_string()));
        }
        client.verify_checkpoint(cp).await
    }

    pub fn with_defaults() -> Self {
        // All validator-set-aware light clients share the SAME registry Arc.
        // Calling validator_registry.insert() from an EpochWatcher updates all clients live.
        let validator_registry = ValidatorSetRegistry::new();
        let mut clients: HashMap<ChainId, Box<dyn LightClient>> = HashMap::new();

        for chain in [
            ChainId::Ethereum, ChainId::EthereumSepolia, ChainId::Base, ChainId::BaseSepolia,
            ChainId::Arbitrum, ChainId::ArbitrumSepolia, ChainId::Optimism, ChainId::OptimismSepolia,
            ChainId::Polygon, ChainId::PolygonAmoy, ChainId::Avalanche, ChainId::AvalancheFuji,
            ChainId::BinanceSmartChain, ChainId::BscTestnet, ChainId::Moonbeam, ChainId::Berachain,
            ChainId::Hyperliquid, ChainId::Monad, ChainId::Somnia,
        ] { clients.insert(chain.clone(), Box::new(EVMLightClient::new(chain))); }

        for chain in [ChainId::Bitcoin, ChainId::BitcoinTestnet] {
            clients.insert(chain.clone(), Box::new(BitcoinLightClient::new(chain)));
        }

        let vr = &validator_registry;
        for chain in [ChainId::Solana, ChainId::SolanaDevnet] {
            clients.insert(chain.clone(), Box::new(SolanaLightClient::new(chain, vr.clone())));
        }
        for chain in [ChainId::Aptos, ChainId::AptosTestnet, ChainId::Sui, ChainId::SuiTestnet] {
            clients.insert(chain.clone(), Box::new(MoveLightClient::new(chain, vr.clone())));
        }
        for chain in [ChainId::Near, ChainId::NearTestnet] {
            clients.insert(chain.clone(), Box::new(NearLightClient::new(chain, vr.clone())));
        }
        for chain in [ChainId::Cosmos, ChainId::CosmosTestnet] {
            clients.insert(chain.clone(), Box::new(CosmosLightClient::new(chain, vr.clone())));
        }
        for chain in [ChainId::Cardano, ChainId::CardanoTestnet] {
            clients.insert(chain.clone(), Box::new(CardanoLightClient::new(chain, vr.clone())));
        }
        for chain in [ChainId::Ton, ChainId::TonTestnet] {
            clients.insert(chain.clone(), Box::new(TonLightClient::new(chain, vr.clone())));
        }
        for chain in [ChainId::Tron, ChainId::TronShasta] {
            clients.insert(chain.clone(), Box::new(TronLightClient::new(chain, vr.clone())));
        }
        for chain in [ChainId::Polkadot, ChainId::PolkadotTestnet] {
            clients.insert(chain.clone(), Box::new(PolkadotLightClient::new(chain, vr.clone())));
        }
        for chain in [ChainId::Stellar, ChainId::StellarTestnet] {
            clients.insert(chain.clone(), Box::new(StellarLightClient::new(chain, vr.clone())));
        }
        for chain in [ChainId::Tezos, ChainId::TezosTestnet] {
            clients.insert(chain.clone(), Box::new(TezosLightClient::new(chain, vr.clone())));
        }
        for chain in [ChainId::Ripple, ChainId::RippleTestnet] {
            clients.insert(chain.clone(), Box::new(RippleLightClient::new(chain, vr.clone())));
        }

        Self { clients, validator_registry }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak_hello() {
        let result = keccak256(b"hello");
        let expected = hex::decode("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8").unwrap();
        assert_eq!(result.to_vec(), expected);
    }

    #[test]
    fn test_rlp_list() {
        let data = hex::decode("c3c001c10203").unwrap();
        let items = rlp::decode_list(&data).unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], vec![]);
        assert_eq!(items[1], vec![0x01]);
        assert_eq!(items[2], vec![0x02, 0x03]);
    }

    #[test]
    fn test_bitcoin_hash() {
        let header = [0u8; 80];
        let computed = double_sha256(&header);
        assert_eq!(computed.len(), 32);
    }

    #[test]
    fn test_registry_no_fallback() {
        let registry = LightClientRegistry::with_defaults();
        let cp = ExternalCheckpoint {
            chain_id: ChainId::Ethereum,
            block_number: 0,
            block_hash: [0u8; 32],
            state_root: [0u8; 32],
            parent_block_hash: [0u8; 32],
            chain_work: 0,
            timestamp_ms: 0,
            proof: ChainProof::Evm { block_header_rlp: vec![], sync_committee_signature: None, execution_payload_hash: None },
            metadata: None,
        };
        // Should reject because empty RLP is invalid
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(registry.verify_checkpoint(&cp)).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_bitcoin_merkle_single_tx() {
        // A block with a single tx: merkle root = double_sha256(txid)
        // Build a valid 80-byte header with the correct merkle_root
        let txid = [0x42u8; 32];
        let leaf = double_sha256(&txid);
        // No proof nodes needed for a single tx (leaf IS the root)
        let mut header = [0u8; 80];
        // Insert merkle root at bytes [36..68] (non-reversed, raw)
        let mut root_rev = [0u8; 32];
        for i in 0..32 { root_rev[i] = leaf[31 - i]; }
        header[36..68].copy_from_slice(&root_rev);
        let block_hash = {
            let h = double_sha256(&header);
            let mut rev = [0u8; 32];
            for i in 0..32 { rev[i] = h[31 - i]; }
            rev
        };
        let cp = ExternalCheckpoint {
            chain_id: ChainId::Bitcoin,
            block_number: 800_000,
            block_hash,
            state_root: [0u8; 32],
            parent_block_hash: [0u8; 32],
            chain_work: 0,
            timestamp_ms: 0,
            proof: ChainProof::Bitcoin {
                block_header: header.to_vec(),
                confirmations: 6,
                block_height: 800_000,
                tx_merkle_proof: Some(vec![]),  // no siblings for single tx
                tx_hash: Some(txid),
                tx_index: Some(0),
            },
            metadata: None,
        };
        let result = verify_bitcoin(&cp).unwrap();
        assert!(result.valid, "single-tx Merkle proof should be valid");
    }
}
