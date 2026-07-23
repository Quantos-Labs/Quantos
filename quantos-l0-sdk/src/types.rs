// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use serde::{Deserialize, Serialize};

pub type Hash = [u8; 32];

pub const L0_PROOF_VERSION: u16 = 1;

/// Domain separator for checkpoint signatures (must match L1's DOMAIN_CHECKPOINT).
pub const DOMAIN_CHECKPOINT: &[u8] = b"QUANTOS_CHECKPOINT_V1";

/// Identifier for external chains (must match L1's ChainId).
/// Stored as a string in the proof header.
type ChainId = String;

/// Prepends a domain tag to raw message bytes.
/// Must match L1's `crypto::domains::with_domain`.
pub fn with_domain(domain: &[u8], message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + domain.len() + message.len());
    out.extend_from_slice(&(domain.len() as u16).to_le_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(message);
    out
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PqcSignatureAlgo {
    MlDsa65 = 1,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct L0ProofHeader {
    pub version: u16,
    pub external_chain: Option<ChainId>,
    pub epoch: u64,
    pub slot: u64,
    pub previous_proof_hash: Hash,
    pub state_root: Hash,
    pub dag_root: Hash,
    pub parent_block_hash: Hash,
    pub chain_work: u128,
    pub validator_set_root: Hash,
    pub total_stake: u128,
    pub stake_threshold: u128,
    pub emitted_at_ms: u64,
    pub stark_commitment: Hash,
    /// Hash of the underlying checkpoint that validators actually signed.
    /// For native proofs: `checkpoint.hash()` — the verifier applies
    /// `with_domain(DOMAIN_CHECKPOINT, &checkpoint_hash)` to recover the
    /// signing message.
    /// For external proofs: `[0u8; 32]` — the verifier uses
    /// `proof.signing_digest()` directly.
    pub checkpoint_hash: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorRecord {
    pub address: [u8; 32],
    pub public_key: Vec<u8>,
    pub stake: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofSignature {
    pub validator_index: u32,
    pub algo: PqcSignatureAlgo,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct L0FinalityProof {
    pub header: L0ProofHeader,
    pub validators: Vec<ValidatorRecord>,
    pub signatures: Vec<ProofSignature>,
    /// Optional ZK-STARK batch proof (not verified by the SDK; included for
    /// forward compatibility with L1).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub stark_proof: Option<serde_json::Value>,
}

impl L0FinalityProof {
    pub fn signing_digest(&self) -> Hash {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&self.header.version.to_be_bytes());
        if let Some(ref chain) = self.header.external_chain {
            hasher.update([1u8]);
            hasher.update(chain.as_bytes());
        } else {
            hasher.update([0u8]);
        }
        hasher.update(&self.header.epoch.to_be_bytes());
        hasher.update(&self.header.slot.to_be_bytes());
        hasher.update(self.header.previous_proof_hash);
        hasher.update(self.header.state_root);
        hasher.update(self.header.dag_root);
        hasher.update(self.header.parent_block_hash);
        hasher.update(self.header.chain_work.to_be_bytes());
        hasher.update(self.header.validator_set_root);
        hasher.update(self.header.total_stake.to_be_bytes());
        hasher.update(self.header.stake_threshold.to_be_bytes());
        hasher.update(self.header.emitted_at_ms.to_be_bytes());
        for v in &self.validators {
            hasher.update(v.address);
            hasher.update((v.public_key.len() as u32).to_be_bytes());
            hasher.update(&v.public_key);
            hasher.update(v.stake.to_be_bytes());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    /// Returns the message that validators actually signed.
    /// For native proofs (no external_chain): `with_domain(DOMAIN_CHECKPOINT, &checkpoint_hash)`.
    /// For external proofs: `proof.signing_digest()`.
    pub fn signed_message(&self) -> Vec<u8> {
        if self.header.external_chain.is_none() && self.header.checkpoint_hash != [0u8; 32] {
            with_domain(DOMAIN_CHECKPOINT, &self.header.checkpoint_hash)
        } else {
            self.signing_digest().to_vec()
        }
    }

    pub fn proof_hash(&self) -> Hash {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(self.signing_digest());
        for sig in &self.signatures {
            hasher.update(sig.validator_index.to_be_bytes());
            hasher.update([sig.algo as u8]);
            hasher.update((sig.signature.len() as u32).to_be_bytes());
            hasher.update(&sig.signature);
        }
        hasher.update(self.header.stark_commitment);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    pub fn signed_stake(&self) -> u128 {
        self.signatures
            .iter()
            .filter_map(|s| self.validators.get(s.validator_index as usize))
            .fold(0u128, |acc, v| acc.saturating_add(v.stake))
    }

    pub fn meets_threshold(&self) -> bool {
        self.signed_stake() >= self.header.stake_threshold
    }
}
