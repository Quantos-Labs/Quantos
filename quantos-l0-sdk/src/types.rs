use serde::{Deserialize, Serialize};

pub type Hash = [u8; 32];

pub const L0_PROOF_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PqcSignatureAlgo {
    Falcon512 = 1,
    Dilithium3 = 2,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct L0ProofHeader {
    pub version: u16,
    pub epoch: u64,
    pub slot: u64,
    pub previous_proof_hash: Hash,
    pub state_root: Hash,
    pub dag_root: Hash,
    pub validator_set_root: Hash,
    pub total_stake: u128,
    pub stake_threshold: u128,
    pub emitted_at_ms: u64,
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
}

impl L0FinalityProof {
    pub fn signing_digest(&self) -> Hash {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&self.header.version.to_be_bytes());
        hasher.update(&self.header.epoch.to_be_bytes());
        hasher.update(&self.header.slot.to_be_bytes());
        hasher.update(self.header.previous_proof_hash);
        hasher.update(self.header.state_root);
        hasher.update(self.header.dag_root);
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
