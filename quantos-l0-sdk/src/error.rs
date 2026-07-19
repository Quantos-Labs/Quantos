use crate::types::{Hash, ValidatorRecord};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum L0Error {
    #[error("unsupported proof version: {0}")]
    UnsupportedVersion(u16),
    #[error("unknown validator set: {0}")]
    UnknownValidatorSet(String),
    #[error("invalid checkpoint: {0}")]
    InvalidCheckpoint(String),
    #[error("insufficient stake: signed={signed}, required={required}")]
    InsufficientStake { signed: u128, required: u128 },
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("permanent relay error: {0}")]
    PermanentRelay(String),
    #[error("http error: {0}")]
    Http(String),
}

pub type L0Result<T> = Result<T, L0Error>;

#[derive(Clone, Debug)]
pub struct ValidatorSetSnapshot {
    pub root: Hash,
    pub validators: Vec<ValidatorRecord>,
}

impl ValidatorSetSnapshot {
    pub fn total_stake(&self) -> u128 {
        self.validators
            .iter()
            .fold(0u128, |acc, v| acc.saturating_add(v.stake))
    }

    pub fn position_of(&self, address: &[u8; 32]) -> Option<usize> {
        self.validators.iter().position(|v| v.address == *address)
    }

    pub fn compute_root(records: &[ValidatorRecord]) -> Hash {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        for v in records {
            hasher.update(v.address);
            hasher.update((v.public_key.len() as u32).to_be_bytes());
            hasher.update(&v.public_key);
            hasher.update(v.stake.to_be_bytes());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }
}

#[derive(Clone, Debug)]
pub struct VerificationReport {
    pub signed_stake: u128,
    pub stake_threshold: u128,
    pub valid_signatures: usize,
    pub invalid_signatures: usize,
}

impl VerificationReport {
    pub fn is_final(&self) -> bool {
        self.invalid_signatures == 0 && self.signed_stake >= self.stake_threshold
    }
}
