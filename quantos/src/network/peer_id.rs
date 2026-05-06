//! Quantos peer identifier: SHA2-256 multihash (same wire layout as legacy libp2p PeerIds).

use std::fmt;
use std::str::FromStr;

/// Raw multihash bytes: `0x12` (SHA2-256) + `0x20` (32) + digest.
pub const PEER_ID_RAW_LEN: usize = 34;

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PeerId(pub [u8; PEER_ID_RAW_LEN]);

#[derive(Debug, Clone)]
pub enum PeerIdParseError {
    BadBase58(bs58::decode::Error),
    BadLength(usize),
}

impl fmt::Display for PeerIdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerIdParseError::BadBase58(e) => write!(f, "invalid base58: {}", e),
            PeerIdParseError::BadLength(n) => write!(f, "expected {} raw bytes, got {}", PEER_ID_RAW_LEN, n),
        }
    }
}

impl std::error::Error for PeerIdParseError {}

impl PeerId {
    #[must_use]
    pub fn from_raw(raw: [u8; PEER_ID_RAW_LEN]) -> Self {
        Self(raw)
    }

    pub fn try_from_multihash_slice(slice: &[u8]) -> Result<Self, PeerIdParseError> {
        if slice.len() != PEER_ID_RAW_LEN {
            return Err(PeerIdParseError::BadLength(slice.len()));
        }
        let mut a = [0u8; PEER_ID_RAW_LEN];
        a.copy_from_slice(slice);
        Ok(Self(a))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
    }

    pub fn from_base58(s: &str) -> Result<Self, PeerIdParseError> {
        let v = bs58::decode(s).into_vec().map_err(PeerIdParseError::BadBase58)?;
        Self::try_from_multihash_slice(&v)
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base58())
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", self.to_base58())
    }
}

impl FromStr for PeerId {
    type Err = PeerIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_base58(s)
    }
}
