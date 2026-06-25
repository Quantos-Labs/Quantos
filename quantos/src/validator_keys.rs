//! # Quantos Validator Key Management
//!
//! Production-grade persistence for validator identity keys.
//! Each validator owns a unique set of three post-quantum keypairs:
//!
//! - **Dilithium-3** (`signing`) — vertex signatures, transaction auth, P2P identity.
//! - **SPHINCS+ / QR-VRF** (`vrf`) — committee selection and sortition.
//! - **ML-DSA-65** (`finality`) — checkpoint finality signatures (FIPS 204).
//!
//! Keys are stored in JSON with `0o600` permissions. The file is never sent over
//! the network and must be backed up securely.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::crypto::{DilithiumKeypair, MlDsa65Keypair, VRFKeypair};
use crate::types::{Address, hash_data};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct KeypairJson {
    pub algorithm: String,
    pub public_key: String,
    pub secret_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ValidatorKeySet {
    pub version: u32,
    pub name: Option<String>,
    pub address: String,
    pub address_hex: String,
    pub signing: KeypairJson,
    pub vrf: KeypairJson,
    pub finality: KeypairJson,
}

impl ValidatorKeySet {
    /// Generate a fresh validator key set from a secure RNG.
    pub fn generate(name: Option<String>) -> anyhow::Result<Self> {
        let signing = DilithiumKeypair::generate()
            .map_err(|e| anyhow::anyhow!("Dilithium key generation failed: {:?}", e))?;
        let vrf = VRFKeypair::generate()
            .map_err(|e| anyhow::anyhow!("VRF key generation failed: {:?}", e))?;
        let finality = MlDsa65Keypair::generate()
            .map_err(|e| anyhow::anyhow!("ML-DSA-65 key generation failed: {:?}", e))?;

        let address = signing.address();
        let address_hex = hex::encode(&address);
        let qts_address = crate::types::address_to_qts(&address);

        Ok(Self {
            version: 1,
            name,
            address: qts_address,
            address_hex,
            signing: KeypairJson {
                algorithm: "dilithium3".to_string(),
                public_key: hex::encode(&signing.public_key),
                secret_key: hex::encode(&signing.secret_key),
            },
            vrf: KeypairJson {
                algorithm: "qr_vrf".to_string(),
                public_key: hex::encode(vrf.public_key()),
                secret_key: hex::encode(vrf.secret_key()),
            },
            finality: KeypairJson {
                algorithm: "ml_dsa65".to_string(),
                public_key: hex::encode(&finality.public_key),
                secret_key: hex::encode(&finality.secret_key),
            },
        })
    }

    /// Load a key set from a JSON file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to read key file: {e}"))?;
        let keyset: Self = serde_json::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("Failed to parse key file: {e}"))?;
        Ok(keyset)
    }

    /// Save the key set to a JSON file with restrictive permissions.
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let raw = serde_json::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize key file: {e}"))?;
        std::fs::write(path.as_ref(), raw)
            .map_err(|e| anyhow::anyhow!("Failed to write key file: {e}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path.as_ref(), std::fs::Permissions::from_mode(0o600))
                .map_err(|e| anyhow::anyhow!("Failed to set key file permissions: {e}"))?;
        }
        Ok(())
    }

    /// Default key file path inside a data directory.
    pub fn default_path(datadir: &str) -> PathBuf {
        Path::new(datadir).join("validator_keys.json")
    }

    /// Reconstruct the Dilithium keypair from the stored secret key.
    pub fn signing_keypair(&self) -> anyhow::Result<DilithiumKeypair> {
        let secret_key = hex::decode(&self.signing.secret_key)
            .map_err(|e| anyhow::anyhow!("Invalid signing secret key: {e}"))?;
        DilithiumKeypair::from_secret_key(&secret_key)
            .map_err(|e| anyhow::anyhow!("Failed to load signing keypair: {e:?}"))
    }

    /// Reconstruct the VRF keypair from the stored secret key.
    pub fn vrf_keypair(&self) -> anyhow::Result<VRFKeypair> {
        let secret_key = hex::decode(&self.vrf.secret_key)
            .map_err(|e| anyhow::anyhow!("Invalid VRF secret key: {e}"))?;
        let public_key = hex::decode(&self.vrf.public_key)
            .map_err(|e| anyhow::anyhow!("Invalid VRF public key: {e}"))?;
        VRFKeypair::from_keys(public_key, secret_key)
            .map_err(|e| anyhow::anyhow!("Failed to load VRF keypair: {e:?}"))
    }

    /// Reconstruct the ML-DSA-65 keypair from the stored secret key.
    pub fn finality_keypair(&self) -> anyhow::Result<MlDsa65Keypair> {
        let secret_key = hex::decode(&self.finality.secret_key)
            .map_err(|e| anyhow::anyhow!("Invalid finality secret key: {e}"))?;
        MlDsa65Keypair::from_secret_key(&secret_key)
            .map_err(|e| anyhow::anyhow!("Failed to load finality keypair: {e:?}"))
    }

    /// Address bytes derived from the signing public key.
    pub fn address(&self) -> Address {
        let mut addr = [0u8; 32];
        if let Ok(bytes) = hex::decode(&self.address_hex) {
            if bytes.len() == 32 {
                addr.copy_from_slice(&bytes);
            }
        }
        addr
    }
}

/// Helper to derive a stable Quantos address from a public key.
pub fn address_from_pubkey(public_key: &[u8]) -> Address {
    hash_data(public_key)
}
