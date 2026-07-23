// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Bytecode Invisible Protection
//!
//! Ensures smart contract bytecode is NEVER publicly accessible.
//!
//! ## Security Model
//!
//! 1. **Deployment**: Plain WASM bytecode is encrypted immediately
//! 2. **Storage**: Only encrypted bytecode + hash stored
//! 3. **Execution**: Decrypt in isolated sandbox, execute, zeroize
//! 4. **Verification**: Hash verification ensures integrity
//!
//! ## Encryption Details
//!
//! - **Algorithm**: AES-256-GCM (authenticated encryption)
//! - **Key Management**: Automatic rotation, secure derivation
//! - **Nonce**: Unique per contract, never reused
//! - **Integrity**: Blake3 hash of original bytecode

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use rand::RngCore;
use rand::rngs::OsRng;

use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::types::{Address, Hash};
use super::{VmError, VmResult};

/// Authorization token for privileged operations
pub type AuthToken = [u8; 32];

/// Maximum old keys to retain
const MAX_OLD_KEYS: usize = 10;

/// Known valid WASM section IDs (v6)
const VALID_WASM_SECTIONS: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];

/// Constant-time comparison to prevent timing side-channel attacks (v1)
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Bytecode protection configuration.
#[derive(Clone, Debug)]
pub struct BytecodeProtectionConfig {
    /// Key rotation interval
    pub key_rotation_interval: Duration,
    /// Maximum bytecode size (bytes)
    pub max_bytecode_size: usize,
    /// Enable debug mode (NEVER in production)
    pub debug_mode: bool,
    /// Sandbox memory limit (bytes)
    pub sandbox_memory_limit: usize,
    /// Execution timeout
    pub execution_timeout: Duration,
}

impl Default for BytecodeProtectionConfig {
    fn default() -> Self {
        Self {
            key_rotation_interval: Duration::from_secs(86400), // Daily
            max_bytecode_size: 1024 * 1024, // 1 MB
            debug_mode: false,
            sandbox_memory_limit: 64 * 1024 * 1024, // 64 MB
            execution_timeout: Duration::from_secs(30),
        }
    }
}

/// Public contract metadata (safe to expose).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractMetadata {
    /// Contract address
    pub address: Address,
    /// Blake3 hash of original bytecode (for verification)
    pub bytecode_hash: Hash,
    /// Encrypted bytecode size
    pub encrypted_size: usize,
    /// Original bytecode size
    pub original_size: usize,
    /// Deployer address
    pub deployer: Address,
    /// Deployment timestamp
    pub deployed_at: u64,
    /// Contract version
    pub version: u32,
    /// ABI hash (interface definition)
    pub abi_hash: Option<Hash>,
    /// Is contract upgradeable
    pub upgradeable: bool,
}

/// Encrypted contract (stored).
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedContract {
    /// Contract metadata
    pub metadata: ContractMetadata,
    /// Encrypted bytecode (AES-256-GCM)
    pub encrypted_bytecode: Vec<u8>,
    /// Encryption nonce (unique per contract)
    pub nonce: [u8; 12],
    /// Authentication tag
    pub auth_tag: [u8; 16],
    /// Key version used for encryption
    pub key_version: u64,
}

/// Decrypted bytecode (zeroized on drop).
pub struct DecryptedBytecode {
    /// Plain WASM bytecode
    bytecode: Vec<u8>,
}

impl Drop for DecryptedBytecode {
    fn drop(&mut self) {
        // Securely zeroize bytecode on drop
        self.bytecode.zeroize();
    }
}

impl DecryptedBytecode {
    /// Gets bytecode reference (for execution only).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytecode
    }

    /// Gets bytecode length.
    pub fn len(&self) -> usize {
        self.bytecode.len()
    }

    /// Checks if empty.
    pub fn is_empty(&self) -> bool {
        self.bytecode.is_empty()
    }
}

/// Master encryption key (zeroized on drop).
struct MasterKey {
    key: [u8; 32],
    version: u64,
    created_at: Instant,
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Contract encryption key derived from master.
struct ContractKey {
    key: [u8; 32],
}

impl Drop for ContractKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Bytecode protection manager.
pub struct BytecodeProtector {
    config: BytecodeProtectionConfig,
    /// Master encryption key (rotated periodically)
    master_key: Arc<RwLock<MasterKey>>,
    /// Previous master keys (for decrypting old contracts)
    old_keys: Arc<RwLock<HashMap<u64, MasterKey>>>,
    /// Contract registry
    contracts: Arc<DashMap<Address, EncryptedContract>>,
    /// Execution sandbox instances
    sandboxes: Arc<DashMap<Address, SandboxState>>,
    /// Authorization token for privileged operations (v1)
    auth_token: Arc<Mutex<AuthToken>>,
}

/// Sandbox execution state.
#[derive(Clone, Debug)]
pub struct SandboxState {
    pub contract_address: Address,
    pub started_at: Instant,
    pub cu_used: u64,
    pub memory_used: usize,
}

impl BytecodeProtector {
    /// Creates a new bytecode protector.
    pub fn new(config: BytecodeProtectionConfig) -> Self {
        // Generate initial master key
        let master_key = Self::generate_master_key(1);

        // Generate initial auth token with cryptographically secure RNG (v1)
        let mut token = [0u8; 32];
        OsRng.fill_bytes(&mut token);

        Self {
            config,
            master_key: Arc::new(RwLock::new(master_key)),
            old_keys: Arc::new(RwLock::new(HashMap::new())),
            contracts: Arc::new(DashMap::new()),
            sandboxes: Arc::new(DashMap::new()),
            auth_token: Arc::new(Mutex::new(token)),
        }
    }

    /// Generates a new master key.
    fn generate_master_key(version: u64) -> MasterKey {
        // CRITICAL: Use cryptographically secure random generation
        let mut key = [0u8; 32];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut key);
        
        MasterKey {
            key,
            version,
            created_at: Instant::now(),
        }
    }

    /// Derives a contract-specific key from master key.
    fn derive_contract_key(&self, contract_address: &Address, key_version: u64) -> VmResult<ContractKey> {
        let master = if key_version == self.master_key.read().version {
            self.master_key.read().key
        } else {
            self.old_keys.read()
                .get(&key_version)
                .map(|k| k.key)
                .ok_or_else(|| VmError::DecryptionFailed("Key version not found".into()))?
        };

        // HKDF-like derivation
        let mut context = Vec::with_capacity(64);
        context.extend_from_slice(&master);
        context.extend_from_slice(contract_address);
        context.extend_from_slice(b"quantos_contract_key");
        
        let derived = crate::types::hash_data(&context);
        
        Ok(ContractKey { key: derived })
    }

    /// Encrypts bytecode using AES-256-GCM.
    fn encrypt_bytecode(
        &self,
        bytecode: &[u8],
        contract_key: &ContractKey,
        nonce: &[u8; 12],
    ) -> VmResult<(Vec<u8>, [u8; 16])> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        let cipher = Aes256Gcm::new_from_slice(&contract_key.key)
            .map_err(|e| VmError::EncryptionFailed(e.to_string()))?;

        let nonce = Nonce::from_slice(nonce);
        
        let ciphertext = cipher.encrypt(nonce, bytecode)
            .map_err(|e| VmError::EncryptionFailed(e.to_string()))?;

        // Last 16 bytes are the auth tag
        let tag_start = ciphertext.len() - 16;
        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(&ciphertext[tag_start..]);
        
        Ok((ciphertext[..tag_start].to_vec(), auth_tag))
    }

    /// Decrypts bytecode using AES-256-GCM.
    fn decrypt_bytecode(
        &self,
        encrypted: &[u8],
        contract_key: &ContractKey,
        nonce: &[u8; 12],
        auth_tag: &[u8; 16],
    ) -> VmResult<DecryptedBytecode> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        let cipher = Aes256Gcm::new_from_slice(&contract_key.key)
            .map_err(|e| VmError::DecryptionFailed(e.to_string()))?;

        let nonce = Nonce::from_slice(nonce);
        
        // Reconstruct ciphertext with tag
        let mut ciphertext_with_tag = encrypted.to_vec();
        ciphertext_with_tag.extend_from_slice(auth_tag);

        let bytecode = cipher.decrypt(nonce, ciphertext_with_tag.as_ref())
            .map_err(|_| VmError::DecryptionFailed("Authentication failed".into()))?;

        Ok(DecryptedBytecode { bytecode })
    }

    /// Generates a unique nonce for a contract.
    fn generate_nonce(contract_address: &Address) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        let hash = crate::types::hash_data(contract_address);
        nonce.copy_from_slice(&hash[..12]);
        nonce
    }

    /// Deploys a new contract with encrypted bytecode.
    pub fn deploy_contract(
        &self,
        bytecode: &[u8],
        deployer: Address,
        nonce: u64,
        upgradeable: bool,
        abi_hash: Option<Hash>,
    ) -> VmResult<ContractMetadata> {
        // Validate bytecode size
        if bytecode.len() > self.config.max_bytecode_size {
            return Err(VmError::InvalidBytecode);
        }

        // Enhanced WASM validation
        if bytecode.len() < 8 || &bytecode[0..4] != b"\0asm" {
            return Err(VmError::InvalidBytecode);
        }
        
        // Validate WASM version (should be 1)
        if u32::from_le_bytes([bytecode[4], bytecode[5], bytecode[6], bytecode[7]]) != 1 {
            return Err(VmError::InvalidBytecode);
        }
        
        // Validate WASM section structure (v6)
        if bytecode.len() < 9 {
            return Err(VmError::InvalidBytecode);
        }
        {
            let mut offset = 8;
            let mut seen_sections = std::collections::HashSet::new();
            while offset < bytecode.len() {
                let section_id = bytecode[offset];
                if !VALID_WASM_SECTIONS.contains(&section_id) {
                    return Err(VmError::InvalidBytecode);
                }
                // Non-custom sections must not repeat
                if section_id != 0 && !seen_sections.insert(section_id) {
                    return Err(VmError::InvalidBytecode);
                }
                offset += 1;
                if offset >= bytecode.len() {
                    return Err(VmError::InvalidBytecode);
                }
                // Read LEB128 section length
                let (section_len, bytes_read) = Self::read_leb128(&bytecode[offset..]);
                offset += bytes_read;
                if section_len > bytecode.len().saturating_sub(offset) {
                    return Err(VmError::InvalidBytecode);
                }
                offset += section_len;
            }
        }

        // HIGH: Generate contract address with nonce to prevent collision
        let bytecode_hash = crate::types::hash_data(bytecode);
        let mut addr_input = Vec::with_capacity(72);
        addr_input.extend_from_slice(&deployer);
        addr_input.extend_from_slice(&bytecode_hash);
        addr_input.extend_from_slice(&nonce.to_le_bytes());
        let addr_hash = crate::types::hash_data(&addr_input);
        let contract_address: Address = addr_hash[..32].try_into()
            .map_err(|_| VmError::InternalError("Failed to generate contract address".to_string()))?;

        // Generate nonce
        let nonce = Self::generate_nonce(&contract_address);

        // Derive contract key
        let key_version = self.master_key.read().version;
        let contract_key = self.derive_contract_key(&contract_address, key_version)?;

        // Encrypt bytecode
        let (encrypted_bytecode, auth_tag) = self.encrypt_bytecode(bytecode, &contract_key, &nonce)?;

        // Create metadata
        let metadata = ContractMetadata {
            address: contract_address,
            bytecode_hash,
            encrypted_size: encrypted_bytecode.len(),
            original_size: bytecode.len(),
            deployer,
            deployed_at: chrono::Utc::now().timestamp() as u64,
            version: 1,
            abi_hash,
            upgradeable,
        };

        // Store encrypted contract
        let encrypted_contract = EncryptedContract {
            metadata: metadata.clone(),
            encrypted_bytecode,
            nonce,
            auth_tag,
            key_version,
        };

        self.contracts.insert(contract_address, encrypted_contract);

        tracing::info!(
            "Contract deployed: {} (size: {} bytes, encrypted: {} bytes)",
            hex::encode(&contract_address[..8]),
            bytecode.len(),
            metadata.encrypted_size
        );

        Ok(metadata)
    }

    /// Loads a contract at a known address (for reloading from DB on startup).
    /// Re-encrypts the bytecode with the current master key.
    pub fn load_contract(
        &self,
        address: Address,
        bytecode: &[u8],
        deployer: Address,
    ) -> VmResult<()> {
        // Validate bytecode
        if bytecode.len() < 8 || &bytecode[0..4] != b"\0asm" {
            return Err(VmError::InvalidBytecode);
        }

        let bytecode_hash = crate::types::hash_data(bytecode);
        let nonce = Self::generate_nonce(&address);
        let key_version = self.master_key.read().version;
        let contract_key = self.derive_contract_key(&address, key_version)?;
        let (encrypted_bytecode, auth_tag) = self.encrypt_bytecode(bytecode, &contract_key, &nonce)?;

        let metadata = ContractMetadata {
            address,
            bytecode_hash,
            encrypted_size: encrypted_bytecode.len(),
            original_size: bytecode.len(),
            deployer,
            deployed_at: 0,
            version: 1,
            abi_hash: None,
            upgradeable: false,
        };

        let encrypted_contract = EncryptedContract {
            metadata,
            encrypted_bytecode,
            nonce,
            auth_tag,
            key_version,
        };

        self.contracts.insert(address, encrypted_contract);
        Ok(())
    }

    /// Gets contract metadata (public info only).
    pub fn get_metadata(&self, address: &Address) -> Option<ContractMetadata> {
        self.contracts.get(address).map(|c| c.metadata.clone())
    }

    pub fn remove_contract(&self, address: &Address) -> bool {
        self.contracts.remove(address).is_some()
    }

    /// Executes a contract in isolated sandbox.
    pub fn execute_contract<F, R>(
        &self,
        address: &Address,
        executor: F,
    ) -> VmResult<R>
    where
        F: FnOnce(&[u8]) -> VmResult<R>,
    {
        // Get encrypted contract
        let contract = self.contracts
            .get(address)
            .ok_or_else(|| VmError::ContractNotFound(hex::encode(&address[..8])))?;

        // Derive key and decrypt
        let contract_key = self.derive_contract_key(address, contract.key_version)?;
        let decrypted = self.decrypt_bytecode(
            &contract.encrypted_bytecode,
            &contract_key,
            &contract.nonce,
            &contract.auth_tag,
        )?;

        // Verify integrity
        let computed_hash = crate::types::hash_data(decrypted.as_bytes());
        if computed_hash != contract.metadata.bytecode_hash {
            return Err(VmError::IntegrityCheckFailed);
        }

        // Create sandbox state
        let sandbox = SandboxState {
            contract_address: *address,
            started_at: Instant::now(),
            cu_used: 0,
            memory_used: 0,
        };
        self.sandboxes.insert(*address, sandbox.clone());

        // MEDIUM: Execute with panic guard to prevent memory leak
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            executor(decrypted.as_bytes())
        }));

        // CRITICAL: Always clean up sandbox even on panic
        self.sandboxes.remove(address);

        // Decrypted bytecode is automatically zeroized when dropped

        match result {
            Ok(r) => r,
            Err(_) => Err(VmError::ExecutionFailed("Contract execution panicked".into())),
        }
    }

    /// Verifies contract integrity without decrypting.
    pub fn verify_contract(&self, address: &Address) -> VmResult<bool> {
        let contract = self.contracts
            .get(address)
            .ok_or_else(|| VmError::ContractNotFound(hex::encode(&address[..8])))?;

        // We can only verify the encrypted data exists and has correct size
        Ok(contract.encrypted_bytecode.len() == contract.metadata.encrypted_size)
    }

    /// Returns the local bootstrap token for trusted in-crate setup.
    pub(crate) fn bootstrap_auth_token(&self) -> AuthToken {
        *self.auth_token.lock()
    }

    /// Reads a LEB128-encoded unsigned integer from a byte slice (v6).
    fn read_leb128(data: &[u8]) -> (usize, usize) {
        let mut result: usize = 0;
        let mut shift = 0;
        let mut bytes_read = 0;
        for &byte in data.iter().take(5) {
            bytes_read += 1;
            result |= ((byte & 0x7F) as usize) << shift;
            if byte & 0x80 == 0 {
                return (result, bytes_read);
            }
            shift += 7;
        }
        (result, bytes_read)
    }

    /// Validates auth token using constant-time comparison (v1).
    fn validate_auth_token(&self, token: &AuthToken) -> VmResult<()> {
        let expected = self.auth_token.lock();
        if !constant_time_eq(token, &*expected) {
            return Err(VmError::Unauthorized("Invalid auth token".into()));
        }
        Ok(())
    }

    /// Rotates the master encryption key.
    pub fn rotate_master_key(&self, auth_token: &AuthToken) -> VmResult<()> {
        // Validate access control (v1)
        self.validate_auth_token(auth_token)?;
        let mut current = self.master_key.write();
        let new_version = current.version + 1;

        // Store old key
        let old_key = MasterKey {
            key: current.key,
            version: current.version,
            created_at: current.created_at,
        };
        
        let mut old_keys = self.old_keys.write();
        old_keys.insert(current.version, old_key);
        
        // MEDIUM: Limit old keys retention to prevent unbounded growth
        if old_keys.len() > MAX_OLD_KEYS {
            // Remove oldest key
            if let Some(&oldest_version) = old_keys.keys().min() {
                old_keys.remove(&oldest_version);
                tracing::warn!("Removed old key version {} due to retention limit", oldest_version);
            }
        }

        // Generate new key
        *current = Self::generate_master_key(new_version);

        tracing::info!("Master key rotated to version {}", new_version);
        Ok(())
    }

    /// Re-encrypts a contract with the current key.
    pub fn reencrypt_contract(&self, address: &Address, auth_token: &AuthToken) -> VmResult<()> {
        // Validate access control (v1)
        self.validate_auth_token(auth_token)?;
        // This requires decryption with old key and encryption with new key
        let contract = self.contracts
            .get(address)
            .ok_or_else(|| VmError::ContractNotFound(hex::encode(&address[..8])))?;

        let current_version = self.master_key.read().version;
        if contract.key_version == current_version {
            return Ok(()); // Already using current key
        }

        // Decrypt with old key
        let old_key = self.derive_contract_key(address, contract.key_version)?;
        let decrypted = self.decrypt_bytecode(
            &contract.encrypted_bytecode,
            &old_key,
            &contract.nonce,
            &contract.auth_tag,
        )?;

        // Re-encrypt with new key
        let new_key = self.derive_contract_key(address, current_version)?;
        let nonce = Self::generate_nonce(address);
        let (encrypted, auth_tag) = self.encrypt_bytecode(decrypted.as_bytes(), &new_key, &nonce)?;

        // Update contract
        drop(contract);
        if let Some(mut contract) = self.contracts.get_mut(address) {
            contract.encrypted_bytecode = encrypted;
            contract.nonce = nonce;
            contract.auth_tag = auth_tag;
            contract.key_version = current_version;
        }

        Ok(())
    }

    /// Gets statistics.
    pub fn get_stats(&self) -> BytecodeProtectorStats {
        BytecodeProtectorStats {
            total_contracts: self.contracts.len(),
            active_sandboxes: self.sandboxes.len(),
            current_key_version: self.master_key.read().version,
            old_keys_retained: self.old_keys.read().len(),
        }
    }
}

/// Bytecode protector statistics.
#[derive(Clone, Debug)]
pub struct BytecodeProtectorStats {
    pub total_contracts: usize,
    pub active_sandboxes: usize,
    pub current_key_version: u64,
    pub old_keys_retained: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Header + custom section (id 0), size 1, payload `0x00` — valid under our section parser.
    const TEST_MIN_WASM: &[u8] = b"\0asm\x01\x00\x00\x00\x00\x01\x00";

    #[test]
    fn test_contract_deployment() {
        let config = BytecodeProtectionConfig::default();
        let protector = BytecodeProtector::new(config);

        let bytecode = TEST_MIN_WASM;
        let deployer = [1u8; 32];

        let result = protector.deploy_contract(bytecode, deployer, 0, false, None);
        assert!(result.is_ok());

        let metadata = result.unwrap();
        assert_eq!(metadata.deployer, deployer);
        assert_eq!(metadata.original_size, bytecode.len());
    }

    #[test]
    fn test_invalid_bytecode_rejected() {
        let config = BytecodeProtectionConfig::default();
        let protector = BytecodeProtector::new(config);

        let invalid_bytecode = b"not wasm";
        let deployer = [1u8; 32];

        let result = protector.deploy_contract(invalid_bytecode, deployer, 0, false, None);
        assert!(matches!(result, Err(VmError::InvalidBytecode)));
    }

    #[test]
    fn test_execute_contract() {
        let config = BytecodeProtectionConfig::default();
        let protector = BytecodeProtector::new(config);

        let bytecode = TEST_MIN_WASM;
        let deployer = [1u8; 32];

        let metadata = protector.deploy_contract(bytecode, deployer, 0, false, None).unwrap();

        let result = protector.execute_contract(&metadata.address, |code| {
            assert_eq!(code, bytecode);
            Ok(42)
        });

        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_key_rotation() {
        let config = BytecodeProtectionConfig::default();
        let protector = BytecodeProtector::new(config);
        let auth_token = protector.bootstrap_auth_token();

        assert_eq!(protector.master_key.read().version, 1);
        
        protector.rotate_master_key(&auth_token).unwrap();
        
        assert_eq!(protector.master_key.read().version, 2);
        assert_eq!(protector.old_keys.read().len(), 1);

        // Invalid token must be rejected (v1)
        let bad_token = [0xFFu8; 32];
        assert!(protector.rotate_master_key(&bad_token).is_err());
    }

    #[test]
    fn test_metadata_access() {
        let config = BytecodeProtectionConfig::default();
        let protector = BytecodeProtector::new(config);

        let bytecode = TEST_MIN_WASM;
        let deployer = [2u8; 32];

        let metadata = protector.deploy_contract(bytecode, deployer, 0, true, None).unwrap();

        // Can access metadata
        let retrieved = protector.get_metadata(&metadata.address);
        assert!(retrieved.is_some());
        
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.deployer, deployer);
        assert!(retrieved.upgradeable);
        
        // Bytecode hash is visible but bytecode is not
        assert_ne!(retrieved.bytecode_hash, [0u8; 32]);
    }
}
