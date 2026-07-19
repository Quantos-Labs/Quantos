// src/crypto.rs — Post-quantum cryptography for the wallet server

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AesOsRng},
    Aes256Gcm, Nonce,
};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey, SignedMessage};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use crate::error::{WalletError, WalletResult};
use crate::types::{Amount, SignedTransaction, Transaction, TransactionType, VmKind};

const DOMAIN_TX: &[u8] = b"QUANTOS_TX_V1";

pub const PK_SIZE: usize = 1952;
pub const SK_SIZE: usize = 4032; // pqcrypto-mldsa actual size
pub const SIG_SIZE: usize = 3309;

// ── Keypair ───────────────────────────────────────────────────────────────────

pub struct ZeroizedSecretKey(pub Vec<u8>);

impl Drop for ZeroizedSecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct MlDsa65Keypair {
    pub public_key: Vec<u8>,
    pub secret_key: ZeroizedSecretKey,
    pub address: [u8; 32],
}

impl MlDsa65Keypair {
    pub fn generate() -> WalletResult<Self> {
        let (pk, sk) = mldsa65::keypair();
        let pk_bytes = pk.as_bytes().to_vec();
        let sk_bytes = sk.as_bytes().to_vec();
        let address = derive_address(&pk_bytes);
        Ok(Self {
            public_key: pk_bytes,
            secret_key: ZeroizedSecretKey(sk_bytes),
            address,
        })
    }

    pub fn from_secret_key_hex(sk_hex: &str) -> WalletResult<Self> {
        let sk_bytes = hex::decode(sk_hex)
            .map_err(|e| WalletError::InvalidSecretKey(format!("Bad hex: {}", e)))?;
        if sk_bytes.len() != SK_SIZE {
            return Err(WalletError::InvalidSecretKey(format!(
                "Expected {} bytes, got {}",
                SK_SIZE,
                sk_bytes.len()
            )));
        }
        
        // Reconstruct keypair from secret key to get the correct public key
        let sk = mldsa65::SecretKey::from_bytes(&sk_bytes)
            .map_err(|e| WalletError::InvalidSecretKey(format!("Invalid SK bytes: {:?}", e)))?;
        
        // Extract public key from secret key bytes.
        // In pqcrypto-mldsa, the SK contains the PK at the end.
        let sk_len = sk_bytes.len();
        let pk_bytes = sk_bytes[sk_len - PK_SIZE..].to_vec();
        let address = derive_address(&pk_bytes);
        
        Ok(Self {
            public_key: pk_bytes,
            secret_key: ZeroizedSecretKey(sk_bytes),
            address,
        })
    }

    /// Reconstruct keypair from separate SK and PK hex strings (preferred method).
    pub fn from_sk_and_pk_hex(sk_hex: &str, pk_hex: &str) -> WalletResult<Self> {
        let sk_bytes = hex::decode(sk_hex)
            .map_err(|e| WalletError::InvalidSecretKey(format!("Bad SK hex: {}", e)))?;
        let pk_bytes = hex::decode(pk_hex)
            .map_err(|e| WalletError::InvalidSecretKey(format!("Bad PK hex: {}", e)))?;

        // Validate both keys can be parsed by pqcrypto
        let _sk = mldsa65::SecretKey::from_bytes(&sk_bytes)
            .map_err(|e| WalletError::InvalidSecretKey(format!("Invalid SK: {:?}", e)))?;
        let _pk = mldsa65::PublicKey::from_bytes(&pk_bytes)
            .map_err(|e| WalletError::InvalidSecretKey(format!("Invalid PK: {:?}", e)))?;

        let address = derive_address(&pk_bytes);
        Ok(Self {
            public_key: pk_bytes,
            secret_key: ZeroizedSecretKey(sk_bytes),
            address,
        })
    }

    pub fn sign(&self, data: &[u8]) -> WalletResult<Vec<u8>> {
        let sk = mldsa65::SecretKey::from_bytes(&self.secret_key.0)
            .map_err(|e| WalletError::CryptoError(format!("Invalid SK: {:?}", e)))?;
        let sig = mldsa65::detached_sign(data, &sk);
        let sig_bytes = sig.as_bytes().to_vec();

        Ok(sig_bytes)
    }
}

/// Verify an ML-DSA-65 detached signature against a public key.
pub fn verify_ml_dsa_65_signature(
    message: &[u8],
    signature_hex: &str,
    public_key_hex: &str,
) -> WalletResult<bool> {
    let sig_bytes = hex::decode(signature_hex)
        .map_err(|e| WalletError::CryptoError(format!("Bad signature hex: {}", e)))?;
    let pk_bytes = hex::decode(public_key_hex)
        .map_err(|e| WalletError::CryptoError(format!("Bad public key hex: {}", e)))?;

    let sig = mldsa65::DetachedSignature::from_bytes(&sig_bytes)
        .map_err(|e| WalletError::CryptoError(format!("Invalid signature: {:?}", e)))?;
    let pk = mldsa65::PublicKey::from_bytes(&pk_bytes)
        .map_err(|e| WalletError::CryptoError(format!("Invalid public key: {:?}", e)))?;

    match mldsa65::verify_detached_signature(&sig, message, &pk) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ── Address ───────────────────────────────────────────────────────────────────

pub fn derive_address(public_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(public_key);
    let result = hasher.finalize();
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&result);
    addr
}

pub fn address_to_qts(address: &[u8; 32]) -> String {
    let checksum = {
        let mut h = Sha3_256::new();
        h.update(address);
        h.finalize()
    };
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(address);         // full 32 bytes
    data.extend_from_slice(&checksum[..4]);  // 4-byte checksum
    let encoded = data_encoding::BASE32_NOPAD.encode(&data).to_lowercase();
    format!("qts1{}", encoded)
}

pub fn parse_address(s: &str) -> WalletResult<[u8; 32]> {
    if s.starts_with("qts1") {
        return decode_qts_address(s);
    }
    let hex_s = s
        .strip_prefix("QTS:")
        .or_else(|| s.strip_prefix("qts:"))
        .or_else(|| s.strip_prefix("0x"))
        .unwrap_or(s);
    let bytes = hex::decode(hex_s)
        .map_err(|e| WalletError::InvalidAddress(format!("Bad hex: {}", e)))?;
    bytes
        .try_into()
        .map_err(|_| WalletError::InvalidAddress("Expected 32 bytes".to_string()))
}

fn decode_qts_address(qts_addr: &str) -> WalletResult<[u8; 32]> {
    let encoded = &qts_addr[4..];
    let decoded = data_encoding::BASE32_NOPAD
        .decode(encoded.to_uppercase().as_bytes())
        .map_err(|e| WalletError::InvalidAddress(format!("Bad base32: {}", e)))?;
    // Support both old 24-byte (20+4) and new 36-byte (32+4) formats
    if decoded.len() == 36 {
        let addr_bytes = &decoded[..32];
        let checksum_bytes = &decoded[32..36];
        let expected = {
            let mut h = Sha3_256::new();
            h.update(addr_bytes);
            h.finalize()
        };
        if checksum_bytes != &expected[..4] {
            return Err(WalletError::InvalidAddress("Invalid checksum".to_string()));
        }
        let mut full = [0u8; 32];
        full.copy_from_slice(addr_bytes);
        Ok(full)
    } else if decoded.len() == 24 {
        // Legacy 20-byte format — pad with zeros (backward compat)
        let addr_bytes = &decoded[..20];
        let checksum_bytes = &decoded[20..24];
        let expected = {
            let mut h = Sha3_256::new();
            h.update(addr_bytes);
            h.finalize()
        };
        if checksum_bytes != &expected[..4] {
            return Err(WalletError::InvalidAddress("Invalid checksum".to_string()));
        }
        let mut full = [0u8; 32];
        full[..20].copy_from_slice(addr_bytes);
        Ok(full)
    } else {
        Err(WalletError::InvalidAddress(format!(
            "Expected 36 or 24 bytes, got {}", decoded.len()
        )))
    }
}

// ── AES-256-GCM PIN encryption ────────────────────────────────────────────────

pub fn encrypt_with_pin(secret_key_hex: &str, pin: &str) -> WalletResult<String> {
    let key_bytes = pin_to_key(pin);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| WalletError::EncryptionError(e.to_string()))?;
    let nonce = Aes256Gcm::generate_nonce(&mut AesOsRng);
    let ciphertext = cipher
        .encrypt(&nonce, secret_key_hex.as_bytes())
        .map_err(|e| WalletError::EncryptionError(e.to_string()))?;
    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ciphertext);
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &combined,
    ))
}

pub fn decrypt_with_pin(encrypted_b64: &str, pin: &str) -> WalletResult<String> {
    let combined = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        encrypted_b64,
    )
    .map_err(|_| WalletError::DecryptionFailed)?;

    if combined.len() < 12 {
        return Err(WalletError::DecryptionFailed);
    }
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let key_bytes = pin_to_key(pin);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|_| WalletError::DecryptionFailed)?;
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| WalletError::DecryptionFailed)?;
    String::from_utf8(plaintext).map_err(|_| WalletError::DecryptionFailed)
}

fn pin_to_key(pin: &str) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"quantos-wallet-pin-v1:");
    hasher.update(pin.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

pub fn validate_pin(pin: &str) -> WalletResult<()> {
    if pin.len() != 6 || !pin.chars().all(|c| c.is_ascii_digit()) {
        return Err(WalletError::InvalidPin);
    }
    Ok(())
}

// ── Transaction building ───────────────────────────────────────────────────────

pub fn build_signed_transaction(
    keypair: &MlDsa65Keypair,
    tx_type: TransactionType,
    to: [u8; 32],
    amount: u128,
    nonce: u64,
    chain_id: u64,
    num_shards: u16,
) -> WalletResult<(String, String)> {
    let from = keypair.address;
    let num_shards = if num_shards == 0 { 1 } else { num_shards };
    let shard_id = target_shard(&from, num_shards);
    let timestamp = chrono::Utc::now().timestamp() as u64;

    let mut tx = Transaction {
        tx_type,
        from,
        to,
        amount: Amount(amount),
        nonce,
        max_compute_units: 21000,
        boost: None,
        vm_kind: VmKind::Qvm,
        data: Vec::new(),
        shard_id,
        timestamp,
        signature: Vec::new(),
        public_key: Vec::new(),
        chain_id,
    };

    let signing_data = transaction_signing_data(&tx);
    let signature = keypair.sign(&signing_data)?;
    tx.signature = signature;
    tx.public_key = keypair.public_key.clone();

    let hash = transaction_hash(&tx);
    let size = bincode::serialize(&tx).map(|v| v.len()).unwrap_or(0);

    let signed = SignedTransaction {
        transaction: tx,
        hash,
        size,
    };

    let tx_bytes = bincode::serialize(&signed)
        .map_err(|e| WalletError::SerializationError(e.to_string()))?;
    let tx_hex = hex::encode(&tx_bytes);
    let tx_hash = hex::encode(hash);

    Ok((tx_hex, tx_hash))
}

pub fn build_signed_transaction_with_data(
    keypair: &MlDsa65Keypair,
    tx_type: TransactionType,
    to: [u8; 32],
    amount: u128,
    data: Vec<u8>,
    gas_limit: u64,
    nonce: u64,
    chain_id: u64,
    num_shards: u16,
) -> WalletResult<(String, String)> {
    let from = keypair.address;
    let num_shards = if num_shards == 0 { 1 } else { num_shards };
    let shard_id = target_shard(&from, num_shards);
    let timestamp = chrono::Utc::now().timestamp() as u64;

    let mut tx = Transaction {
        tx_type,
        from,
        to,
        amount: Amount(amount),
        nonce,
        max_compute_units: gas_limit,
        boost: None,
        vm_kind: VmKind::Qvm,
        data,
        shard_id,
        timestamp,
        signature: Vec::new(),
        public_key: Vec::new(),
        chain_id,
    };

    let signing_data = transaction_signing_data(&tx);
    let signature = keypair.sign(&signing_data)?;
    tx.signature = signature;
    tx.public_key = keypair.public_key.clone();

    let hash = transaction_hash(&tx);
    let size = bincode::serialize(&tx).map(|v| v.len()).unwrap_or(0);

    let signed = SignedTransaction {
        transaction: tx,
        hash,
        size,
    };

    let tx_bytes = bincode::serialize(&signed)
        .map_err(|e| WalletError::SerializationError(e.to_string()))?;
    let tx_hex = hex::encode(&tx_bytes);
    let tx_hash = hex::encode(hash);

    Ok((tx_hex, tx_hash))
}

fn transaction_signing_data(tx: &Transaction) -> Vec<u8> {
    let mut data = Vec::new();
    data.push(match &tx.tx_type {
        TransactionType::Transfer => 0u8,
        TransactionType::Stake => 1u8,
        TransactionType::Unstake => 2u8,
        TransactionType::ValidatorRegister => 3u8,
        TransactionType::ValidatorExit => 4u8,
        TransactionType::ContractCall => 5u8,
        TransactionType::ContractDeploy => 6u8,
    });
    data.extend_from_slice(&tx.from);
    data.extend_from_slice(&tx.to);
    data.extend_from_slice(&tx.amount.0.to_le_bytes());
    data.extend_from_slice(&tx.nonce.to_le_bytes());
    data.extend_from_slice(&tx.max_compute_units.to_le_bytes());
    if let Some(boost) = &tx.boost {
        data.extend_from_slice(&boost.locked_tokens.to_le_bytes());
        data.extend_from_slice(&boost.lock_duration_blocks.to_le_bytes());
    } else {
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
    }
    data.push(match tx.vm_kind {
        VmKind::Qvm => 0u8,
        VmKind::Evm => 1u8,
    });
    data.extend_from_slice(&tx.data);
    data.extend_from_slice(&tx.shard_id.to_le_bytes());
    data.extend_from_slice(&tx.timestamp.to_le_bytes());
    data.extend_from_slice(&tx.chain_id.to_le_bytes());

    let mut domain_prefixed = Vec::with_capacity(2 + DOMAIN_TX.len() + data.len());
    domain_prefixed.extend_from_slice(&(DOMAIN_TX.len() as u16).to_le_bytes());
    domain_prefixed.extend_from_slice(DOMAIN_TX);
    domain_prefixed.extend_from_slice(&data);
    domain_prefixed
}

fn transaction_hash(tx: &Transaction) -> [u8; 32] {
    let data = transaction_signing_data(tx);
    let mut hasher = Sha3_256::new();
    hasher.update(&data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

fn target_shard(address: &[u8; 32], num_shards: u16) -> u16 {
    let shard_bytes: [u8; 8] = address[..8].try_into().unwrap_or([0u8; 8]);
    let value = u64::from_le_bytes(shard_bytes);
    (value % num_shards as u64) as u16
}

pub fn format_qts(amount: u128, decimals: u32) -> String {
    let divisor = 10u128.pow(decimals);
    let whole = amount / divisor;
    let fraction = amount % divisor;
    format!("{}.{:0>width$} QTEST", whole, fraction, width = decimals as usize)
}

/// Format token amount with limited decimal places for display (e.g., 2 decimals for QTEST)
pub fn format_token(amount: u128, decimals: u32, display_decimals: u32, symbol: &str) -> String {
    let divisor = 10u128.pow(decimals);
    let whole = amount / divisor;
    let fraction = amount % divisor;
    
    // Scale fraction to display_decimals
    let display_divisor = 10u128.pow(decimals.saturating_sub(display_decimals));
    let scaled_fraction = if display_divisor > 0 {
        fraction / display_divisor
    } else {
        fraction
    };
    
    format!("{}.{:0>width$} {}", whole, scaled_fraction, symbol, width = display_decimals as usize)
}
