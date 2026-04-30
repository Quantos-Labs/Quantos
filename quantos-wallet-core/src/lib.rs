use wasm_bindgen::prelude::*;
use pqc_dilithium::Keypair;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

// Dilithium-3 constants
const SECRETKEYBYTES: usize = 4000;
const PUBLICKEYBYTES: usize = 1952;
const SIGNATUREBYTES: usize = 3293;

// ── Domain separation (must stay in sync with quantos/src/crypto/domains.rs) ──
//
// Every `signing_data()` method in the node prepends a length-prefixed domain
// tag so that a signature over a transaction cannot be replayed as a vote, a
// checkpoint, or any other message type.
//
// The tag format is: [u16-LE tag length] || [tag bytes] || [message bytes]
const DOMAIN_TX: &[u8] = b"QUANTOS_TX_V1";

/// Prepends the domain tag to `message`, mirroring `crypto::with_domain`.
fn with_domain(domain: &[u8], message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + domain.len() + message.len());
    out.extend_from_slice(&(domain.len() as u16).to_le_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(message);
    out
}

/// Constructs a `pqc_dilithium::Keypair` from raw public and secret key bytes.
///
/// # Safety
///
/// `pqc_dilithium 0.2.0::Keypair` is defined as:
/// ```ignore
/// pub struct Keypair {
///     pub public: [u8; 1952],
///     secret:     [u8; 4000],  // private field
/// }
/// ```
/// The struct carries no `#[repr(C)]` attribute, but both fields are `[u8; N]`
/// (alignment = 1, no padding possible). Rust's ABI for this specific layout
/// is identical to `([u8; 1952], [u8; 4000])`, making the transmute safe.
///
/// Risks and mitigations:
/// * **Field reorder**: the Rust compiler may reorder fields of structs
///   without `#[repr(C)]`, but gains nothing here (all fields have alignment 1),
///   so no reorder is expected or observed with rustc up to 1.87.
/// * **Version drift**: pinned to `pqc_dilithium = "0.2"` in `Cargo.toml`.
///   Any minor-version upgrade that changes the struct must be audited here.
/// * **Alternative**: `pqc_dilithium` does not expose a `Keypair::from_bytes`
///   constructor and `crypto_sign_signature` is not public, leaving transmute
///   as the only option short of forking the crate.
unsafe fn keypair_from_bytes(public: &[u8; PUBLICKEYBYTES], secret: &[u8; SECRETKEYBYTES]) -> Keypair {
    std::mem::transmute::<([u8; PUBLICKEYBYTES], [u8; SECRETKEYBYTES]), Keypair>((*public, *secret))
}

// ============================================================================
// Types — exact copy from quantos/src/types/
// These MUST stay in sync with the node for bincode compatibility.
// ============================================================================

pub type Address = [u8; 32];
pub type Hash = [u8; 32];
pub type Signature = Vec<u8>;
pub type PublicKey = Vec<u8>;
pub type ShardId = u16;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Amount(pub u128);

fn hash_data(data: &[u8]) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// ── Transaction types (from quantos/src/types/transaction.rs) ──

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransactionType {
    Transfer,
    Stake,
    Unstake,
    ValidatorRegister,
    ValidatorExit,
    ContractCall,
    ContractDeploy,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub tx_type: TransactionType,
    pub from: Address,
    pub to: Address,
    pub amount: Amount,
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub data: Vec<u8>,
    pub shard_id: ShardId,
    pub timestamp: u64,
    pub signature: Signature,
    pub public_key: PublicKey,
    pub chain_id: u64,
}

impl Transaction {
    /// Produces the byte string that is signed by the sender's Dilithium-3 key.
    ///
    /// **Must stay byte-for-byte identical to
    /// `quantos/src/types/transaction.rs::Transaction::signing_data()`.**
    ///
    /// Format: `with_domain(DOMAIN_TX, raw_fields)` where `raw_fields` is the
    /// concatenation of all transaction fields in the order below.
    pub fn signing_data(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&[self.tx_type.clone() as u8]);
        msg.extend_from_slice(&self.from);
        msg.extend_from_slice(&self.to);
        msg.extend_from_slice(&self.amount.0.to_le_bytes());
        msg.extend_from_slice(&self.nonce.to_le_bytes());
        msg.extend_from_slice(&self.gas_limit.to_le_bytes());
        msg.extend_from_slice(&self.gas_price.to_le_bytes());
        msg.extend_from_slice(&self.data);
        msg.extend_from_slice(&self.shard_id.to_le_bytes());
        msg.extend_from_slice(&self.timestamp.to_le_bytes());
        msg.extend_from_slice(&self.chain_id.to_le_bytes());
        with_domain(DOMAIN_TX, &msg)
    }

    pub fn hash(&self) -> Hash {
        hash_data(&self.signing_data())
    }

    pub fn target_shard(address: &Address, num_shards: u16) -> ShardId {
        let shard_bytes: [u8; 8] = address[..8].try_into().unwrap_or([0u8; 8]);
        let value = u64::from_le_bytes(shard_bytes);
        (value % num_shards as u64) as ShardId
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedTransaction {
    pub transaction: Transaction,
    pub hash: Hash,
    pub size: usize,
}

impl SignedTransaction {
    pub fn new(transaction: Transaction) -> Self {
        let hash = transaction.hash();
        let size = bincode::serialize(&transaction).map(|v| v.len()).unwrap_or(0);
        Self { transaction, hash, size }
    }
}

// ============================================================================
// WASM Exports
// ============================================================================

// ── Key Generation ──────────────────────────────────────────

/// Generate a new Dilithium-3 keypair.
/// Returns JSON: { "publicKey": hex, "secretKey": hex, "address": hex, "qtsAddress": string }
#[wasm_bindgen(js_name = "generateKeypair")]
pub fn generate_keypair() -> Result<String, JsValue> {
    let keys = Keypair::generate();
    let pk_bytes = keys.public.as_ref();
    let sk_bytes = keys.expose_secret().as_ref();
    let address = hash_data(pk_bytes);

    let qts_address = encode_qts_address(&address)
        .map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "publicKey": hex::encode(pk_bytes),
        "secretKey": hex::encode(sk_bytes),
        "address": hex::encode(address),
        "qtsAddress": qts_address,
    });

    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))
}

// ── Build + Sign + Serialize Transaction ────────────────────

/// Build, sign, and bincode-serialize a transfer transaction.
/// Returns JSON: { "txHex": hex, "txHash": hex }
///
/// This is the main function the wallet uses. The returned txHex can be
/// sent directly to qnt_sendRawTransaction.
#[wasm_bindgen(js_name = "buildSignedTransfer")]
pub fn build_signed_transfer(
    secret_key_hex: &str,
    to_hex: &str,
    amount_str: &str,
    nonce: u64,
    chain_id: u64,
    num_shards: u16,
) -> Result<String, JsValue> {
    // Parse inputs
    let sk_bytes = hex::decode(secret_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid secret key hex: {}", e)))?;
    let to = parse_address_hex(to_hex)?;
    let amount: u128 = amount_str.parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid amount: {}", e)))?;

    // Derive public key from secret key (last 1952 bytes, same as node)
    let pk_size = 1952usize;
    if sk_bytes.len() != 4000 {
        return Err(JsValue::from_str(&format!(
            "Invalid secret key length: {} (expected 4000)", sk_bytes.len()
        )));
    }
    let pk_bytes = &sk_bytes[sk_bytes.len() - pk_size..];
    let from = hash_data(pk_bytes);

    // Calculate shard
    let num_shards = if num_shards == 0 { 1 } else { num_shards };
    let shard_id = Transaction::target_shard(&from, num_shards);

    // Timestamp
    let timestamp = chrono::Utc::now().timestamp_millis() as u64;

    // Build transaction (gasless: gas_limit=21000, gas_price=0)
    let mut tx = Transaction {
        tx_type: TransactionType::Transfer,
        from,
        to,
        amount: Amount(amount),
        nonce,
        gas_limit: 21000,
        gas_price: 0,
        data: Vec::new(),
        shard_id,
        timestamp,
        signature: Vec::new(),
        public_key: Vec::new(),
        chain_id,
    };

    // Sign with Dilithium
    let signing_data = tx.signing_data();
    let pk_array: [u8; PUBLICKEYBYTES] = pk_bytes.try_into()
        .map_err(|_| JsValue::from_str("Invalid public key length"))?;
    let sk_array: [u8; SECRETKEYBYTES] = sk_bytes.as_slice().try_into()
        .map_err(|_| JsValue::from_str("Invalid secret key length"))?;
    
    let keypair = unsafe { keypair_from_bytes(&pk_array, &sk_array) };
    let sig = keypair.sign(&signing_data);

    tx.signature = sig.as_ref().to_vec();
    tx.public_key = pk_bytes.to_vec();

    // Create SignedTransaction (same struct as node)
    let signed_tx = SignedTransaction::new(tx);
    let tx_hash = hex::encode(signed_tx.hash);

    // Bincode serialize (same as node's serialize_transaction)
    let tx_bytes = bincode::serialize(&signed_tx)
        .map_err(|e| JsValue::from_str(&format!("Bincode error: {}", e)))?;
    let tx_hex = hex::encode(&tx_bytes);

    let result = serde_json::json!({
        "txHex": tx_hex,
        "txHash": tx_hash,
    });

    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))
}

/// Build, sign, and serialize a stake transaction.
#[wasm_bindgen(js_name = "buildSignedStake")]
pub fn build_signed_stake(
    secret_key_hex: &str,
    amount_str: &str,
    nonce: u64,
    chain_id: u64,
    num_shards: u16,
) -> Result<String, JsValue> {
    let sk_bytes = hex::decode(secret_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid secret key hex: {}", e)))?;
    let amount: u128 = amount_str.parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid amount: {}", e)))?;

    let pk_bytes = &sk_bytes[sk_bytes.len() - 1952..];
    let from = hash_data(pk_bytes);
    let num_shards = if num_shards == 0 { 1 } else { num_shards };
    let shard_id = Transaction::target_shard(&from, num_shards);
    let timestamp = chrono::Utc::now().timestamp_millis() as u64;

    let mut tx = Transaction {
        tx_type: TransactionType::Stake,
        from,
        to: from, // Stake goes to self
        amount: Amount(amount),
        nonce,
        gas_limit: 21000,
        gas_price: 0,
        data: Vec::new(),
        shard_id,
        timestamp,
        signature: Vec::new(),
        public_key: Vec::new(),
        chain_id,
    };

    let signing_data = tx.signing_data();
    let pk_array: [u8; PUBLICKEYBYTES] = pk_bytes.try_into()
        .map_err(|_| JsValue::from_str("PK length"))?;
    let sk_array: [u8; SECRETKEYBYTES] = sk_bytes.as_slice().try_into()
        .map_err(|_| JsValue::from_str("SK length"))?;
    
    let keypair = unsafe { keypair_from_bytes(&pk_array, &sk_array) };
    let sig = keypair.sign(&signing_data);
    tx.signature = sig.as_ref().to_vec();
    tx.public_key = pk_bytes.to_vec();

    let signed_tx = SignedTransaction::new(tx);
    let tx_hash = hex::encode(signed_tx.hash);
    let tx_bytes = bincode::serialize(&signed_tx)
        .map_err(|e| JsValue::from_str(&format!("Bincode: {}", e)))?;

    let result = serde_json::json!({ "txHex": hex::encode(&tx_bytes), "txHash": tx_hash });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Build, sign, and serialize an unstake transaction.
#[wasm_bindgen(js_name = "buildSignedUnstake")]
pub fn build_signed_unstake(
    secret_key_hex: &str,
    amount_str: &str,
    nonce: u64,
    chain_id: u64,
    num_shards: u16,
) -> Result<String, JsValue> {
    let sk_bytes = hex::decode(secret_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid secret key hex: {}", e)))?;
    let amount: u128 = amount_str.parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid amount: {}", e)))?;

    let pk_bytes = &sk_bytes[sk_bytes.len() - 1952..];
    let from = hash_data(pk_bytes);
    let num_shards = if num_shards == 0 { 1 } else { num_shards };
    let shard_id = Transaction::target_shard(&from, num_shards);
    let timestamp = chrono::Utc::now().timestamp_millis() as u64;

    let mut tx = Transaction {
        tx_type: TransactionType::Unstake,
        from,
        to: from,
        amount: Amount(amount),
        nonce,
        gas_limit: 21000,
        gas_price: 0,
        data: Vec::new(),
        shard_id,
        timestamp,
        signature: Vec::new(),
        public_key: Vec::new(),
        chain_id,
    };

    let signing_data = tx.signing_data();
    let pk_array: [u8; PUBLICKEYBYTES] = pk_bytes.try_into()
        .map_err(|_| JsValue::from_str("PK length"))?;
    let sk_array: [u8; SECRETKEYBYTES] = sk_bytes.as_slice().try_into()
        .map_err(|_| JsValue::from_str("SK length"))?;
    
    let keypair = unsafe { keypair_from_bytes(&pk_array, &sk_array) };
    let sig = keypair.sign(&signing_data);
    tx.signature = sig.as_ref().to_vec();
    tx.public_key = pk_bytes.to_vec();

    let signed_tx = SignedTransaction::new(tx);
    let tx_hash = hex::encode(signed_tx.hash);
    let tx_bytes = bincode::serialize(&signed_tx)
        .map_err(|e| JsValue::from_str(&format!("Bincode: {}", e)))?;

    let result = serde_json::json!({ "txHex": hex::encode(&tx_bytes), "txHash": tx_hash });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Build, sign, and serialize a contract deploy transaction.
/// `bytecode_hex` is the WASM bytecode (hex). `constructor_data_hex` is optional ABI-encoded constructor args.
/// Returns JSON: { "txHex": hex, "txHash": hex }
#[wasm_bindgen(js_name = "buildSignedDeploy")]
pub fn build_signed_deploy(
    secret_key_hex: &str,
    bytecode_hex: &str,
    constructor_data_hex: &str,
    nonce: u64,
    chain_id: u64,
    num_shards: u16,
) -> Result<String, JsValue> {
    let sk_bytes = hex::decode(secret_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid secret key hex: {}", e)))?;
    if sk_bytes.len() != SECRETKEYBYTES {
        return Err(JsValue::from_str(&format!("Invalid SK length: {} (expected {})", sk_bytes.len(), SECRETKEYBYTES)));
    }

    let bytecode = hex::decode(bytecode_hex.strip_prefix("0x").unwrap_or(bytecode_hex))
        .map_err(|e| JsValue::from_str(&format!("Invalid bytecode hex: {}", e)))?;

    let constructor_data = if constructor_data_hex.is_empty() {
        Vec::new()
    } else {
        hex::decode(constructor_data_hex.strip_prefix("0x").unwrap_or(constructor_data_hex))
            .map_err(|e| JsValue::from_str(&format!("Invalid constructor data hex: {}", e)))?
    };

    let mut deploy_data = Vec::with_capacity(12 + bytecode.len() + constructor_data.len());
    deploy_data.extend_from_slice(b"QDP1");
    deploy_data.extend_from_slice(&(bytecode.len() as u32).to_le_bytes());
    deploy_data.extend_from_slice(&(constructor_data.len() as u32).to_le_bytes());
    deploy_data.extend_from_slice(&bytecode);
    deploy_data.extend_from_slice(&constructor_data);

    let pk_bytes = &sk_bytes[sk_bytes.len() - PUBLICKEYBYTES..];
    let from = hash_data(pk_bytes);
    let num_shards = if num_shards == 0 { 1 } else { num_shards };
    let shard_id = Transaction::target_shard(&from, num_shards);
    let timestamp = chrono::Utc::now().timestamp_millis() as u64;

    let mut tx = Transaction {
        tx_type: TransactionType::ContractDeploy,
        from,
        to: [0u8; 32], // zero address for deploy
        amount: Amount(0),
        nonce,
        gas_limit: 10_000_000,
        gas_price: 0,
        data: deploy_data,
        shard_id,
        timestamp,
        signature: Vec::new(),
        public_key: Vec::new(),
        chain_id,
    };

    let signing_data = tx.signing_data();
    let pk_array: [u8; PUBLICKEYBYTES] = pk_bytes.try_into()
        .map_err(|_| JsValue::from_str("PK length"))?;
    let sk_array: [u8; SECRETKEYBYTES] = sk_bytes.as_slice().try_into()
        .map_err(|_| JsValue::from_str("SK length"))?;

    let keypair = unsafe { keypair_from_bytes(&pk_array, &sk_array) };
    let sig = keypair.sign(&signing_data);
    tx.signature = sig.as_ref().to_vec();
    tx.public_key = pk_bytes.to_vec();

    let signed_tx = SignedTransaction::new(tx);
    let tx_hash = hex::encode(signed_tx.hash);
    let tx_bytes = bincode::serialize(&signed_tx)
        .map_err(|e| JsValue::from_str(&format!("Bincode: {}", e)))?;

    let result = serde_json::json!({ "txHex": hex::encode(&tx_bytes), "txHash": tx_hash });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Build, sign, and serialize a contract call transaction.
/// `contract_address_hex` is the deployed contract address.
/// `calldata_hex` is the ABI-encoded function call.
/// `amount_str` is the value to send (0 for non-payable).
/// Returns JSON: { "txHex": hex, "txHash": hex }
#[wasm_bindgen(js_name = "buildSignedContractCall")]
pub fn build_signed_contract_call(
    secret_key_hex: &str,
    contract_address_hex: &str,
    calldata_hex: &str,
    amount_str: &str,
    nonce: u64,
    chain_id: u64,
    num_shards: u16,
) -> Result<String, JsValue> {
    let sk_bytes = hex::decode(secret_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid secret key hex: {}", e)))?;
    if sk_bytes.len() != SECRETKEYBYTES {
        return Err(JsValue::from_str(&format!("Invalid SK length: {} (expected {})", sk_bytes.len(), SECRETKEYBYTES)));
    }

    let to = parse_address_hex(contract_address_hex)?;
    let calldata = hex::decode(calldata_hex.strip_prefix("0x").unwrap_or(calldata_hex))
        .map_err(|e| JsValue::from_str(&format!("Invalid calldata hex: {}", e)))?;
    let amount: u128 = amount_str.parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid amount: {}", e)))?;

    let pk_bytes = &sk_bytes[sk_bytes.len() - PUBLICKEYBYTES..];
    let from = hash_data(pk_bytes);
    let num_shards = if num_shards == 0 { 1 } else { num_shards };
    let shard_id = Transaction::target_shard(&from, num_shards);
    let timestamp = chrono::Utc::now().timestamp_millis() as u64;

    let mut tx = Transaction {
        tx_type: TransactionType::ContractCall,
        from,
        to,
        amount: Amount(amount),
        nonce,
        gas_limit: 1_000_000,
        gas_price: 0,
        data: calldata,
        shard_id,
        timestamp,
        signature: Vec::new(),
        public_key: Vec::new(),
        chain_id,
    };

    let signing_data = tx.signing_data();
    let pk_array: [u8; PUBLICKEYBYTES] = pk_bytes.try_into()
        .map_err(|_| JsValue::from_str("PK length"))?;
    let sk_array: [u8; SECRETKEYBYTES] = sk_bytes.as_slice().try_into()
        .map_err(|_| JsValue::from_str("SK length"))?;

    let keypair = unsafe { keypair_from_bytes(&pk_array, &sk_array) };
    let sig = keypair.sign(&signing_data);
    tx.signature = sig.as_ref().to_vec();
    tx.public_key = pk_bytes.to_vec();

    let signed_tx = SignedTransaction::new(tx);
    let tx_hash = hex::encode(signed_tx.hash);
    let tx_bytes = bincode::serialize(&signed_tx)
        .map_err(|e| JsValue::from_str(&format!("Bincode: {}", e)))?;

    let result = serde_json::json!({ "txHex": hex::encode(&tx_bytes), "txHash": tx_hash });
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

// ── Signing (arbitrary message) ─────────────────────────────

/// Sign an arbitrary message (hex) with a secret key (hex).
/// Returns hex-encoded Dilithium-3 signature.
#[wasm_bindgen(js_name = "signMessage")]
pub fn sign_message(message_hex: &str, secret_key_hex: &str) -> Result<String, JsValue> {
    let msg = hex::decode(message_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid message hex: {}", e)))?;
    let sk_bytes = hex::decode(secret_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid secret key hex: {}", e)))?;

    if sk_bytes.len() != 4000 {
        return Err(JsValue::from_str("Invalid secret key length"));
    }

    let pk_bytes = &sk_bytes[sk_bytes.len() - PUBLICKEYBYTES..];
    let pk_array: [u8; PUBLICKEYBYTES] = pk_bytes.try_into()
        .map_err(|_| JsValue::from_str("PK length"))?;
    let sk_array: [u8; SECRETKEYBYTES] = sk_bytes.as_slice().try_into()
        .map_err(|_| JsValue::from_str("SK length"))?;
    
    let keypair = unsafe { keypair_from_bytes(&pk_array, &sk_array) };
    let sig = keypair.sign(&msg);
    Ok(hex::encode(sig.as_ref()))
}

/// Verify a Dilithium-3 signature.
#[wasm_bindgen(js_name = "verifySignature")]
pub fn verify_signature(signature_hex: &str, message_hex: &str, public_key_hex: &str) -> Result<bool, JsValue> {
    let sig = hex::decode(signature_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid sig hex: {}", e)))?;
    let msg = hex::decode(message_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid msg hex: {}", e)))?;
    let pk = hex::decode(public_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid pk hex: {}", e)))?;

    if sig.len() != 3293 {
        return Err(JsValue::from_str("Invalid signature length (expected 3293 bytes)"));
    }
    if pk.len() != 1952 {
        return Err(JsValue::from_str("Invalid public key length (expected 1952 bytes)"));
    }

    let sig_array: &[u8; 3293] = sig.as_slice().try_into()
        .map_err(|_| JsValue::from_str("Signature conversion failed"))?;
    let pk_array: &[u8; 1952] = pk.as_slice().try_into()
        .map_err(|_| JsValue::from_str("Public key conversion failed"))?;

    match pqc_dilithium::verify(sig_array, &msg, pk_array) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ── Address Utilities ───────────────────────────────────────

/// Derive address (hex) from secret key (hex).
/// Returns JSON: { "address": hex, "publicKey": hex, "qtsAddress": string }
#[wasm_bindgen(js_name = "addressFromSecretKey")]
pub fn address_from_secret_key(secret_key_hex: &str) -> Result<String, JsValue> {
    let sk_bytes = hex::decode(secret_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid hex: {}", e)))?;
    if sk_bytes.len() != 4000 {
        return Err(JsValue::from_str("Invalid secret key length (expected 4000 bytes)"));
    }

    let pk_bytes = &sk_bytes[sk_bytes.len() - 1952..];
    let address = hash_data(pk_bytes);
    let qts_address = encode_qts_address(&address)
        .map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "address": hex::encode(address),
        "publicKey": hex::encode(pk_bytes),
        "qtsAddress": qts_address,
    });

    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Encode a 32-byte address (hex) to qts1... format.
#[wasm_bindgen(js_name = "addressToQts")]
pub fn address_to_qts(address_hex: &str) -> Result<String, JsValue> {
    let address = parse_address_hex(address_hex)?;
    encode_qts_address(&address).map_err(|e| JsValue::from_str(&e))
}

/// Decode a qts1... address back to hex.
#[wasm_bindgen(js_name = "qtsToAddress")]
pub fn qts_to_address(qts_addr: &str) -> Result<String, JsValue> {
    let addr = decode_qts_address(qts_addr)?;
    Ok(hex::encode(addr))
}

/// Convert qts1... to QTS:hex format used by RPC.
#[wasm_bindgen(js_name = "qtsToRpcFormat")]
pub fn qts_to_rpc_format(qts_addr: &str) -> Result<String, JsValue> {
    let addr = decode_qts_address(qts_addr)?;
    Ok(format!("QTS:{}", hex::encode(addr)))
}

/// SHA3-256 hash (same as node's hash_data).
#[wasm_bindgen(js_name = "sha3Hash")]
pub fn sha3_hash(data_hex: &str) -> Result<String, JsValue> {
    let data = hex::decode(data_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid hex: {}", e)))?;
    Ok(hex::encode(hash_data(&data)))
}

// ============================================================================
// Internal helpers
// ============================================================================

fn parse_address_hex(s: &str) -> Result<Address, JsValue> {
    // Support QTS:hex, qts:hex, 0x hex, or raw hex
    let hex_str = s.strip_prefix("QTS:")
        .or_else(|| s.strip_prefix("qts:"))
        .or_else(|| s.strip_prefix("0x"))
        .unwrap_or(s);

    let bytes = hex::decode(hex_str)
        .map_err(|e| JsValue::from_str(&format!("Invalid address hex: {}", e)))?;

    bytes.try_into()
        .map_err(|_| JsValue::from_str("Invalid address length (expected 32 bytes)"))
}

fn encode_qts_address(address: &Address) -> Result<String, String> {
    let addr_bytes = &address[..20];
    let checksum = hash_data(addr_bytes);
    let checksum_bytes = &checksum[..4];

    let mut data = Vec::with_capacity(24);
    data.extend_from_slice(addr_bytes);
    data.extend_from_slice(checksum_bytes);

    let encoded = data_encoding::BASE32_NOPAD.encode(&data).to_lowercase();
    Ok(format!("qts1{}", encoded))
}

fn decode_qts_address(qts_addr: &str) -> Result<Address, JsValue> {
    if !qts_addr.starts_with("qts1") {
        return Err(JsValue::from_str("Invalid Quantos address: must start with qts1"));
    }

    let encoded = &qts_addr[4..];
    let decoded = data_encoding::BASE32_NOPAD
        .decode(encoded.to_uppercase().as_bytes())
        .map_err(|e| JsValue::from_str(&format!("Invalid base32: {}", e)))?;

    if decoded.len() != 24 {
        return Err(JsValue::from_str("Invalid address length"));
    }

    let addr_bytes = &decoded[..20];
    let checksum_bytes = &decoded[20..24];

    let expected_checksum = hash_data(addr_bytes);
    if checksum_bytes != &expected_checksum[..4] {
        return Err(JsValue::from_str("Invalid checksum"));
    }

    let mut full_address = [0u8; 32];
    full_address[..20].copy_from_slice(addr_bytes);
    Ok(full_address)
}
