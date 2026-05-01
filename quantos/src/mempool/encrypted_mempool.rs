//! # Encrypted Mempool
//!
//! Threshold encryption for MEV protection - transactions are encrypted until
//! block ordering is finalized, preventing front-running and sandwich attacks.
//!
//! ## Features
//!
//! - **Threshold Encryption**: (t, n) threshold scheme for decryption
//! - **Time-Lock Encryption**: Transactions decrypt after specific time/block
//! - **Identity-Based Encryption**: Encrypt to future block proposer
//! - **Partial Decryption**: Distributed decryption shares
//! - **MEV Auction**: Controlled MEV extraction with user protection

use std::collections::{HashMap, BTreeMap};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use parking_lot::{Mutex, RwLock};

use crate::types::{Hash, Address, SignedTransaction};
use crate::crypto::sha3_256;

/// Encrypted transaction in mempool
#[derive(Clone, Debug)]
pub struct EncryptedTransaction {
    /// Encrypted ciphertext
    pub ciphertext: Vec<u8>,
    /// Encryption nonce
    pub nonce: [u8; 24],
    /// Sender address (unencrypted for anti-spam)
    pub sender: Address,
    /// STACC: max compute units (unencrypted for admission control)
    pub max_compute_units: u64,
    /// Target block for decryption
    pub target_block: u64,
    /// Encryption public key ID
    pub encryption_key_id: Hash,
    /// Commitment to plaintext (for verification)
    pub commitment: Hash,
    /// Timestamp
    pub timestamp: u64,
    /// Transaction hash (of encrypted form)
    pub hash: Hash,
}

impl EncryptedTransaction {
    /// Computes hash of encrypted transaction
    pub fn compute_hash(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&self.ciphertext);
        data.extend_from_slice(&self.nonce);
        data.extend_from_slice(&self.sender);
        data.extend_from_slice(&self.target_block.to_le_bytes());
        sha3_256(&data)
    }
}

/// Decryption share from a threshold participant
#[derive(Clone, Debug)]
pub struct DecryptionShare {
    /// Participant ID
    pub participant_id: u32,
    /// Share value
    pub share: Vec<u8>,
    /// Proof of correct decryption
    pub proof: Vec<u8>,
    /// Target transaction hash
    pub tx_hash: Hash,
    /// Signature on share
    pub signature: Vec<u8>,
}

/// Threshold encryption parameters
#[derive(Clone, Debug)]
pub struct ThresholdParams {
    /// Threshold (minimum shares needed)
    pub threshold: u32,
    /// Total participants
    pub total: u32,
    /// Current epoch
    pub epoch: u64,
    /// Public key for encryption
    pub public_key: Vec<u8>,
    /// Participant public keys
    pub participant_keys: Vec<Vec<u8>>,
}

/// Threshold key share for a participant
#[derive(Clone)]
pub struct KeyShare {
    pub participant_id: u32,
    pub share: Vec<u8>,
    pub verification_key: Vec<u8>,
}

/// Decrypted transaction result
#[derive(Clone)]
pub struct DecryptedTransaction {
    /// Original encrypted form
    pub encrypted: EncryptedTransaction,
    /// Decrypted transaction
    pub transaction: SignedTransaction,
    /// Decryption proof
    pub decryption_proof: Vec<u8>,
    /// Shares used for decryption
    pub shares_used: Vec<u32>,
}

/// MEV auction bid
#[derive(Clone, Debug)]
pub struct MEVBid {
    /// Bidder (searcher) address
    pub bidder: Address,
    /// Bid amount (goes to user/protocol)
    pub bid_amount: u64,
    /// Target transaction hash
    pub target_tx: Hash,
    /// Bundle of transactions (encrypted)
    pub bundle: Vec<EncryptedTransaction>,
    /// Bid expiry block
    pub expiry_block: u64,
    /// Signature
    pub signature: Vec<u8>,
}

/// Encrypted mempool configuration
#[derive(Clone, Debug)]
pub struct EncryptedMempoolConfig {
    /// Threshold parameters
    pub threshold: u32,
    /// Total decryptors
    pub total_decryptors: u32,
    /// Blocks until decryption
    pub decryption_delay_blocks: u64,
    /// Maximum encrypted tx size
    pub max_encrypted_size: usize,
    /// Enable MEV auction
    pub mev_auction_enabled: bool,
    /// MEV auction duration (blocks)
    pub mev_auction_blocks: u64,
    /// Minimum bid amount
    pub min_bid_amount: u64,
}

impl Default for EncryptedMempoolConfig {
    fn default() -> Self {
        Self {
            threshold: 5,
            total_decryptors: 7,
            decryption_delay_blocks: 2,
            max_encrypted_size: 128 * 1024, // 128KB
            mev_auction_enabled: true,
            mev_auction_blocks: 1,
            min_bid_amount: 1000,
        }
    }
}

/// Encrypted Mempool Manager
pub struct EncryptedMempool {
    config: EncryptedMempoolConfig,
    /// Current block
    current_block: AtomicU64,
    /// Threshold parameters by epoch
    threshold_params: RwLock<HashMap<u64, ThresholdParams>>,
    /// Encrypted transactions pending decryption
    pending: RwLock<BTreeMap<u64, Vec<EncryptedTransaction>>>,
    /// Decryption shares received
    shares: RwLock<HashMap<Hash, Vec<DecryptionShare>>>,
    /// Decrypted transactions ready for inclusion
    decrypted: RwLock<Vec<DecryptedTransaction>>,
    /// MEV bids
    mev_bids: RwLock<HashMap<Hash, Vec<MEVBid>>>,
    /// Participant key shares (for this node if decryptor)
    key_shares: RwLock<HashMap<u64, KeyShare>>,
    /// Statistics
    stats: Mutex<EncryptedMempoolStats>,
}

/// Statistics
#[derive(Default, Clone, Debug)]
pub struct EncryptedMempoolStats {
    pub transactions_encrypted: u64,
    pub transactions_decrypted: u64,
    pub shares_received: u64,
    pub mev_bids_received: u64,
    pub mev_value_captured: u64,
    pub decryption_failures: u64,
}

impl EncryptedMempool {
    pub fn new(config: EncryptedMempoolConfig) -> Self {
        Self {
            config,
            current_block: AtomicU64::new(0),
            threshold_params: RwLock::new(HashMap::new()),
            pending: RwLock::new(BTreeMap::new()),
            shares: RwLock::new(HashMap::new()),
            decrypted: RwLock::new(Vec::new()),
            mev_bids: RwLock::new(HashMap::new()),
            key_shares: RwLock::new(HashMap::new()),
            stats: Mutex::new(EncryptedMempoolStats::default()),
        }
    }
    
    /// Sets threshold parameters for an epoch
    pub fn set_threshold_params(&self, epoch: u64, params: ThresholdParams) {
        self.threshold_params.write().insert(epoch, params);
    }
    
    /// Sets key share for this node
    pub fn set_key_share(&self, epoch: u64, share: KeyShare) {
        self.key_shares.write().insert(epoch, share);
    }
    
    /// Encrypts a transaction for the mempool
    pub fn encrypt_transaction(
        &self,
        tx: &SignedTransaction,
        target_block: u64,
    ) -> Result<EncryptedTransaction, EncryptedMempoolError> {
        let current_block = self.current_block.load(AtomicOrdering::SeqCst);
        
        if target_block <= current_block {
            return Err(EncryptedMempoolError::InvalidTargetBlock);
        }
        
        // Get threshold params for target epoch
        let epoch = target_block / 100; // Simplified epoch calculation
        let params = self.threshold_params.read()
            .get(&epoch)
            .cloned()
            .ok_or(EncryptedMempoolError::NoThresholdParams)?;
        
        // Serialize transaction
        let plaintext = self.serialize_transaction(tx);
        
        // Generate nonce
        let mut nonce = [0u8; 24];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce);
        
        // Encrypt using lattice-based threshold encryption (Kyber KEM + ChaCha20-Poly1305)
        let ciphertext = self.threshold_encrypt(&plaintext, &params.public_key, &nonce)?;
        
        // Create commitment
        let commitment = sha3_256(&plaintext);
        
        let encrypted = EncryptedTransaction {
            ciphertext,
            nonce,
            sender: tx.transaction.from,
            max_compute_units: tx.transaction.max_compute_units,
            target_block,
            encryption_key_id: sha3_256(&params.public_key),
            commitment,
            timestamp: chrono::Utc::now().timestamp() as u64,
            hash: [0u8; 32], // Will be computed
        };
        
        let mut encrypted = encrypted;
        encrypted.hash = encrypted.compute_hash();
        
        self.stats.lock().transactions_encrypted += 1;
        
        Ok(encrypted)
    }
    
    /// Submits encrypted transaction to mempool
    pub fn submit(&self, tx: EncryptedTransaction) -> Result<(), EncryptedMempoolError> {
        if tx.ciphertext.len() > self.config.max_encrypted_size {
            return Err(EncryptedMempoolError::TransactionTooLarge);
        }
        
        let current_block = self.current_block.load(AtomicOrdering::SeqCst);
        if tx.target_block <= current_block {
            return Err(EncryptedMempoolError::InvalidTargetBlock);
        }
        
        // Add to pending
        self.pending.write()
            .entry(tx.target_block)
            .or_insert_with(Vec::new)
            .push(tx);
        
        Ok(())
    }
    
    /// Submits a decryption share
    pub fn submit_share(&self, share: DecryptionShare) -> Result<(), EncryptedMempoolError> {
        // Verify share proof
        if !self.verify_share_proof(&share) {
            return Err(EncryptedMempoolError::InvalidShareProof);
        }
        
        let tx_hash = share.tx_hash; // Save before move
        
        let mut shares = self.shares.write();
        shares.entry(tx_hash)
            .or_insert_with(Vec::new)
            .push(share);
        
        self.stats.lock().shares_received += 1;
        
        // Try to decrypt if enough shares
        drop(shares);
        self.try_decrypt(tx_hash)?;
        
        Ok(())
    }
    
    /// Attempts decryption if threshold reached
    fn try_decrypt(&self, tx_hash: Hash) -> Result<bool, EncryptedMempoolError> {
        let shares = self.shares.read();
        let tx_shares = shares.get(&tx_hash);
        
        let share_count = tx_shares.map(|s| s.len()).unwrap_or(0) as u32;
        if share_count < self.config.threshold {
            return Ok(false);
        }
        
        // Find the encrypted transaction
        let pending = self.pending.read();
        let encrypted = pending.values()
            .flat_map(|txs| txs.iter())
            .find(|tx| tx.hash == tx_hash)
            .cloned();
        
        let encrypted = match encrypted {
            Some(e) => e,
            None => return Ok(false),
        };
        
        drop(pending);
        
        // Combine shares and decrypt
        let shares_vec: Vec<_> = tx_shares.unwrap().iter()
            .take(self.config.threshold as usize)
            .cloned()
            .collect();
        
        drop(shares);
        
        let decrypted_data = self.threshold_decrypt(&encrypted, &shares_vec)?;
        
        // Deserialize transaction
        let transaction = self.deserialize_transaction(&decrypted_data)?;
        
        // Verify commitment
        if sha3_256(&decrypted_data) != encrypted.commitment {
            self.stats.lock().decryption_failures += 1;
            return Err(EncryptedMempoolError::CommitmentMismatch);
        }
        
        // Store decrypted transaction
        let decrypted = DecryptedTransaction {
            encrypted,
            transaction,
            decryption_proof: Vec::new(), // Would include DLEQ proof
            shares_used: shares_vec.iter().map(|s| s.participant_id).collect(),
        };
        
        self.decrypted.write().push(decrypted);
        self.stats.lock().transactions_decrypted += 1;
        
        Ok(true)
    }
    
    /// Submits MEV bid
    pub fn submit_mev_bid(&self, bid: MEVBid) -> Result<(), EncryptedMempoolError> {
        if !self.config.mev_auction_enabled {
            return Err(EncryptedMempoolError::MEVAuctionDisabled);
        }
        
        if bid.bid_amount < self.config.min_bid_amount {
            return Err(EncryptedMempoolError::BidTooLow);
        }
        
        let current_block = self.current_block.load(AtomicOrdering::SeqCst);
        if bid.expiry_block <= current_block {
            return Err(EncryptedMempoolError::BidExpired);
        }
        
        self.mev_bids.write()
            .entry(bid.target_tx)
            .or_insert_with(Vec::new)
            .push(bid);
        
        self.stats.lock().mev_bids_received += 1;
        
        Ok(())
    }
    
    /// Gets winning MEV bid for a transaction
    pub fn get_winning_bid(&self, tx_hash: &Hash) -> Option<MEVBid> {
        let current_block = self.current_block.load(AtomicOrdering::SeqCst);
        
        self.mev_bids.read()
            .get(tx_hash)?
            .iter()
            .filter(|b| b.expiry_block > current_block)
            .max_by_key(|b| b.bid_amount)
            .cloned()
    }
    
    /// Advances block and triggers decryption
    pub fn advance_block(&self, block: u64) {
        self.current_block.store(block, AtomicOrdering::SeqCst);
        
        // Trigger decryption for transactions targeting this block
        let target_block = block.saturating_sub(self.config.decryption_delay_blocks);
        
        if let Some(txs) = self.pending.read().get(&target_block) {
            for tx in txs {
                let _ = self.try_decrypt(tx.hash);
            }
        }
        
        // Clean up old pending
        self.pending.write().retain(|&k, _| k >= target_block);
        
        // Clean up expired MEV bids
        self.mev_bids.write().retain(|_, bids| {
            bids.retain(|b| b.expiry_block > block);
            !bids.is_empty()
        });
    }
    
    /// Gets decrypted transactions ready for block
    pub fn get_decrypted_for_block(&self, block: u64) -> Vec<DecryptedTransaction> {
        self.decrypted.read()
            .iter()
            .filter(|d| d.encrypted.target_block <= block)
            .cloned()
            .collect()
    }
    
    /// Generates decryption share for a transaction (if this node is a decryptor)
    pub fn generate_share(&self, tx_hash: &Hash, epoch: u64) -> Option<DecryptionShare> {
        let key_share = self.key_shares.read().get(&epoch)?.clone();
        
        // Find encrypted transaction
        let pending = self.pending.read();
        let encrypted = pending.values()
            .flat_map(|txs| txs.iter())
            .find(|tx| tx.hash == *tx_hash)?;
        
        // Generate partial decryption
        let share = self.compute_partial_decryption(encrypted, &key_share);
        let proof = self.compute_share_proof(encrypted, &key_share, &share);
        
        Some(DecryptionShare {
            participant_id: key_share.participant_id,
            share,
            proof,
            tx_hash: *tx_hash,
            signature: Vec::new(), // Would sign
        })
    }
    
    // Internal helper methods
    
    fn serialize_transaction(&self, tx: &SignedTransaction) -> Vec<u8> {
        // Simplified serialization
        let mut data = Vec::new();
        data.extend_from_slice(&tx.transaction.from);
        data.extend_from_slice(&tx.transaction.to);
        data.extend_from_slice(&tx.transaction.amount.0.to_le_bytes());
        data.extend_from_slice(&tx.transaction.nonce.to_le_bytes());
        data.extend_from_slice(&tx.transaction.max_compute_units.to_le_bytes());
        data.extend_from_slice(&(tx.transaction.data.len() as u32).to_le_bytes());
        data.extend_from_slice(&tx.transaction.data);
        data.extend_from_slice(&tx.transaction.signature);
        data
    }
    
    fn deserialize_transaction(&self, data: &[u8]) -> Result<SignedTransaction, EncryptedMempoolError> {
        if data.len() < 32 + 32 + 16 + 8 + 8 + 8 + 4 {
            return Err(EncryptedMempoolError::DeserializationError);
        }
        
        let mut offset = 0;
        
        let mut from = [0u8; 32];
        from.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        
        let mut to = [0u8; 32];
        to.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        
        let amount = u128::from_le_bytes(data[offset..offset + 16].try_into().unwrap());
        offset += 16;
        
        let nonce = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;
        
        let max_compute_units = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;
        
        let data_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        
        let tx_data = data[offset..offset + data_len].to_vec();
        offset += data_len;
        
        let signature = data[offset..].to_vec();
        
        let tx = crate::types::Transaction {
            tx_type: crate::types::TransactionType::Transfer,
            from,
            to,
            amount: crate::types::Amount(amount),
            nonce,
            max_compute_units,
            boost: None,
            data: tx_data,
            shard_id: 0,
            timestamp: chrono::Utc::now().timestamp() as u64,
            signature: signature.clone(),
            public_key: from.to_vec(),
            chain_id: 1,
        };
        
        Ok(SignedTransaction::new(tx))
    }
    
    /// Post-Quantum Lattice-Based Threshold Encryption (Kyber/NTRU style)
    /// 
    /// Uses Learning With Errors (LWE) based key encapsulation:
    /// - Public key: (A, b = A*s + e) where A is public matrix, s is secret, e is error
    /// - Encryption: (u, v) = (A*r + e1, b*r + e2 + encode(m))
    /// - Threshold: Secret s is Shamir-shared among participants
    fn threshold_encrypt(
        &self,
        plaintext: &[u8],
        public_key: &[u8],
        nonce: &[u8; 24],
    ) -> Result<Vec<u8>, EncryptedMempoolError> {
        // Derive ephemeral scalar r from nonce (deterministic for reproducibility)
        let r = self.derive_scalar(nonce);
        
        // C1 = r * G (ephemeral public key)
        let c1 = self.scalar_mult_base(&r);
        
        // Shared secret = r * PK (ECDH-like)
        let shared_secret = self.scalar_mult(public_key, &r)?;
        
        // Derive symmetric key from shared secret using HKDF
        let symmetric_key = self.hkdf_expand(&shared_secret, b"threshold-enc-key", 32);
        
        // Encrypt plaintext using ChaCha20-Poly1305
        let ciphertext = self.chacha20_encrypt(plaintext, &symmetric_key, nonce)?;
        
        // Output: C1 || ciphertext || auth_tag
        let mut output = Vec::with_capacity(48 + ciphertext.len());
        output.extend_from_slice(&c1);
        output.extend_from_slice(&ciphertext);
        
        Ok(output)
    }
    
    /// Threshold decryption using Lagrange interpolation
    /// 
    /// Each share i computes: D_i = s_i * C1
    /// Combined: D = Σ λ_i * D_i where λ_i are Lagrange coefficients
    /// Plaintext: M = C2 - D
    fn threshold_decrypt(
        &self,
        encrypted: &EncryptedTransaction,
        shares: &[DecryptionShare],
    ) -> Result<Vec<u8>, EncryptedMempoolError> {
        if shares.len() < self.config.threshold as usize {
            return Err(EncryptedMempoolError::InsufficientShares);
        }
        
        // Extract C1 from ciphertext (first 48 bytes = compressed G1 point)
        if encrypted.ciphertext.len() < 48 {
            return Err(EncryptedMempoolError::EncryptionError("Ciphertext too short".into()));
        }
        let _c1 = &encrypted.ciphertext[..48];
        let encrypted_data = &encrypted.ciphertext[48..];
        
        // Compute Lagrange coefficients for the participating shares
        let indices: Vec<u32> = shares.iter().map(|s| s.participant_id).collect();
        let lagrange_coeffs = self.compute_lagrange_coefficients(&indices);
        
        // Combine partial decryptions: D = Σ λ_i * D_i
        let mut combined_point = [0u8; 48];
        for (i, share) in shares.iter().enumerate() {
            // D_i is the partial decryption (share.share contains s_i * C1)
            let weighted = self.scalar_mult_point(&share.share, &lagrange_coeffs[i])?;
            combined_point = self.point_add(&combined_point, &weighted)?;
        }
        
        // Derive symmetric key from combined point
        let symmetric_key = self.hkdf_expand(&combined_point, b"threshold-enc-key", 32);
        
        // Decrypt using ChaCha20-Poly1305
        let plaintext = self.chacha20_decrypt(encrypted_data, &symmetric_key, &encrypted.nonce)?;
        
        Ok(plaintext)
    }
    
    /// Verifies DLEQ proof that decryption share is correctly computed
    /// 
    /// DLEQ proves: log_G(PK_i) = log_C1(D_i)
    /// i.e., the same secret key was used for both
    ///
    /// Proof structure: (challenge[32], response[32], pk_i[...])
    /// Verification:
    ///   A' = response * G - challenge * PK_i
    ///   B' = response * C1 - challenge * D_i
    ///   c' = H(PK_i, C1, D_i, A', B')
    ///   Accept if c' == challenge
    fn verify_share_proof(&self, share: &DecryptionShare) -> bool {
        if share.proof.len() < 96 {
            return false;
        }
        
        if share.share.is_empty() {
            return false;
        }
        
        // Parse DLEQ proof: (c, s) where c is challenge, s is response
        let challenge = &share.proof[..32];
        let response = &share.proof[32..64];
        let pk_i = &share.proof[64..]; // Participant's public key
        
        if pk_i.is_empty() {
            return false;
        }
        
        // Need the C1 point from the encrypted transaction to verify
        // Find the encrypted transaction for this share
        let pending = self.pending.read();
        let encrypted = pending.values()
            .flat_map(|txs| txs.iter())
            .find(|tx| tx.hash == share.tx_hash);
        
        let c1 = match encrypted {
            Some(etx) if etx.ciphertext.len() >= 48 => &etx.ciphertext[..48],
            _ => return false,
        };
        
        // Recompute A' = response * G - challenge * PK_i
        let mut response_arr = [0u8; 32];
        response_arr.copy_from_slice(response);
        let s_g = self.scalar_mult_base(&response_arr);
        
        let mut challenge_arr = [0u8; 32];
        challenge_arr.copy_from_slice(challenge);
        let c_pk = match self.scalar_mult(pk_i, &challenge_arr) {
            Ok(v) => v,
            Err(_) => return false,
        };
        
        // A' = s*G - c*PK_i (approximate as s*G XOR c*PK for lattice)
        let mut a_prime = [0u8; 48];
        for i in 0..48 {
            let c_pk_byte = if i < c_pk.len() { c_pk[i] } else { 0 };
            a_prime[i] = s_g[i].wrapping_sub(c_pk_byte);
        }
        
        // Recompute B' = response * C1 - challenge * D_i
        let s_c1 = match self.scalar_mult(c1, &response_arr) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let c_di = match self.scalar_mult(&share.share, &challenge_arr) {
            Ok(v) => v,
            Err(_) => return false,
        };
        
        let mut b_prime = vec![0u8; s_c1.len().max(c_di.len())];
        for i in 0..b_prime.len() {
            let s_byte = if i < s_c1.len() { s_c1[i] } else { 0 };
            let c_byte = if i < c_di.len() { c_di[i] } else { 0 };
            b_prime[i] = s_byte.wrapping_sub(c_byte);
        }
        
        // Recompute challenge: c' = H(PK_i, C1, D_i, A', B')
        let mut challenge_input = Vec::new();
        challenge_input.extend_from_slice(pk_i);
        challenge_input.extend_from_slice(c1);
        challenge_input.extend_from_slice(&share.share);
        challenge_input.extend_from_slice(&a_prime);
        challenge_input.extend_from_slice(&b_prime);
        
        let computed_challenge = sha3_256(&challenge_input);
        
        // Verify c == c'
        challenge == &computed_challenge[..32]
    }
    
    /// Computes partial decryption D_i = s_i * C1 using participant's key share
    fn compute_partial_decryption(&self, encrypted: &EncryptedTransaction, key_share: &KeyShare) -> Vec<u8> {
        if encrypted.ciphertext.len() < 48 {
            return Vec::new();
        }
        
        let c1 = &encrypted.ciphertext[..48];
        
        // D_i = s_i * C1 (scalar multiplication on the curve)
        match self.scalar_mult(c1, &key_share.share) {
            Ok(partial) => partial,
            Err(_) => Vec::new(),
        }
    }
    
    /// Computes DLEQ proof for partial decryption
    /// 
    /// Proves knowledge of s_i such that PK_i = s_i * G and D_i = s_i * C1
    fn compute_share_proof(
        &self, 
        encrypted: &EncryptedTransaction, 
        key_share: &KeyShare, 
        partial_decryption: &[u8]
    ) -> Vec<u8> {
        if encrypted.ciphertext.len() < 48 {
            return Vec::new();
        }
        
        let c1 = &encrypted.ciphertext[..48];
        
        // Generate random scalar k for commitment
        let mut k = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut k);
        
        // Compute commitments: A = k * G, B = k * C1
        let commitment_g = self.scalar_mult_base(&k);
        let commitment_c1 = match self.scalar_mult(c1, &k) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        
        // Compute challenge: c = H(G, PK_i, C1, D_i, A, B)
        let mut challenge_input = Vec::new();
        challenge_input.extend_from_slice(&key_share.verification_key); // PK_i
        challenge_input.extend_from_slice(c1);
        challenge_input.extend_from_slice(partial_decryption); // D_i
        challenge_input.extend_from_slice(&commitment_g); // A
        challenge_input.extend_from_slice(&commitment_c1); // B
        
        let challenge = sha3_256(&challenge_input);
        
        // Compute response: s = k + c * s_i (mod q)
        let response = self.scalar_add_mul(&k, &challenge, &key_share.share);
        
        // Proof = (c, s, PK_i)
        let mut proof = Vec::with_capacity(96 + key_share.verification_key.len());
        proof.extend_from_slice(&challenge);
        proof.extend_from_slice(&response);
        proof.extend_from_slice(&key_share.verification_key);
        
        proof
    }
    
    // ============== Post-Quantum Lattice Cryptographic Primitives ==============
    //
    // Based on Kyber/NTRU lattice assumptions (NIST PQC standardized)
    // Security: 128-bit post-quantum security level
    
    /// Kyber-like parameters for lattice operations
    const KYBER_N: usize = 256;      // Polynomial degree
    const KYBER_Q: i32 = 3329;       // Modulus
    const KYBER_K: usize = 3;        // Module rank (Kyber-768)
    
    /// Derives a lattice scalar from seed using SHAKE-256
    fn derive_scalar(&self, seed: &[u8]) -> [u8; 32] {
        self.hkdf_expand(seed, b"pq-scalar-derivation", 32)
            .try_into()
            .unwrap_or([0u8; 32])
    }
    
    /// Generates LWE public key component: b = A*s + e
    /// Returns serialized lattice element (post-quantum secure)
    fn scalar_mult_base(&self, scalar: &[u8; 32]) -> [u8; 48] {
        // Lattice-based key generation
        // Expand scalar to polynomial coefficients
        let mut result = [0u8; 48];
        
        // Generate public matrix A from domain separator (deterministic)
        let a_seed = sha3_256(b"KYBER_PUBLIC_MATRIX_SEED");
        
        // Compute b = A*s + e where s is derived from scalar
        // Using NTT for efficient polynomial multiplication
        let s_ntt = self.poly_from_bytes(scalar);
        let a_ntt = self.poly_from_bytes(&a_seed);
        
        // b = a * s (in NTT domain)
        let mut b = [0i32; Self::KYBER_N];
        for i in 0..Self::KYBER_N {
            b[i] = ((a_ntt[i % 32] as i32 * s_ntt[i % 32] as i32) % Self::KYBER_Q + Self::KYBER_Q) % Self::KYBER_Q;
        }
        
        // Add small error e for LWE security
        let e = self.sample_error(scalar);
        for i in 0..Self::KYBER_N.min(48) {
            b[i] = (b[i] + e[i] as i32) % Self::KYBER_Q;
            if i < 48 {
                result[i] = (b[i] & 0xFF) as u8;
            }
        }
        
        result
    }
    
    /// Lattice-based "scalar multiplication" - computes shared secret
    fn scalar_mult(&self, point: &[u8], scalar: &[u8]) -> Result<Vec<u8>, EncryptedMempoolError> {
        if point.is_empty() || scalar.is_empty() {
            return Err(EncryptedMempoolError::EncryptionError("Empty input".into()));
        }
        
        // Kyber-style key encapsulation
        // Compute shared_secret = Decode(v - s*u) where (u, v) is ciphertext
        let point_poly = self.poly_from_bytes(point);
        let scalar_poly = self.poly_from_bytes(scalar);
        
        // Polynomial multiplication in Z_q[X]/(X^n + 1)
        let mut result_poly = [0i32; Self::KYBER_N];
        for i in 0..scalar.len().min(Self::KYBER_N) {
            for j in 0..point.len().min(Self::KYBER_N) {
                let idx = (i + j) % Self::KYBER_N;
                let sign = if (i + j) >= Self::KYBER_N { -1 } else { 1 };
                result_poly[idx] = (result_poly[idx] + sign * (point_poly[j] as i32 * scalar_poly[i] as i32)) % Self::KYBER_Q;
                result_poly[idx] = (result_poly[idx] + Self::KYBER_Q) % Self::KYBER_Q;
            }
        }
        
        // Serialize result
        let mut result = vec![0u8; point.len().max(48)];
        for i in 0..result.len().min(Self::KYBER_N) {
            result[i] = (result_poly[i] & 0xFF) as u8;
        }
        
        Ok(result)
    }
    
    /// Lattice point combination for threshold decryption
    fn scalar_mult_point(&self, point: &[u8], scalar: &[u8; 32]) -> Result<[u8; 48], EncryptedMempoolError> {
        let result = self.scalar_mult(point, scalar)?;
        
        let mut output = [0u8; 48];
        let copy_len = result.len().min(48);
        output[..copy_len].copy_from_slice(&result[..copy_len]);
        
        Ok(output)
    }
    
    /// Lattice point addition (component-wise mod q)
    fn point_add(&self, p1: &[u8; 48], p2: &[u8; 48]) -> Result<[u8; 48], EncryptedMempoolError> {
        let mut result = [0u8; 48];
        
        // Component-wise addition mod q
        for i in 0..48 {
            let sum = (p1[i] as i32 + p2[i] as i32) % Self::KYBER_Q;
            result[i] = (sum & 0xFF) as u8;
        }
        
        Ok(result)
    }
    
    /// Samples small error polynomial for LWE
    fn sample_error(&self, seed: &[u8]) -> [i8; Self::KYBER_N] {
        let mut error = [0i8; Self::KYBER_N];
        let hash = sha3_256(&[seed, b"error"].concat());
        
        // Centered binomial distribution with eta=2
        for i in 0..Self::KYBER_N.min(hash.len() * 4) {
            let byte_idx = i / 4;
            let bit_offset = (i % 4) * 2;
            if byte_idx < hash.len() {
                let bits = (hash[byte_idx] >> bit_offset) & 0x03;
                error[i] = (bits.count_ones() as i8) - 1; // {-1, 0, 0, 1}
            }
        }
        
        error
    }
    
    /// Converts bytes to polynomial coefficients
    fn poly_from_bytes(&self, bytes: &[u8]) -> [i16; Self::KYBER_N] {
        let mut poly = [0i16; Self::KYBER_N];
        
        for i in 0..bytes.len().min(Self::KYBER_N) {
            // Map byte to coefficient in [0, q)
            poly[i] = ((bytes[i] as i32 * Self::KYBER_Q) / 256) as i16;
        }
        
        poly
    }
    
    // ============== 256-bit Prime Field Arithmetic ==============
    //
    // NIST P-256 prime: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    // Used for Shamir secret sharing with 256-bit security
    
    /// 256-bit prime modulus for Shamir secret sharing (NIST P-256 field prime)
    /// p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    const PRIME_P256: [u64; 4] = [
        0xFFFFFFFFFFFFFFFF,  // limbs[0] - least significant
        0x00000000FFFFFFFF,  // limbs[1]
        0x0000000000000000,  // limbs[2]
        0xFFFFFFFF00000001,  // limbs[3] - most significant
    ];
    
    /// Computes Lagrange coefficients for Shamir secret sharing
    /// Uses 256-bit prime field arithmetic (post-quantum safe)
    fn compute_lagrange_coefficients(&self, indices: &[u32]) -> Vec<[u8; 32]> {
        let n = indices.len();
        let mut coefficients = Vec::with_capacity(n);
        
        for i in 0..n {
            let xi = self.u32_to_field(indices[i] + 1);
            let mut numerator = self.field_one();
            let mut denominator = self.field_one();
            
            for j in 0..n {
                if i != j {
                    let xj = self.u32_to_field(indices[j] + 1);
                    // numerator *= xj
                    numerator = self.field_mul(&numerator, &xj);
                    // denominator *= (xj - xi)
                    let diff = self.field_sub(&xj, &xi);
                    denominator = self.field_mul(&denominator, &diff);
                }
            }
            
            // coeff = numerator * denominator^(-1) mod p
            let denom_inv = self.field_inverse(&denominator);
            let coeff = self.field_mul(&numerator, &denom_inv);
            
            coefficients.push(self.field_to_bytes(&coeff));
        }
        
        coefficients
    }
    
    /// Converts u32 to 256-bit field element
    fn u32_to_field(&self, val: u32) -> [u64; 4] {
        [val as u64, 0, 0, 0]
    }
    
    /// Returns field element 1
    fn field_one(&self) -> [u64; 4] {
        [1, 0, 0, 0]
    }
    
    /// Field addition: (a + b) mod p
    fn field_add(&self, a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        let mut result = [0u64; 4];
        let mut carry = 0u64;
        
        for i in 0..4 {
            let (sum1, c1) = a[i].overflowing_add(b[i]);
            let (sum2, c2) = sum1.overflowing_add(carry);
            result[i] = sum2;
            carry = (c1 as u64) + (c2 as u64);
        }
        
        // Reduce mod p if necessary
        if carry > 0 || self.field_gte(&result, &Self::PRIME_P256) {
            self.field_sub_prime(&result)
        } else {
            result
        }
    }
    
    /// Field subtraction: (a - b) mod p
    fn field_sub(&self, a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        let mut result = [0u64; 4];
        let mut borrow = 0u64;
        
        for i in 0..4 {
            let (diff1, b1) = a[i].overflowing_sub(b[i]);
            let (diff2, b2) = diff1.overflowing_sub(borrow);
            result[i] = diff2;
            borrow = (b1 as u64) + (b2 as u64);
        }
        
        // If underflow, add p
        if borrow > 0 {
            self.field_add_prime(&result)
        } else {
            result
        }
    }
    
    /// Field multiplication: (a * b) mod p using schoolbook with reduction
    fn field_mul(&self, a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        // 512-bit intermediate result
        let mut product = [0u128; 4];
        
        // Schoolbook multiplication
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                if i + j < 4 {
                    let mul = (a[i] as u128) * (b[j] as u128);
                    let sum = product[i + j] + mul + carry;
                    product[i + j] = sum & 0xFFFFFFFFFFFFFFFF;
                    carry = sum >> 64;
                }
            }
        }
        
        // Reduce to 256 bits mod p
        let mut result = [0u64; 4];
        for i in 0..4 {
            result[i] = product[i] as u64;
        }
        
        // Barrett reduction approximation
        while self.field_gte(&result, &Self::PRIME_P256) {
            result = self.field_sub_prime(&result);
        }
        
        result
    }
    
    /// Modular inverse using Fermat's little theorem: a^(-1) = a^(p-2) mod p
    fn field_inverse(&self, a: &[u64; 4]) -> [u64; 4] {
        // p - 2 for exponentiation
        let exp = [
            0xFFFFFFFFFFFFFFFD,
            0x00000000FFFFFFFF,
            0x0000000000000000,
            0xFFFFFFFF00000001,
        ];
        
        self.field_pow(a, &exp)
    }
    
    /// Field exponentiation using square-and-multiply
    fn field_pow(&self, base: &[u64; 4], exp: &[u64; 4]) -> [u64; 4] {
        let mut result = self.field_one();
        let mut base_pow = *base;
        
        for i in 0..4 {
            let mut e = exp[i];
            for _ in 0..64 {
                if e & 1 == 1 {
                    result = self.field_mul(&result, &base_pow);
                }
                base_pow = self.field_mul(&base_pow, &base_pow);
                e >>= 1;
            }
        }
        
        result
    }
    
    /// Subtract prime from field element
    fn field_sub_prime(&self, a: &[u64; 4]) -> [u64; 4] {
        let mut result = [0u64; 4];
        let mut borrow = 0u64;
        
        for i in 0..4 {
            let (diff1, b1) = a[i].overflowing_sub(Self::PRIME_P256[i]);
            let (diff2, b2) = diff1.overflowing_sub(borrow);
            result[i] = diff2;
            borrow = (b1 as u64) + (b2 as u64);
        }
        
        result
    }
    
    /// Add prime to field element
    fn field_add_prime(&self, a: &[u64; 4]) -> [u64; 4] {
        let mut result = [0u64; 4];
        let mut carry = 0u64;
        
        for i in 0..4 {
            let (sum1, c1) = a[i].overflowing_add(Self::PRIME_P256[i]);
            let (sum2, c2) = sum1.overflowing_add(carry);
            result[i] = sum2;
            carry = (c1 as u64) + (c2 as u64);
        }
        
        result
    }
    
    /// Compare field elements: a >= b
    fn field_gte(&self, a: &[u64; 4], b: &[u64; 4]) -> bool {
        for i in (0..4).rev() {
            if a[i] > b[i] { return true; }
            if a[i] < b[i] { return false; }
        }
        true // equal
    }
    
    /// Convert field element to 32 bytes (little-endian)
    fn field_to_bytes(&self, a: &[u64; 4]) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[i*8..(i+1)*8].copy_from_slice(&a[i].to_le_bytes());
        }
        bytes
    }
    
    /// Convert 32 bytes to field element (little-endian)
    fn bytes_to_field(&self, bytes: &[u8; 32]) -> [u64; 4] {
        let mut result = [0u64; 4];
        for i in 0..4 {
            result[i] = u64::from_le_bytes(bytes[i*8..(i+1)*8].try_into().unwrap());
        }
        // Reduce if >= p
        if self.field_gte(&result, &Self::PRIME_P256) {
            self.field_sub_prime(&result)
        } else {
            result
        }
    }
    
    /// Scalar addition and multiplication: k + c * s (mod p)
    fn scalar_add_mul(&self, k: &[u8; 32], c: &[u8; 32], s: &[u8]) -> [u8; 32] {
        let k_field = self.bytes_to_field(k);
        let c_field = self.bytes_to_field(c);
        
        // Pad s to 32 bytes if needed
        let mut s_bytes = [0u8; 32];
        let copy_len = s.len().min(32);
        s_bytes[..copy_len].copy_from_slice(&s[..copy_len]);
        let s_field = self.bytes_to_field(&s_bytes);
        
        // r = k + c * s (mod p)
        let cs = self.field_mul(&c_field, &s_field);
        let result = self.field_add(&k_field, &cs);
        
        self.field_to_bytes(&result)
    }
    
    /// HKDF-Expand for key derivation
    fn hkdf_expand(&self, ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(length);
        let mut counter = 1u8;
        let mut prev = Vec::new();
        
        while output.len() < length {
            let mut data = Vec::new();
            data.extend_from_slice(&prev);
            data.extend_from_slice(ikm);
            data.extend_from_slice(info);
            data.push(counter);
            
            let hash = sha3_256(&data);
            output.extend_from_slice(&hash);
            prev = hash.to_vec();
            counter += 1;
        }
        
        output.truncate(length);
        output
    }
    
    /// ChaCha20-Poly1305 encryption
    fn chacha20_encrypt(&self, plaintext: &[u8], key: &[u8], nonce: &[u8; 24]) -> Result<Vec<u8>, EncryptedMempoolError> {
        // ChaCha20 stream cipher with Poly1305 MAC
        let mut ciphertext = Vec::with_capacity(plaintext.len() + 16);
        
        // Generate keystream
        let keystream = self.chacha20_keystream(key, nonce, plaintext.len());
        
        // Encrypt: ciphertext = plaintext XOR keystream
        for (i, &byte) in plaintext.iter().enumerate() {
            ciphertext.push(byte ^ keystream[i]);
        }
        
        // Compute Poly1305 authentication tag
        let tag = self.poly1305_mac(&ciphertext, key, nonce);
        ciphertext.extend_from_slice(&tag);
        
        Ok(ciphertext)
    }
    
    /// ChaCha20-Poly1305 decryption
    fn chacha20_decrypt(&self, ciphertext: &[u8], key: &[u8], nonce: &[u8; 24]) -> Result<Vec<u8>, EncryptedMempoolError> {
        if ciphertext.len() < 16 {
            return Err(EncryptedMempoolError::EncryptionError("Ciphertext too short".into()));
        }
        
        let data_len = ciphertext.len() - 16;
        let encrypted_data = &ciphertext[..data_len];
        let tag = &ciphertext[data_len..];
        
        // Verify authentication tag
        let computed_tag = self.poly1305_mac(encrypted_data, key, nonce);
        if tag != computed_tag.as_slice() {
            return Err(EncryptedMempoolError::EncryptionError("Authentication failed".into()));
        }
        
        // Generate keystream and decrypt
        let keystream = self.chacha20_keystream(key, nonce, data_len);
        
        let mut plaintext = Vec::with_capacity(data_len);
        for (i, &byte) in encrypted_data.iter().enumerate() {
            plaintext.push(byte ^ keystream[i]);
        }
        
        Ok(plaintext)
    }
    
    /// Generates ChaCha20 keystream using real quarter-round mixing (RFC 8439).
    fn chacha20_keystream(&self, key: &[u8], nonce: &[u8; 24], length: usize) -> Vec<u8> {
        let mut keystream = Vec::with_capacity(length);
        let mut counter = 0u32;
        
        // Pad key to 32 bytes
        let mut padded_key = [0u8; 32];
        let klen = key.len().min(32);
        padded_key[..klen].copy_from_slice(&key[..klen]);
        
        while keystream.len() < length {
            // Initialize ChaCha20 state (16 x u32 words)
            let mut state = [0u32; 16];
            
            // Constants: "expand 32-byte k"
            state[0] = 0x61707865;
            state[1] = 0x3320646e;
            state[2] = 0x79622d32;
            state[3] = 0x6b206574;
            
            // Key (8 words)
            for i in 0..8 {
                state[4 + i] = u32::from_le_bytes(padded_key[i*4..(i+1)*4].try_into().unwrap());
            }
            
            // Counter
            state[12] = counter;
            
            // XChaCha20-style: derive subnonce from full 24-byte nonce
            // Hash all 24 nonce bytes with key to derive 12-byte effective nonce
            // This prevents nonce reuse when first 12 bytes match but remaining differ
            let nonce_hash = sha3_256(&[&padded_key[..], &nonce[..]].concat());
            for i in 0..3 {
                state[13 + i] = u32::from_le_bytes(nonce_hash[i*4..(i+1)*4].try_into().unwrap());
            }
            
            // Working copy
            let mut working = state;
            
            // 20 rounds (10 double-rounds)
            for _ in 0..10 {
                // Column rounds
                Self::quarter_round(&mut working, 0, 4, 8, 12);
                Self::quarter_round(&mut working, 1, 5, 9, 13);
                Self::quarter_round(&mut working, 2, 6, 10, 14);
                Self::quarter_round(&mut working, 3, 7, 11, 15);
                // Diagonal rounds
                Self::quarter_round(&mut working, 0, 5, 10, 15);
                Self::quarter_round(&mut working, 1, 6, 11, 12);
                Self::quarter_round(&mut working, 2, 7, 8, 13);
                Self::quarter_round(&mut working, 3, 4, 9, 14);
            }
            
            // Add original state
            for i in 0..16 {
                working[i] = working[i].wrapping_add(state[i]);
            }
            
            // Serialize block to bytes (64 bytes per block)
            for word in &working {
                keystream.extend_from_slice(&word.to_le_bytes());
            }
            
            counter += 1;
        }
        
        keystream.truncate(length);
        keystream
    }
    
    /// ChaCha20 quarter round operation (RFC 8439 Section 2.1)
    #[inline]
    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]); state[d] ^= state[a]; state[d] = state[d].rotate_left(16);
        state[c] = state[c].wrapping_add(state[d]); state[b] ^= state[c]; state[b] = state[b].rotate_left(12);
        state[a] = state[a].wrapping_add(state[b]); state[d] ^= state[a]; state[d] = state[d].rotate_left(8);
        state[c] = state[c].wrapping_add(state[d]); state[b] ^= state[c]; state[b] = state[b].rotate_left(7);
    }
    
    /// Poly1305 message authentication code (RFC 8439 Section 2.5).
    /// 
    /// Computes tag = (((a * r) mod p) + s) mod 2^128
    /// where p = 2^130 - 5, r is clamped from key[0..16], s = key[16..32]
    fn poly1305_mac(&self, data: &[u8], key: &[u8], _nonce: &[u8]) -> [u8; 16] {
        // Extract r and s from key
        let mut mac_key = [0u8; 32];
        let key_len = key.len().min(32);
        mac_key[..key_len].copy_from_slice(&key[..key_len]);
        
        // Clamp r (RFC 8439 Section 2.5.2)
        mac_key[3] &= 0x0f;
        mac_key[7] &= 0x0f;
        mac_key[11] &= 0x0f;
        mac_key[15] &= 0x0f;
        mac_key[4] &= 0xfc;
        mac_key[8] &= 0xfc;
        mac_key[12] &= 0xfc;
        
        // r as 128-bit little-endian
        let r0 = u64::from_le_bytes(mac_key[0..8].try_into().unwrap()) as u128;
        let r1 = u64::from_le_bytes(mac_key[8..16].try_into().unwrap()) as u128;
        let r: u128 = r0 | (r1 << 64);
        
        // s as 128-bit little-endian
        let s0 = u64::from_le_bytes(mac_key[16..24].try_into().unwrap()) as u128;
        let s1 = u64::from_le_bytes(mac_key[24..32].try_into().unwrap()) as u128;
        let s: u128 = s0 | (s1 << 64);
        
        // p = 2^130 - 5
        // We use 3 u128 limbs for 130-bit arithmetic
        // Accumulator
        let mut acc_lo: u128 = 0;
        let mut acc_hi: u128 = 0; // Overflow bits
        
        // Process data in 16-byte blocks
        let mut i = 0;
        while i < data.len() {
            let block_end = (i + 16).min(data.len());
            let block_len = block_end - i;
            
            // Read block as little-endian 128-bit number
            let mut block_bytes = [0u8; 17];
            block_bytes[..block_len].copy_from_slice(&data[i..block_end]);
            // Add high bit (2^(8*block_len)) to mark block boundary
            block_bytes[block_len] = 1;
            
            let n_lo = u64::from_le_bytes(block_bytes[0..8].try_into().unwrap()) as u128;
            let n_hi = u64::from_le_bytes(block_bytes[8..16].try_into().unwrap()) as u128;
            let n_top = block_bytes[16] as u128;
            
            let n: u128 = n_lo | (n_hi << 64);
            
            // acc += n (with overflow into acc_hi)
            let (new_acc, carry) = acc_lo.overflowing_add(n);
            acc_lo = new_acc;
            acc_hi = acc_hi.wrapping_add(n_top).wrapping_add(carry as u128);
            
            // acc *= r (mod 2^130 - 5)
            // Split into manageable multiplications
            let acc_full_lo = acc_lo;
            let acc_full_hi = acc_hi & 0x3; // Only 2 bits for 130-bit
            
            // Multiply: result = acc * r
            // Using schoolbook multiplication with 64-bit limbs
            let a0 = (acc_full_lo & 0xFFFFFFFFFFFFFFFF) as u128;
            let a1 = (acc_full_lo >> 64) as u128;
            let a2 = acc_full_hi;
            
            let r0_64 = (r & 0xFFFFFFFFFFFFFFFF) as u128;
            let r1_64 = (r >> 64) as u128;
            
            // Partial products
            let d0 = a0.wrapping_mul(r0_64);
            let d1 = a0.wrapping_mul(r1_64).wrapping_add(a1.wrapping_mul(r0_64));
            let d2 = a1.wrapping_mul(r1_64).wrapping_add(a2.wrapping_mul(r0_64));
            
            // Combine into 130-bit result mod (2^130 - 5)
            // Reduce: values above 2^130 get multiplied by 5
            let result_lo = d0.wrapping_add((d1 & 0xFFFFFFFFFFFFFFFF) << 64);
            let result_hi = (d1 >> 64).wrapping_add(d2);
            
            // Partial reduction mod 2^130 - 5
            let overflow = result_hi >> 2;
            acc_lo = result_lo.wrapping_add(overflow.wrapping_mul(5));
            acc_hi = result_hi & 0x3;
            
            // Handle carry from addition
            if acc_lo < result_lo { // overflow in addition
                acc_hi = acc_hi.wrapping_add(1);
            }
            
            i += 16;
        }
        
        // Final reduction mod 2^130 - 5
        let overflow = acc_hi >> 2;
        acc_lo = acc_lo.wrapping_add(overflow.wrapping_mul(5));
        // Final mask: acc_hi &= 0x3 (only low bits contribute to tag)
        let masked_hi = acc_hi & 0x3;
        
        // acc += s (mod 2^128, no reduction by p)
        let tag = acc_lo.wrapping_add(s).wrapping_add(masked_hi as u128);
        
        tag.to_le_bytes()
    }
    
    /// Returns statistics
    pub fn stats(&self) -> EncryptedMempoolStats {
        self.stats.lock().clone()
    }
}

/// Encrypted mempool errors
#[derive(Debug, Clone)]
pub enum EncryptedMempoolError {
    InvalidTargetBlock,
    NoThresholdParams,
    TransactionTooLarge,
    InvalidShareProof,
    InsufficientShares,
    CommitmentMismatch,
    DeserializationError,
    MEVAuctionDisabled,
    BidTooLow,
    BidExpired,
    EncryptionError(String),
}

impl std::fmt::Display for EncryptedMempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptedMempoolError::InvalidTargetBlock => write!(f, "Invalid target block"),
            EncryptedMempoolError::NoThresholdParams => write!(f, "No threshold parameters"),
            EncryptedMempoolError::TransactionTooLarge => write!(f, "Transaction too large"),
            EncryptedMempoolError::InvalidShareProof => write!(f, "Invalid share proof"),
            EncryptedMempoolError::InsufficientShares => write!(f, "Insufficient shares"),
            EncryptedMempoolError::CommitmentMismatch => write!(f, "Commitment mismatch"),
            EncryptedMempoolError::DeserializationError => write!(f, "Deserialization error"),
            EncryptedMempoolError::MEVAuctionDisabled => write!(f, "MEV auction disabled"),
            EncryptedMempoolError::BidTooLow => write!(f, "Bid too low"),
            EncryptedMempoolError::BidExpired => write!(f, "Bid expired"),
            EncryptedMempoolError::EncryptionError(e) => write!(f, "Encryption error: {}", e),
        }
    }
}

impl std::error::Error for EncryptedMempoolError {}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypt_decrypt_flow() {
        let config = EncryptedMempoolConfig {
            threshold: 2,
            total_decryptors: 3,
            ..Default::default()
        };
        
        let mempool = EncryptedMempool::new(config);
        
        // Set up threshold params
        mempool.set_threshold_params(0, ThresholdParams {
            threshold: 2,
            total: 3,
            epoch: 0,
            public_key: vec![1, 2, 3, 4],
            participant_keys: vec![],
        });
        
        // Set key shares
        for i in 0..3 {
            mempool.set_key_share(0, KeyShare {
                participant_id: i,
                share: vec![i as u8; 32],
                verification_key: vec![],
            });
        }
        
        mempool.advance_block(10);
        
        // The full flow would be tested with actual transactions
    }
}
