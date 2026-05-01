use serde::{Deserialize, Serialize};
use crate::types::{Address, Amount, Hash, PublicKey, ShardId, Signature, hash_data};
use crate::crypto::{verify_dilithium, with_domain, DOMAIN_TX};

/// MEDIUM (z7): Reduced timestamp drift from 5 min to 30 sec to limit manipulation
const MAX_TIMESTAMP_DRIFT: u64 = 30;

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
    /// Maximum compute units allowed for this transaction (STACC).
    pub max_compute_units: u64,
    /// Optional priority boost lock (STACC). Tokens are never burned.
    #[serde(default)]
    pub boost: Option<PriorityBoost>,
    pub data: Vec<u8>,
    pub shard_id: ShardId,
    pub timestamp: u64,
    pub signature: Signature,
    pub public_key: PublicKey,
    pub chain_id: u64,
}

/// Priority boost lock (STACC).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PriorityBoost {
    /// Tokens locked temporarily to signal urgency.
    pub locked_tokens: u64,
    /// Lock duration in blocks.
    pub lock_duration_blocks: u64,
}

impl Transaction {
    pub fn new(
        tx_type: TransactionType,
        from: Address,
        to: Address,
        amount: Amount,
        nonce: u64,
        max_compute_units: u64,
        boost: Option<PriorityBoost>,
        data: Vec<u8>,
        shard_id: ShardId,
    ) -> Self {
        Self {
            tx_type,
            from,
            to,
            amount,
            nonce,
            max_compute_units,
            boost,
            data,
            shard_id,
            timestamp: chrono::Utc::now().timestamp() as u64,
            signature: Vec::new(),
            public_key: Vec::new(),
            chain_id: 1, // Default chain ID
        }
    }

    pub fn hash(&self) -> Hash {
        let data = self.signing_data();
        hash_data(&data)
    }

    pub fn signing_data(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&[self.tx_type.clone() as u8]);
        msg.extend_from_slice(&self.from);
        msg.extend_from_slice(&self.to);
        msg.extend_from_slice(&self.amount.0.to_le_bytes());
        msg.extend_from_slice(&self.nonce.to_le_bytes());
        msg.extend_from_slice(&self.max_compute_units.to_le_bytes());
        if let Some(boost) = &self.boost {
            msg.extend_from_slice(&boost.locked_tokens.to_le_bytes());
            msg.extend_from_slice(&boost.lock_duration_blocks.to_le_bytes());
        } else {
            msg.extend_from_slice(&0u64.to_le_bytes());
            msg.extend_from_slice(&0u64.to_le_bytes());
        }
        msg.extend_from_slice(&self.data);
        msg.extend_from_slice(&self.shard_id.to_le_bytes());
        msg.extend_from_slice(&self.timestamp.to_le_bytes());
        msg.extend_from_slice(&self.chain_id.to_le_bytes());
        with_domain(DOMAIN_TX, &msg)
    }

    pub fn set_signature(&mut self, signature: Signature, public_key: PublicKey) -> Result<(), String> {
        // CRITICAL: Verify signature before accepting
        let signing_data = self.signing_data();
        match verify_dilithium(&public_key, &signing_data, &signature) {
            Ok(true) => {
                self.signature = signature;
                self.public_key = public_key;
                Ok(())
            }
            Ok(false) => Err("Invalid signature".to_string()),
            Err(e) => Err(format!("Signature verification error: {:?}", e)),
        }
    }
    
    pub fn validate_timestamp(&self, current_time: u64) -> Result<(), String> {
        if self.timestamp > current_time + MAX_TIMESTAMP_DRIFT {
            return Err("Transaction timestamp too far in future".to_string());
        }
        if current_time > self.timestamp + MAX_TIMESTAMP_DRIFT {
            return Err("Transaction timestamp too old".to_string());
        }
        Ok(())
    }

    /// Total locked tokens required by this tx (priority boost only).
    pub fn boost_locked_tokens(&self) -> u64 {
        self.boost.as_ref().map(|b| b.locked_tokens).unwrap_or(0)
    }

    /// Native balance that must be coverable by `from` (value + boost lock). CU limits do not spend balance.
    pub fn balance_commitment(&self) -> Option<u128> {
        (self.amount.0 as u128).checked_add(self.boost_locked_tokens() as u128)
    }

    /// MEDIUM (z10): Use more address bytes for better entropy in shard mapping.
    /// Uses first 8 bytes (64 bits) instead of 2 bytes (16 bits) to prevent
    /// attackers from easily generating addresses targeting specific shards.
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
        Self {
            transaction,
            hash,
            size,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub tx_hash: Hash,
    pub status: TransactionStatus,
    pub cu_used: u64,
    pub vertex_hash: Hash,
    pub shard_id: ShardId,
    pub logs: Vec<Log>,
    pub slot: u64,
    pub from: Address,
    pub to: Address,
    pub success: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransactionStatus {
    Pending,
    Included,
    PreConfirmed,
    Finalized,
    Failed(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<Hash>,
    pub data: Vec<u8>,
}
