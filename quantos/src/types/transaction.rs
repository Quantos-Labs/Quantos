use serde::{Deserialize, Serialize};
use crate::types::{Address, Amount, Hash, PublicKey, ShardId, Signature, hash_data};
use crate::crypto::verify_dilithium;

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
    pub fn new(
        tx_type: TransactionType,
        from: Address,
        to: Address,
        amount: Amount,
        nonce: u64,
        gas_limit: u64,
        gas_price: u64,
        data: Vec<u8>,
        shard_id: ShardId,
    ) -> Self {
        Self {
            tx_type,
            from,
            to,
            amount,
            nonce,
            gas_limit,
            gas_price,
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
        let mut data = Vec::new();
        data.extend_from_slice(&[self.tx_type.clone() as u8]);
        data.extend_from_slice(&self.from);
        data.extend_from_slice(&self.to);
        data.extend_from_slice(&self.amount.0.to_le_bytes());
        data.extend_from_slice(&self.nonce.to_le_bytes());
        data.extend_from_slice(&self.gas_limit.to_le_bytes());
        data.extend_from_slice(&self.gas_price.to_le_bytes());
        data.extend_from_slice(&self.data);
        data.extend_from_slice(&self.shard_id.to_le_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&self.chain_id.to_le_bytes());
        data
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

    pub fn gas_cost(&self) -> Option<u128> {
        // CRITICAL: Use checked arithmetic to prevent overflow
        (self.gas_limit as u128).checked_mul(self.gas_price as u128)
    }

    pub fn total_cost(&self) -> Option<u128> {
        // CRITICAL: Use checked arithmetic to prevent overflow
        self.gas_cost()?.checked_add(self.amount.0)
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
    pub gas_used: u64,
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
