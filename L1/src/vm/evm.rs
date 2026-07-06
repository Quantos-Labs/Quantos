//! EVM execution engine (revm) integrated with STACC Compute Units (no fees).

use std::collections::HashMap;

use sha3::{Digest, Keccak256};

use parking_lot::Mutex;
use revm::context::TxEnv;
use revm::database::{CacheDB, WrapDatabaseRef};
use revm::handler::{ExecuteEvm, MainBuilder, MainContext};
use revm::primitives::{keccak256, Address as EvmAddress, Bytes, TxKind, U256, B256};
use revm::state::{AccountInfo, Bytecode};
use revm::context_interface::result::{ExecutionResult, Output};
use revm::database_interface::{ErasedError, DatabaseRef};
use revm::state::AccountStatus;

use crate::storage::Storage;
use crate::types::{Account, Address, Amount};

#[derive(Clone)]
pub struct EvmEngine {
    storage: Storage,
}

#[derive(Clone, Debug)]
pub struct EvmExecOutcome {
    pub success: bool,
    pub return_data: Vec<u8>,
    pub logs: Vec<crate::vm::runtime::ContractLog>,
    pub cu_used: u64,
    pub created_address: Option<Address>,
    pub deployed_code: Option<Vec<u8>>,
    pub storage_writes: HashMap<Vec<u8>, Vec<u8>>,
}

#[derive(Clone)]
struct QuantosEvmDb {
    storage: Storage,
    storage_cache: ArcStorageCache,
    code_cache: ArcCodeCache,
}

type ArcStorageCache = std::sync::Arc<Mutex<HashMap<Address, HashMap<Vec<u8>, Vec<u8>>>>>;
type ArcCodeCache = std::sync::Arc<Mutex<HashMap<Address, Vec<u8>>>>;

impl QuantosEvmDb {
    fn new(storage: Storage) -> Self {
        Self {
            storage,
            storage_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
            code_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn addr32_from_evm(a: EvmAddress) -> Address {
        let mut out = [0u8; 32];
        out[12..32].copy_from_slice(a.as_slice());
        out
    }

    fn load_code(&self, a32: &Address) -> Result<Vec<u8>, String> {
        if let Some(code) = self.code_cache.lock().get(a32).cloned() {
            return Ok(code);
        }
        let code = self
            .storage
            .get_contract_bytecode(a32)
            .map_err(|e| format!("get_contract_bytecode: {e}"))?
            .unwrap_or_default();
        self.code_cache.lock().insert(*a32, code.clone());
        Ok(code)
    }

    fn cache_storage_slot(&self, a32: &Address, k: &[u8; 32], v: Vec<u8>) {
        let mut guard = self.storage_cache.lock();
        let entry = guard.entry(*a32).or_default();
        entry.insert(k.to_vec(), v);
    }
}

impl DatabaseRef for QuantosEvmDb {
    type Error = ErasedError;

    fn basic_ref(&self, address: EvmAddress) -> Result<Option<AccountInfo>, Self::Error> {
        let a32 = Self::addr32_from_evm(address);
        let acc = self
            .storage
            .get_account(&a32)
            .map_err(|e| ErasedError::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
        let Some(acc) = acc else {
            return Ok(None);
        };

        let code = self
            .load_code(&a32)
            .map_err(|e| ErasedError::new(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        let code_hash: B256 = keccak256(&code);

        let mut info = AccountInfo::default();
        info.balance = U256::from(acc.balance.0);
        info.nonce = acc.nonce;
        info.code_hash = code_hash;
        info.code = Some(Bytecode::new_raw(Bytes::from(code)));
        Ok(Some(info))
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        // We always provide code in `basic_ref`.
        Ok(Bytecode::default())
    }

    fn storage_ref(&self, address: EvmAddress, index: U256) -> Result<U256, Self::Error> {
        let a32 = Self::addr32_from_evm(address);
        let key = index.to_be_bytes::<32>().to_vec();
        if let Some(v) = self
            .storage_cache
            .lock()
            .get(&a32)
            .and_then(|m| m.get(&key).cloned())
        {
            return Ok(U256::from_be_slice(&pad32_be(&v)));
        }

        let mut k32 = [0u8; 32];
        k32.copy_from_slice(&key);
        let v = self
            .storage
            .get_contract_storage_value(&a32, &k32)
            .map_err(|e| ErasedError::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

        match v {
            Some(vbytes) => {
                self.cache_storage_slot(&a32, &k32, vbytes.clone());
                Ok(U256::from_be_slice(&pad32_be(&vbytes)))
            }
            None => Ok(U256::ZERO),
        }
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        Ok(keccak256(number.to_be_bytes()))
    }
}

impl EvmEngine {
    pub fn new(storage: Storage) -> Self {
        Self { storage }
    }

    pub fn deploy(
        &self,
        caller: Address,
        nonce: u64,
        value: Amount,
        init_code: Vec<u8>,
        max_cu: u64,
        _chain_id: u64,
    ) -> Result<EvmExecOutcome, String> {
        let contract = evm_create_address(caller, nonce);
        let res = self.execute_inner(
            caller,
            Some(contract),
            value,
            init_code,
            max_cu,
            true,
        )?;
        Ok(EvmExecOutcome { created_address: Some(contract), ..res })
    }

    pub fn call(
        &self,
        caller: Address,
        contract: Address,
        value: Amount,
        input: Vec<u8>,
        max_cu: u64,
        _chain_id: u64,
    ) -> Result<EvmExecOutcome, String> {
        self.execute_inner(caller, Some(contract), value, input, max_cu, false)
    }

    fn execute_inner(
        &self,
        caller: Address,
        contract: Option<Address>,
        value: Amount,
        input: Vec<u8>,
        max_cu: u64,
        is_create: bool,
    ) -> Result<EvmExecOutcome, String> {
        let caller_evm = to_evm_address(caller);
        let ext = QuantosEvmDb::new(self.storage.clone());
        let mut db = CacheDB::new(WrapDatabaseRef(ext));

        let tx = TxEnv::builder()
            .caller(caller_evm)
            .gas_limit(max_cu)
            .gas_price(0)
            .value(U256::from(value.0))
            .data(Bytes::from(input))
            .kind(if is_create {
                TxKind::Create
            } else {
                let to = contract.ok_or("missing contract")?;
                TxKind::Call(to_evm_address(to))
            })
            .build()
            .map_err(|e| format!("tx build: {e:?}"))?;

        let mut evm = revm::Context::mainnet().with_db(db).build_mainnet();
        let out = evm.transact(tx).map_err(|e| format!("evm transact: {e:?}"))?;

        // Collect EVM logs into Quantos format (address 20 -> 32; topics B256 -> [u8;32]).
        let mut logs: Vec<crate::vm::runtime::ContractLog> = Vec::new();
        match &out.result {
            ExecutionResult::Success { logs: evm_logs, .. }
            | ExecutionResult::Revert { logs: evm_logs, .. }
            | ExecutionResult::Halt { logs: evm_logs, .. } => {
                for l in evm_logs {
                    let mut addr32 = [0u8; 32];
                    addr32[12..32].copy_from_slice(l.address.as_slice());
                    let topics: Vec<[u8; 32]> = l.topics().iter().map(|t| t.0).collect();
                    logs.push(crate::vm::runtime::ContractLog {
                        address: addr32,
                        topics,
                        data: l.data.data.to_vec(),
                    });
                }
            }
        }

        // Persist touched accounts (balances/nonces), contract bytecode and storage writes.
        // NOTE: addresses are 20-byte EVM; we map to Quantos 32-byte by left-padding zeros.
        let mut deployed_code: Option<Vec<u8>> = None;
        let mut storage_writes: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        for (addr20, evm_acc) in &out.state {
            let a32 = QuantosEvmDb::addr32_from_evm(*addr20);

            // Handle SELFDESTRUCT: purge contract storage + bytecode.
            if evm_acc.status.contains(AccountStatus::SelfDestructed) {
                self.storage
                    .delete_contract_storage_all(&a32)
                    .map_err(|e| format!("delete_contract_storage_all: {e}"))?;
                self.storage
                    .delete_contract_bytecode(&a32)
                    .map_err(|e| format!("delete_contract_bytecode: {e}"))?;
            }

            let mut qacc = self
                .storage
                .get_account(&a32)
                .map_err(|e| format!("get_account: {e}"))?
                .unwrap_or_else(|| Account::new(a32));

            // Persist balance/nonce (best-effort: clamp to u128).
            qacc.nonce = evm_acc.info.nonce;
            qacc.balance = Amount(u256_to_u128_saturating(evm_acc.info.balance));

            // Persist bytecode if present.
            if let Some(code) = &evm_acc.info.code {
                if !code.is_empty() {
                    let raw = code.bytes();
                    self.storage
                        .put_contract_bytecode(&a32, raw.as_ref())
                        .map_err(|e| format!("put_contract_bytecode: {e}"))?;
                    qacc.code_hash = Some(crate::types::hash_data(raw.as_ref()));
                    if is_create {
                        if let Some(ca) = contract {
                            if a32 == ca {
                                deployed_code = Some(raw.as_ref().to_vec());
                            }
                        }
                    }
                }
            }

            // Persist storage writes for this account (only if it has any).
            if !evm_acc.storage.is_empty() {
                let mut writes = HashMap::new();
                for (slot, val) in &evm_acc.storage {
                    writes.insert(slot.to_be_bytes::<32>().to_vec(), val.present_value().to_be_bytes::<32>().to_vec());
                }
                // Keep return value for the main target (for receipts/debug).
                if let Some(ca) = contract {
                    if a32 == ca {
                        storage_writes = writes.clone();
                    }
                }
                self.storage
                    .update_contract_storage(&a32, &writes, &[])
                    .map_err(|e| format!("update_contract_storage: {e}"))?;
            }

            self.storage
                .put_account(&qacc)
                .map_err(|e| format!("put_account: {e}"))?;
        }

        let (success, cu_used, return_data) = match out.result {
            ExecutionResult::Success { output, gas, .. } => {
                let data = match output {
                    Output::Call(b) => b.to_vec(),
                    Output::Create(b, _) => b.to_vec(),
                };
                (true, gas.tx_gas_used(), data)
            }
            ExecutionResult::Revert { output, gas, .. } => (false, gas.tx_gas_used(), output.to_vec()),
            ExecutionResult::Halt { gas, .. } => (false, gas.tx_gas_used(), Vec::new()),
        };

        Ok(EvmExecOutcome {
            success,
            return_data,
            logs,
            cu_used,
            created_address: None,
            deployed_code,
            storage_writes,
        })
    }
}

fn to_evm_address(a: Address) -> EvmAddress {
    let mut out = [0u8; 20];
    out.copy_from_slice(&a[12..32]);
    EvmAddress::from_slice(&out)
}

fn evm_create_address(caller: Address, nonce: u64) -> Address {
    // Ethereum CREATE: keccak256(rlp([caller20, nonce]))[12..]
    let caller20 = &caller[12..32];
    let rlp = rlp_list(&[rlp_bytes(caller20), rlp_u64(nonce)]);
    let h = Keccak256::digest(rlp);
    let mut out = [0u8; 32];
    out[12..32].copy_from_slice(&h[12..32]);
    out
}

fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    if b.len() == 1 && b[0] <= 0x7f {
        return vec![b[0]];
    }
    if b.len() <= 55 {
        let mut out = Vec::with_capacity(1 + b.len());
        out.push(0x80 + (b.len() as u8));
        out.extend_from_slice(b);
        out
    } else {
        let len_bytes = be_len_bytes(b.len());
        let mut out = Vec::with_capacity(1 + len_bytes.len() + b.len());
        out.push(0xb7 + (len_bytes.len() as u8));
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(b);
        out
    }
}

fn rlp_u64(v: u64) -> Vec<u8> {
    if v == 0 {
        return vec![0x80];
    }
    if v <= 0x7f {
        return vec![v as u8];
    }
    let mut buf = Vec::new();
    let mut x = v;
    while x > 0 {
        buf.push((x & 0xff) as u8);
        x >>= 8;
    }
    buf.reverse();
    rlp_bytes(&buf)
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_len: usize = items.iter().map(|v| v.len()).sum();
    let mut out = Vec::new();
    if payload_len <= 55 {
        out.push(0xc0 + (payload_len as u8));
    } else {
        let len_bytes = be_len_bytes(payload_len);
        out.push(0xf7 + (len_bytes.len() as u8));
        out.extend_from_slice(&len_bytes);
    }
    for it in items {
        out.extend_from_slice(it);
    }
    out
}

fn be_len_bytes(mut n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    while n > 0 {
        out.push((n & 0xff) as u8);
        n >>= 8;
    }
    out.reverse();
    out
}

fn pad32_be(v: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    if v.len() >= 32 {
        out.copy_from_slice(&v[v.len() - 32..]);
    } else {
        out[32 - v.len()..].copy_from_slice(v);
    }
    out
}

fn u256_to_u128_saturating(v: U256) -> u128 {
    // Keep low 128 bits; saturate if higher limbs are set.
    let limbs = v.as_limbs();
    if limbs[2] != 0 || limbs[3] != 0 {
        return u128::MAX;
    }
    ((limbs[1] as u128) << 64) | (limbs[0] as u128)
}

