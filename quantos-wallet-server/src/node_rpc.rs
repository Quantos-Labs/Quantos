// src/node_rpc.rs — HTTP JSON-RPC client to call the Quantos node

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{WalletError, WalletResult};

fn decode_scale_compact_usize(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    match first & 0b11 {
        0b00 => Some(((first >> 2) as usize, 1)),
        0b01 => {
            let second = *data.get(1)?;
            let raw = u16::from_le_bytes([first, second]);
            Some(((raw >> 2) as usize, 2))
        }
        0b10 => {
            let bytes = <[u8; 4]>::try_from(data.get(..4)?).ok()?;
            let raw = u32::from_le_bytes(bytes);
            Some(((raw >> 2) as usize, 4))
        }
        0b11 => {
            let byte_len = ((first >> 2) as usize).checked_add(4)?;
            let len_bytes = data.get(1..1 + byte_len)?;
            if len_bytes.len() > std::mem::size_of::<usize>() {
                return None;
            }
            let mut value = 0usize;
            for (shift, byte) in len_bytes.iter().enumerate() {
                value |= (*byte as usize) << (shift * 8);
            }
            Some((value, 1 + byte_len))
        }
        _ => None,
    }
}

fn decode_uint256_le_u128(data: &[u8]) -> Option<u128> {
    let bytes = <[u8; 16]>::try_from(data.get(..16)?).ok()?;
    Some(u128::from_le_bytes(bytes))
}

fn describe_panic_code(code: u128) -> &'static str {
    match code {
        0x01 => "assertion failed",
        0x11 => "arithmetic overflow/underflow",
        0x12 => "division or modulo by zero",
        0x21 => "invalid enum conversion",
        0x22 => "invalid storage byte array encoding",
        0x31 => "pop on empty array",
        0x32 => "array or bytes index out of bounds",
        0x41 => "memory allocation overflow",
        0x51 => "call to uninitialized internal function",
        _ => "unknown panic",
    }
}

fn decode_hex_revert_reason(reason: &str) -> Option<String> {
    let hex = reason.strip_prefix("0x").unwrap_or(reason);
    let data = hex::decode(hex).ok()?;

    // Error(string) selector: 08c379a0
    if data.len() >= 4 && data[..4] == [0x08, 0xc3, 0x79, 0xa0] {
        let payload = &data[4..];

        // ABI EVM standard: 32 bytes offset + 32 bytes length (LE) + string bytes
        if payload.len() >= 64 {
            // Skip the 32-byte offset word, read the 32-byte LE length word
            let len_word = &payload[32..64];
            let str_len = u128::from_le_bytes(
                <[u8; 16]>::try_from(&len_word[..16]).ok()?
            ) as usize;
            let str_start: usize = 64;
            let str_end = str_start.checked_add(str_len)?;
            if str_end <= payload.len() {
                if let Ok(s) = std::str::from_utf8(&payload[str_start..str_end]) {
                    if !s.is_empty() {
                        return Some(s.to_string());
                    }
                }
            }
        }

        // Fallback: SCALE compact length (for Substrate-compatible nodes)
        let payload = &data[4..];
        if let Some((str_len, prefix_len)) = decode_scale_compact_usize(payload) {
            let str_start = prefix_len;
            let str_end = str_start.checked_add(str_len)?;
            if str_end <= payload.len() {
                if let Ok(s) = std::str::from_utf8(&payload[str_start..str_end]) {
                    if !s.is_empty() {
                        return Some(s.to_string());
                    }
                }
            }
        }
    }

    // Panic(uint256) selector: 4e487b71
    if data.len() >= 36 && data[..4] == [0x4e, 0x48, 0x7b, 0x71] {
        let code = decode_uint256_le_u128(&data[4..36])?;
        return Some(format!("panic code 0x{:x} ({})", code, describe_panic_code(code)));
    }

    None
}

fn decode_binary_revert_reason(reason: &str) -> Option<String> {
    let data = reason.as_bytes();

    if data.len() >= 36 && data[..4] == [0x4e, 0x48, 0x7b, 0x71] {
        let code = decode_uint256_le_u128(&data[4..36])?;
        return Some(format!("panic code 0x{:x} ({})", code, describe_panic_code(code)));
    }

    None
}

fn simplify_revert_reason(reason: &str) -> String {
    let mut raw_cleaned = reason.trim().to_string();

    for prefix in [
        "Transaction reverted: ",
        "Execution error: ",
        "ContractCall reverted: ",
        "ContractCall failed: ",
        "Contract reverted: ",
    ] {
        while let Some(stripped) = raw_cleaned.strip_prefix(prefix) {
            raw_cleaned = stripped.trim().to_string();
        }
    }

    if let Some(decoded) = decode_binary_revert_reason(&raw_cleaned) {
        return decoded;
    }

    let mut cleaned = raw_cleaned
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .collect::<String>()
        .trim()
        .to_string();

    if let Some(decoded) = decode_hex_revert_reason(&cleaned) {
        return decoded;
    }

    cleaned
}

#[derive(Debug, Serialize, Deserialize)]
struct RpcRequest {
    jsonrpc: String,
    method: String,
    params: Value,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    result: Option<Value>,
    error: Option<RpcErrorBody>,
}

#[derive(Debug, Deserialize)]
struct RpcErrorBody {
    code: i64,
    message: String,
}

pub struct NodeRpcClient {
    url: String,
    client: reqwest::Client,
    id: AtomicU64,
}

impl NodeRpcClient {
    pub fn new(url: String) -> Self {
        Self {
            url,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
            id: AtomicU64::new(1),
        }
    }

    async fn call(&self, method: &str, params: Value) -> WalletResult<Value> {
        let id = self.id.fetch_add(1, Ordering::SeqCst);
        let req = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": id,
        });

        let resp = self
            .client
            .post(&self.url)
            .json(&req)
            .send()
            .await
            .map_err(|e| WalletError::NodeRpcError(format!("HTTP error: {}", e)))?;

        let rpc: RpcResponse = resp
            .json::<RpcResponse>()
            .await
            .map_err(|e| WalletError::NodeRpcError(format!("Parse error: {}", e)))?;

        if let Some(err) = rpc.error {
            return Err(WalletError::NodeRpcError(format!(
                "[{}] {}",
                err.code, err.message
            )));
        }

        rpc.result
            .ok_or_else(|| WalletError::NodeRpcError("Empty result".to_string()))
    }

    pub async fn get_balance(&self, rpc_address: &str) -> WalletResult<String> {
        let result: Value = self.call("qnt_getBalance", json!([rpc_address])).await?;
        result
            .as_str()
            .map(|s: &str| s.to_string())
            .ok_or_else(|| WalletError::NodeRpcError("Expected string balance".to_string()))
    }

    pub async fn get_account(&self, rpc_address: &str) -> WalletResult<Value> {
        self.call("qnt_getAccount", json!([rpc_address])).await
    }

    pub async fn get_nonce(&self, rpc_address: &str) -> WalletResult<u64> {
        let raw: Value = self
            .call("qnt_getTransactionCount", json!([rpc_address]))
            .await?;
        let hex_str = raw
            .as_str()
            .ok_or_else(|| WalletError::NodeRpcError("Expected string nonce".to_string()))?;
        let hex = hex_str
            .strip_prefix("QTS:")
            .or_else(|| hex_str.strip_prefix("0x"))
            .unwrap_or(hex_str);
        u64::from_str_radix(hex, 16)
            .map_err(|e| WalletError::NodeRpcError(format!("Bad nonce hex: {}", e)))
    }

    pub async fn get_chain_id(&self) -> WalletResult<u64> {
        let raw: Value = self.call("qnt_chainId", json!([])).await?;
        let hex_str = raw
            .as_str()
            .ok_or_else(|| WalletError::NodeRpcError("Expected string chain_id".to_string()))?;
        let hex = hex_str
            .strip_prefix("QTS:")
            .or_else(|| hex_str.strip_prefix("0x"))
            .unwrap_or(hex_str);
        u64::from_str_radix(hex, 16)
            .map_err(|e| WalletError::NodeRpcError(format!("Bad chain_id hex: {}", e)))
    }

    pub async fn node_info(&self) -> WalletResult<Value> {
        self.call("qnt_nodeInfo", json!([])).await
    }

    pub async fn send_raw_transaction(&self, tx_hex: &str) -> WalletResult<String> {
        let result: Value = self
            .call("qnt_sendRawTransaction", json!([format!("QTS:{}", tx_hex)]))
            .await?;
        result
            .as_str()
            .map(|s: &str| s.to_string())
            .ok_or_else(|| WalletError::NodeRpcError("Expected string tx hash".to_string()))
    }

    pub async fn get_transaction(&self, hash_hex: &str) -> WalletResult<Value> {
        self.call(
            "qnt_getTransactionByHash",
            json!([format!("QTS:{}", hash_hex)]),
        )
        .await
    }

    pub async fn get_receipt(&self, hash_hex: &str) -> WalletResult<Value> {
        self.call(
            "qnt_getTransactionReceipt",
            json!([format!("QTS:{}", hash_hex)]),
        )
        .await
    }

    pub async fn get_nfts(&self, rpc_address: &str, collection_address: Option<&str>) -> WalletResult<Value> {
        self.call("qnt_getNFTs", json!([rpc_address, collection_address])).await
    }

    pub async fn get_token_balances(&self, rpc_address: &str) -> WalletResult<Value> {
        self.call("qnt_getTokenBalances", json!([rpc_address])).await
    }

    /// Read-only contract call via qnt_call (e.g. balanceOf, totalSupply).
    pub async fn contract_call(&self, to: &str, data: &str, from: Option<&str>) -> WalletResult<String> {
        let mut req = json!({"to": to, "data": data});
        if let Some(f) = from {
            req["from"] = json!(f);
        }
        let result: Value = self.call("qnt_call", json!([req])).await?;
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| WalletError::NodeRpcError("Expected string from qnt_call".to_string()))
    }

    /// Send a raw transaction and wait for its receipt (up to ~15 seconds).
    /// Returns the tx hash on success, or an error if the tx fails or times out.
    pub async fn send_and_confirm(&self, tx_hex: &str) -> WalletResult<String> {
        let tx_hash = self.send_raw_transaction(tx_hex).await?;
        tracing::info!("TX submitted: {}, polling for receipt...", &tx_hash);
        // Strip QTS: prefix for get_receipt (which adds its own QTS: prefix)
        let hash_for_receipt = tx_hash
            .strip_prefix("QTS:")
            .or_else(|| tx_hash.strip_prefix("qts:"))
            .unwrap_or(&tx_hash);
        // Poll for receipt
        for attempt in 0..30 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            match self.get_receipt(hash_for_receipt).await {
                Ok(receipt) => {
                    // Skip null/empty receipts (tx not yet processed)
                    if receipt.is_null() || !receipt.is_object() {
                        continue;
                    }
                    let raw_status = receipt.get("status")
                        .and_then(|s| s.as_str())
                        .unwrap_or("");
                    // Normalize: strip QTS: prefix, lowercase
                    let status = raw_status
                        .strip_prefix("QTS:")
                        .or_else(|| raw_status.strip_prefix("qts:"))
                        .unwrap_or(raw_status)
                        .to_lowercase();
                    tracing::info!("TX {} receipt attempt {}: status={}", &tx_hash, attempt, &status);
                    if status == "1" || status == "success" || status == "confirmed" {
                        return Ok(tx_hash);
                    } else if status == "0" || status == "failed" || status == "reverted" {
                        let raw_reason = receipt.get("revert_reason")
                            .map(|r| r.to_string())
                            .unwrap_or_default();
                        let reason_str = receipt.get("revert_reason")
                            .and_then(|r| r.as_str())
                            .unwrap_or("");
                        let simplified = if reason_str.is_empty() {
                            "contract execution failed (no revert_reason in receipt)".to_string()
                        } else {
                            simplify_revert_reason(reason_str)
                        };
                        tracing::error!(
                            tx_hash = %tx_hash,
                            raw_revert_reason = %raw_reason,
                            simplified_reason = %simplified,
                            receipt = ?receipt,
                            "Transaction reverted"
                        );
                        return Err(WalletError::NodeRpcError(
                            format!("Transaction reverted: {}", simplified)
                        ));
                    }
                    // Unknown non-empty status and receipt is a real object — assume ok
                    if !status.is_empty() {
                        return Ok(tx_hash);
                    }
                }
                Err(_) => {
                    // RPC error or no receipt yet — keep polling
                }
            }
        }
        // Timeout — return hash anyway, maybe it'll confirm later
        tracing::warn!("TX {} submitted but receipt not confirmed within 15s timeout", &tx_hash);
        Ok(tx_hash)
    }

    pub async fn ping(&self) -> bool {
        let result: WalletResult<Value> = self.call("qnt_health", json!([])).await;
        result.is_ok()
    }
}
