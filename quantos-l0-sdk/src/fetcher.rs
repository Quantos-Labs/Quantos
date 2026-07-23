// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use crate::error::{L0Error, L0Result};
use crate::types::L0FinalityProof;

pub fn fetch_proof(rpc_url: &str, proof_hash: &[u8; 32]) -> L0Result<L0FinalityProof> {
    let client = reqwest::blocking::Client::new();
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "qnt_getL0Proof",
        "params": [hex::encode(proof_hash)]
    });

    let response = client
        .post(rpc_url)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .map_err(|e| L0Error::Http(e.to_string()))?;

    if !response.status().is_success() {
        return Err(L0Error::Http(format!(
            "RPC returned status {}",
            response.status()
        )));
    }

    let json: serde_json::Value = response
        .json()
        .map_err(|e| L0Error::Http(e.to_string()))?;

    if let Some(err) = json.get("error") {
        return Err(L0Error::Http(format!("RPC error: {err}")));
    }

    let proof_hex = json["result"]
        .as_str()
        .ok_or_else(|| L0Error::Http("missing result field".into()))?;

    let proof_bytes =
        hex::decode(proof_hex).map_err(|e| L0Error::Encoding(format!("hex decode: {e}")))?;

    let proof: L0FinalityProof = serde_json::from_slice(&proof_bytes)
        .map_err(|e| L0Error::Encoding(format!("json decode: {e}")))?;

    Ok(proof)
}

pub fn fetch_latest_proof(rpc_url: &str) -> L0Result<L0FinalityProof> {
    let client = reqwest::blocking::Client::new();
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "qnt_getLatestL0Proof",
        "params": []
    });

    let response = client
        .post(rpc_url)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .map_err(|e| L0Error::Http(e.to_string()))?;

    if !response.status().is_success() {
        return Err(L0Error::Http(format!(
            "RPC returned status {}",
            response.status()
        )));
    }

    let json: serde_json::Value = response
        .json()
        .map_err(|e| L0Error::Http(e.to_string()))?;

    if let Some(err) = json.get("error") {
        return Err(L0Error::Http(format!("RPC error: {err}")));
    }

    let proof_hex = json["result"]
        .as_str()
        .ok_or_else(|| L0Error::Http("missing result field".into()))?;

    let proof_bytes =
        hex::decode(proof_hex).map_err(|e| L0Error::Encoding(format!("hex decode: {e}")))?;

    let proof: L0FinalityProof = serde_json::from_slice(&proof_bytes)
        .map_err(|e| L0Error::Encoding(format!("json decode: {e}")))?;

    Ok(proof)
}
