// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! # Contract ABI (Application Binary Interface)
//!
//! ABI parsing and function routing for smart contracts.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use crate::crypto::sha3_256;
use crate::vm::{VmError, VmResult};

/// Function selector (first 4 bytes of SHA3(signature))
pub type Selector = [u8; 4];

/// ABI parameter type.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ParamType {
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Uint128,
    Uint256,
    Int8,
    Int16,
    Int32,
    Int64,
    Int128,
    Int256,
    Bool,
    Address,
    Bytes,
    String,
    #[serde(rename = "bytes32")]
    Bytes32,
    Array(Box<ParamType>),
    Tuple(Vec<ParamType>),
}

/// ABI function parameter.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AbiParam {
    pub name: String,
    #[serde(rename = "type")]
    pub param_type: ParamType,
    #[serde(default)]
    pub indexed: bool,
}

/// ABI function definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AbiFunction {
    pub name: String,
    #[serde(default)]
    pub inputs: Vec<AbiParam>,
    #[serde(default)]
    pub outputs: Vec<AbiParam>,
    #[serde(rename = "stateMutability", default)]
    pub state_mutability: StateMutability,
}

/// State mutability of a function.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StateMutability {
    Pure,
    View,
    #[default]
    Nonpayable,
    Payable,
}

/// ABI event definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AbiEvent {
    pub name: String,
    pub inputs: Vec<AbiParam>,
    #[serde(default)]
    pub anonymous: bool,
}

/// ABI entry (function, event, or constructor).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AbiEntry {
    Function(AbiFunction),
    Event(AbiEvent),
    Constructor { inputs: Vec<AbiParam> },
    Fallback,
    Receive,
}

/// Parsed contract ABI.
#[derive(Clone, Debug, Default)]
pub struct ContractAbi {
    /// Function selector -> function definition
    pub functions: HashMap<Selector, AbiFunction>,
    /// Function name -> selector (for reverse lookup)
    pub function_names: HashMap<String, Selector>,
    /// Events
    pub events: Vec<AbiEvent>,
    /// Constructor
    pub constructor: Option<Vec<AbiParam>>,
    /// Has fallback function
    pub has_fallback: bool,
    /// Has receive function  
    pub has_receive: bool,
}

impl ContractAbi {
    /// Parses ABI from JSON string.
    pub fn from_json(json: &str) -> VmResult<Self> {
        let entries: Vec<AbiEntry> = serde_json::from_str(json)
            .map_err(|e| VmError::InvalidAbi(format!("Parse error: {}", e)))?;

        let mut abi = ContractAbi::default();

        for entry in entries {
            match entry {
                AbiEntry::Function(func) => {
                    let selector = compute_selector(&func.name, &func.inputs);
                    abi.function_names.insert(func.name.clone(), selector);
                    abi.functions.insert(selector, func);
                }
                AbiEntry::Event(event) => {
                    abi.events.push(event);
                }
                AbiEntry::Constructor { inputs } => {
                    abi.constructor = Some(inputs);
                }
                AbiEntry::Fallback => {
                    abi.has_fallback = true;
                }
                AbiEntry::Receive => {
                    abi.has_receive = true;
                }
            }
        }

        Ok(abi)
    }

    /// Gets function by selector.
    pub fn get_function(&self, selector: &Selector) -> Option<&AbiFunction> {
        self.functions.get(selector)
    }

    /// Gets function by name.
    pub fn get_function_by_name(&self, name: &str) -> Option<&AbiFunction> {
        self.function_names.get(name)
            .and_then(|sel| self.functions.get(sel))
    }

    /// Gets selector for a function name.
    pub fn get_selector(&self, name: &str) -> Option<Selector> {
        self.function_names.get(name).copied()
    }

    /// Checks if function is read-only (view/pure).
    pub fn is_read_only(&self, selector: &Selector) -> bool {
        self.functions.get(selector)
            .map(|f| f.state_mutability == StateMutability::View || 
                     f.state_mutability == StateMutability::Pure)
            .unwrap_or(false)
    }
}

/// Computes function selector from name and parameters.
pub fn compute_selector(name: &str, params: &[AbiParam]) -> Selector {
    let signature = format_signature(name, params);
    let hash = sha3_256(signature.as_bytes());
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&hash[..4]);
    selector
}

/// Formats function signature for hashing.
fn format_signature(name: &str, params: &[AbiParam]) -> String {
    let param_types: Vec<String> = params.iter()
        .map(|p| format_param_type(&p.param_type))
        .collect();
    format!("{}({})", name, param_types.join(","))
}

/// Formats parameter type for signature.
fn format_param_type(param_type: &ParamType) -> String {
    match param_type {
        ParamType::Uint8 => "uint8".to_string(),
        ParamType::Uint16 => "uint16".to_string(),
        ParamType::Uint32 => "uint32".to_string(),
        ParamType::Uint64 => "uint64".to_string(),
        ParamType::Uint128 => "uint128".to_string(),
        ParamType::Uint256 => "uint256".to_string(),
        ParamType::Int8 => "int8".to_string(),
        ParamType::Int16 => "int16".to_string(),
        ParamType::Int32 => "int32".to_string(),
        ParamType::Int64 => "int64".to_string(),
        ParamType::Int128 => "int128".to_string(),
        ParamType::Int256 => "int256".to_string(),
        ParamType::Bool => "bool".to_string(),
        ParamType::Address => "address".to_string(),
        ParamType::Bytes => "bytes".to_string(),
        ParamType::String => "string".to_string(),
        ParamType::Bytes32 => "bytes32".to_string(),
        ParamType::Array(inner) => format!("{}[]", format_param_type(inner)),
        ParamType::Tuple(types) => {
            let inner: Vec<String> = types.iter().map(format_param_type).collect();
            format!("({})", inner.join(","))
        }
    }
}

/// Encodes function call data (selector + encoded params).
pub fn encode_call(name: &str, params: &[AbiParam], values: &[AbiValue]) -> VmResult<Vec<u8>> {
    if params.len() != values.len() {
        return Err(VmError::InvalidAbi("Parameter count mismatch".into()));
    }

    let selector = compute_selector(name, params);
    let mut data = selector.to_vec();

    for (param, value) in params.iter().zip(values.iter()) {
        let encoded = encode_value(&param.param_type, value)?;
        data.extend(encoded);
    }

    Ok(data)
}

/// Decodes function call data.
pub fn decode_call(data: &[u8], abi: &ContractAbi) -> VmResult<(AbiFunction, Vec<AbiValue>)> {
    if data.len() < 4 {
        return Err(VmError::InvalidAbi("Data too short for selector".into()));
    }

    let mut selector = [0u8; 4];
    selector.copy_from_slice(&data[..4]);

    let func = abi.get_function(&selector)
        .ok_or_else(|| VmError::InvalidAbi("Unknown function selector".into()))?
        .clone();

    let values = decode_params(&data[4..], &func.inputs)?;

    Ok((func, values))
}

/// ABI-encoded value.
#[derive(Clone, Debug)]
pub enum AbiValue {
    Uint(u128),
    Int(i128),
    Bool(bool),
    Address([u8; 32]),
    Bytes(Vec<u8>),
    String(String),
    Array(Vec<AbiValue>),
    Tuple(Vec<AbiValue>),
}

/// Encodes a single value.
fn encode_value(param_type: &ParamType, value: &AbiValue) -> VmResult<Vec<u8>> {
    let mut encoded = vec![0u8; 32]; // Most values are 32 bytes

    match (param_type, value) {
        (ParamType::Uint8 | ParamType::Uint16 | ParamType::Uint32 | 
         ParamType::Uint64 | ParamType::Uint128 | ParamType::Uint256, AbiValue::Uint(n)) => {
            let bytes = n.to_be_bytes();
            encoded[16..].copy_from_slice(&bytes);
        }
        (ParamType::Int8 | ParamType::Int16 | ParamType::Int32 |
         ParamType::Int64 | ParamType::Int128 | ParamType::Int256, AbiValue::Int(n)) => {
            let bytes = n.to_be_bytes();
            encoded[16..].copy_from_slice(&bytes);
        }
        (ParamType::Bool, AbiValue::Bool(b)) => {
            encoded[31] = if *b { 1 } else { 0 };
        }
        (ParamType::Address, AbiValue::Address(addr)) => {
            encoded.copy_from_slice(addr);
        }
        (ParamType::Bytes32, AbiValue::Bytes(b)) if b.len() == 32 => {
            encoded.copy_from_slice(b);
        }
        (ParamType::Bytes, AbiValue::Bytes(b)) => {
            // Dynamic type - encode offset + length + data
            return Ok(encode_dynamic_bytes(b));
        }
        (ParamType::String, AbiValue::String(s)) => {
            return Ok(encode_dynamic_bytes(s.as_bytes()));
        }
        _ => return Err(VmError::InvalidAbi("Type mismatch in encoding".into())),
    }

    Ok(encoded)
}

/// Encodes dynamic bytes (bytes, string).
fn encode_dynamic_bytes(data: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    
    // Length (32 bytes)
    let mut len_bytes = [0u8; 32];
    len_bytes[24..].copy_from_slice(&(data.len() as u64).to_be_bytes());
    encoded.extend_from_slice(&len_bytes);
    
    // Data (padded to 32 bytes)
    encoded.extend_from_slice(data);
    let padding = (32 - (data.len() % 32)) % 32;
    encoded.extend(vec![0u8; padding]);
    
    encoded
}

/// Decodes parameters from calldata.
fn decode_params(data: &[u8], params: &[AbiParam]) -> VmResult<Vec<AbiValue>> {
    let mut values = Vec::new();
    let mut offset = 0;

    for param in params {
        let (value, consumed) = decode_value(data, offset, &param.param_type)?;
        values.push(value);
        offset += consumed;
    }

    Ok(values)
}

/// Decodes a single value.
fn decode_value(data: &[u8], offset: usize, param_type: &ParamType) -> VmResult<(AbiValue, usize)> {
    if offset + 32 > data.len() {
        return Err(VmError::InvalidAbi("Data too short".into()));
    }

    let chunk = &data[offset..offset + 32];

    match param_type {
        ParamType::Uint8 | ParamType::Uint16 | ParamType::Uint32 |
        ParamType::Uint64 | ParamType::Uint128 | ParamType::Uint256 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&chunk[16..32]);
            Ok((AbiValue::Uint(u128::from_be_bytes(bytes)), 32))
        }
        ParamType::Int8 | ParamType::Int16 | ParamType::Int32 |
        ParamType::Int64 | ParamType::Int128 | ParamType::Int256 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&chunk[16..32]);
            Ok((AbiValue::Int(i128::from_be_bytes(bytes)), 32))
        }
        ParamType::Bool => {
            Ok((AbiValue::Bool(chunk[31] != 0), 32))
        }
        ParamType::Address => {
            let mut addr = [0u8; 32];
            addr.copy_from_slice(chunk);
            Ok((AbiValue::Address(addr), 32))
        }
        ParamType::Bytes32 => {
            Ok((AbiValue::Bytes(chunk.to_vec()), 32))
        }
        ParamType::Bytes | ParamType::String => {
            // HIGH: Enhanced bounds validation for dynamic types
            let mut len_bytes = [0u8; 8];
            len_bytes.copy_from_slice(&chunk[24..32]);
            let data_offset = u64::from_be_bytes(len_bytes) as usize;
            
            // Validate offset is within bounds
            if data_offset + 32 > data.len() {
                return Err(VmError::InvalidAbi("Invalid dynamic offset".into()));
            }
            
            // Validate we can read the length field
            if data_offset + 32 > data.len() {
                return Err(VmError::InvalidAbi("Cannot read length at offset".into()));
            }
            
            let mut len_at_offset = [0u8; 8];
            len_at_offset.copy_from_slice(&data[data_offset + 24..data_offset + 32]);
            let length = u64::from_be_bytes(len_at_offset) as usize;
            
            // CRITICAL: Validate length to prevent out-of-bounds read
            if length > 1024 * 1024 {
                return Err(VmError::InvalidAbi("Dynamic data too large (max 1MB)".into()));
            }
            
            // Validate we can read the actual data
            let data_end = data_offset.checked_add(32)
                .and_then(|v| v.checked_add(length))
                .ok_or_else(|| VmError::InvalidAbi("Data offset overflow".into()))?;
            
            if data_end > data.len() {
                return Err(VmError::InvalidAbi("Dynamic data exceeds buffer".into()));
            }
            
            let bytes = data[data_offset + 32..data_end].to_vec();
            
            if matches!(param_type, ParamType::String) {
                let s = String::from_utf8(bytes)
                    .map_err(|_| VmError::InvalidAbi("Invalid UTF-8 string".into()))?;
                Ok((AbiValue::String(s), 32))
            } else {
                Ok((AbiValue::Bytes(bytes), 32))
            }
        }
        _ => Err(VmError::InvalidAbi("Unsupported type in decoding".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_selector() {
        // transfer(address,uint256) -> 0xa9059cbb
        let params = vec![
            AbiParam { name: "to".to_string(), param_type: ParamType::Address, indexed: false },
            AbiParam { name: "amount".to_string(), param_type: ParamType::Uint256, indexed: false },
        ];
        let selector = compute_selector("transfer", &params);
        assert_eq!(selector, [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn test_parse_abi() {
        let json = r#"[
            {
                "type": "function",
                "name": "transfer",
                "inputs": [
                    {"name": "to", "type": "address"},
                    {"name": "amount", "type": "uint256"}
                ],
                "outputs": [{"name": "", "type": "bool"}],
                "stateMutability": "nonpayable"
            },
            {
                "type": "event",
                "name": "Transfer",
                "inputs": [
                    {"name": "from", "type": "address", "indexed": true},
                    {"name": "to", "type": "address", "indexed": true},
                    {"name": "value", "type": "uint256", "indexed": false}
                ]
            }
        ]"#;

        let abi = ContractAbi::from_json(json).unwrap();
        assert_eq!(abi.functions.len(), 1);
        assert_eq!(abi.events.len(), 1);
        assert!(abi.get_function_by_name("transfer").is_some());
    }

    #[test]
    fn test_encode_uint() {
        let value = AbiValue::Uint(100);
        let encoded = encode_value(&ParamType::Uint256, &value).unwrap();
        assert_eq!(encoded.len(), 32);
        assert_eq!(encoded[31], 100);
    }

    #[test]
    fn test_encode_bool() {
        let true_val = encode_value(&ParamType::Bool, &AbiValue::Bool(true)).unwrap();
        let false_val = encode_value(&ParamType::Bool, &AbiValue::Bool(false)).unwrap();
        
        assert_eq!(true_val[31], 1);
        assert_eq!(false_val[31], 0);
    }

    #[test]
    fn test_format_signature() {
        let params = vec![
            AbiParam { name: "a".to_string(), param_type: ParamType::Uint256, indexed: false },
            AbiParam { name: "b".to_string(), param_type: ParamType::Bool, indexed: false },
        ];
        let sig = format_signature("foo", &params);
        assert_eq!(sig, "foo(uint256,bool)");
    }
}
