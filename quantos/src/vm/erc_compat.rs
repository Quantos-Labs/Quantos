//! # ERC Compatibility Shim
//!
//! Bridges Ethereum ERC-20/721/1155 ABI calldata to native Quantos
//! QN4/QN8/QN12 token operations, enabling standard Ethereum tooling
//! (ethers.js, wagmi, Hardhat, MetaMask) to interact with Quantos tokens.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │  Ethereum tooling (ethers.js / wagmi / MetaMask)     │
//! │  sends standard ERC-20/721/1155 ABI calldata         │
//! └────────────────────┬─────────────────────────────────┘
//!                      │  4-byte selector + ABI-encoded params
//! ┌────────────────────▼─────────────────────────────────┐
//! │              ErcCompatRouter                          │
//! │  • Decodes Ethereum ABI calldata                     │
//! │  • Maps address (20-byte → 32-byte)                  │
//! │  • Maps uint256 → u64 (with overflow check)          │
//! │  • Routes to QN4/QN8/QN12 trait methods              │
//! │  • Encodes return values as Ethereum ABI             │
//! │  • Emits Ethereum-format log topics for indexers     │
//! └────────────────────┬─────────────────────────────────┘
//!                      │  native Quantos calls
//! ┌────────────────────▼─────────────────────────────────┐
//! │  QN4 / QN8 / QN12 (unchanged, WASM, gasless, PQC)   │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! ## Supported Selectors
//!
//! All standard ERC-20, ERC-721, and ERC-1155 function selectors are
//! recognized and dispatched automatically. Unknown selectors return
//! [`ErcCompatError::UnknownSelector`].
//!
//! ## Determinism
//!
//! All operations in this module are purely deterministic: no RNG,
//! no time-dependence, no floating-point. Safe for consensus paths.

use crate::crypto::sha3_256;
use crate::types::Address;
use crate::standards::{
    TokenError, TokenEvent,
    QN4, QN4Token, QN4Mintable, QN4Burnable, QN4Pausable,
    QN8, QN8Token, QN8Mintable, QN8Burnable,
    QN12, QN12Token, QN12Mintable, QN12Burnable, QN12Supply,
};

use std::fmt;

// ══════════════════════════════════════════════════════════
//  Constants — well-known ERC selectors (Keccak256[:4])
// ══════════════════════════════════════════════════════════

/// Computes a 4-byte Ethereum function selector from a canonical signature.
const fn const_selector(bytes: [u8; 4]) -> [u8; 4] { bytes }

// --- ERC-20 selectors ---
pub const SEL_NAME:             [u8; 4] = const_selector([0x06, 0xfd, 0xde, 0x03]); // name()
pub const SEL_SYMBOL:           [u8; 4] = const_selector([0x95, 0xd8, 0x9b, 0x41]); // symbol()
pub const SEL_DECIMALS:         [u8; 4] = const_selector([0x31, 0x3c, 0xe5, 0x67]); // decimals()
pub const SEL_TOTAL_SUPPLY:     [u8; 4] = const_selector([0x18, 0x16, 0x0d, 0xdd]); // totalSupply()
pub const SEL_BALANCE_OF:       [u8; 4] = const_selector([0x70, 0xa0, 0x82, 0x31]); // balanceOf(address)
pub const SEL_TRANSFER:         [u8; 4] = const_selector([0xa9, 0x05, 0x9c, 0xbb]); // transfer(address,uint256)
pub const SEL_APPROVE:          [u8; 4] = const_selector([0x09, 0x5e, 0xa7, 0xb3]); // approve(address,uint256)
pub const SEL_ALLOWANCE:        [u8; 4] = const_selector([0xdd, 0x62, 0xed, 0x3e]); // allowance(address,address)
pub const SEL_TRANSFER_FROM:    [u8; 4] = const_selector([0x23, 0xb8, 0x72, 0xdd]); // transferFrom(address,address,uint256)

// --- ERC-721 selectors ---
pub const SEL_OWNER_OF:         [u8; 4] = const_selector([0x63, 0x52, 0x21, 0x1e]); // ownerOf(uint256)
pub const SEL_TOKEN_URI:        [u8; 4] = const_selector([0xc8, 0x7b, 0x56, 0xdd]); // tokenURI(uint256)
pub const SEL_APPROVE_NFT:      [u8; 4] = const_selector([0x09, 0x5e, 0xa7, 0xb3]); // approve(address,uint256) — same as ERC-20
pub const SEL_GET_APPROVED:     [u8; 4] = const_selector([0x08, 0x18, 0x12, 0xfc]); // getApproved(uint256)
pub const SEL_SET_APPROVAL_ALL: [u8; 4] = const_selector([0xa2, 0x2c, 0xb4, 0x65]); // setApprovalForAll(address,bool)
pub const SEL_IS_APPROVED_ALL:  [u8; 4] = const_selector([0xe9, 0x85, 0xe9, 0xc5]); // isApprovedForAll(address,address)
pub const SEL_SAFE_TRANSFER_FR: [u8; 4] = const_selector([0x42, 0x84, 0x2e, 0x0e]); // safeTransferFrom(address,address,uint256)
pub const SEL_SAFE_TFR_DATA:    [u8; 4] = const_selector([0xb8, 0x8d, 0x4f, 0xde]); // safeTransferFrom(address,address,uint256,bytes)

// --- ERC-1155 selectors ---
pub const SEL_BALANCE_OF_1155:  [u8; 4] = const_selector([0x00, 0xfd, 0xd5, 0x8e]); // balanceOf(address,uint256)
pub const SEL_BALANCE_BATCH:    [u8; 4] = const_selector([0x4e, 0x12, 0x73, 0xf4]); // balanceOfBatch(address[],uint256[])
pub const SEL_SAFE_TFR_1155:    [u8; 4] = const_selector([0xf2, 0x42, 0x43, 0x2a]); // safeTransferFrom(address,address,uint256,uint256,bytes)
pub const SEL_SAFE_BATCH_TFR:   [u8; 4] = const_selector([0x2e, 0xb2, 0xc2, 0xd6]); // safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)
pub const SEL_URI:              [u8; 4] = const_selector([0x0e, 0x89, 0x34, 0x1c]); // uri(uint256)

// --- ERC-165 (interface detection) ---
pub const SEL_SUPPORTS_IFACE:   [u8; 4] = const_selector([0x01, 0xff, 0xc9, 0xa7]); // supportsInterface(bytes4)

// --- Interface IDs (ERC-165) ---
pub const IFACE_ERC20:   [u8; 4] = [0x36, 0x37, 0x2b, 0x07];
pub const IFACE_ERC721:  [u8; 4] = [0x80, 0xac, 0x58, 0xcd];
pub const IFACE_ERC1155: [u8; 4] = [0xd9, 0xb6, 0x7a, 0x26];
pub const IFACE_ERC165:  [u8; 4] = [0x01, 0xff, 0xc9, 0xa7];

// ══════════════════════════════════════════════════════════
//  Error types
// ══════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErcCompatError {
    /// Calldata shorter than 4 bytes (no selector)
    CalldataTooShort,
    /// 4-byte selector not recognized as any ERC function
    UnknownSelector([u8; 4]),
    /// ABI decoding failed (malformed params)
    AbiDecodeFailed(String),
    /// uint256 value exceeds u64::MAX
    Uint256Overflow,
    /// Underlying QN token error
    TokenError(TokenError),
    /// Wrong token type for this call (e.g. ERC-721 call on QN4)
    TokenTypeMismatch(&'static str),
}

impl fmt::Display for ErcCompatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CalldataTooShort => write!(f, "Calldata too short (need >= 4 bytes)"),
            Self::UnknownSelector(s) => write!(f, "Unknown selector: 0x{}", hex::encode(s)),
            Self::AbiDecodeFailed(msg) => write!(f, "ABI decode failed: {}", msg),
            Self::Uint256Overflow => write!(f, "uint256 value exceeds u64::MAX"),
            Self::TokenError(e) => write!(f, "Token error: {:?}", e),
            Self::TokenTypeMismatch(msg) => write!(f, "Token type mismatch: {}", msg),
        }
    }
}

impl From<TokenError> for ErcCompatError {
    fn from(e: TokenError) -> Self {
        Self::TokenError(e)
    }
}

pub type ErcCompatResult<T> = Result<T, ErcCompatError>;

// ══════════════════════════════════════════════════════════
//  Address mapping: Ethereum 20-byte ↔ Quantos 32-byte
// ══════════════════════════════════════════════════════════

/// Converts an Ethereum 20-byte address (right-aligned in 32-byte ABI
/// word) to a Quantos 32-byte address.
///
/// Convention: the 20 ETH bytes occupy positions `[12..32]` in the
/// Quantos address. Bytes `[0..12]` are zero.
pub fn eth_address_to_quantos(abi_word: &[u8; 32]) -> Address {
    // The ABI already has the address right-aligned in 32 bytes,
    // which matches our convention perfectly.
    *abi_word
}

/// Converts a Quantos 32-byte address to an Ethereum 20-byte address
/// (right-aligned in a 32-byte ABI word).
///
/// If the first 12 bytes are non-zero, this is a native Quantos address
/// that doesn't map cleanly to Ethereum. We still encode the last 20
/// bytes but callers should be aware of potential truncation.
pub fn quantos_address_to_eth(addr: &Address) -> [u8; 32] {
    let mut word = [0u8; 32];
    word.copy_from_slice(addr);
    // Zero-out the first 12 bytes for clean Ethereum encoding
    word[..12].fill(0);
    word
}

// ══════════════════════════════════════════════════════════
//  uint256 → u64 safe conversion
// ══════════════════════════════════════════════════════════

/// Decodes a uint256 (32-byte big-endian) as u64.
/// Returns `Uint256Overflow` if the value exceeds `u64::MAX`.
pub fn uint256_to_u64(word: &[u8; 32]) -> ErcCompatResult<u64> {
    // Bytes [0..24] must all be zero for the value to fit in u64
    if word[..24] != [0u8; 24] {
        return Err(ErcCompatError::Uint256Overflow);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&word[24..32]);
    Ok(u64::from_be_bytes(buf))
}

/// Encodes a u64 as a 32-byte big-endian uint256 word.
pub fn u64_to_uint256(val: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&val.to_be_bytes());
    word
}

/// Encodes a bool as a 32-byte ABI word.
pub fn bool_to_word(val: bool) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[31] = if val { 1 } else { 0 };
    word
}

// ══════════════════════════════════════════════════════════
//  ABI decoding helpers (from raw calldata after selector)
// ══════════════════════════════════════════════════════════

fn read_word(data: &[u8], offset: usize) -> ErcCompatResult<[u8; 32]> {
    if offset + 32 > data.len() {
        return Err(ErcCompatError::AbiDecodeFailed(
            format!("need 32 bytes at offset {}, have {}", offset, data.len())
        ));
    }
    let mut word = [0u8; 32];
    word.copy_from_slice(&data[offset..offset + 32]);
    Ok(word)
}

fn read_address(data: &[u8], offset: usize) -> ErcCompatResult<Address> {
    let word = read_word(data, offset)?;
    Ok(eth_address_to_quantos(&word))
}

fn read_uint256_as_u64(data: &[u8], offset: usize) -> ErcCompatResult<u64> {
    let word = read_word(data, offset)?;
    uint256_to_u64(&word)
}

fn read_bool(data: &[u8], offset: usize) -> ErcCompatResult<bool> {
    let word = read_word(data, offset)?;
    Ok(word[31] != 0)
}

/// Reads a dynamic `uint256[]` array from ABI-encoded calldata.
fn read_uint256_array_as_u64(data: &[u8], head_offset: usize) -> ErcCompatResult<Vec<u64>> {
    let offset_word = read_word(data, head_offset)?;
    let array_offset = uint256_to_u64(&offset_word)? as usize;
    
    let len_word = read_word(data, array_offset)?;
    let len = uint256_to_u64(&len_word)? as usize;
    
    if len > 10_000 {
        return Err(ErcCompatError::AbiDecodeFailed("Array too large".into()));
    }
    
    let mut result = Vec::with_capacity(len);
    for i in 0..len {
        result.push(read_uint256_as_u64(data, array_offset + 32 + i * 32)?);
    }
    Ok(result)
}

/// Reads a dynamic `address[]` array from ABI-encoded calldata.
fn read_address_array(data: &[u8], head_offset: usize) -> ErcCompatResult<Vec<Address>> {
    let offset_word = read_word(data, head_offset)?;
    let array_offset = uint256_to_u64(&offset_word)? as usize;
    
    let len_word = read_word(data, array_offset)?;
    let len = uint256_to_u64(&len_word)? as usize;
    
    if len > 10_000 {
        return Err(ErcCompatError::AbiDecodeFailed("Array too large".into()));
    }
    
    let mut result = Vec::with_capacity(len);
    for i in 0..len {
        result.push(read_address(data, array_offset + 32 + i * 32)?);
    }
    Ok(result)
}

/// Reads dynamic `bytes` from ABI-encoded calldata.
fn read_bytes(data: &[u8], head_offset: usize) -> ErcCompatResult<Vec<u8>> {
    let offset_word = read_word(data, head_offset)?;
    let bytes_offset = uint256_to_u64(&offset_word)? as usize;
    
    let len_word = read_word(data, bytes_offset)?;
    let len = uint256_to_u64(&len_word)? as usize;
    
    if len > 1_048_576 {
        return Err(ErcCompatError::AbiDecodeFailed("Bytes too large (max 1MB)".into()));
    }
    
    let data_start = bytes_offset + 32;
    if data_start + len > data.len() {
        return Err(ErcCompatError::AbiDecodeFailed("Bytes data out of bounds".into()));
    }
    
    Ok(data[data_start..data_start + len].to_vec())
}

// ══════════════════════════════════════════════════════════
//  ABI return encoding helpers
// ══════════════════════════════════════════════════════════

/// Encodes a string as ABI return data (offset + length + padded data).
fn encode_string_return(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    // offset to data (always 0x20 for single dynamic return)
    out.extend_from_slice(&u64_to_uint256(32));
    // length
    out.extend_from_slice(&u64_to_uint256(s.len() as u64));
    // data + padding
    out.extend_from_slice(s.as_bytes());
    let pad = (32 - (s.len() % 32)) % 32;
    out.extend(vec![0u8; pad]);
    out
}

// ══════════════════════════════════════════════════════════
//  Ethereum-compatible event log encoding
// ══════════════════════════════════════════════════════════

/// An Ethereum-format log entry, compatible with standard indexers
/// (The Graph, ethers.js event filters, etc.).
#[derive(Debug, Clone)]
pub struct EthLog {
    /// Keccak256 event signature + indexed params
    pub topics: Vec<[u8; 32]>,
    /// ABI-encoded non-indexed params
    pub data: Vec<u8>,
}

/// Computes the Keccak256 topic hash for an event signature.
fn event_topic(signature: &str) -> [u8; 32] {
    sha3_256(signature.as_bytes())
}

/// Converts a Quantos `TokenEvent` into an Ethereum-compatible log.
pub fn token_event_to_eth_log(event: &TokenEvent) -> EthLog {
    match event {
        // ERC-20: Transfer(address indexed from, address indexed to, uint256 value)
        TokenEvent::Transfer { from, to, value } => EthLog {
            topics: vec![
                event_topic("Transfer(address,address,uint256)"),
                quantos_address_to_eth(from),
                quantos_address_to_eth(to),
            ],
            data: u64_to_uint256(*value).to_vec(),
        },
        
        // ERC-20: Approval(address indexed owner, address indexed spender, uint256 value)
        TokenEvent::Approval { owner, spender, value } => EthLog {
            topics: vec![
                event_topic("Approval(address,address,uint256)"),
                quantos_address_to_eth(owner),
                quantos_address_to_eth(spender),
            ],
            data: u64_to_uint256(*value).to_vec(),
        },
        
        // ERC-721: Transfer(address indexed from, address indexed to, uint256 indexed tokenId)
        TokenEvent::TransferNFT { from, to, token_id } => EthLog {
            topics: vec![
                event_topic("Transfer(address,address,uint256)"),
                quantos_address_to_eth(from),
                quantos_address_to_eth(to),
                u64_to_uint256(*token_id),
            ],
            data: Vec::new(),
        },
        
        // ERC-721: Approval(address indexed owner, address indexed approved, uint256 indexed tokenId)
        TokenEvent::ApprovalNFT { owner, approved, token_id } => EthLog {
            topics: vec![
                event_topic("Approval(address,address,uint256)"),
                quantos_address_to_eth(owner),
                quantos_address_to_eth(approved),
                u64_to_uint256(*token_id),
            ],
            data: Vec::new(),
        },
        
        // ERC-721/1155: ApprovalForAll(address indexed owner, address indexed operator, bool approved)
        TokenEvent::ApprovalForAll { owner, operator, approved } => EthLog {
            topics: vec![
                event_topic("ApprovalForAll(address,address,bool)"),
                quantos_address_to_eth(owner),
                quantos_address_to_eth(operator),
            ],
            data: bool_to_word(*approved).to_vec(),
        },
        
        // ERC-1155: TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value)
        TokenEvent::TransferSingle { operator, from, to, token_id, value } => {
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(&u64_to_uint256(*token_id));
            data.extend_from_slice(&u64_to_uint256(*value));
            EthLog {
                topics: vec![
                    event_topic("TransferSingle(address,address,address,uint256,uint256)"),
                    quantos_address_to_eth(operator),
                    quantos_address_to_eth(from),
                    quantos_address_to_eth(to),
                ],
                data,
            }
        },
        
        // ERC-1155: TransferBatch(address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values)
        TokenEvent::TransferBatch { operator, from, to, token_ids, values } => {
            let mut data = Vec::new();
            // Offset to ids array
            data.extend_from_slice(&u64_to_uint256(64));
            // Offset to values array
            let ids_size = 32 + token_ids.len() * 32;
            data.extend_from_slice(&u64_to_uint256((64 + ids_size) as u64));
            // ids array
            data.extend_from_slice(&u64_to_uint256(token_ids.len() as u64));
            for id in token_ids {
                data.extend_from_slice(&u64_to_uint256(*id));
            }
            // values array
            data.extend_from_slice(&u64_to_uint256(values.len() as u64));
            for v in values {
                data.extend_from_slice(&u64_to_uint256(*v));
            }
            EthLog {
                topics: vec![
                    event_topic("TransferBatch(address,address,address,uint256[],uint256[])"),
                    quantos_address_to_eth(operator),
                    quantos_address_to_eth(from),
                    quantos_address_to_eth(to),
                ],
                data,
            }
        },
        
        // Administrative events — use custom topic hashes
        TokenEvent::OwnershipTransferred { previous_owner, new_owner } => EthLog {
            topics: vec![
                event_topic("OwnershipTransferred(address,address)"),
                quantos_address_to_eth(previous_owner),
                quantos_address_to_eth(new_owner),
            ],
            data: Vec::new(),
        },
        
        TokenEvent::OwnershipTransferStarted { previous_owner, new_owner } => EthLog {
            topics: vec![
                event_topic("OwnershipTransferStarted(address,address)"),
                quantos_address_to_eth(previous_owner),
                quantos_address_to_eth(new_owner),
            ],
            data: Vec::new(),
        },
        
        TokenEvent::Paused { account } => EthLog {
            topics: vec![
                event_topic("Paused(address)"),
                quantos_address_to_eth(account),
            ],
            data: Vec::new(),
        },
        
        TokenEvent::Unpaused { account } => EthLog {
            topics: vec![
                event_topic("Unpaused(address)"),
                quantos_address_to_eth(account),
            ],
            data: Vec::new(),
        },
    }
}

// ══════════════════════════════════════════════════════════
//  Token type enum for the router
// ══════════════════════════════════════════════════════════

/// Wraps any Quantos token standard for unified dispatch.
pub enum AnyToken<'a> {
    QN4(&'a mut QN4Token),
    QN8(&'a mut QN8Token),
    QN12(&'a mut QN12Token),
}

// ══════════════════════════════════════════════════════════
//  ERC Compatibility Router — main dispatch logic
// ══════════════════════════════════════════════════════════

/// Routes Ethereum ABI calldata to the appropriate Quantos token method.
///
/// # Arguments
/// * `calldata` — Raw Ethereum ABI-encoded calldata (selector + params)
/// * `caller`   — Transaction sender (Quantos 32-byte address)
/// * `token`    — Mutable reference to the target token
///
/// # Returns
/// * `Ok(Vec<u8>)` — ABI-encoded return value (ready for Ethereum clients)
/// * `Err(ErcCompatError)` — Dispatch or execution error
pub fn dispatch_erc_call(
    calldata: &[u8],
    caller: &Address,
    token: &mut AnyToken<'_>,
) -> ErcCompatResult<(Vec<u8>, Option<EthLog>)> {
    if calldata.len() < 4 {
        return Err(ErcCompatError::CalldataTooShort);
    }
    
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&calldata[..4]);
    let params = &calldata[4..];
    
    // ERC-165: supportsInterface(bytes4)
    if selector == SEL_SUPPORTS_IFACE {
        return dispatch_supports_interface(params, token);
    }
    
    match token {
        AnyToken::QN4(t) => dispatch_erc20(selector, params, caller, t),
        AnyToken::QN8(t) => dispatch_erc721(selector, params, caller, t),
        AnyToken::QN12(t) => dispatch_erc1155(selector, params, caller, t),
    }
}

// ══════════════════════════════════════════════════════════
//  ERC-165 supportsInterface
// ══════════════════════════════════════════════════════════

fn dispatch_supports_interface(
    params: &[u8],
    token: &AnyToken<'_>,
) -> ErcCompatResult<(Vec<u8>, Option<EthLog>)> {
    let word = read_word(params, 0)?;
    let mut iface_id = [0u8; 4];
    iface_id.copy_from_slice(&word[..4]);
    
    let supported = match token {
        AnyToken::QN4(_) => iface_id == IFACE_ERC20 || iface_id == IFACE_ERC165,
        AnyToken::QN8(_) => iface_id == IFACE_ERC721 || iface_id == IFACE_ERC165,
        AnyToken::QN12(_) => iface_id == IFACE_ERC1155 || iface_id == IFACE_ERC165,
    };
    
    Ok((bool_to_word(supported).to_vec(), None))
}

// ══════════════════════════════════════════════════════════
//  ERC-20 dispatch
// ══════════════════════════════════════════════════════════

fn dispatch_erc20(
    selector: [u8; 4],
    params: &[u8],
    caller: &Address,
    token: &mut QN4Token,
) -> ErcCompatResult<(Vec<u8>, Option<EthLog>)> {
    match selector {
        SEL_NAME => {
            let name = token.name().to_string();
            Ok((encode_string_return(&name), None))
        }
        SEL_SYMBOL => {
            let symbol = token.symbol().to_string();
            Ok((encode_string_return(&symbol), None))
        }
        SEL_DECIMALS => {
            Ok((u64_to_uint256(token.decimals() as u64).to_vec(), None))
        }
        SEL_TOTAL_SUPPLY => {
            Ok((u64_to_uint256(token.total_supply()).to_vec(), None))
        }
        SEL_BALANCE_OF => {
            let account = read_address(params, 0)?;
            let balance = token.balance_of(&account);
            Ok((u64_to_uint256(balance).to_vec(), None))
        }
        SEL_TRANSFER => {
            let to = read_address(params, 0)?;
            let amount = read_uint256_as_u64(params, 32)?;
            let event = token.transfer(caller, &to, amount)?;
            let log = token_event_to_eth_log(&event);
            Ok((bool_to_word(true).to_vec(), Some(log)))
        }
        SEL_APPROVE => {
            let spender = read_address(params, 0)?;
            let amount = read_uint256_as_u64(params, 32)?;
            let event = token.approve(caller, &spender, amount)?;
            let log = token_event_to_eth_log(&event);
            Ok((bool_to_word(true).to_vec(), Some(log)))
        }
        SEL_ALLOWANCE => {
            let owner = read_address(params, 0)?;
            let spender = read_address(params, 32)?;
            let allowance = token.allowance(&owner, &spender);
            Ok((u64_to_uint256(allowance).to_vec(), None))
        }
        SEL_TRANSFER_FROM => {
            let from = read_address(params, 0)?;
            let to = read_address(params, 32)?;
            let amount = read_uint256_as_u64(params, 64)?;
            let event = token.transfer_from(caller, &from, &to, amount)?;
            let log = token_event_to_eth_log(&event);
            Ok((bool_to_word(true).to_vec(), Some(log)))
        }
        _ => Err(ErcCompatError::UnknownSelector(selector)),
    }
}

// ══════════════════════════════════════════════════════════
//  ERC-721 dispatch
// ══════════════════════════════════════════════════════════

fn dispatch_erc721(
    selector: [u8; 4],
    params: &[u8],
    caller: &Address,
    token: &mut QN8Token,
) -> ErcCompatResult<(Vec<u8>, Option<EthLog>)> {
    match selector {
        SEL_NAME => {
            let name = token.name().to_string();
            Ok((encode_string_return(&name), None))
        }
        SEL_SYMBOL => {
            let symbol = token.symbol().to_string();
            Ok((encode_string_return(&symbol), None))
        }
        SEL_BALANCE_OF => {
            let owner = read_address(params, 0)?;
            let balance = token.balance_of(&owner);
            Ok((u64_to_uint256(balance).to_vec(), None))
        }
        SEL_OWNER_OF => {
            let token_id = read_uint256_as_u64(params, 0)?;
            let owner = token.owner_of(token_id)?;
            Ok((quantos_address_to_eth(&owner).to_vec(), None))
        }
        SEL_TOKEN_URI => {
            let token_id = read_uint256_as_u64(params, 0)?;
            let uri = token.token_uri(token_id)?;
            Ok((encode_string_return(&uri), None))
        }
        SEL_APPROVE_NFT => {
            let to = read_address(params, 0)?;
            let token_id = read_uint256_as_u64(params, 32)?;
            let event = token.approve(caller, &to, token_id)?;
            let log = token_event_to_eth_log(&event);
            Ok((Vec::new(), Some(log)))
        }
        SEL_GET_APPROVED => {
            let token_id = read_uint256_as_u64(params, 0)?;
            let approved = token.get_approved(token_id);
            let addr = approved.unwrap_or([0u8; 32]);
            Ok((quantos_address_to_eth(&addr).to_vec(), None))
        }
        SEL_SET_APPROVAL_ALL => {
            let operator = read_address(params, 0)?;
            let approved = read_bool(params, 32)?;
            let event = token.set_approval_for_all(caller, &operator, approved)?;
            let log = token_event_to_eth_log(&event);
            Ok((Vec::new(), Some(log)))
        }
        SEL_IS_APPROVED_ALL => {
            let owner = read_address(params, 0)?;
            let operator = read_address(params, 32)?;
            let approved = token.is_approved_for_all(&owner, &operator);
            Ok((bool_to_word(approved).to_vec(), None))
        }
        SEL_TRANSFER_FROM => {
            let from = read_address(params, 0)?;
            let to = read_address(params, 32)?;
            let token_id = read_uint256_as_u64(params, 64)?;
            let event = token.transfer_from(caller, &from, &to, token_id)?;
            let log = token_event_to_eth_log(&event);
            Ok((Vec::new(), Some(log)))
        }
        SEL_SAFE_TRANSFER_FR => {
            let from = read_address(params, 0)?;
            let to = read_address(params, 32)?;
            let token_id = read_uint256_as_u64(params, 64)?;
            let event = token.safe_transfer_from(caller, &from, &to, token_id, &[])?;
            let log = token_event_to_eth_log(&event);
            Ok((Vec::new(), Some(log)))
        }
        SEL_SAFE_TFR_DATA => {
            let from = read_address(params, 0)?;
            let to = read_address(params, 32)?;
            let token_id = read_uint256_as_u64(params, 64)?;
            let data = read_bytes(params, 96)?;
            let event = token.safe_transfer_from(caller, &from, &to, token_id, &data)?;
            let log = token_event_to_eth_log(&event);
            Ok((Vec::new(), Some(log)))
        }
        _ => Err(ErcCompatError::UnknownSelector(selector)),
    }
}

// ══════════════════════════════════════════════════════════
//  ERC-1155 dispatch
// ══════════════════════════════════════════════════════════

fn dispatch_erc1155(
    selector: [u8; 4],
    params: &[u8],
    caller: &Address,
    token: &mut QN12Token,
) -> ErcCompatResult<(Vec<u8>, Option<EthLog>)> {
    match selector {
        SEL_NAME => {
            let name = token.name().to_string();
            Ok((encode_string_return(&name), None))
        }
        SEL_URI => {
            let token_id = read_uint256_as_u64(params, 0)?;
            let uri = token.uri(token_id);
            Ok((encode_string_return(&uri), None))
        }
        SEL_BALANCE_OF_1155 => {
            let account = read_address(params, 0)?;
            let token_id = read_uint256_as_u64(params, 32)?;
            let balance = token.balance_of(&account, token_id);
            Ok((u64_to_uint256(balance).to_vec(), None))
        }
        SEL_BALANCE_BATCH => {
            let accounts = read_address_array(params, 0)?;
            let token_ids = read_uint256_array_as_u64(params, 32)?;
            let balances = token.balance_of_batch(&accounts, &token_ids)?;
            
            // Encode as dynamic uint256[] return
            let mut out = Vec::new();
            out.extend_from_slice(&u64_to_uint256(32)); // offset
            out.extend_from_slice(&u64_to_uint256(balances.len() as u64)); // length
            for b in &balances {
                out.extend_from_slice(&u64_to_uint256(*b));
            }
            Ok((out, None))
        }
        SEL_SET_APPROVAL_ALL => {
            let operator = read_address(params, 0)?;
            let approved = read_bool(params, 32)?;
            let event = token.set_approval_for_all(caller, &operator, approved)?;
            let log = token_event_to_eth_log(&event);
            Ok((Vec::new(), Some(log)))
        }
        SEL_IS_APPROVED_ALL => {
            let owner = read_address(params, 0)?;
            let operator = read_address(params, 32)?;
            let approved = token.is_approved_for_all(&owner, &operator);
            Ok((bool_to_word(approved).to_vec(), None))
        }
        SEL_SAFE_TFR_1155 => {
            let from = read_address(params, 0)?;
            let to = read_address(params, 32)?;
            let token_id = read_uint256_as_u64(params, 64)?;
            let amount = read_uint256_as_u64(params, 96)?;
            let data = read_bytes(params, 128)?;
            let event = token.safe_transfer_from(caller, &from, &to, token_id, amount, &data)?;
            let log = token_event_to_eth_log(&event);
            Ok((Vec::new(), Some(log)))
        }
        SEL_SAFE_BATCH_TFR => {
            let from = read_address(params, 0)?;
            let to = read_address(params, 32)?;
            let token_ids = read_uint256_array_as_u64(params, 64)?;
            let amounts = read_uint256_array_as_u64(params, 96)?;
            let data = read_bytes(params, 128)?;
            let event = token.safe_batch_transfer_from(
                caller, &from, &to, &token_ids, &amounts, &data,
            )?;
            let log = token_event_to_eth_log(&event);
            Ok((Vec::new(), Some(log)))
        }
        _ => Err(ErcCompatError::UnknownSelector(selector)),
    }
}

// ══════════════════════════════════════════════════════════
//  Utility: build calldata from ethers.js-like API
// ══════════════════════════════════════════════════════════

/// Builds raw Ethereum ABI calldata for a function call.
/// Useful for testing and for SDK integration.
pub fn build_calldata(selector: [u8; 4], params: &[&[u8; 32]]) -> Vec<u8> {
    let mut data = selector.to_vec();
    for param in params {
        data.extend_from_slice(*param);
    }
    data
}

// ══════════════════════════════════════════════════════════
//  Tests
// ══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────

    fn make_eth_address(byte: u8) -> [u8; 32] {
        let mut addr = [0u8; 32];
        addr[31] = byte;
        addr
    }

    fn make_qn4() -> QN4Token {
        let owner = make_eth_address(0x01);
        QN4Token::new_full(
            "Test Token".into(), "TST".into(), 18, 1_000_000, owner,
            true, true, true,
        )
    }

    fn make_qn8() -> QN8Token {
        let owner = make_eth_address(0x01);
        QN8Token::new("Test NFT".into(), "TNFT".into(), owner, "ipfs://".into())
    }

    fn make_qn12() -> QN12Token {
        let owner = make_eth_address(0x01);
        QN12Token::new("Multi Token".into(), owner, "ipfs://".into())
    }

    // ── Address mapping ──────────────────────────────────

    #[test]
    fn test_address_round_trip() {
        let eth_addr = make_eth_address(0xAB);
        let quantos = eth_address_to_quantos(&eth_addr);
        let back = quantos_address_to_eth(&quantos);
        assert_eq!(eth_addr, back);
    }

    #[test]
    fn test_native_quantos_address_truncation() {
        let mut native = [0xFFu8; 32];
        let eth = quantos_address_to_eth(&native);
        // First 12 bytes zeroed
        assert_eq!(&eth[..12], &[0u8; 12]);
        // Last 20 preserved
        assert_eq!(&eth[12..], &native[12..]);
    }

    // ── uint256 conversion ───────────────────────────────

    #[test]
    fn test_uint256_to_u64_valid() {
        let word = u64_to_uint256(42);
        assert_eq!(uint256_to_u64(&word).unwrap(), 42);
    }

    #[test]
    fn test_uint256_to_u64_max() {
        let word = u64_to_uint256(u64::MAX);
        assert_eq!(uint256_to_u64(&word).unwrap(), u64::MAX);
    }

    #[test]
    fn test_uint256_to_u64_overflow() {
        let mut word = [0u8; 32];
        word[23] = 1; // value > u64::MAX
        assert_eq!(uint256_to_u64(&word), Err(ErcCompatError::Uint256Overflow));
    }

    // ── ERC-20 via dispatch ──────────────────────────────

    #[test]
    fn test_erc20_name() {
        let mut token = make_qn4();
        let caller = make_eth_address(0x01);
        let calldata = build_calldata(SEL_NAME, &[]);
        let (ret, log) = dispatch_erc_call(&calldata, &caller, &mut AnyToken::QN4(&mut token)).unwrap();
        assert!(log.is_none());
        // Return should contain "Test Token"
        assert!(ret.len() >= 96);
    }

    #[test]
    fn test_erc20_balance_of() {
        let mut token = make_qn4();
        let owner = make_eth_address(0x01);
        let calldata = build_calldata(SEL_BALANCE_OF, &[&owner]);
        let (ret, _) = dispatch_erc_call(&calldata, &owner, &mut AnyToken::QN4(&mut token)).unwrap();
        let balance = uint256_to_u64(&ret[..32].try_into().unwrap()).unwrap();
        assert_eq!(balance, 1_000_000);
    }

    #[test]
    fn test_erc20_transfer() {
        let mut token = make_qn4();
        let owner = make_eth_address(0x01);
        let recipient = make_eth_address(0x02);
        let amount = u64_to_uint256(500);

        let calldata = build_calldata(SEL_TRANSFER, &[&recipient, &amount]);
        let (ret, log) = dispatch_erc_call(&calldata, &owner, &mut AnyToken::QN4(&mut token)).unwrap();

        // Returns true
        assert_eq!(ret, bool_to_word(true).to_vec());

        // Event emitted
        let log = log.unwrap();
        assert_eq!(log.topics[0], event_topic("Transfer(address,address,uint256)"));

        // Balances updated
        assert_eq!(token.balance_of(&owner), 999_500);
        assert_eq!(token.balance_of(&recipient), 500);
    }

    #[test]
    fn test_erc20_approve_and_transfer_from() {
        let mut token = make_qn4();
        let owner = make_eth_address(0x01);
        let spender = make_eth_address(0x02);
        let recipient = make_eth_address(0x03);

        // approve(spender, 1000)
        let calldata = build_calldata(SEL_APPROVE, &[&spender, &u64_to_uint256(1000)]);
        let (_, log) = dispatch_erc_call(&calldata, &owner, &mut AnyToken::QN4(&mut token)).unwrap();
        assert!(log.is_some());

        // transferFrom(owner, recipient, 600)
        let calldata = build_calldata(SEL_TRANSFER_FROM, &[
            &owner, &recipient, &u64_to_uint256(600),
        ]);
        let (ret, log) = dispatch_erc_call(&calldata, &spender, &mut AnyToken::QN4(&mut token)).unwrap();
        assert_eq!(ret, bool_to_word(true).to_vec());
        assert!(log.is_some());

        assert_eq!(token.balance_of(&recipient), 600);
        assert_eq!(token.allowance(&owner, &spender), 400);
    }

    #[test]
    fn test_erc20_total_supply() {
        let mut token = make_qn4();
        let caller = make_eth_address(0x01);
        let calldata = build_calldata(SEL_TOTAL_SUPPLY, &[]);
        let (ret, _) = dispatch_erc_call(&calldata, &caller, &mut AnyToken::QN4(&mut token)).unwrap();
        let supply = uint256_to_u64(&ret[..32].try_into().unwrap()).unwrap();
        assert_eq!(supply, 1_000_000);
    }

    // ── ERC-721 via dispatch ─────────────────────────────

    #[test]
    fn test_erc721_mint_and_owner_of() {
        let mut token = make_qn8();
        let owner = make_eth_address(0x01);
        let alice = make_eth_address(0x02);

        // Mint via native API
        token.mint(&owner, &alice, Some("ipfs://1".into())).unwrap();

        // ownerOf(1) via ERC calldata
        let calldata = build_calldata(SEL_OWNER_OF, &[&u64_to_uint256(1)]);
        let (ret, _) = dispatch_erc_call(&calldata, &owner, &mut AnyToken::QN8(&mut token)).unwrap();
        
        let mut returned_addr = [0u8; 32];
        returned_addr.copy_from_slice(&ret[..32]);
        assert_eq!(returned_addr, quantos_address_to_eth(&alice));
    }

    #[test]
    fn test_erc721_transfer_from() {
        let mut token = make_qn8();
        let owner = make_eth_address(0x01);
        let alice = make_eth_address(0x02);
        let bob = make_eth_address(0x03);

        token.mint(&owner, &alice, None).unwrap();

        // transferFrom(alice, bob, 1) — called by alice
        let calldata = build_calldata(SEL_TRANSFER_FROM, &[
            &alice, &bob, &u64_to_uint256(1),
        ]);
        let (_, log) = dispatch_erc_call(&calldata, &alice, &mut AnyToken::QN8(&mut token)).unwrap();
        
        let log = log.unwrap();
        assert_eq!(log.topics[0], event_topic("Transfer(address,address,uint256)"));
        assert_eq!(token.owner_of(1).unwrap(), bob);
    }

    // ── ERC-1155 via dispatch ────────────────────────────

    #[test]
    fn test_erc1155_balance_of() {
        let mut token = make_qn12();
        let owner = make_eth_address(0x01);

        token.create_token(&owner, 1000, "ipfs://gold.json".into()).unwrap();

        let calldata = build_calldata(SEL_BALANCE_OF_1155, &[&owner, &u64_to_uint256(1)]);
        let (ret, _) = dispatch_erc_call(&calldata, &owner, &mut AnyToken::QN12(&mut token)).unwrap();
        let balance = uint256_to_u64(&ret[..32].try_into().unwrap()).unwrap();
        assert_eq!(balance, 1000);
    }

    #[test]
    fn test_erc1155_safe_transfer_from() {
        let mut token = make_qn12();
        let owner = make_eth_address(0x01);
        let alice = make_eth_address(0x02);

        token.create_token(&owner, 1000, "".into()).unwrap();

        // Build safeTransferFrom(owner, alice, 1, 300, "") calldata
        let mut calldata = SEL_SAFE_TFR_1155.to_vec();
        calldata.extend_from_slice(&owner);                 // from
        calldata.extend_from_slice(&alice);                 // to
        calldata.extend_from_slice(&u64_to_uint256(1));     // id
        calldata.extend_from_slice(&u64_to_uint256(300));   // amount
        calldata.extend_from_slice(&u64_to_uint256(160));   // offset to bytes
        calldata.extend_from_slice(&u64_to_uint256(0));     // bytes length = 0

        let (_, log) = dispatch_erc_call(&calldata, &owner, &mut AnyToken::QN12(&mut token)).unwrap();
        assert!(log.is_some());
        assert_eq!(token.balance_of(&owner, 1), 700);
        assert_eq!(token.balance_of(&alice, 1), 300);
    }

    // ── ERC-165 supportsInterface ────────────────────────

    #[test]
    fn test_supports_interface_erc20() {
        let mut token = make_qn4();
        let caller = make_eth_address(0x01);
        
        let mut iface_word = [0u8; 32];
        iface_word[..4].copy_from_slice(&IFACE_ERC20);
        let calldata = build_calldata(SEL_SUPPORTS_IFACE, &[&iface_word]);
        
        let (ret, _) = dispatch_erc_call(&calldata, &caller, &mut AnyToken::QN4(&mut token)).unwrap();
        assert_eq!(ret, bool_to_word(true).to_vec());
    }

    #[test]
    fn test_supports_interface_wrong_type() {
        let mut token = make_qn4();
        let caller = make_eth_address(0x01);
        
        let mut iface_word = [0u8; 32];
        iface_word[..4].copy_from_slice(&IFACE_ERC721);
        let calldata = build_calldata(SEL_SUPPORTS_IFACE, &[&iface_word]);
        
        let (ret, _) = dispatch_erc_call(&calldata, &caller, &mut AnyToken::QN4(&mut token)).unwrap();
        assert_eq!(ret, bool_to_word(false).to_vec());
    }

    // ── Error cases ──────────────────────────────────────

    #[test]
    fn test_calldata_too_short() {
        let mut token = make_qn4();
        let caller = make_eth_address(0x01);
        let result = dispatch_erc_call(&[0x01, 0x02], &caller, &mut AnyToken::QN4(&mut token));
        assert!(matches!(result, Err(ErcCompatError::CalldataTooShort)));
    }

    #[test]
    fn test_unknown_selector() {
        let mut token = make_qn4();
        let caller = make_eth_address(0x01);
        let calldata = build_calldata([0xDE, 0xAD, 0xBE, 0xEF], &[]);
        let result = dispatch_erc_call(&calldata, &caller, &mut AnyToken::QN4(&mut token));
        assert!(matches!(result, Err(ErcCompatError::UnknownSelector(_))));
    }

    #[test]
    fn test_uint256_overflow_rejected() {
        let mut token = make_qn4();
        let caller = make_eth_address(0x01);
        let recipient = make_eth_address(0x02);
        let mut huge_amount = [0u8; 32];
        huge_amount[0] = 1; // value > u64::MAX

        let calldata = build_calldata(SEL_TRANSFER, &[&recipient, &huge_amount]);
        let result = dispatch_erc_call(&calldata, &caller, &mut AnyToken::QN4(&mut token));
        assert!(matches!(result, Err(ErcCompatError::Uint256Overflow)));
    }

    // ── Event encoding ───────────────────────────────────

    #[test]
    fn test_transfer_event_encoding() {
        let event = TokenEvent::Transfer {
            from: make_eth_address(0x01),
            to: make_eth_address(0x02),
            value: 1000,
        };
        let log = token_event_to_eth_log(&event);

        assert_eq!(log.topics.len(), 3);
        assert_eq!(log.topics[0], event_topic("Transfer(address,address,uint256)"));
        assert_eq!(log.data.len(), 32);
        let value = uint256_to_u64(&log.data[..32].try_into().unwrap()).unwrap();
        assert_eq!(value, 1000);
    }

    #[test]
    fn test_transfer_single_event_encoding() {
        let event = TokenEvent::TransferSingle {
            operator: make_eth_address(0x01),
            from: make_eth_address(0x02),
            to: make_eth_address(0x03),
            token_id: 5,
            value: 100,
        };
        let log = token_event_to_eth_log(&event);

        assert_eq!(log.topics.len(), 4);
        assert_eq!(log.topics[0], event_topic("TransferSingle(address,address,address,uint256,uint256)"));
        assert_eq!(log.data.len(), 64);
    }

    // ── Determinism ──────────────────────────────────────

    #[test]
    fn test_determinism_same_calldata_same_result() {
        let calldata = build_calldata(SEL_BALANCE_OF, &[&make_eth_address(0x01)]);
        let caller = make_eth_address(0x01);

        let results: Vec<Vec<u8>> = (0..10)
            .map(|_| {
                let mut token = make_qn4();
                let (ret, _) = dispatch_erc_call(&calldata, &caller, &mut AnyToken::QN4(&mut token)).unwrap();
                ret
            })
            .collect();

        for r in &results[1..] {
            assert_eq!(r, &results[0], "ERC compat shim must be deterministic");
        }
    }
}
