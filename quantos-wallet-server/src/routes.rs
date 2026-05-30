// src/routes.rs — Axum routes + handlers
//
// POST /wallet/create         — generate new Dilithium-3 wallet
// POST /wallet/import         — import from secret key hex
// POST /wallet/unlock         — decrypt with PIN, return session token
// POST /wallet/lock           — invalidate session
// POST /wallet/send           — sign + broadcast transfer
// POST /wallet/stake          — sign + broadcast stake
// POST /wallet/unstake        — sign + broadcast unstake
// POST /wallet/sign           — sign arbitrary message
// GET  /wallet/:address/balance
// GET  /wallet/:address/info
// GET  /wallet/:address/nfts
// GET  /health

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::sync::Arc;

use crate::{
    crypto::{
        address_to_qts, build_signed_transaction, build_signed_transaction_with_data,
        decrypt_with_pin, derive_address, encrypt_with_pin,
        format_qts, format_token, parse_address, validate_pin, verify_dilithium_signature,
        DilithiumKeypair,
    },
    error::{WalletError, WalletResult},
    state::AppState,
    types::{
        CreateWalletRequest, ImportWalletRequest, SendTransferRequest,
        DeployContractRequest, CallContractRequest, ReadContractRequest, FaucetClaimRequest, TransferTokenRequest,
        BatchCallContractRequest,
        BridgeApproveRequest, BridgeDepositRequest, BridgeReleaseRequest,
        SessionTokenResponse, SignMessageRequest, WalletBalanceResponse, WalletInfoResponse,
        TransactionType, DecryptKeyRequest,
    },
};

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Wallet lifecycle
        .route("/wallet/create", post(create_wallet))
        .route("/wallet/import", post(import_wallet))
        .route("/wallet/unlock", post(unlock_wallet))
        .route("/wallet/lock", post(lock_wallet))
        .route("/wallet/decrypt-key", post(decrypt_key))
        // Read (no session required)
        .route("/wallet/:address/balance", get(get_balance))
        .route("/wallet/:address/info", get(get_account_info))
        .route("/wallet/:address/nfts", get(get_nfts))
        .route("/wallet/:address/tokens", get(get_token_balances))
        // Transactions (session required)
        .route("/wallet/send", post(send_transfer))
        .route("/wallet/transfer-token", post(transfer_token))
        .route("/wallet/deploy", post(deploy_contract))
        .route("/wallet/call", post(call_contract))
        .route("/wallet/batch-call", post(batch_call_contract))
        .route("/wallet/read-contract", post(read_contract))
        .route("/wallet/sign", post(sign_message))
        .route("/bridge/approve", post(bridge_approve))
        .route("/bridge/deposit", post(bridge_deposit))
        .route("/bridge/release", post(bridge_release))
        .route("/bridge/receipt/:tx_hash", get(bridge_receipt))
        // Faucet
        .route("/faucet/claim", post(faucet_claim))
        .route("/faucet/status/:address", get(faucet_status))
        // QNS (Quantos Name Service)
        .route("/qns/register", post(qns_register))
        .route("/qns/renew", post(qns_renew))
        .route("/qns/set-primary", post(qns_set_primary))
        .route("/qns/resolve/:name", get(qns_resolve))
        .route("/qns/reverse/:address", get(qns_reverse))
        .route("/qns/info/:name", get(qns_info))
        .route("/qns/available/:name", get(qns_available))
        .route("/qns/owned/:address", get(qns_owned))
        // Auth (challenge-response login)
        .route("/auth/challenge", post(auth_challenge))
        .route("/auth/verify", post(auth_verify))
        // Health
        .route("/health", get(health))
        .route("/node/info", get(node_info))
        .with_state(state)
}

// ── POST /wallet/create ───────────────────────────────────────────────────────

async fn create_wallet(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<CreateWalletRequest>,
) -> Result<impl IntoResponse, WalletError> {
    validate_pin(&req.pin)?;

    let keypair = DilithiumKeypair::generate()?;
    let address_hex = hex::encode(keypair.address);
    let qts_address = address_to_qts(&keypair.address);
    let rpc_address = format!("QTS:{}", address_hex);
    let public_key_hex = hex::encode(&keypair.public_key);

    // Store both SK and PK in encrypted blob (format: "SK_HEX:PK_HEX")
    let key_data = format!("{}:{}", hex::encode(&keypair.secret_key.0), public_key_hex);
    let encrypted_secret_key = encrypt_with_pin(&key_data, &req.pin)?;

    let wallet = WalletInfoResponse {
        address: address_hex,
        qts_address,
        rpc_address,
        public_key: public_key_hex,
        label: req.label,
        created_at: Utc::now().timestamp(),
    };

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "wallet": wallet,
            // Return the encrypted key blob — client MUST store this locally
            // (localStorage / chrome.storage). Server does NOT persist it.
            "encrypted_key": encrypted_secret_key,
        })),
    ))
}

// ── POST /wallet/import ───────────────────────────────────────────────────────

async fn import_wallet(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<ImportWalletRequest>,
) -> Result<impl IntoResponse, WalletError> {
    validate_pin(&req.pin)?;

    // Validate and derive address from secret key
    let keypair = DilithiumKeypair::from_secret_key_hex(&req.secret_key_hex)?;
    let address_hex = hex::encode(keypair.address);
    let qts_address = address_to_qts(&keypair.address);
    let rpc_address = format!("QTS:{}", address_hex);
    let public_key_hex = hex::encode(&keypair.public_key);

    // Store both SK and PK in encrypted blob (format: "SK_HEX:PK_HEX")
    let key_data = format!("{}:{}", req.secret_key_hex, public_key_hex);
    let encrypted_secret_key = encrypt_with_pin(&key_data, &req.pin)?;

    let wallet = WalletInfoResponse {
        address: address_hex,
        qts_address,
        rpc_address,
        public_key: public_key_hex,
        label: req.label,
        created_at: Utc::now().timestamp(),
    };

    Ok(Json(json!({
        "wallet": wallet,
        "encrypted_key": encrypted_secret_key,
    })))
}

// ── POST /wallet/unlock ───────────────────────────────────────────────────────
// Body: { address, encrypted_key, pin }

#[derive(serde::Deserialize)]
struct UnlockBody {
    address: String,
    encrypted_key: String,
    pin: String,
}

const MAX_PIN_ATTEMPTS: u32 = 3;
const PIN_LOCKOUT_SECS: u64 = 60;

async fn unlock_wallet(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UnlockBody>,
) -> Result<impl IntoResponse, WalletError> {
    validate_pin(&req.pin)?;

    // Anti-brute-force: check if address is locked out
    let addr_key = req.address.clone();
    if let Some(attempts) = state.pin_attempts.get(&addr_key) {
        if let Some(locked_until) = attempts.locked_until {
            if std::time::Instant::now() < locked_until {
                let remaining = locked_until.duration_since(std::time::Instant::now()).as_secs();
                return Err(WalletError::RateLimited(remaining));
            }
        }
    }

    // Decrypt the encrypted key blob (format: "SK_HEX:PK_HEX")
    let decrypted = match decrypt_with_pin(&req.encrypted_key, &req.pin) {
        Ok(d) => {
            // Success: reset attempts
            state.pin_attempts.remove(&addr_key);
            d
        }
        Err(e) => {
            // Failed: increment attempts
            let mut entry = state.pin_attempts.entry(addr_key.clone()).or_insert(
                crate::state::PinAttempts { failures: 0, locked_until: None }
            );
            entry.failures += 1;
            if entry.failures >= MAX_PIN_ATTEMPTS {
                entry.locked_until = Some(
                    std::time::Instant::now() + std::time::Duration::from_secs(PIN_LOCKOUT_SECS)
                );
                tracing::warn!("PIN locked for {} ({} failures)", &addr_key, entry.failures);
            }
            return Err(e);
        }
    };
    
    let parts: Vec<&str> = decrypted.split(':').collect();
    if parts.len() != 2 {
        return Err(WalletError::DecryptionFailed);
    }
    
    let secret_key_hex = parts[0];
    let public_key_hex = parts[1];

    // Validate secret key
    let sk_bytes = hex::decode(secret_key_hex)
        .map_err(|_| WalletError::InvalidSecretKey("Bad SK hex".to_string()))?;
    let pk_bytes = hex::decode(public_key_hex)
        .map_err(|_| WalletError::InvalidSecretKey("Bad PK hex".to_string()))?;
    
    // Derive address from public key
    let address = crate::crypto::derive_address(&pk_bytes);
    let address_hex = hex::encode(address);

    // Sanity check: derived address should match requested address
    // Handle all formats: hex, QTS:hex, 0x hex, qts1 bech32
    let expected_hex = if req.address.starts_with("qts1") {
        let parsed = parse_address(&req.address)?;
        hex::encode(parsed)
    } else {
        req.address
            .strip_prefix("QTS:")
            .or_else(|| req.address.strip_prefix("0x"))
            .unwrap_or(&req.address)
            .to_lowercase()
    };
    if address_hex != expected_hex {
        // Key decrypted successfully (PIN correct) and PK is valid,
        // so the derived address is canonical. Log warning and continue.
        tracing::warn!(
            "Address mismatch during unlock: derived={}, expected={}. Using derived address.",
            &address_hex[..address_hex.len().min(16)],
            &expected_hex[..expected_hex.len().min(16)]
        );
    }

    let token = state.sessions.create_session(
        address_hex.clone(),
        secret_key_hex.to_string(),
        public_key_hex.to_string(),
    );

    let expires_at = Utc::now().timestamp() + state.config.session_ttl_secs as i64;

    Ok(Json(SessionTokenResponse {
        session_token: token,
        expires_at,
        address: address_hex,
    }))
}

// ── POST /wallet/lock ─────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct LockBody {
    session_token: String,
}

async fn lock_wallet(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LockBody>,
) -> Result<impl IntoResponse, WalletError> {
    state.sessions.remove_session(&req.session_token);
    Ok(Json(json!({ "locked": true })))
}

// ── POST /wallet/decrypt-key ──────────────────────────────────────────────

async fn decrypt_key(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<DecryptKeyRequest>,
) -> Result<impl IntoResponse, WalletError> {
    validate_pin(&req.pin)?;

    // Decrypt the encrypted key blob (format: "SK_HEX:PK_HEX")
    let decrypted = decrypt_with_pin(&req.encrypted_key, &req.pin)?;
    
    let parts: Vec<&str> = decrypted.split(':').collect();
    if parts.len() != 2 {
        return Err(WalletError::DecryptionFailed);
    }
    
    let secret_key_hex = parts[0];
    
    Ok(Json(json!({
        "secret_key_hex": secret_key_hex,
    })))
}

// ── GET /wallet/:address/balance ──────────────────────────────────────────────

async fn get_balance(
    State(state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> Result<impl IntoResponse, WalletError> {
    let rpc_address = if address.starts_with("QTS:") {
        address.clone()
    } else if address.starts_with("qts1") {
        let addr = parse_address(&address)?;
        format!("QTS:{}", hex::encode(addr))
    } else {
        format!("QTS:{}", address)
    };

    let account = state.node_client.get_account(&rpc_address).await?;

    let balance_raw = account["balance"]
        .as_str()
        .unwrap_or("QTS:0")
        .to_string();
    let stake_raw = account["stake"]
        .as_str()
        .unwrap_or("QTS:0")
        .to_string();
    let nonce_raw = account["nonce"]
        .as_str()
        .unwrap_or("QTS:0")
        .to_string();
    let is_validator = account["is_validator"].as_bool().unwrap_or(false);

    let balance = parse_qts_hex(&balance_raw);
    let stake = parse_qts_hex(&stake_raw);
    let nonce = parse_qts_hex(&nonce_raw) as u64;

    // Re-derive qts_address from the hex address
    let addr_hex = rpc_address.strip_prefix("QTS:").unwrap_or(&rpc_address);
    let addr_bytes = hex::decode(addr_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .unwrap_or([0u8; 32]);
    let qts_address = address_to_qts(&addr_bytes);

    let (qtest_balance, qtest_balance_formatted) = fetch_contract_token_balance(
        &state,
        state.config.qtest_contract_address.as_deref(),
        &rpc_address,
        "QTEST",
    ).await;
    let (sqtest_balance, sqtest_balance_formatted) = fetch_contract_token_balance(
        &state,
        state.config.sqtest_contract_address.as_deref(),
        &rpc_address,
        "SQTEST",
    ).await;

    Ok(Json(WalletBalanceResponse {
        address: addr_hex.to_string(),
        qts_address,
        balance: balance.to_string(),
        stake: stake.to_string(),
        nonce,
        is_validator,
        balance_formatted: format_qts(balance, 6),
        stake_formatted: format_qts(stake, 6),
        qtest_balance,
        qtest_balance_formatted,
        sqtest_balance,
        sqtest_balance_formatted,
    }))
}

// ── GET /wallet/:address/info ─────────────────────────────────────────────────

async fn get_account_info(
    State(state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> Result<impl IntoResponse, WalletError> {
    let rpc_address = normalize_rpc_address(&address)?;
    let account = state.node_client.get_account(&rpc_address).await?;
    Ok(Json(account))
}

// ── GET /wallet/:address/tokens ───────────────────────────────────────────────

async fn get_token_balances(
    State(state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> Result<impl IntoResponse, WalletError> {
    let rpc_address = normalize_rpc_address(&address)?;
    let tokens = state.node_client.get_token_balances(&rpc_address).await?;
    let mut entries = match tokens {
        Value::Array(items) => items,
        other => vec![other],
    };

    upsert_contract_token_balance(
        &mut entries,
        &state,
        state.config.sqtest_contract_address.as_deref(),
        &rpc_address,
        "SQTEST",
        "SQTEST Stablecoin",
    ).await;

    Ok(Json(Value::Array(entries)))
}

// ── GET /wallet/:address/nfts ─────────────────────────────────────────────────

async fn get_nfts(
    State(state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> Result<impl IntoResponse, WalletError> {
    let rpc_address = normalize_rpc_address(&address)?;
    let nfts = state.node_client.get_nfts(&rpc_address, None).await?;
    Ok(Json(nfts))
}

// ── POST /wallet/send ─────────────────────────────────────────────────────────

async fn send_transfer(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SendTransferRequest>,
) -> Result<impl IntoResponse, WalletError> {
    let session = state.sessions.get_session(&req.session_token)?;
    let keypair = DilithiumKeypair::from_sk_and_pk_hex(&session.secret_key_hex, &session.public_key_hex)?;

    // Resolve .qts domain names to addresses
    let to = match resolve_qts_name_if_needed(&state, &req.to).await? {
        Some(addr) => addr,
        None => parse_address(&req.to)?,
    };
    let amount: u128 = req
        .amount
        .parse()
        .map_err(|_| WalletError::InvalidAmount("Must be a decimal integer".to_string()))?;

    let rpc_address = format!("QTS:{}", hex::encode(keypair.address));
    let nonce = state.node_client.get_nonce(&rpc_address).await?;
    let chain_id = state.node_client.get_chain_id().await?;
    let node_info = state.node_client.node_info().await?;
    let num_shards = node_info["num_shards"].as_u64().unwrap_or(1000) as u16;

    let (tx_hex, tx_hash) = build_signed_transaction(
        &keypair,
        TransactionType::Transfer,
        to,
        amount,
        nonce,
        chain_id,
        num_shards,
    )?;

    let _response = state.node_client.send_raw_transaction(&tx_hex).await?;

    Ok(Json(json!({
        "tx_hash": tx_hash,
        "status": "sent"
    })))
}

// ── POST /wallet/deploy ──────────────────────────────────────────────────────

async fn deploy_contract(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DeployContractRequest>,
) -> Result<impl IntoResponse, WalletError> {
    let session = state.sessions.get_session(&req.session_token)?;
    let keypair = DilithiumKeypair::from_sk_and_pk_hex(&session.secret_key_hex, &session.public_key_hex)?;

    let bytecode = if let Some(bytecode_hex) = req.bytecode_hex.as_deref() {
        let bytecode_str = bytecode_hex.strip_prefix("0x").unwrap_or(bytecode_hex);
        hex::decode(bytecode_str)
            .map_err(|e| WalletError::InvalidAddress(format!("Bad bytecode hex: {}", e)))?
    } else if let Some(wasm_url) = req.wasm_url.as_deref() {
        let relative = wasm_url.trim_start_matches('/');
        let cwd = std::env::current_dir()
            .map_err(|e| WalletError::Internal(format!("Failed to resolve current dir: {}", e)))?;
        let candidates = [
            cwd.join(relative),
            cwd.join("public").join(relative),
            cwd.join("..").join("quantos").join("solidity-contracts").join(relative),
        ];
        let wasm_path = candidates
            .into_iter()
            .find(|path| path.is_file())
            .ok_or_else(|| WalletError::InvalidAddress(format!("WASM not found for url: {}", wasm_url)))?;
        std::fs::read(&wasm_path)
            .map_err(|e| WalletError::Internal(format!("Failed to read WASM {}: {}", wasm_path.display(), e)))?
    } else {
        return Err(WalletError::InvalidAddress(
            "Missing deploy payload: provide bytecode_hex or wasm_url".to_string(),
        ));
    };

    let constructor_data = if let Some(ctor_hex) = &req.constructor_data_hex {
        let ctor_str = ctor_hex.strip_prefix("0x").unwrap_or(ctor_hex);
        if ctor_str.is_empty() {
            Vec::new()
        } else {
            hex::decode(ctor_str)
                .map_err(|e| WalletError::InvalidAddress(format!("Bad constructor data hex: {}", e)))?
        }
    } else {
        Vec::new()
    };

    let mut deploy_data = Vec::with_capacity(12 + bytecode.len() + constructor_data.len());
    deploy_data.extend_from_slice(b"QDP1");
    deploy_data.extend_from_slice(&(bytecode.len() as u32).to_le_bytes());
    deploy_data.extend_from_slice(&(constructor_data.len() as u32).to_le_bytes());
    deploy_data.extend_from_slice(&bytecode);
    deploy_data.extend_from_slice(&constructor_data);

    let rpc_address = format!("QTS:{}", hex::encode(keypair.address));
    let nonce = state.node_client.get_nonce(&rpc_address).await?;
    let chain_id = state.node_client.get_chain_id().await?;
    let node_info = state.node_client.node_info().await?;
    let num_shards = node_info["num_shards"].as_u64().unwrap_or(1000) as u16;
    let predicted_contract_address = predict_contract_address(keypair.address, &bytecode, nonce);

    let (tx_hex, tx_hash) = build_signed_transaction_with_data(
        &keypair,
        TransactionType::ContractDeploy,
        [0u8; 32], // zero address for deploy
        0,
        deploy_data,
        10_000_000,
        nonce,
        chain_id,
        num_shards,
    )?;

    state.node_client.send_and_confirm(&tx_hex).await
        .map_err(|e| {
            let raw = e.to_string();
            let cleaned = raw
                .strip_prefix("Transaction reverted: ")
                .unwrap_or_else(|| raw.strip_prefix("Node RPC error: ").unwrap_or(&raw));

            WalletError::TransactionFailed(format!("Contract deploy failed: {}", cleaned))
        })?;

    Ok(Json(json!({
        "tx_hash": tx_hash,
        "status": "confirmed",
        "contract_address": format!("QTS:{}", hex::encode(predicted_contract_address))
    })))
}

fn predict_contract_address(deployer: [u8; 32], bytecode: &[u8], nonce: u64) -> [u8; 32] {
    let mut bytecode_hasher = Sha3_256::new();
    bytecode_hasher.update(bytecode);
    let bytecode_hash = bytecode_hasher.finalize();

    let mut address_hasher = Sha3_256::new();
    address_hasher.update(deployer);
    address_hasher.update(bytecode_hash);
    address_hasher.update(nonce.to_le_bytes());
    let result = address_hasher.finalize();

    let mut address = [0u8; 32];
    address.copy_from_slice(&result);
    address
}

// ── POST /wallet/call ────────────────────────────────────────────────────────

async fn call_contract(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CallContractRequest>,
) -> Result<impl IntoResponse, WalletError> {
    let session = state.sessions.get_session(&req.session_token)?;
    let keypair = DilithiumKeypair::from_sk_and_pk_hex(&session.secret_key_hex, &session.public_key_hex)?;

    let to = parse_address(&req.contract_address)?;
    let calldata_str = req.calldata_hex.strip_prefix("0x").unwrap_or(&req.calldata_hex);
    let calldata = hex::decode(calldata_str)
        .map_err(|e| WalletError::InvalidAddress(format!("Bad calldata hex: {}", e)))?;
    let amount: u128 = req.amount.as_deref().unwrap_or("0").parse()
        .map_err(|_| WalletError::InvalidAmount("Must be a decimal integer".to_string()))?;

    let rpc_address = format!("QTS:{}", hex::encode(keypair.address));
    let selector = calldata_str.get(..8).unwrap_or("unknown");

    tracing::info!(
        contract = %req.contract_address,
        selector = %selector,
        calldata_len = %calldata.len(),
        caller = %rpc_address,
        "call_contract: dispatching"
    );

    let nonce = state.node_client.get_nonce(&rpc_address).await?;
    let chain_id = state.node_client.get_chain_id().await?;
    let node_info = state.node_client.node_info().await?;
    let num_shards = node_info["num_shards"].as_u64().unwrap_or(1000) as u16;

    let (tx_hex, tx_hash) = build_signed_transaction_with_data(
        &keypair,
        TransactionType::ContractCall,
        to,
        amount,
        calldata,
        100_000_000,
        nonce,
        chain_id,
        num_shards,
    )?;

    tracing::info!(
        contract = %req.contract_address,
        selector = %selector,
        tx_hash = %tx_hash,
        "call_contract: tx signed, submitting"
    );

    if let Err(e) = state.node_client.send_and_confirm(&tx_hex).await {
        tracing::error!(
            contract = %req.contract_address,
            selector = %selector,
            tx_hash = %tx_hash,
            caller = %rpc_address,
            error = %e,
            "call_contract: REVERTED"
        );
        return Err(e);
    }

    tracing::info!(
        contract = %req.contract_address,
        selector = %selector,
        tx_hash = %tx_hash,
        "call_contract: confirmed"
    );

    Ok(Json(json!({
        "tx_hash": tx_hash,
        "status": "confirmed"
    })))
}

// ── POST /wallet/batch-call ──────────────────────────────────────────────────

async fn batch_call_contract(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BatchCallContractRequest>,
) -> Result<impl IntoResponse, WalletError> {
    if req.calls.is_empty() {
        return Err(WalletError::InvalidAmount("Empty batch".to_string()));
    }
    if req.calls.len() > 10 {
        return Err(WalletError::InvalidAmount("Batch too large (max 10)".to_string()));
    }

    let session = state.sessions.get_session(&req.session_token)?;
    let keypair = DilithiumKeypair::from_sk_and_pk_hex(&session.secret_key_hex, &session.public_key_hex)?;
    let chain_id = state.node_client.get_chain_id().await?;
    let node_info = state.node_client.node_info().await?;
    let num_shards = node_info["num_shards"].as_u64().unwrap_or(1000) as u16;
    let mut nonce = state.node_client.get_nonce(
        &format!("QTS:{}", hex::encode(keypair.address))
    ).await?;

    let mut results = Vec::new();
    for (i, call) in req.calls.iter().enumerate() {
        let to = parse_address(&call.contract_address)?;
        let calldata_str = call.calldata_hex.strip_prefix("0x").unwrap_or(&call.calldata_hex);
        let calldata = hex::decode(calldata_str)
            .map_err(|e| WalletError::InvalidAddress(format!("Bad calldata hex in call {}: {}", i, e)))?;
        let amount: u128 = call.amount.as_deref().unwrap_or("0").parse()
            .map_err(|_| WalletError::InvalidAmount("Must be a decimal integer".to_string()))?;
        let selector = calldata_str.get(..8).unwrap_or("unknown");

        let (tx_hex, tx_hash) = build_signed_transaction_with_data(
            &keypair,
            TransactionType::ContractCall,
            to,
            amount,
            calldata,
            100_000_000,
            nonce,
            chain_id,
            num_shards,
        )?;
        nonce += 1;

        tracing::info!(
            contract = %call.contract_address,
            selector = %selector,
            tx_hash = %tx_hash,
            batch_index = i,
            "batch_call: submitting"
        );

        if let Err(e) = state.node_client.send_and_confirm(&tx_hex).await {
            tracing::error!(
                contract = %call.contract_address,
                selector = %selector,
                tx_hash = %tx_hash,
                batch_index = i,
                error = %e,
                "batch_call: REVERTED"
            );
            return Err(e);
        }

        results.push(json!({
            "tx_hash": tx_hash,
            "contract_address": call.contract_address,
            "status": "confirmed"
        }));
    }

    Ok(Json(json!({
        "results": results,
        "status": "confirmed"
    })))
}

async fn read_contract(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ReadContractRequest>,
) -> Result<impl IntoResponse, WalletError> {
    let calldata = if req.calldata_hex.starts_with("0x") {
        req.calldata_hex.clone()
    } else {
        format!("0x{}", req.calldata_hex)
    };

    let result = state
        .node_client
        .contract_call(&req.contract_address, &calldata, req.from_address.as_deref())
        .await?;

    Ok(Json(json!({
        "result": result
    })))
}

// ── POST /wallet/transfer-token ───────────────────────────────────────────────
// ERC-20 transfer: calls transfer(address,uint256) on the QTEST contract.

/// transfer(address,uint256) selector = 0xa9059cbb
const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const APPROVE_SELECTOR: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
const ALLOWANCE_SELECTOR: [u8; 4] = [0xdd, 0x62, 0xed, 0x3e];
const TOKEN_SELECTOR: [u8; 4] = [0xfc, 0x0c, 0x54, 0x6a];
const BRIDGE_DEPOSIT_SELECTOR: [u8; 4] = [0x1d, 0xe2, 0x6e, 0x16];
const BRIDGE_RELEASE_SELECTOR: [u8; 4] = [0xf5, 0xb1, 0x6b, 0x84];

/// Parse "100.5" with decimals into raw integer (no f64 precision loss)
fn parse_token_amount(s: &str, decimals: u32) -> Result<u128, WalletError> {
    let parts: Vec<&str> = s.split('.').collect();
    let (whole, frac_str) = match parts.len() {
        1 => (parts[0], ""),
        2 => (parts[0], parts[1]),
        _ => return Err(WalletError::InvalidAmount("Invalid amount".into())),
    };
    let whole: u128 = whole.parse().map_err(|_| WalletError::InvalidAmount("Invalid whole".into()))?;
    let frac: u128 = if frac_str.is_empty() { 0 } else {
        let trimmed = if frac_str.len() > decimals as usize { &frac_str[..decimals as usize] } else { frac_str };
        trimmed.parse().map_err(|_| WalletError::InvalidAmount("Invalid fraction".into()))?
    };
    let pow10 = 10u128.pow(decimals);
    let frac_scaled = if frac_str.is_empty() || frac == 0 { 0 } else {
        let frac_len = frac_str.len() as u32;
        frac * 10u128.pow(decimals - frac_len)
    };
    Ok(whole * pow10 + frac_scaled)
}

async fn transfer_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TransferTokenRequest>,
) -> Result<impl IntoResponse, WalletError> {
    let contract_address = state
        .config
        .qtest_contract_address
        .as_ref()
        .ok_or_else(|| WalletError::InvalidAddress("QTEST contract not configured".into()))?
        .clone();

    let session = state.sessions.get_session(&req.session_token)?;
    let keypair = DilithiumKeypair::from_sk_and_pk_hex(&session.secret_key_hex, &session.public_key_hex)?;

    // Resolve .qts domain names to addresses
    let to_addr = match resolve_qts_name_if_needed(&state, &req.to).await? {
        Some(addr) => addr,
        None => parse_address(&req.to)?,
    };
    let contract_addr = parse_address(&contract_address)?;

    // Reject truncated 20-byte addresses (old qts1 format) — last 12 bytes are zero
    if to_addr[20..] == [0u8; 12] {
        return Err(WalletError::InvalidAddress(
            "Old qts1 address format (20 bytes). Please use the full QTS:hex address or recreate the wallet.".into()
        ));
    }

    // Integer-safe amount parsing
    let raw_amount = parse_token_amount(&req.amount, 18)?;
    if raw_amount == 0 {
        return Err(WalletError::InvalidAmount("Amount must be > 0".into()));
    }

    // Pre-check balance via balanceOf
    let rpc_address = format!("QTS:{}", hex::encode(keypair.address));
    let sender_hex = hex::encode(keypair.address);
    let balance_calldata = format!("0x70a08231{}", sender_hex);
    tracing::info!("transfer pre-check: sender={}, calldata={}", &rpc_address, &balance_calldata);
    let sender_balance = match state.node_client.contract_call(&contract_address, &balance_calldata, Some(&rpc_address)).await {
        Ok(r) => {
            tracing::info!("transfer pre-check raw result: {}", &r);
            let hex = r.strip_prefix("qts:").or_else(|| r.strip_prefix("QTS:")).unwrap_or(&r);
            let bytes = hex::decode(hex).unwrap_or_default();
            let mut be = bytes; be.reverse();
            let trimmed: Vec<u8> = be.iter().skip_while(|&&b| b == 0).cloned().collect();
            if trimmed.len() <= 16 {
                let mut buf = [0u8; 16];
                if !trimmed.is_empty() { buf[16 - trimmed.len()..].copy_from_slice(&trimmed); }
                u128::from_be_bytes(buf)
            } else { 0 }
        }
        Err(e) => { tracing::warn!("transfer pre-check balanceOf failed: {}", e); 0 },
    };
    if sender_balance < raw_amount {
        return Err(WalletError::InvalidAmount(format!(
            "Insufficient QTEST balance: have {}, need {}",
            format_token(sender_balance, 18, 2, "QTEST"),
            format_token(raw_amount, 18, 2, "QTEST")
        )));
    }

    // Build calldata: selector + address + uint256(LE) = 68 bytes
    let mut calldata = Vec::with_capacity(68);
    calldata.extend_from_slice(&TRANSFER_SELECTOR);
    calldata.extend_from_slice(&to_addr);
    calldata.extend_from_slice(&raw_amount.to_le_bytes()); // 16 bytes LE
    calldata.extend_from_slice(&[0u8; 16]);                // pad to 32

    let nonce = state.node_client.get_nonce(&rpc_address).await?;
    let chain_id = state.node_client.get_chain_id().await?;
    let node_info = state.node_client.node_info().await?;
    let num_shards = node_info["num_shards"].as_u64().unwrap_or(1000) as u16;

    let (tx_hex, tx_hash) = build_signed_transaction_with_data(
        &keypair,
        TransactionType::ContractCall,
        contract_addr,
        0,
        calldata,
        1_000_000,
        nonce,
        chain_id,
        num_shards,
    )?;

    let _ = state.node_client.send_raw_transaction(&tx_hex).await?;

    tracing::info!(
        "Token transfer: from={}, to={}, amount={} QTEST, tx={}",
        &rpc_address[..20], &req.to[..std::cmp::min(20, req.to.len())], req.amount, tx_hash
    );

    Ok(Json(json!({
        "tx_hash": tx_hash,
        "status": "success",
        "token": "QTEST",
        "amount": req.amount
    })))
}

async fn bridge_approve(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BridgeApproveRequest>,
) -> Result<impl IntoResponse, WalletError> {
    let vault_address = configured_bridge_vault(&state, req.vault_address.as_deref())?;
    let qtest_contract = fetch_bridge_vault_token_address(&state, &vault_address).await?;
    let session = state.sessions.get_session(&req.session_token)?;
    let keypair = DilithiumKeypair::from_sk_and_pk_hex(&session.secret_key_hex, &session.public_key_hex)?;
    let amount = parse_token_amount(&req.amount, 18)?;
    if amount == 0 {
        return Err(WalletError::InvalidAmount("Amount must be > 0".into()));
    }

    tracing::info!(
        caller = %format!("QTS:{}", hex::encode(keypair.address)),
        vault = %vault_address,
        token = %qtest_contract,
        amount = %amount,
        amount_human = %req.amount,
        "bridge_approve: preparing approval"
    );

    let mut calldata = Vec::with_capacity(68);
    calldata.extend_from_slice(&APPROVE_SELECTOR);
    calldata.extend_from_slice(&parse_address(&vault_address)?);
    calldata.extend_from_slice(&encode_uint256_le_32(amount));

    let tx_hash = submit_contract_call(&state, &keypair, &qtest_contract, calldata, 0).await?;
    let receipt = fetch_receipt_by_tx_hash(&state, &tx_hash).await?;

    Ok(Json(json!({
        "tx_hash": tx_hash,
        "status": "confirmed",
        "token": "QTEST",
        "vault_address": vault_address,
        "amount": req.amount,
        "receipt": receipt,
    })))
}

async fn bridge_deposit(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BridgeDepositRequest>,
) -> Result<impl IntoResponse, WalletError> {
    let vault_address = configured_bridge_vault(&state, req.vault_address.as_deref())?;
    let qtest_contract = fetch_bridge_vault_token_address(&state, &vault_address).await?;
    let session = state.sessions.get_session(&req.session_token)?;
    let keypair = DilithiumKeypair::from_sk_and_pk_hex(&session.secret_key_hex, &session.public_key_hex)?;
    let amount = parse_token_amount(&req.amount, 18)?;
    if amount == 0 {
        return Err(WalletError::InvalidAmount("Amount must be > 0".into()));
    }
    let base_recipient = parse_bytes32_hex(&req.base_recipient)?;
    let rpc_address = format!("QTS:{}", hex::encode(keypair.address));

    let sender_balance = fetch_qtest_balance(&state, &qtest_contract, &rpc_address, &keypair.address).await;
    let sender_allowance = fetch_qtest_allowance(&state, &qtest_contract, &rpc_address, &keypair.address, &vault_address).await;

    tracing::info!(
        caller = %rpc_address,
        vault = %vault_address,
        token = %qtest_contract,
        amount = %amount,
        amount_human = %req.amount,
        balance = %sender_balance,
        allowance = %sender_allowance,
        base_recipient = %normalize_bytes32_hex(&base_recipient),
        "bridge_deposit: preflight"
    );

    if sender_balance < amount {
        return Err(WalletError::InvalidAmount(format!(
            "Insufficient QTEST balance for bridge deposit: have {}, need {}",
            format_token(sender_balance, 18, 2, "QTEST"),
            format_token(amount, 18, 2, "QTEST")
        )));
    }

    if sender_allowance < amount {
        return Err(WalletError::TransactionFailed(format!(
            "Bridge vault allowance too low: approved {}, need {}. Approve the bridge vault before depositing.",
            format_token(sender_allowance, 18, 2, "QTEST"),
            format_token(amount, 18, 2, "QTEST")
        )));
    }

    // Call vault.deposit(baseRecipient, amount) which internally does transferFrom
    // User must have approved the vault beforehand via /bridge/approve
    let mut calldata = Vec::with_capacity(68);
    calldata.extend_from_slice(&BRIDGE_DEPOSIT_SELECTOR);
    calldata.extend_from_slice(&base_recipient);
    calldata.extend_from_slice(&encode_uint256_le_32(amount));

    let tx_hash = submit_contract_call(&state, &keypair, &vault_address, calldata, 0).await?;
    let receipt = fetch_receipt_by_tx_hash(&state, &tx_hash).await?;

    tracing::info!(
        "Bridge deposit: sender={}, vault={}, amount={}, base_recipient={}",
        format!("QTS:{}", hex::encode(keypair.address)),
        vault_address,
        req.amount,
        normalize_bytes32_hex(&base_recipient),
    );

    Ok(Json(json!({
        "tx_hash": tx_hash,
        "status": "confirmed",
        "vault_address": vault_address,
        "amount": req.amount,
        "base_recipient": normalize_bytes32_hex(&base_recipient),
        "receipt": receipt,
    })))
}

async fn bridge_release(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BridgeReleaseRequest>,
) -> Result<impl IntoResponse, WalletError> {
    let vault_address = configured_bridge_vault(&state, req.vault_address.as_deref())?;
    let session = state.sessions.get_session(&req.session_token)?;
    let keypair = DilithiumKeypair::from_sk_and_pk_hex(&session.secret_key_hex, &session.public_key_hex)?;
    let amount = parse_token_amount(&req.amount, 18)?;
    if amount == 0 {
        return Err(WalletError::InvalidAmount("Amount must be > 0".into()));
    }

    let mut calldata = Vec::with_capacity(100);
    calldata.extend_from_slice(&BRIDGE_RELEASE_SELECTOR);
    calldata.extend_from_slice(&parse_bytes32_hex(&req.release_id)?);
    calldata.extend_from_slice(&parse_address(&req.to)?);
    calldata.extend_from_slice(&encode_uint256_le_32(amount));

    let tx_hash = submit_contract_call(&state, &keypair, &vault_address, calldata, 0).await?;
    let receipt = fetch_receipt_by_tx_hash(&state, &tx_hash).await?;

    Ok(Json(json!({
        "tx_hash": tx_hash,
        "status": "confirmed",
        "vault_address": vault_address,
        "to": req.to,
        "amount": req.amount,
        "receipt": receipt,
    })))
}

async fn bridge_receipt(
    State(state): State<Arc<AppState>>,
    Path(tx_hash): Path<String>,
) -> Result<impl IntoResponse, WalletError> {
    let receipt = fetch_receipt_by_tx_hash(&state, &tx_hash).await?;
    Ok(Json(receipt))
}

// ── POST /wallet/sign ─────────────────────────────────────────────────────────

async fn sign_message(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SignMessageRequest>,
) -> Result<impl IntoResponse, WalletError> {
    let session = state.sessions.get_session(&req.session_token)?;
    let keypair = DilithiumKeypair::from_sk_and_pk_hex(&session.secret_key_hex, &session.public_key_hex)?;

    let message_bytes = if req.message.starts_with("0x") || req.message.starts_with("0X") {
        hex::decode(&req.message[2..])
            .map_err(|e| WalletError::InvalidAddress(format!("Bad hex message: {}", e)))?
    } else {
        req.message.as_bytes().to_vec()
    };

    let sig = keypair.sign(&message_bytes)?;

    Ok(Json(json!({
        "message": req.message,
        "signature_hex": hex::encode(&sig),
        "public_key_hex": hex::encode(&keypair.public_key),
        "address": hex::encode(keypair.address),
    })))
}

// ── GET /health ───────────────────────────────────────────────────────────────

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let node_connected = state.node_client.ping().await;
    Json(json!({
        "status": if node_connected { "ok" } else { "degraded" },
        "version": env!("CARGO_PKG_VERSION"),
        "node_connected": node_connected,
        "node_rpc_url": state.config.node_rpc_url,
    }))
}

// ── GET /node/info ────────────────────────────────────────────────────────────

async fn node_info(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, WalletError> {
    let info = state.node_client.node_info().await?;
    Ok(Json(info))
}

// ── POST /faucet/claim ───────────────────────────────────────────────────────
// Calls QTEST contract's claim() function on behalf of the authenticated user.
// The contract enforces 24h cooldown per address.

/// keccak256("claim()") first 4 bytes = 0x4e71d92d
const QTEST_CLAIM_SELECTOR: [u8; 4] = [0x4e, 0x71, 0xd9, 0x2d];

async fn faucet_claim(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FaucetClaimRequest>,
) -> Result<impl IntoResponse, WalletError> {
    let contract_address = state
        .config
        .qtest_contract_address
        .as_deref()
        .ok_or_else(|| WalletError::Internal("QTEST_CONTRACT_ADDRESS not configured".to_string()))?;

    let session = state.sessions.get_session(&req.session_token)?;
    let keypair = DilithiumKeypair::from_sk_and_pk_hex(&session.secret_key_hex, &session.public_key_hex)?;

    let rpc_address = format!("QTS:{}", hex::encode(keypair.address));

    let to = parse_address(contract_address)?;
    let calldata = QTEST_CLAIM_SELECTOR.to_vec();

    let nonce = state.node_client.get_nonce(&rpc_address).await?;
    let chain_id = state.node_client.get_chain_id().await?;
    let node_info = state.node_client.node_info().await?;
    let num_shards = node_info["num_shards"].as_u64().unwrap_or(1000) as u16;

    let (tx_hex, tx_hash) = build_signed_transaction_with_data(
        &keypair,
        TransactionType::ContractCall,
        to,
        0,
        calldata,
        1_000_000,
        nonce,
        chain_id,
        num_shards,
    )?;

    // Wait for receipt and verify success (instead of fire-and-forget)
    state.node_client.send_and_confirm(&tx_hex).await
        .map_err(|e| {
            let raw = e.to_string();
            let cleaned = raw
                .strip_prefix("Node RPC error: ")
                .unwrap_or(&raw)
                .strip_prefix("Transaction reverted: ")
                .unwrap_or_else(|| raw.strip_prefix("Node RPC error: ").unwrap_or(&raw));

            WalletError::TransactionFailed(format!("Faucet claim failed: {}", cleaned))
        })?;

    // Record claim only after confirmed success
    state.faucet_claims.insert(rpc_address.clone(), std::time::Instant::now());

    tracing::info!(
        "Faucet claim confirmed: address={}, tx_hash={}",
        rpc_address,
        tx_hash
    );

    Ok(Json(json!({
        "tx_hash": tx_hash,
        "status": "confirmed",
        "token": "QTEST",
        "amount": "1000000000000000000000",
        "amount_formatted": "1000 QTEST"
    })))
}

// ── GET /faucet/status/:address ──────────────────────────────────────────────
// Returns QTEST balance and cooldown status for an address.

async fn faucet_status(
    State(state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> Result<impl IntoResponse, WalletError> {
    let contract_address = state
        .config
        .qtest_contract_address
        .as_deref()
        .ok_or_else(|| WalletError::Internal("QTEST_CONTRACT_ADDRESS not configured".to_string()))?;

    // Return the contract address so clients know where QTEST lives
    Ok(Json(json!({
        "contract_address": contract_address,
        "token": "QTEST",
        "symbol": "QTEST",
        "decimals": 18,
        "claim_amount": "1000000000000000000000",
        "claim_amount_formatted": "1000 QTEST",
        "cooldown_seconds": 86400
    }))) 
}

// ══════════════════════════════════════════════════════════════════════════════
// ── QNS (Quantos Name Service) ──────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

/// Registration fee: 300 QTEST (18 decimals)
const QNS_REGISTRATION_FEE: u128 = 300 * 1_000_000_000_000_000_000;

// Keccak-256 selectors for QNS contract
const QNS_REGISTER_SELECTOR: [u8; 4] = [0xf2, 0xc2, 0x98, 0xbe];   // register(string)
const QNS_RENEW_SELECTOR: [u8; 4] = [0xa4, 0xa9, 0xa6, 0x12];      // renew(string)
const QNS_SET_PRIMARY_SELECTOR: [u8; 4] = [0x78, 0x55, 0x0b, 0x91]; // setReverseRecord(string)
const QNS_RESOLVE_SELECTOR: [u8; 4] = [0x46, 0x1a, 0x44, 0x78];    // resolve(string)
const QNS_REVERSE_SELECTOR: [u8; 4] = [0x9a, 0xf8, 0xb7, 0xaa];    // reverseResolve(address)
const QNS_GET_DOMAIN_SELECTOR: [u8; 4] = [0xec, 0xdd, 0x04, 0xda]; // getDomain(string)
const QNS_IS_AVAILABLE_SELECTOR: [u8; 4] = [0x96, 0x53, 0x06, 0xaa]; // isAvailable(string)
const QNS_NAME_OF_SELECTOR: [u8; 4] = [0x05, 0x1a, 0x26, 0x64];    // nameOf(uint256)
const QNS_BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31]; // balanceOf(address)
const QNS_OWNER_OF_SELECTOR: [u8; 4] = [0x63, 0x52, 0x21, 0x1e];   // ownerOf(uint256)
const QNS_TOTAL_SUPPLY_SELECTOR: [u8; 4] = [0x18, 0x16, 0x0d, 0xdd]; // totalSupply()

/// Encode a string argument for Solang (Polkadot target) using SCALE codec.
/// SCALE string = compact-encoded length + raw bytes, NO padding.
fn abi_encode_string(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut encoded = Vec::new();
    // SCALE compact encoding for length
    let len = bytes.len();
    if len < 64 {
        // Single-byte mode: value << 2
        encoded.push((len as u8) << 2);
    } else if len < 16384 {
        // Two-byte mode: (value << 2) | 0b01
        let v = ((len as u16) << 2) | 0b01;
        encoded.extend_from_slice(&v.to_le_bytes());
    } else {
        // Four-byte mode: (value << 2) | 0b10
        let v = ((len as u32) << 2) | 0b10;
        encoded.extend_from_slice(&v.to_le_bytes());
    }
    encoded.extend_from_slice(bytes);
    encoded
}

/// Build calldata: selector + abi_encode_string(name)
fn qns_string_calldata(selector: &[u8; 4], name: &str) -> Vec<u8> {
    let mut calldata = Vec::new();
    calldata.extend_from_slice(selector);
    calldata.extend_from_slice(&abi_encode_string(name));
    calldata
}

/// Build calldata: selector + uint256(tokenId) LE-encoded
fn qns_uint256_calldata(selector: &[u8; 4], value: u128) -> Vec<u8> {
    let mut calldata = Vec::new();
    calldata.extend_from_slice(selector);
    calldata.extend_from_slice(&value.to_le_bytes()); // 16 bytes LE
    calldata.extend_from_slice(&[0u8; 16]);            // pad to 32 bytes
    calldata
}

/// Decode a SCALE-encoded string from contract return hex.
fn decode_scale_string(hex_result: &str) -> Option<String> {
    let hex = hex_result
        .strip_prefix("qts:")
        .or_else(|| hex_result.strip_prefix("QTS:"))
        .unwrap_or(hex_result);
    let bytes = hex::decode(hex).ok()?;
    if bytes.is_empty() {
        return None;
    }
    // SCALE compact length prefix
    let (len, offset) = match bytes[0] & 0b11 {
        0b00 => ((bytes[0] >> 2) as usize, 1usize),
        0b01 => {
            if bytes.len() < 2 { return None; }
            let v = u16::from_le_bytes([bytes[0], bytes[1]]);
            ((v >> 2) as usize, 2usize)
        }
        0b10 => {
            if bytes.len() < 4 { return None; }
            let v = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            ((v >> 2) as usize, 4usize)
        }
        _ => return None,
    };
    if offset + len > bytes.len() || len == 0 {
        return None;
    }
    String::from_utf8(bytes[offset..offset + len].to_vec()).ok()
}

/// Decode a LE uint256 from hex result. Handles both 32-byte and short SCALE returns.
fn decode_le_u128(hex_result: &str) -> u128 {
    let hex = hex_result
        .strip_prefix("qts:")
        .or_else(|| hex_result.strip_prefix("QTS:"))
        .unwrap_or(hex_result);
    let bytes = hex::decode(hex).unwrap_or_default();
    if bytes.is_empty() {
        return 0;
    }
    // Pad to 16 bytes LE
    let mut buf = [0u8; 16];
    let copy_len = bytes.len().min(16);
    buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
    u128::from_le_bytes(buf)
}

/// Decode a 32-byte address from hex result. Pads short results to 32 bytes.
fn decode_address_result(hex_result: &str) -> String {
    let hex = hex_result
        .strip_prefix("qts:")
        .or_else(|| hex_result.strip_prefix("QTS:"))
        .unwrap_or(hex_result);
    let bytes = hex::decode(hex).unwrap_or_default();
    if bytes.len() >= 32 {
        hex::encode(&bytes[..32])
    } else {
        // Pad short SCALE return to 32 bytes
        let mut padded = vec![0u8; 32];
        padded[..bytes.len()].copy_from_slice(&bytes);
        hex::encode(&padded)
    }
}

fn decode_qns_domain_result(hex_result: &str) -> WalletResult<(String, String, u128, u128, bool)> {
    let hex = hex_result
        .strip_prefix("qts:")
        .or_else(|| hex_result.strip_prefix("QTS:"))
        .unwrap_or(hex_result);
    let bytes = hex::decode(hex)
        .map_err(|e| WalletError::NodeRpcError(format!("Bad QNS domain result hex: {}", e)))?;

    if bytes.len() < 128 {
        return Err(WalletError::NodeRpcError(format!(
            "QNS getDomain returned {} bytes, expected at least 128",
            bytes.len()
        )));
    }

    let owner = hex::encode(&bytes[0..32]);
    let resolver = hex::encode(&bytes[32..64]);
    let raw_expiry = u128::from_le_bytes(bytes[64..80].try_into().unwrap_or([0; 16]));
    let token_id = u128::from_le_bytes(bytes[96..112].try_into().unwrap_or([0; 16]));

    // Normalize expiry: legacy domains may have expiry stored in milliseconds
    // (any value > 100 billion is definitely ms, since that's year 5138 in seconds)
    let expiry = if raw_expiry > 100_000_000_000 { raw_expiry / 1000 } else { raw_expiry };

    // Server-side is_expired: override contract's potentially buggy flag
    // with a real Unix timestamp comparison
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as u128;
    let is_expired = if expiry > 0 { now_secs >= expiry } else { false };

    Ok((owner, resolver, expiry, token_id, is_expired))
}

/// Validate a .qts domain name
fn validate_domain_name(name: &str) -> WalletResult<String> {
    let name = name.to_lowercase().trim().to_string();
    if !name.ends_with(".qts") {
        return Err(WalletError::InvalidAddress("Domain must end with .qts".into()));
    }
    let label = name.strip_suffix(".qts").unwrap();
    if label.is_empty() || label.len() < 3 {
        return Err(WalletError::InvalidAddress("Domain label must be at least 3 characters".into()));
    }
    if label.len() > 63 {
        return Err(WalletError::InvalidAddress("Domain label too long (max 63 chars)".into()));
    }
    if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(WalletError::InvalidAddress("Domain label can only contain a-z, 0-9, -, _".into()));
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(WalletError::InvalidAddress("Domain label cannot start or end with -".into()));
    }
    Ok(name)
}

fn get_qns_address(state: &AppState) -> WalletResult<String> {
    state.config.qns_contract_address.clone()
        .ok_or_else(|| WalletError::Internal("QNS_CONTRACT_ADDRESS not configured".into()))
}

/// Resolve a `.qts` domain name to a 32-byte address via the QNS contract.
/// If the input doesn't end with `.qts`, returns None (caller should use parse_address).
async fn resolve_qts_name_if_needed(state: &Arc<AppState>, recipient: &str) -> WalletResult<Option<[u8; 32]>> {
    let trimmed = recipient.trim().to_lowercase();
    if !trimmed.ends_with(".qts") {
        return Ok(None);
    }
    let qns_addr_str = get_qns_address(state)?;
    let domain = validate_domain_name(&trimmed)?;
    let calldata = hex::encode(qns_string_calldata(&QNS_RESOLVE_SELECTOR, &domain));
    let result = state.node_client
        .contract_call(&qns_addr_str, &format!("0x{}", calldata), None)
        .await?;
    let resolved = decode_address_result(&result);
    let zero = "0".repeat(64);
    if resolved == zero {
        return Err(WalletError::InvalidAddress(format!("Domain '{}' not registered or expired", domain)));
    }
    let bytes = hex::decode(&resolved)
        .map_err(|_| WalletError::Internal("Failed to decode resolved address".into()))?;
    let addr: [u8; 32] = bytes.try_into()
        .map_err(|_| WalletError::Internal("Resolved address is not 32 bytes".into()))?;
    tracing::info!("QNS resolved '{}' -> QTS:{}", domain, resolved);
    Ok(Some(addr))
}

fn get_qtest_address(state: &AppState) -> WalletResult<String> {
    state.config.qtest_contract_address.clone()
        .ok_or_else(|| WalletError::Internal("QTEST_CONTRACT_ADDRESS not configured".into()))
}

// ── POST /qns/register ──────────────────────────────────────────────────────
// Registers a .qts domain. Pays 300 QTEST, then calls register(string).

#[derive(serde::Deserialize)]
struct QnsRegisterRequest {
    session_token: String,
    domain_name: String,
}

async fn qns_register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<QnsRegisterRequest>,
) -> Result<impl IntoResponse, WalletError> {
    let qns_addr_str = get_qns_address(&state)?;
    let qtest_addr_str = get_qtest_address(&state)?;
    let domain = validate_domain_name(&req.domain_name)?;

    let session = state.sessions.get_session(&req.session_token)?;
    let keypair = DilithiumKeypair::from_sk_and_pk_hex(&session.secret_key_hex, &session.public_key_hex)?;
    let rpc_address = format!("QTS:{}", hex::encode(keypair.address));

    let qns_addr = parse_address(&qns_addr_str)?;
    let qtest_addr = parse_address(&qtest_addr_str)?;

    // 1. Check domain availability via getDomain + server-side expiry check
    let avail_calldata = hex::encode(qns_string_calldata(&QNS_GET_DOMAIN_SELECTOR, &domain));
    let avail_result = state.node_client
        .contract_call(&qns_addr_str, &format!("0x{}", avail_calldata), Some(&rpc_address))
        .await?;
    let is_available = match decode_qns_domain_result(&avail_result) {
        Ok((owner, _, _, _, is_expired)) => {
            let zero = "0".repeat(64);
            owner == zero || is_expired
        }
        Err(_) => true,
    };
    if !is_available {
        return Err(WalletError::InvalidAddress(format!("Domain '{}' is already taken", domain)));
    }

    // 2. Check QTEST balance
    let sender_hex = hex::encode(keypair.address);
    let balance_calldata = format!("0x70a08231{}", sender_hex);
    let balance_result = state.node_client
        .contract_call(&qtest_addr_str, &balance_calldata, Some(&rpc_address))
        .await
        .unwrap_or_default();
    let balance = decode_le_u128(&balance_result);
    if balance < QNS_REGISTRATION_FEE {
        return Err(WalletError::InvalidAmount(format!(
            "Insufficient QTEST: have {}, need 300 QTEST",
            format_token(balance, 18, 2, "QTEST")
        )));
    }

    // 3. Transfer 300 QTEST to QNS contract
    let mut transfer_calldata = Vec::with_capacity(68);
    transfer_calldata.extend_from_slice(&TRANSFER_SELECTOR);
    transfer_calldata.extend_from_slice(&qns_addr);
    transfer_calldata.extend_from_slice(&QNS_REGISTRATION_FEE.to_le_bytes());
    transfer_calldata.extend_from_slice(&[0u8; 16]);

    let nonce = state.node_client.get_nonce(&rpc_address).await?;
    let chain_id = state.node_client.get_chain_id().await?;
    let node_info = state.node_client.node_info().await?;
    let num_shards = node_info["num_shards"].as_u64().unwrap_or(1000) as u16;

    let (tx1_hex, tx1_hash) = build_signed_transaction_with_data(
        &keypair,
        TransactionType::ContractCall,
        qtest_addr,
        0,
        transfer_calldata,
        1_000_000,
        nonce,
        chain_id,
        num_shards,
    )?;
    // Wait for TX1 to confirm before sending TX2
    let tx1_confirmed = state.node_client.send_and_confirm(&tx1_hex).await;
    if let Err(e) = &tx1_confirmed {
        tracing::error!("QNS payment TX failed: {} — domain={}, addr={}", e, domain, &rpc_address);
        return Err(WalletError::NodeRpcError(format!("QTEST payment failed: {}", e)));
    }

    // 4. Call QNS.register(domain)
    let register_calldata = qns_string_calldata(&QNS_REGISTER_SELECTOR, &domain);

    // Fetch fresh nonce after TX1 to be absolutely certain
    let nonce_tx2 = state.node_client.get_nonce(&rpc_address).await?;

    let (tx2_hex, tx2_hash) = build_signed_transaction_with_data(
        &keypair,
        TransactionType::ContractCall,
        qns_addr,
        0,
        register_calldata,
        2_000_000,
        nonce_tx2,
        chain_id,
        num_shards,
    )?;
    // Wait for TX2 to confirm
    let tx2_confirmed = state.node_client.send_and_confirm(&tx2_hex).await;
    if let Err(e) = &tx2_confirmed {
        tracing::error!("QNS register TX failed: {} — domain={}, addr={}", e, domain, &rpc_address);
        return Err(WalletError::NodeRpcError(format!("Domain registration failed: {}", e)));
    }

    tracing::info!("QNS registered: {} by {}", domain, &rpc_address);

    Ok(Json(json!({
        "domain": domain,
        "owner": rpc_address,
        "payment_tx": tx1_hash,
        "register_tx": tx2_hash,
        "fee": "300 QTEST",
        "expires_in_days": 365,
        "status": "registered"
    })))
}

// ── POST /qns/renew ─────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct QnsRenewRequest {
    session_token: String,
    domain_name: String,
}

#[derive(serde::Deserialize)]
struct QnsSetPrimaryRequest {
    session_token: String,
    domain_name: String,
}

async fn qns_renew(
    State(state): State<Arc<AppState>>,
    Json(req): Json<QnsRenewRequest>,
) -> Result<impl IntoResponse, WalletError> {
    let qns_addr_str = get_qns_address(&state)?;
    let qtest_addr_str = get_qtest_address(&state)?;
    let domain = validate_domain_name(&req.domain_name)?;

    let session = state.sessions.get_session(&req.session_token)?;
    let keypair = DilithiumKeypair::from_sk_and_pk_hex(&session.secret_key_hex, &session.public_key_hex)?;
    let rpc_address = format!("QTS:{}", hex::encode(keypair.address));

    let qns_addr = parse_address(&qns_addr_str)?;
    let qtest_addr = parse_address(&qtest_addr_str)?;

    // Pay 300 QTEST
    let mut transfer_calldata = Vec::with_capacity(68);
    transfer_calldata.extend_from_slice(&TRANSFER_SELECTOR);
    transfer_calldata.extend_from_slice(&qns_addr);
    transfer_calldata.extend_from_slice(&QNS_REGISTRATION_FEE.to_le_bytes());
    transfer_calldata.extend_from_slice(&[0u8; 16]);

    let nonce = state.node_client.get_nonce(&rpc_address).await?;
    let chain_id = state.node_client.get_chain_id().await?;
    let node_info = state.node_client.node_info().await?;
    let num_shards = node_info["num_shards"].as_u64().unwrap_or(1000) as u16;

    let (tx1_hex, tx1_hash) = build_signed_transaction_with_data(
        &keypair,
        TransactionType::ContractCall,
        qtest_addr,
        0,
        transfer_calldata,
        1_000_000,
        nonce,
        chain_id,
        num_shards,
    )?;
    // Wait for TX1 to confirm before sending TX2
    let tx1_confirmed = state.node_client.send_and_confirm(&tx1_hex).await;
    if let Err(e) = &tx1_confirmed {
        tracing::error!("QNS renew payment TX failed: {} — domain={}, addr={}", e, domain, &rpc_address);
        return Err(WalletError::NodeRpcError(format!("QTEST payment failed: {}", e)));
    }

    // Call QNS.renew(domain)
    let renew_calldata = qns_string_calldata(&QNS_RENEW_SELECTOR, &domain);

    let (tx2_hex, tx2_hash) = build_signed_transaction_with_data(
        &keypair,
        TransactionType::ContractCall,
        qns_addr,
        0,
        renew_calldata,
        2_000_000,
        nonce + 1,
        chain_id,
        num_shards,
    )?;
    // Wait for TX2 to confirm
    let tx2_confirmed = state.node_client.send_and_confirm(&tx2_hex).await;
    if let Err(e) = &tx2_confirmed {
        tracing::error!("QNS renew TX failed: {} — domain={}, addr={}", e, domain, &rpc_address);
        return Err(WalletError::NodeRpcError(format!("Domain renewal failed: {}", e)));
    }

    tracing::info!("QNS renewed: {} by {}", domain, &rpc_address);

    Ok(Json(json!({
        "domain": domain,
        "payment_tx": tx1_hash,
        "renew_tx": tx2_hash,
        "fee": "300 QTEST",
        "extended_days": 365,
        "status": "renewed"
    })))
}

async fn qns_set_primary(
    State(state): State<Arc<AppState>>,
    Json(req): Json<QnsSetPrimaryRequest>,
) -> Result<impl IntoResponse, WalletError> {
    let qns_addr_str = get_qns_address(&state)?;
    let domain = validate_domain_name(&req.domain_name)?;

    let session = state.sessions.get_session(&req.session_token)?;
    let keypair = DilithiumKeypair::from_sk_and_pk_hex(&session.secret_key_hex, &session.public_key_hex)?;
    let rpc_address = format!("QTS:{}", hex::encode(keypair.address));

    let qns_addr = parse_address(&qns_addr_str)?;
    let calldata = qns_string_calldata(&QNS_SET_PRIMARY_SELECTOR, &domain);

    let nonce = state.node_client.get_nonce(&rpc_address).await?;
    let chain_id = state.node_client.get_chain_id().await?;
    let node_info = state.node_client.node_info().await?;
    let num_shards = node_info["num_shards"].as_u64().unwrap_or(1000) as u16;

    let (tx_hex, tx_hash) = build_signed_transaction_with_data(
        &keypair,
        TransactionType::ContractCall,
        qns_addr,
        0,
        calldata,
        1_000_000,
        nonce,
        chain_id,
        num_shards,
    )?;

    let confirmed = state.node_client.send_and_confirm(&tx_hex).await;
    if let Err(e) = &confirmed {
        tracing::error!("QNS set primary TX failed: {} — domain={}, addr={}", e, domain, &rpc_address);
        return Err(WalletError::NodeRpcError(format!("Set primary failed: {}", e)));
    }

    tracing::info!("QNS primary set: {} by {}", domain, &rpc_address);

    Ok(Json(json!({
        "domain": domain,
        "tx_hash": tx_hash,
        "status": "primary_set"
    })))
}

// ── GET /qns/resolve/:name ──────────────────────────────────────────────────

async fn qns_resolve(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, WalletError> {
    let qns_addr_str = get_qns_address(&state)?;
    let domain = validate_domain_name(&name)?;

    let calldata = hex::encode(qns_string_calldata(&QNS_RESOLVE_SELECTOR, &domain));
    let result = state.node_client
        .contract_call(&qns_addr_str, &format!("0x{}", calldata), None)
        .await?;

    let resolved = decode_address_result(&result);
    let zero = "0".repeat(64);
    if resolved == zero {
        return Err(WalletError::InvalidAddress(format!("Domain '{}' not found or expired", domain)));
    }

    Ok(Json(json!({
        "domain": domain,
        "address": format!("QTS:{}", resolved),
        "qts_address": address_to_qts(&hex::decode(&resolved).unwrap_or_default().try_into().unwrap_or([0u8; 32]))
    })))
}

// ── GET /qns/reverse/:address ───────────────────────────────────────────────

async fn qns_reverse(
    State(state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> Result<impl IntoResponse, WalletError> {
    let qns_addr_str = get_qns_address(&state)?;
    let addr = parse_address(&address)?;
    let addr_hex = hex::encode(addr);

    let mut calldata = Vec::new();
    calldata.extend_from_slice(&QNS_REVERSE_SELECTOR);
    calldata.extend_from_slice(&addr);
    let calldata_hex = format!("0x{}", hex::encode(&calldata));

    let result = state.node_client
        .contract_call(&qns_addr_str, &calldata_hex, None)
        .await?;

    let name_hash = decode_address_result(&result);
    let zero = "0".repeat(64);
    if name_hash == zero {
        return Ok(Json(json!({ "address": format!("QTS:{}", addr_hex), "domain": null })));
    }

    // Scan token IDs to find the one matching this nameHash, then get its name
    let domain_name = scan_token_for_name_hash(&state, &qns_addr_str, &name_hash).await;

    Ok(Json(json!({
        "address": format!("QTS:{}", addr_hex),
        "name_hash": name_hash,
        "domain": domain_name
    })))
}

/// Scan token IDs 0..max to find a token whose nameHash matches, then return its name via nameOf.
async fn scan_token_for_name_hash(
    state: &Arc<AppState>,
    qns_addr_str: &str,
    target_name_hash: &str,
) -> Option<String> {
    // Get totalSupply to bound the scan
    let ts_calldata = format!("0x{}", hex::encode(QNS_TOTAL_SUPPLY_SELECTOR));
    let ts_result = state.node_client
        .contract_call(qns_addr_str, &ts_calldata, None)
        .await
        .unwrap_or_default();
    let total_supply = decode_le_u128(&ts_result) as u64;
    // nextTokenId >= totalSupply; scan up to totalSupply + some margin for burned tokens
    let max_scan = (total_supply + 50).min(500);

    for token_id in 0..max_scan {
        // Call nameOf(tokenId) — if it returns a name, compute its keccak hash and compare
        let name_calldata = qns_uint256_calldata(&QNS_NAME_OF_SELECTOR, token_id as u128);
        let name_result = state.node_client
            .contract_call(qns_addr_str, &format!("0x{}", hex::encode(&name_calldata)), None)
            .await;
        if let Ok(ref result) = name_result {
            if let Some(name) = decode_scale_string(result) {
                if !name.is_empty() {
                    // Compute keccak256 of the name and compare with target
                    use sha3::{Digest, Keccak256};
                    let hash = Keccak256::digest(name.as_bytes());
                    let hash_hex = hex::encode(hash);
                    if hash_hex == *target_name_hash {
                        return Some(name);
                    }
                }
            }
        }
    }
    None
}

// ── GET /qns/info/:name ─────────────────────────────────────────────────────

async fn qns_info(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, WalletError> {
    let qns_addr_str = get_qns_address(&state)?;
    let domain = validate_domain_name(&name)?;

    let calldata = hex::encode(qns_string_calldata(&QNS_GET_DOMAIN_SELECTOR, &domain));
    let result = state.node_client
        .contract_call(&qns_addr_str, &format!("0x{}", calldata), None)
        .await?;

    let (owner, resolver, expiry, token_id, is_expired) = decode_qns_domain_result(&result)?;

    let zero = "0".repeat(64);
    if owner == zero {
        return Ok(Json(json!({
            "domain": domain,
            "registered": false,
            "available": true
        })));
    }

    Ok(Json(json!({
        "domain": domain,
        "registered": true,
        "available": is_expired,
        "owner": format!("QTS:{}", owner),
        "resolver": format!("QTS:{}", resolver),
        "expiry_timestamp": expiry,
        "token_id": token_id,
        "is_expired": is_expired
    })))
}

// ── GET /qns/available/:name ────────────────────────────────────────────────

async fn qns_available(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, WalletError> {
    let qns_addr_str = get_qns_address(&state)?;
    let domain = validate_domain_name(&name)?;

    // Use getDomain + server-side expiry check instead of contract's isAvailable
    // which can return wrong results for legacy domains with corrupted timestamps
    let calldata = hex::encode(qns_string_calldata(&QNS_GET_DOMAIN_SELECTOR, &domain));
    let result = state.node_client
        .contract_call(&qns_addr_str, &format!("0x{}", calldata), None)
        .await?;

    let available = match decode_qns_domain_result(&result) {
        Ok((owner, _, _, _, is_expired)) => {
            let zero = "0".repeat(64);
            owner == zero || is_expired
        }
        Err(_) => true, // If we can't decode, treat as available
    };

    Ok(Json(json!({
        "domain": domain,
        "available": available,
        "fee": "300 QTEST",
        "duration_days": 365
    })))
}

// ── GET /qns/owned/:address ─────────────────────────────────────────────────
// Scans token IDs to enumerate all domains owned by an address.

async fn qns_owned(
    State(state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> Result<impl IntoResponse, WalletError> {
    let qns_addr_str = get_qns_address(&state)?;
    let addr = parse_address(&address)?;
    let addr_hex = hex::encode(addr);

    // balanceOf(address) to get count of owned domain NFTs
    let calldata = format!("0x70a08231{}", hex::encode(addr));
    let result = state.node_client
        .contract_call(&qns_addr_str, &calldata, None)
        .await?;
    let count = decode_le_u128(&result) as u64;

    if count == 0 {
        return Ok(Json(json!({
            "address": format!("QTS:{}", addr_hex),
            "domain_count": 0,
            "domains": []
        })));
    }

    // Get totalSupply to bound the scan
    let ts_calldata = format!("0x{}", hex::encode(QNS_TOTAL_SUPPLY_SELECTOR));
    let ts_result = state.node_client
        .contract_call(&qns_addr_str, &ts_calldata, None)
        .await
        .unwrap_or_default();
    let total_supply = decode_le_u128(&ts_result) as u64;
    let max_scan = (total_supply + 50).min(500);

    let mut domains = Vec::new();
    let mut found: u64 = 0;

    for token_id in 0..max_scan {
        if found >= count {
            break;
        }
        // ownerOf(tokenId)
        let owner_calldata = qns_uint256_calldata(&QNS_OWNER_OF_SELECTOR, token_id as u128);
        let owner_result = state.node_client
            .contract_call(&qns_addr_str, &format!("0x{}", hex::encode(&owner_calldata)), None)
            .await;
        if let Ok(ref result) = owner_result {
            let owner = decode_address_result(result);
            if owner == addr_hex {
                // This token belongs to our address — get its name
                let name_calldata = qns_uint256_calldata(&QNS_NAME_OF_SELECTOR, token_id as u128);
                let name_result = state.node_client
                    .contract_call(&qns_addr_str, &format!("0x{}", hex::encode(&name_calldata)), None)
                    .await;
                if let Ok(ref nr) = name_result {
                    if let Some(name) = decode_scale_string(nr) {
                        if !name.is_empty() {
                            // Get domain info (expiry etc.) via getDomain
                            let info_calldata = hex::encode(qns_string_calldata(&QNS_GET_DOMAIN_SELECTOR, &name));
                            let info_result = state.node_client
                                .contract_call(&qns_addr_str, &format!("0x{}", info_calldata), None)
                                .await;
                            let (expiry, is_expired) = if let Ok(ref ir) = info_result {
                                match decode_qns_domain_result(ir) {
                                    Ok((_, _, exp, _, expired)) => (exp, expired),
                                    Err(_) => (0u128, false),
                                }
                            } else {
                                (0u128, false)
                            };

                            domains.push(json!({
                                "name": name,
                                "token_id": token_id,
                                "owner": format!("QTS:{}", addr_hex),
                                "expiry_timestamp": expiry,
                                "is_expired": is_expired
                            }));
                            found += 1;
                        }
                    }
                }
            }
        }
    }

    tracing::info!("QNS owned: {} domains for QTS:{}", domains.len(), &addr_hex);

    Ok(Json(json!({
        "address": format!("QTS:{}", addr_hex),
        "domain_count": domains.len(),
        "domains": domains
    })))
}

// ── POST /auth/challenge ─────────────────────────────────────────────────────
// Returns a random nonce for the given address. The client must sign it.

#[derive(serde::Deserialize)]
struct AuthChallengeRequest {
    address: String,
}

async fn auth_challenge(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuthChallengeRequest>,
) -> Result<impl IntoResponse, WalletError> {
    // Clean up expired challenges (> 5 min)
    let now = std::time::Instant::now();
    state.auth_challenges.retain(|_, v| now.duration_since(v.created_at).as_secs() < 300);

    // Generate random nonce
    let nonce = format!(
        "quantos-login:{}:{}",
        &req.address,
        hex::encode(rand::random::<[u8; 32]>())
    );

    state.auth_challenges.insert(
        nonce.clone(),
        crate::state::AuthChallenge {
            nonce: nonce.clone(),
            address: req.address.clone(),
            created_at: now,
        },
    );

    Ok(Json(json!({
        "nonce": nonce,
        "expires_in": 300
    })))
}

// ── POST /auth/verify ────────────────────────────────────────────────────────
// Verifies the Dilithium signature over the nonce, confirms address ownership.

#[derive(serde::Deserialize)]
struct AuthVerifyRequest {
    address: String,
    nonce: String,
    signature_hex: String,
    public_key_hex: String,
}

async fn auth_verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuthVerifyRequest>,
) -> Result<impl IntoResponse, WalletError> {
    // Look up and consume the challenge
    let challenge = state
        .auth_challenges
        .remove(&req.nonce)
        .map(|(_, v)| v)
        .ok_or_else(|| WalletError::InvalidAddress("Challenge not found or expired".into()))?;

    // Check TTL (5 min)
    if std::time::Instant::now().duration_since(challenge.created_at).as_secs() > 300 {
        return Err(WalletError::InvalidAddress("Challenge expired".into()));
    }

    // Verify the public key derives to the claimed address
    let pk_bytes = hex::decode(&req.public_key_hex)
        .map_err(|e| WalletError::CryptoError(format!("Bad PK hex: {}", e)))?;
    let derived_address = derive_address(&pk_bytes);
    let derived_hex = hex::encode(derived_address);

    let claimed = req.address
        .strip_prefix("QTS:")
        .or_else(|| req.address.strip_prefix("0x"))
        .unwrap_or(&req.address);
    if derived_hex != claimed {
        return Err(WalletError::InvalidAddress(
            "Public key does not match the claimed address".into(),
        ));
    }

    // Verify the Dilithium-3 signature over the nonce
    let valid = verify_dilithium_signature(
        req.nonce.as_bytes(),
        &req.signature_hex,
        &req.public_key_hex,
    )?;

    if !valid {
        return Err(WalletError::CryptoError("Invalid signature".into()));
    }

    tracing::info!("Auth verified for address={}", &req.address);

    Ok(Json(json!({
        "address": req.address,
        "qts_address": address_to_qts(&derived_address),
        "verified": true
    })))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_qts_hex(s: &str) -> u128 {
    let hex = s
        .strip_prefix("QTS:")
        .or_else(|| s.strip_prefix("0x"))
        .unwrap_or(s);
    u128::from_str_radix(hex, 16).unwrap_or(0)
}

fn normalize_rpc_address(address: &str) -> WalletResult<String> {
    if address.starts_with("QTS:") {
        return Ok(address.to_string());
    }
    if address.starts_with("qts1") {
        let addr = parse_address(address)?;
        return Ok(format!("QTS:{}", hex::encode(addr)));
    }
    Ok(format!("QTS:{}", address))
}

fn configured_bridge_vault(state: &Arc<AppState>, override_address: Option<&str>) -> WalletResult<String> {
    if let Some(address) = override_address {
        return normalize_rpc_address(address);
    }
    state
        .config
        .bridge_vault_contract_address
        .clone()
        .ok_or_else(|| WalletError::InvalidAddress("Bridge vault contract not configured".into()))
}

fn encode_uint256_le_32(value: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&value.to_le_bytes());
    out
}

fn parse_bytes32_hex(value: &str) -> WalletResult<[u8; 32]> {
    let cleaned = value
        .strip_prefix("QTS:")
        .or_else(|| value.strip_prefix("qts:"))
        .or_else(|| value.strip_prefix("0x"))
        .unwrap_or(value);

    let raw = hex::decode(cleaned)
        .map_err(|e| WalletError::InvalidAddress(format!("Bad hex value: {}", e)))?;

    match raw.len() {
        32 => raw.try_into().map_err(|_| WalletError::InvalidAddress("Invalid bytes32 value".into())),
        20 => {
            let mut out = [0u8; 32];
            out[12..].copy_from_slice(&raw);
            Ok(out)
        }
        _ => Err(WalletError::InvalidAddress("Expected 20-byte EVM address or 32-byte value".into())),
    }
}

fn normalize_bytes32_hex(value: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(value))
}

async fn fetch_contract_token_balance(
    state: &Arc<AppState>,
    contract_address: Option<&str>,
    rpc_address: &str,
    symbol: &str,
) -> (String, String) {
    let Some(contract_addr) = contract_address else {
        return ("0".to_string(), format!("0.00 {}", symbol));
    };

    let addr_hex = rpc_address.strip_prefix("QTS:").unwrap_or(rpc_address);
    let calldata = format!("0x70a08231{}", addr_hex);

    match state.node_client.contract_call(contract_addr, &calldata, Some(rpc_address)).await {
        Ok(result) => {
            let val = decode_le_uint128_from_contract_result(&result);
            (val.to_string(), format_token(val, 18, 2, symbol))
        }
        Err(e) => {
            tracing::warn!("{} balanceOf failed: {}", symbol, e);
            ("0".to_string(), format!("0.00 {}", symbol))
        }
    }
}

async fn upsert_contract_token_balance(
    entries: &mut Vec<Value>,
    state: &Arc<AppState>,
    contract_address: Option<&str>,
    rpc_address: &str,
    symbol: &str,
    name: &str,
) {
    let Some(contract_addr) = contract_address else {
        return;
    };

    let (balance, balance_formatted) = fetch_contract_token_balance(state, Some(contract_addr), rpc_address, symbol).await;
    let payload = json!({
        "token_address": contract_addr,
        "name": name,
        "symbol": symbol,
        "decimals": 18,
        "balance": balance,
        "balance_formatted": balance_formatted,
    });

    if let Some(existing) = entries.iter_mut().find(|entry| entry.get("symbol").and_then(|v| v.as_str()) == Some(symbol)) {
        *existing = payload;
    } else {
        entries.push(payload);
    }
}

fn decode_le_uint128_from_contract_result(result: &str) -> u128 {
    let hex = result
        .strip_prefix("qts:")
        .or_else(|| result.strip_prefix("QTS:"))
        .unwrap_or(result);

    if hex.is_empty() {
        return 0;
    }

    let bytes = hex::decode(hex).unwrap_or_default();
    let mut be_bytes = bytes.clone();
    be_bytes.reverse();
    let trimmed: Vec<u8> = be_bytes.iter().skip_while(|&&b| b == 0).cloned().collect();

    if trimmed.len() > 16 {
        return 0;
    }

    let mut buf = [0u8; 16];
    buf[16 - trimmed.len()..].copy_from_slice(&trimmed);
    u128::from_be_bytes(buf)
}

async fn submit_contract_call(
    state: &Arc<AppState>,
    keypair: &DilithiumKeypair,
    contract_address: &str,
    calldata: Vec<u8>,
    amount: u128,
) -> WalletResult<String> {
    let to = parse_address(contract_address)?;
    let rpc_address = format!("QTS:{}", hex::encode(keypair.address));
    let nonce = state.node_client.get_nonce(&rpc_address).await?;
    let chain_id = state.node_client.get_chain_id().await?;
    let node_info = state.node_client.node_info().await?;
    let num_shards = node_info["num_shards"].as_u64().unwrap_or(1000) as u16;
    let payload_len = calldata.len();
    let selector = if payload_len >= 4 {
        format!("0x{}", hex::encode(&calldata[..4]))
    } else {
        "0x".to_string()
    };

    let (tx_hex, tx_hash) = build_signed_transaction_with_data(
        keypair,
        TransactionType::ContractCall,
        to,
        amount,
        calldata,
        100_000_000,
        nonce,
        chain_id,
        num_shards,
    )?;

    tracing::info!(
        caller = %rpc_address,
        contract = %contract_address,
        tx_hash = %tx_hash,
        nonce = %nonce,
        gas_limit = 100_000_000u64,
        selector = %selector,
        calldata_len = %payload_len,
        "submit_contract_call: sending transaction"
    );

    state.node_client.send_and_confirm(&tx_hex).await
}

async fn fetch_receipt_by_tx_hash(state: &Arc<AppState>, tx_hash: &str) -> WalletResult<serde_json::Value> {
    let hash = tx_hash
        .strip_prefix("QTS:")
        .or_else(|| tx_hash.strip_prefix("qts:"))
        .unwrap_or(tx_hash);
    state.node_client.get_receipt(hash).await
}

async fn fetch_qtest_balance(
    state: &Arc<AppState>,
    contract_address: &str,
    rpc_address: &str,
    owner: &[u8; 32],
) -> u128 {
    let calldata = format!("0x70a08231{}", hex::encode(owner));

    match state.node_client.contract_call(contract_address, &calldata, Some(rpc_address)).await {
        Ok(result) => decode_le_u128(&result),
        Err(err) => {
            tracing::warn!(
                contract = %contract_address,
                owner = %rpc_address,
                error = %err,
                "fetch_qtest_balance: balanceOf failed"
            );
            0
        }
    }
}

async fn fetch_bridge_vault_token_address(
    state: &Arc<AppState>,
    vault_address: &str,
) -> WalletResult<String> {
    let calldata = format!("0x{}", hex::encode(TOKEN_SELECTOR));
    let result = state.node_client.contract_call(vault_address, &calldata, None).await?;
    Ok(format!("QTS:{}", decode_address_result(&result)))
}

async fn fetch_qtest_allowance(
    state: &Arc<AppState>,
    contract_address: &str,
    rpc_address: &str,
    owner: &[u8; 32],
    spender: &str,
) -> u128 {
    let spender_addr = match parse_address(spender) {
        Ok(addr) => addr,
        Err(err) => {
            tracing::warn!(spender = %spender, error = %err, "fetch_qtest_allowance: invalid spender address");
            return 0;
        }
    };

    let mut calldata = Vec::with_capacity(68);
    calldata.extend_from_slice(&ALLOWANCE_SELECTOR);
    calldata.extend_from_slice(owner);
    calldata.extend_from_slice(&spender_addr);
    let calldata_hex = format!("0x{}", hex::encode(calldata));

    match state.node_client.contract_call(contract_address, &calldata_hex, Some(rpc_address)).await {
        Ok(result) => decode_le_u128(&result),
        Err(err) => {
            tracing::warn!(
                contract = %contract_address,
                owner = %rpc_address,
                spender = %spender,
                error = %err,
                "fetch_qtest_allowance: allowance failed"
            );
            0
        }
    }
}
