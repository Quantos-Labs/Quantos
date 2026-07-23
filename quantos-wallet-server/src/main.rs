// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

// src/main.rs — Quantos Wallet Server entry point (stateless)

mod crypto;
mod error;
mod node_rpc;
mod routes;
mod session;
mod state;
mod types;

use anyhow::Result;
use axum::Router;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use crate::node_rpc::NodeRpcClient;
use crate::session::SessionStore;
use crate::state::AppState;

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: String,
    pub node_rpc_url: String,
    pub session_ttl_secs: u64,
    pub qtest_contract_address: Option<String>,
    pub sqtest_contract_address: Option<String>,
    pub sqtest_engine_contract_address: Option<String>,
    pub bridge_vault_contract_address: Option<String>,
    pub base_bridge_chain_id: Option<u64>,
    pub qns_contract_address: Option<String>,
}

impl Config {
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();
        Self {
            listen_addr: std::env::var("WALLET_LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:3001".to_string()),
            node_rpc_url: std::env::var("NODE_RPC_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8545".to_string()),
            session_ttl_secs: std::env::var("SESSION_TTL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1800), // 30 min
            qtest_contract_address: std::env::var("QTEST_CONTRACT_ADDRESS").ok(),
            sqtest_contract_address: std::env::var("SQTEST_CONTRACT_ADDRESS").ok(),
            sqtest_engine_contract_address: std::env::var("SQTEST_ENGINE_CONTRACT_ADDRESS").ok(),
            bridge_vault_contract_address: std::env::var("BRIDGE_VAULT_CONTRACT_ADDRESS").ok(),
            base_bridge_chain_id: std::env::var("BASE_BRIDGE_CHAIN_ID").ok().and_then(|s| s.parse().ok()),
            qns_contract_address: std::env::var("QNS_CONTRACT_ADDRESS").ok(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(true)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("  ██╗    ██╗ █████╗ ██╗     ██╗     ███████╗████████╗");
    info!("  ██║    ██║██╔══██╗██║     ██║     ██╔════╝╚══██╔══╝");
    info!("  ██║ █╗ ██║███████║██║     ██║     █████╗     ██║   ");
    info!("  ██║███╗██║██╔══██║██║     ██║     ██╔══╝     ██║   ");
    info!("  ╚███╔███╔╝██║  ██║███████╗███████╗███████╗   ██║   ");
    info!("   ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝   ╚═╝   ");
    info!("  Quantos Wallet Server v{} — stateless", env!("CARGO_PKG_VERSION"));

    let config = Config::from_env();
    let node_client = NodeRpcClient::new(config.node_rpc_url.clone());
    info!("✓ Node RPC → {}", config.node_rpc_url);
    info!("✓ QTEST contract → {:?}", config.qtest_contract_address);
    info!("✓ SQTEST contract → {:?}", config.sqtest_contract_address);
    info!("✓ SQTEST engine contract → {:?}", config.sqtest_engine_contract_address);
    info!("✓ Bridge vault contract → {:?}", config.bridge_vault_contract_address);
    info!("✓ Base bridge chain id → {:?}", config.base_bridge_chain_id);
    info!("✓ QNS contract → {:?}", config.qns_contract_address);

    let sessions = SessionStore::new(config.session_ttl_secs);
    info!("✓ Session store (TTL: {}s)", config.session_ttl_secs);

    // Cleanup expired sessions every minute
    let sessions_cleanup = sessions.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            sessions_cleanup.cleanup_expired();
        }
    });

    let state = Arc::new(AppState {
        node_client: Arc::new(node_client),
        sessions,
        config: config.clone(),
        faucet_claims: dashmap::DashMap::new(),
        pin_attempts: dashmap::DashMap::new(),
        auth_challenges: dashmap::DashMap::new(),
    });

    let app = routes::build_router(state)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(TraceLayer::new_for_http());

    info!("🚀 Listening on {}", config.listen_addr);
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
