//! # Quantos Prometheus Metrics
//!
//! Exposes a `/metrics` HTTP endpoint for Prometheus scraping.
//! Runs on a dedicated port (default 9615) separate from the JSON-RPC server.

use std::sync::Arc;
use std::time::Duration;

use prometheus::{
    Encoder, GaugeVec, IntGauge, IntGaugeVec, Registry, TextEncoder,
    Opts, opts, register_int_gauge_with_registry,
    register_int_gauge_vec_with_registry, register_gauge_vec_with_registry,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::{info, warn, error};

use crate::consensus::QuantosConsensus;
use crate::state::StateManager;

// ============================================================================
// Metrics Collector
// ============================================================================

/// Holds all Prometheus metric handles for the Quantos node.
#[derive(Clone)]
pub struct QuantosMetrics {
    pub registry: Registry,

    // -- Consensus --
    pub current_slot: IntGauge,
    pub current_epoch: IntGauge,
    pub finalized_slot: IntGauge,
    pub total_validators: IntGauge,

    // -- DAG --
    pub pending_vertices: IntGauge,
    pub confirmed_vertices: IntGauge,

    // -- Mempool --
    pub pending_transactions: IntGauge,

    // -- Node --
    pub uptime_seconds: IntGauge,
    pub num_shards: IntGauge,

    // -- Per-shard (labeled) --
    pub shard_pending_txs: IntGaugeVec,

    // -- RPC --
    pub rpc_requests_total: IntGauge,
    pub rpc_errors_total: IntGauge,
}

impl QuantosMetrics {
    pub fn new() -> Self {
        let registry = Registry::new_custom(Some("quantos".to_string()), None)
            .expect("Failed to create Prometheus registry");

        let current_slot = register_int_gauge_with_registry!(
            "consensus_current_slot", "Current consensus slot", registry
        ).unwrap();

        let current_epoch = register_int_gauge_with_registry!(
            "consensus_current_epoch", "Current consensus epoch", registry
        ).unwrap();

        let finalized_slot = register_int_gauge_with_registry!(
            "consensus_finalized_slot", "Last finalized slot", registry
        ).unwrap();

        let total_validators = register_int_gauge_with_registry!(
            "consensus_total_validators", "Total registered validators", registry
        ).unwrap();

        let pending_vertices = register_int_gauge_with_registry!(
            "dag_pending_vertices", "Pending DAG vertices", registry
        ).unwrap();

        let confirmed_vertices = register_int_gauge_with_registry!(
            "dag_confirmed_vertices", "Confirmed DAG vertices", registry
        ).unwrap();

        let pending_transactions = register_int_gauge_with_registry!(
            "mempool_pending_transactions", "Total pending transactions in mempool", registry
        ).unwrap();

        let uptime_seconds = register_int_gauge_with_registry!(
            "node_uptime_seconds", "Node uptime in seconds", registry
        ).unwrap();

        let num_shards = register_int_gauge_with_registry!(
            "node_num_shards", "Number of active shards", registry
        ).unwrap();

        let shard_pending_txs = register_int_gauge_vec_with_registry!(
            opts!("shard_pending_transactions", "Pending transactions per shard"),
            &["shard_id"],
            registry
        ).unwrap();

        let rpc_requests_total = register_int_gauge_with_registry!(
            "rpc_requests_total", "Total RPC requests received", registry
        ).unwrap();

        let rpc_errors_total = register_int_gauge_with_registry!(
            "rpc_errors_total", "Total RPC errors", registry
        ).unwrap();

        Self {
            registry,
            current_slot,
            current_epoch,
            finalized_slot,
            total_validators,
            pending_vertices,
            confirmed_vertices,
            pending_transactions,
            uptime_seconds,
            num_shards,
            shard_pending_txs,
            rpc_requests_total,
            rpc_errors_total,
        }
    }
}

// ============================================================================
// Metrics Update Loop
// ============================================================================

/// Spawns a background task that periodically updates Prometheus gauges
/// from the consensus engine and state manager.
pub fn spawn_metrics_updater(
    metrics: QuantosMetrics,
    consensus: QuantosConsensus,
    start_time: std::time::Instant,
    num_shards: usize,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;

            let m = consensus.get_metrics();

            metrics.current_slot.set(m.current_slot as i64);
            metrics.current_epoch.set(m.current_epoch as i64);
            metrics.finalized_slot.set(m.finalized_slot as i64);
            metrics.total_validators.set(m.total_validators as i64);
            metrics.pending_vertices.set(m.pending_vertices as i64);
            metrics.confirmed_vertices.set(m.confirmed_vertices as i64);
            metrics.pending_transactions.set(m.pending_transactions as i64);
            metrics.uptime_seconds.set(start_time.elapsed().as_secs() as i64);
            metrics.num_shards.set(num_shards as i64);

            // Update per-shard metrics (cap at 50 to avoid metric explosion)
            let max_report = num_shards.min(50);
            for shard_id in 0..max_report as u16 {
                let pending = consensus
                    .mempool()
                    .get_pending_for_shard(shard_id, 1)
                    .len();
                metrics
                    .shard_pending_txs
                    .with_label_values(&[&shard_id.to_string()])
                    .set(pending as i64);
            }
        }
    });
}

// ============================================================================
// Metrics HTTP Server
// ============================================================================

/// Starts a lightweight HTTP server on `port` that serves `/metrics`
/// in Prometheus text exposition format.
pub async fn serve_metrics(metrics: QuantosMetrics, port: u16) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    info!("Prometheus metrics server listening on {}", addr);

    loop {
        let (mut stream, _peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!("Metrics server accept error: {}", e);
                continue;
            }
        };

        let metrics = metrics.clone();
        tokio::spawn(async move {
            // Read the request (we only care about serving /metrics)
            let mut buf = [0u8; 1024];
            if let Err(e) = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                warn!("Metrics read error: {}", e);
                return;
            }

            let request = String::from_utf8_lossy(&buf);

            // Only respond to GET /metrics
            if request.starts_with("GET /metrics") {
                let encoder = TextEncoder::new();
                let metric_families = metrics.registry.gather();
                let mut body = Vec::new();
                if let Err(e) = encoder.encode(&metric_families, &mut body) {
                    error!("Metrics encode error: {}", e);
                    let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
                    let _ = stream.write_all(resp.as_bytes()).await;
                    return;
                }

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(&body).await;
            } else if request.starts_with("GET /health") || request.starts_with("GET / ") {
                let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok";
                let _ = stream.write_all(resp.as_bytes()).await;
            } else {
                let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });
    }
}
