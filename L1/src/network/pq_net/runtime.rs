// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Listener, outbound dials, and encrypted gossip fan-out.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use parking_lot::RwLock;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};

use crate::crypto::{MlDsa65Keypair, KemKeypair};
use crate::network::address::parse_quantos_multiaddr;
use crate::network::peer_manager::PeerManager;
use crate::network::peer_id::PeerId;
use crate::network::pq_net::handshake::{client_handshake, server_handshake, SecureTransport};
use crate::network::pq_net::session_crypto::{SessionDecrypt, SessionEncrypt, MAX_FRAME_PLAINTEXT};
use crate::network::protocol::{NetworkMessage, NetworkMetrics, PeerInfo};

const MAX_SEALED_FRAME: usize = MAX_FRAME_PLAINTEXT + 128;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_INBOUND_HANDSHAKES_PER_MINUTE_PER_IP: u32 = 30;

#[derive(Debug, Clone)]
pub enum PqCommand {
    Dial {
        socket: SocketAddr,
        expected_peer: PeerId,
    },
    Disconnect {
        peer_id: PeerId,
    },
    Publish {
        topic: [u8; 32],
        payload: Vec<u8>,
    },
}

#[derive(Clone)]
struct PeerConn {
    tx: mpsc::Sender<GossipEnvelope>,
    shutdown: broadcast::Sender<()>,
}

#[derive(Clone, Serialize, Deserialize)]
struct GossipEnvelope {
    topic: [u8; 32],
    payload: Vec<u8>,
}

fn multiaddr_for_peer(sock: SocketAddr, pid: PeerId) -> String {
    match sock.ip() {
        IpAddr::V4(v4) => format!("/ip4/{}/tcp/{}/p2p/{}", v4, sock.port(), pid),
        IpAddr::V6(v6) => format!("/ip6/{}/tcp/{}/p2p/{}", v6, sock.port(), pid),
    }
}

async fn timed_server_handshake(
    sock: &mut TcpStream,
    dil: &MlDsa65Keypair,
    kem: &KemKeypair,
) -> Result<SecureTransport, String> {
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, server_handshake(sock, dil, kem)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("server handshake timed out".into()),
    }
}

async fn timed_client_handshake(
    sock: &mut TcpStream,
    dil: &MlDsa65Keypair,
    kem: &KemKeypair,
    expected: PeerId,
) -> Result<SecureTransport, String> {
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, client_handshake(sock, dil, kem, expected)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("client handshake timed out".into()),
    }
}

fn allow_handshake(ip: IpAddr, now_ms: u64, state: &DashMap<IpAddr, (u64, u32)>) -> bool {
    // value = (window_start_ms, count)
    const WINDOW_MS: u64 = 60_000;
    match state.entry(ip) {
        Entry::Occupied(mut o) => {
            let (start, count) = *o.get();
            if now_ms.saturating_sub(start) >= WINDOW_MS {
                o.insert((now_ms, 1));
                true
            } else if count < MAX_INBOUND_HANDSHAKES_PER_MINUTE_PER_IP {
                o.insert((start, count + 1));
                true
            } else {
                false
            }
        }
        Entry::Vacant(v) => {
            v.insert((now_ms, 1));
            true
        }
    }
}

async fn write_loop(
    mut wr: tokio::net::tcp::OwnedWriteHalf,
    mut enc: SessionEncrypt,
    mut rx: mpsc::Receiver<GossipEnvelope>,
    mut shutdown: broadcast::Receiver<()>,
) {
    loop {
        let env = tokio::select! {
            _ = shutdown.recv() => { break; }
            v = rx.recv() => v,
        };
        let Some(env) = env else { break; };
        let Ok(plain) = bincode::serialize(&env) else { continue };
        let Ok(sealed) = enc.seal(&plain) else { break };
        if sealed.len() > MAX_SEALED_FRAME {
            continue;
        }
        let len = sealed.len() as u32;
        if wr.write_all(&len.to_le_bytes()).await.is_err() {
            break;
        }
        if wr.write_all(&sealed).await.is_err() {
            break;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn read_loop(
    mut rd: tokio::net::tcp::OwnedReadHalf,
    dec: SessionDecrypt,
    remote: PeerId,
    forward_tx: mpsc::Sender<NetworkMessage>,
    connected_peers: Arc<DashMap<PeerId, PeerInfo>>,
    metrics: Arc<RwLock<NetworkMetrics>>,
    subscribed_topics: Arc<RwLock<HashSet<[u8; 32]>>>,
    mut shutdown: broadcast::Receiver<()>,
    inbound_frames_rl: Arc<DashMap<PeerId, (u64, u32)>>,
) {
    loop {
        let mut lb = [0u8; 4];
        let got = tokio::select! {
            _ = shutdown.recv() => { return; }
            r = rd.read_exact(&mut lb) => r,
        };
        if got.is_err() { break; }
        let n = u32::from_le_bytes(lb) as usize;
        if n == 0 || n > MAX_SEALED_FRAME {
            break;
        }
        let mut buf = vec![0u8; n];
        let got = tokio::select! {
            _ = shutdown.recv() => { return; }
            r = rd.read_exact(&mut buf) => r,
        };
        if got.is_err() { break; }
        let plain = match dec.open(&buf) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let env: GossipEnvelope = match bincode::deserialize(&plain) {
            Ok(e) => e,
            Err(_) => continue,
        };

        // Per-peer inbound frame limiter (windowed)
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        const WINDOW_MS: u64 = 1_000;
        const MAX_FRAMES_PER_SECOND: u32 = 250;
        match inbound_frames_rl.entry(remote) {
            Entry::Occupied(mut o) => {
                let (start, cnt) = *o.get();
                if now_ms.saturating_sub(start) >= WINDOW_MS {
                    o.insert((now_ms, 1));
                } else if cnt < MAX_FRAMES_PER_SECOND {
                    o.insert((start, cnt + 1));
                } else {
                    metrics.write().messages_dropped += 1;
                    continue;
                }
            }
            Entry::Vacant(v) => {
                v.insert((now_ms, 1));
            }
        }

        if !subscribed_topics.read().contains(&env.topic) {
            continue;
        }
        match bincode::deserialize::<NetworkMessage>(&env.payload) {
            Ok(nm) => {
                metrics.write().bytes_received += env.payload.len() as u64;
                metrics.write().messages_received += 1;
                let _ = forward_tx.try_send(nm);
            }
            Err(_) => {}
        }
    }

    connected_peers.remove(&remote);
}

#[allow(clippy::too_many_arguments)]
async fn spawn_peer_tasks(
    sock: TcpStream,
    sec: SecureTransport,
    peers: Arc<DashMap<PeerId, PeerConn>>,
    peer_mgr: Arc<PeerManager>,
    forward_tx: mpsc::Sender<NetworkMessage>,
    connected_peers: Arc<DashMap<PeerId, PeerInfo>>,
    metrics: Arc<RwLock<NetworkMetrics>>,
    subscribed_topics: Arc<RwLock<HashSet<[u8; 32]>>>,
    peer_addr: Option<String>,
    inbound_frames_rl: Arc<DashMap<PeerId, (u64, u32)>>,
) {
    let remote = sec.remote_peer_id;

    if peer_mgr.is_banned(&remote) {
        tracing::warn!("rejecting PQ session from banned peer {}", remote);
        metrics.write().connections_failed += 1;
        return;
    }

    if !peer_mgr.add_peer(remote) {
        tracing::warn!("rejecting PQ session from {} (slots full or duplicate)", remote);
        metrics.write().connections_failed += 1;
        return;
    }

    let (tx, rx) = mpsc::channel::<GossipEnvelope>(512);
    let (sd_tx, _) = broadcast::channel::<()>(1);
    match peers.entry(remote) {
        Entry::Occupied(_) => {
            peer_mgr.remove_peer(&remote);
            tracing::debug!("reject duplicate PQ gossip slot for {}", remote);
            return;
        }
        Entry::Vacant(v) => {
            v.insert(PeerConn { tx, shutdown: sd_tx.clone() });
        }
    }

    let (mut rd, wr) = sock.into_split();
    let dec = sec.dec;
    let enc = sec.enc;

    let mut info = PeerInfo::new(remote);
    info.addr = peer_addr;
    connected_peers.insert(remote, info);
    metrics.write().connections_established += 1;
    metrics.write().peer_count = connected_peers.len();

    tokio::spawn(write_loop(wr, enc, rx, sd_tx.subscribe()));

    read_loop(
        rd,
        dec,
        remote,
        forward_tx,
        Arc::clone(&connected_peers),
        Arc::clone(&metrics),
        Arc::clone(&subscribed_topics),
        sd_tx.subscribe(),
        Arc::clone(&inbound_frames_rl),
    )
    .await;

    peers.remove(&remote);
    inbound_frames_rl.remove(&remote);
    peer_mgr.remove_peer(&remote);
    metrics.write().peer_count = connected_peers.len();
}

#[allow(clippy::too_many_arguments)]
pub async fn run_quantos_pq_p2p(
    listen_port: u16,
    bootstrap: Vec<String>,
    mldsa: MlDsa65Keypair,
    kem: KemKeypair,
    mut cmd_rx: mpsc::Receiver<PqCommand>,
    forward_tx: mpsc::Sender<NetworkMessage>,
    connected_peers: Arc<DashMap<PeerId, PeerInfo>>,
    metrics: Arc<RwLock<NetworkMetrics>>,
    subscribed_topics: Arc<RwLock<HashSet<[u8; 32]>>>,
    peer_manager: Arc<PeerManager>,
    mesh_n: usize,
) {
    let peers: Arc<DashMap<PeerId, PeerConn>> = Arc::new(DashMap::new());
    let max_peers = peer_manager.max_peers();
    let inbound_handshake_rl: Arc<DashMap<IpAddr, (u64, u32)>> = Arc::new(DashMap::new());
    let inbound_frames_rl: Arc<DashMap<PeerId, (u64, u32)>> = Arc::new(DashMap::new());

    let listener = match TcpListener::bind(("0.0.0.0", listen_port)).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("PQ P2P bind failed on {}: {}", listen_port, e);
            return;
        }
    };

    let dil_accept = mldsa.clone();
    let kem_accept = kem.clone();
    let peers_a = peers.clone();
    let fwd_a = forward_tx.clone();
    let cp_a = connected_peers.clone();
    let met_a = metrics.clone();
    let sub_a = subscribed_topics.clone();
    let pm_a = peer_manager.clone();
    let rl_a = inbound_handshake_rl.clone();
    let frames_a = inbound_frames_rl.clone();

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((sock, _addr)) => {
                    if peers_a.len() >= max_peers {
                        drop(sock);
                        continue;
                    }

                    let Ok(peer_addr) = sock.peer_addr() else {
                        drop(sock);
                        continue;
                    };
                    let now_ms = chrono::Utc::now().timestamp_millis() as u64;
                    if !allow_handshake(peer_addr.ip(), now_ms, &rl_a) {
                        drop(sock);
                        continue;
                    }

                    let dil = dil_accept.clone();
                    let kem = kem_accept.clone();
                    let peers_i = peers_a.clone();
                    let fwd = fwd_a.clone();
                    let cp = cp_a.clone();
                    let met = met_a.clone();
                    let sub = sub_a.clone();
                    let pm = pm_a.clone();
                    let frames = frames_a.clone();

                    tokio::spawn(async move {
                        let mut sock = sock;
                        match timed_server_handshake(&mut sock, &dil, &kem).await {
                            Ok(sec) => {
                                let remote = sec.remote_peer_id;
                                let peer_addr = sock.peer_addr().ok().map(|s| multiaddr_for_peer(s, remote));
                                spawn_peer_tasks(sock, sec, peers_i, pm, fwd, cp, met, sub, peer_addr, frames).await;
                            }
                            Err(e) => {
                                tracing::warn!("inbound PQ handshake failed: {}", e);
                                met.write().connections_failed += 1;
                            }
                        }
                    });
                }
                Err(e) => tracing::error!("PQ P2P accept: {}", e),
            }
        }
    });

    for line in bootstrap {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        match parse_quantos_multiaddr(t) {
            Ok(target) => {
                if peer_manager.is_banned(&target.peer_id) {
                    tracing::warn!("bootstrap skip banned peer {}", target.peer_id);
                    continue;
                }
                if peers.len() >= max_peers {
                    tracing::warn!("bootstrap skip (already at max_peers)");
                    continue;
                }

                let dil = mldsa.clone();
                let kem = kem.clone();
                let peers_i = peers.clone();
                let fwd = forward_tx.clone();
                let cp = connected_peers.clone();
                let met = metrics.clone();
                let sub = subscribed_topics.clone();
                let pm = peer_manager.clone();
                let frames = inbound_frames_rl.clone();

                tokio::spawn(async move {
                    let mut sock = match TcpStream::connect(target.socket).await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!("bootstrap connect {}: {}", target.socket, e);
                            return;
                        }
                    };
                    match timed_client_handshake(&mut sock, &dil, &kem, target.peer_id).await {
                        Ok(sec) => {
                            let remote = sec.remote_peer_id;
                            let peer_addr = Some(multiaddr_for_peer(target.socket, remote));
                            spawn_peer_tasks(sock, sec, peers_i, pm, fwd, cp, met, sub, peer_addr, frames).await;
                        }
                        Err(e) => {
                            tracing::warn!("bootstrap PQ handshake {}: {}", target.socket, e);
                            met.write().connections_failed += 1;
                        }
                    }
                });
            }
            Err(e) => tracing::warn!("bootstrap skip {:?}: {}", line, e),
        }
    }

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            PqCommand::Dial { socket, expected_peer } => {
                if peer_manager.is_banned(&expected_peer) {
                    tracing::warn!("dial skip banned peer {}", expected_peer);
                    continue;
                }
                if peers.contains_key(&expected_peer) {
                    continue;
                }
                if peers.len() >= max_peers {
                    tracing::warn!("dial skip (max_peers)");
                    metrics.write().connections_failed += 1;
                    continue;
                }

                let dil = mldsa.clone();
                let kem = kem.clone();
                let peers_i = peers.clone();
                let fwd = forward_tx.clone();
                let cp = connected_peers.clone();
                let met = metrics.clone();
                let sub = subscribed_topics.clone();
                let pm = peer_manager.clone();
                let frames = inbound_frames_rl.clone();

                tokio::spawn(async move {
                    let mut sock = match TcpStream::connect(socket).await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!("dial {}: {}", socket, e);
                            met.write().connections_failed += 1;
                            return;
                        }
                    };
                    match timed_client_handshake(&mut sock, &dil, &kem, expected_peer).await {
                        Ok(sec) => {
                            let remote = sec.remote_peer_id;
                            let peer_addr = Some(multiaddr_for_peer(socket, remote));
                            spawn_peer_tasks(sock, sec, peers_i, pm, fwd, cp, met, sub, peer_addr, frames).await;
                        }
                        Err(e) => {
                            tracing::warn!("outbound PQ handshake {}: {}", socket, e);
                            met.write().connections_failed += 1;
                        }
                    }
                });
            }
            PqCommand::Publish { topic, payload } => {
                let env = GossipEnvelope { topic, payload };
                let mut ids: Vec<PeerId> = peers.iter().map(|e| *e.key()).collect();
                if !ids.is_empty() {
                    let mut rng = rand::thread_rng();
                    ids.shuffle(&mut rng);
                    let k = mesh_n.clamp(1, ids.len());
                    for pid in ids.into_iter().take(k) {
                        if let Some(tx) = peers.get(&pid) {
                            let _ = tx.tx.try_send(env.clone());
                        }
                    }
                    metrics.write().messages_sent += k as u64;
                }
            }
            PqCommand::Disconnect { peer_id } => {
                if let Some(conn) = peers.remove(&peer_id).map(|(_, v)| v) {
                    let _ = conn.shutdown.send(());
                }
                inbound_frames_rl.remove(&peer_id);
                connected_peers.remove(&peer_id);
                peer_manager.remove_peer(&peer_id);
                metrics.write().peer_count = connected_peers.len();
            }
        }
    }

    tracing::info!("PQ P2P command channel closed; runtime stopping");
}
