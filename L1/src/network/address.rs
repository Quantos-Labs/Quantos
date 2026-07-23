// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Minimal multiaddr parsing for PQ TCP dials (`/ip4/.../tcp/.../p2p/...`).

use std::net::SocketAddr;

use crate::network::peer_id::PeerId;
use crate::network::{NetworkError, NetworkResult};

/// Parsed dial target for [`crate::network::p2p::P2PNetwork::connect_to_peer`].
#[derive(Clone, Debug)]
pub struct DialTarget {
    pub socket: SocketAddr,
    pub peer_id: PeerId,
}

/// Parses `/ip4/<addr>/tcp/<port>/p2p/<base58>` or `/ip6/<addr>/tcp/<port>/p2p/<base58>`.
pub fn parse_quantos_multiaddr(s: &str) -> NetworkResult<DialTarget> {
    let s = s.trim();
    if !s.starts_with('/') {
        return Err(NetworkError::InvalidAddress("multiaddr must start with '/'".into()));
    }
    let parts: Vec<&str> = s.trim_matches('/').split('/').filter(|p| !p.is_empty()).collect();
    if parts.len() < 6 {
        return Err(NetworkError::InvalidAddress(
            "expected /ip4|ip6/.../tcp/PORT/p2p/PEER_ID".into(),
        ));
    }

    let mut ip: Option<std::net::IpAddr> = None;
    let mut port: Option<u16> = None;
    let mut peer_id: Option<PeerId> = None;

    let mut i = 0;
    while i < parts.len() {
        match parts[i] {
            "ip4" => {
                let addr = parts.get(i + 1).ok_or_else(|| {
                    NetworkError::InvalidAddress("missing IPv4 after ip4".into())
                })?;
                ip = Some(std::net::IpAddr::V4(
                    addr.parse()
                        .map_err(|e| NetworkError::InvalidAddress(format!("bad ipv4: {}", e)))?,
                ));
                i += 2;
            }
            "ip6" => {
                let addr = parts.get(i + 1).ok_or_else(|| {
                    NetworkError::InvalidAddress("missing IPv6 after ip6".into())
                })?;
                ip = Some(std::net::IpAddr::V6(
                    addr.parse()
                        .map_err(|e| NetworkError::InvalidAddress(format!("bad ipv6: {}", e)))?,
                ));
                i += 2;
            }
            "tcp" => {
                let p = parts.get(i + 1).ok_or_else(|| {
                    NetworkError::InvalidAddress("missing port after tcp".into())
                })?;
                port = Some(
                    p.parse()
                        .map_err(|e| NetworkError::InvalidAddress(format!("bad tcp port: {}", e)))?,
                );
                i += 2;
            }
            "p2p" => {
                let id = parts.get(i + 1).ok_or_else(|| {
                    NetworkError::InvalidAddress("missing peer id after p2p".into())
                })?;
                peer_id = Some(PeerId::from_base58(id).map_err(|e| {
                    NetworkError::InvalidAddress(format!("bad p2p peer id: {}", e))
                })?);
                i += 2;
            }
            other => {
                return Err(NetworkError::InvalidAddress(format!(
                    "unsupported multiaddr component: {}",
                    other
                )));
            }
        }
    }

    let socket = SocketAddr::new(
        ip.ok_or_else(|| NetworkError::InvalidAddress("missing ip4/ip6".into()))?,
        port.ok_or_else(|| NetworkError::InvalidAddress("missing tcp port".into()))?,
    );
    let peer_id = peer_id.ok_or_else(|| NetworkError::InvalidAddress("missing /p2p/<PeerId>".into()))?;

    Ok(DialTarget { socket, peer_id })
}
