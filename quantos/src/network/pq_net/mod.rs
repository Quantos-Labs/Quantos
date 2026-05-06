//! Native Quantos P2P over TCP: ML-DSA + Kyber768 handshake, AES-256-GCM transport.

mod handshake;
mod runtime;
mod session_crypto;

pub use runtime::{run_quantos_pq_p2p, PqCommand};
