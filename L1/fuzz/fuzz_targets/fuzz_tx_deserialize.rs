//! Fuzz target for the transaction deserialization boundary.
//!
//! `SignedTransaction` bytes arrive from fully untrusted sources:
//!   - RPC `send_raw_transaction` / `send_raw_transactions` (hex-decoded, then
//!     `bincode::deserialize`), see `src/rpc/server.rs` and
//!     `src/rpc/handlers.rs::deserialize_transaction`.
//!   - P2P gossip `NetworkMessage::NewTransaction` / `TransactionBatch`.
//!
//! Goal: `bincode::deserialize::<SignedTransaction>` must never panic
//! (no OOM via unbounded Vec/String allocation, no arithmetic overflow,
//! no unwrap on attacker-controlled data) regardless of input bytes.

#![no_main]
use libfuzzer_sys::fuzz_target;
use quantos::types::SignedTransaction;

fuzz_target!(|data: &[u8]| {
    let _ = bincode::deserialize::<SignedTransaction>(data);
});
