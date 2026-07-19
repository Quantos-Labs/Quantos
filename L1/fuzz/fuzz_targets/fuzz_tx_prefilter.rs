//! Fuzz target for `prefilter_tx_bytes`, the stateless "drop obvious garbage"
//! gate applied to raw transaction bytes before expensive signature
//! verification in `Mempool::validate_transaction`
//! (see `src/mempool/mod.rs` and `src/network/prefilter.rs`).
//!
//! This function runs on every inbound transaction (RPC + gossip) before any
//! other validation, so it must never panic on arbitrary attacker bytes.

#![no_main]
use libfuzzer_sys::fuzz_target;
use quantos::network::prefilter_tx_bytes;

fuzz_target!(|data: &[u8]| {
    let _ = prefilter_tx_bytes(data);
});
