//! Fuzz target for external chain proof JSON parsing.
//!
//! `submit_external_checkpoint` (`src/rpc/server.rs`) accepts a
//! `proof_json: String` from any RPC caller and runs
//! `serde_json::from_str::<ChainProof>` on it directly, before any
//! cryptographic verification. Must never panic on malformed/adversarial
//! JSON.

#![no_main]
use libfuzzer_sys::fuzz_target;
use quantos::l0::external::ChainProof;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<ChainProof>(s);
    }
});
