//! Fuzz target for P2P `NetworkMessage` deserialization.
//!
//! After the PQ-encrypted transport frame is decrypted (`src/network/pq_net/runtime.rs`),
//! the plaintext payload is `bincode::deserialize::<NetworkMessage>`-decoded
//! directly from bytes an authenticated-but-potentially-malicious or
//! compromised peer controls. This must never panic.

#![no_main]
use libfuzzer_sys::fuzz_target;
use quantos::network::NetworkMessage;

fuzz_target!(|data: &[u8]| {
    let _ = bincode::deserialize::<NetworkMessage>(data);
});
