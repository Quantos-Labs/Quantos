// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Fuzz target for `L0FinalityProof` deserialization.
//!
//! L0 finality proofs are relayed cross-chain and deserialized by
//! `RelayDispatcher` / `FinalityHub` (`src/l0/relay.rs`, `src/l0/hub.rs`)
//! via `bincode::deserialize::<L0FinalityProof>`. The proof originates
//! from potentially untrusted relayer nodes. The decode must never panic,
//! OOM, or allow unbounded Vec allocation on adversarial input.

#![no_main]
use libfuzzer_sys::fuzz_target;
use quantos::l0::L0FinalityProof;

fuzz_target!(|data: &[u8]| {
    let _ = bincode::deserialize::<L0FinalityProof>(data);
});
