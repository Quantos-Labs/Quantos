// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Fuzz target for `ExternalCheckpoint` deserialization.
//!
//! External checkpoints are submitted via RPC (`submit_external_checkpoint`
//! in `src/rpc/server.rs`) and gossiped among nodes
//! (`src/l0/gossip.rs::CheckpointGossip`). Both paths call
//! `bincode::deserialize::<ExternalCheckpoint>` on data from untrusted
//! sources (any RPC caller or any P2P peer). The decode must never panic
//! or trigger unbounded allocation regardless of input bytes.

#![no_main]
use libfuzzer_sys::fuzz_target;
use quantos::l0::ExternalCheckpoint;

fuzz_target!(|data: &[u8]| {
    let _ = bincode::deserialize::<ExternalCheckpoint>(data);
});
